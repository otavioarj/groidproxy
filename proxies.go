package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

func setupHTTPProxy(proxy, client net.Conn, firstData []byte, host string, port int) error {
	// Extract domain from HTTP request for blacklist checking
	var targetHost string
	data := string(firstData)
	debugf("=== SETUP HTTP PROXY DEBUG ===")
	debugf("Target: %s:%d", host, port)
	debugf("FirstData length: %d", len(firstData))
	//debugf("FirstData preview: %s", string(firstData[:min(200, len(firstData))]))

	if strings.HasPrefix(data, "CONNECT ") {
		// HTTPS CONNECT request - extract host from CONNECT line
		lines := strings.Split(data, "\r\n")
		if len(lines) > 0 {
			parts := strings.Fields(lines[0])
			if len(parts) >= 2 {
				// CONNECT host:port HTTP/1.1
				hostPort := parts[1]
				if idx := strings.LastIndex(hostPort, ":"); idx != -1 {
					targetHost = hostPort[:idx]
				} else {
					targetHost = hostPort
				}
			}
		}
	} else if strings.Contains(data, " HTTP/") {
		// Regular HTTP request - extract from Host header
		lines := strings.Split(data, "\r\n")
		for _, line := range lines {
			if strings.HasPrefix(strings.ToLower(line), "host:") {
				targetHost = strings.TrimSpace(strings.TrimPrefix(strings.ToLower(line), "host:"))
				// Remove port if present
				if idx := strings.LastIndex(targetHost, ":"); idx != -1 {
					targetHost = targetHost[:idx]
				}
				break
			}
		}
	}

	// Check blacklist with extracted domain
	if targetHost != "" && isBlacklisted(targetHost) {
		debugf("Blocked HTTP connection to %s", targetHost)
		return fmt.Errorf("blocked by blacklist: %s", targetHost)
	}

	// If no domain found, check IP
	if targetHost == "" && isBlacklisted(host) {
		debugf("Blocked HTTP connection to IP %s", host)
		return fmt.Errorf("blocked by blacklist: %s", host)
	}

	// ALWAYS use CONNECT method for HTTP proxy compatibility
	connectReq := fmt.Sprintf("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n",
		host, port, host, port)
	debugf("Proxy connection is to: %s", proxy.RemoteAddr())
	debugf("Sending CONNECT for target: %s:%d", host, port)

	_, err := proxy.Write([]byte(connectReq))
	if err != nil {
		return fmt.Errorf("failed to send CONNECT request: %v", err)
	}

	// Read CONNECT response from proxy
	resp := make([]byte, 1024)
	n, err := proxy.Read(resp)
	if err != nil {
		return fmt.Errorf("failed to read CONNECT response: %v", err)
	}

	// Check for successful CONNECT response (200 Connection established)
	responseStr := string(resp[:n])
	if !strings.Contains(responseStr, "200") {
		debugf("HTTP proxy CONNECT failed: %s", strings.TrimSpace(responseStr))
		return fmt.Errorf("proxy CONNECT failed: %s", strings.TrimSpace(responseStr))
	}

	debugf("HTTP proxy CONNECT successful, tunnel established")

	// Now send the original client data through the established tunnel
	_, err = proxy.Write(firstData)
	if err != nil {
		return fmt.Errorf("failed to send original data through tunnel: %v", err)
	}

	debugf("Original client data sent through HTTP proxy tunnel")
	return nil
}

// Doesn't support IPV6 hehe :(
func setupSOCKS5Proxy(proxy net.Conn, host string, port int) error {
	// SOCKS5 handshake
	proxy.Write([]byte{0x05, 0x01, 0x00}) // Version 5, 1 method, no auth

	resp := make([]byte, 2)
	if _, err := io.ReadFull(proxy, resp); err != nil {
		return err
	}

	if resp[0] != 0x05 || resp[1] != 0x00 {
		return fmt.Errorf("SOCKS5 handshake failed")
	}

	// Check if host is IP or domain
	ip := net.ParseIP(host)
	targetDomain := ""

	// If it's not an IP, it's a domain
	if ip == nil {
		targetDomain = host
	}

	// Check blacklist
	if targetDomain != "" && isBlacklisted(targetDomain) {
		debugf("Blocked SOCKS5 connection to domain %s", targetDomain)
		// Send SOCKS5 error response (connection refused)
		errorResp := []byte{0x05, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		proxy.Write(errorResp)
		return fmt.Errorf("blocked by blacklist: %s", targetDomain)
	}

	// Also check IP blacklist
	if isBlacklisted(host) {
		debugf("Blocked SOCKS5 connection to %s", host)
		// Send SOCKS5 error response (connection refused)
		errorResp := []byte{0x05, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		proxy.Write(errorResp)
		return fmt.Errorf("blocked by blacklist: %s", host)
	}

	// Build connect request
	req := []byte{0x05, 0x01, 0x00} // Version 5, connect, reserved

	// Add destination
	if ip != nil && ip.To4() != nil {
		req = append(req, 0x01) // IPv4
		req = append(req, ip.To4()...)
	} else if ip != nil {
		req = append(req, 0x04) // IPv6
		req = append(req, ip.To16()...)
	} else {
		req = append(req, 0x03) // Domain
		req = append(req, byte(len(host)))
		req = append(req, []byte(host)...)
	}

	// Add port
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))
	req = append(req, portBytes...)

	// Send connect
	if _, err := proxy.Write(req); err != nil {
		return err
	}

	// Read response
	resp = make([]byte, 4)
	if _, err := io.ReadFull(proxy, resp); err != nil {
		return err
	}

	if resp[1] != 0x00 {
		return fmt.Errorf("SOCKS5 connect failed: %d", resp[1])
	}

	// Skip bind address
	switch resp[3] {
	case 0x01: // IPv4
		io.ReadFull(proxy, make([]byte, 4+2))
	case 0x03: // Domain
		var len byte
		binary.Read(proxy, binary.BigEndian, &len)
		io.ReadFull(proxy, make([]byte, int(len)+2))
	case 0x04: // IPv6
		io.ReadFull(proxy, make([]byte, 16+2))
	}

	return nil
}

func runProxy() {
	listener, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", config.LocalPort))
	if err != nil {
		fatal("Failed to start proxy: %v", err)
	}
	defer listener.Close()

	for {
		client, err := listener.Accept()
		if err != nil {
			continue
		}

		go handleClient(client)
	}
}

func parseProxyAddr() {
	if config.ProxyAddr == "" && config.SaveDB != "" {
		config.ProxyType = "capture"
		return
	}
	if config.ProxyAddr == "" {
		return
	}
	addr := config.ProxyAddr

	// Determine proxy type
	if strings.HasPrefix(addr, "http://") {
		config.ProxyType = "http"
		addr = strings.TrimPrefix(addr, "http://")
	} else if strings.HasPrefix(addr, "socks5://") {
		config.ProxyType = "socks5"
		addr = strings.TrimPrefix(addr, "socks5://")
	} else if !strings.Contains(addr, "://") {
		config.ProxyType = "redirect"
	} else {
		fatal("Unknown proxy type")
	}

	// Parse host:port
	parts := strings.Split(addr, ":")
	if len(parts) != 2 {
		fatal("Invalid proxy address format")
	}

	config.ProxyHost = parts[0]
	port, err := strconv.Atoi(parts[1])
	if err != nil {
		fatal("Invalid proxy port")
	}
	config.ProxyPort = port
}
