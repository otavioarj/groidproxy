package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

func setupHTTPProxy(proxy net.Conn, firstData []byte, host string, port int) error {
	// Check if it's HTTP request
	data := string(firstData)

	// Extract domain from HTTP request
	var targetHost string

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

	// Continue with normal proxy setup
	if strings.HasPrefix(data, "CONNECT ") {
		// HTTPS CONNECT - forward as-is
		proxy.Write(firstData)
	} else if strings.Contains(data, " HTTP/") {
		// HTTP request - convert to absolute URL
		lines := strings.Split(data, "\r\n")
		if len(lines) > 0 {
			parts := strings.Fields(lines[0])
			if len(parts) >= 3 {
				// Keep original port, not proxy port!
				scheme := "http"
				if port == 443 {
					scheme = "https"
				}
				absoluteURL := fmt.Sprintf("%s://%s:%d%s", scheme, host, port, parts[1])
				lines[0] = fmt.Sprintf("%s %s %s", parts[0], absoluteURL, parts[2])

				proxy.Write([]byte(strings.Join(lines, "\r\n")))
				return nil
			}
		}
		// Fallback - send as-is
		proxy.Write(firstData)
	} else {
		// Not HTTP - send as-is
		proxy.Write(firstData)
	}

	return nil
}

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
