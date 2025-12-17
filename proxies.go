package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

// setupHTTPTunnel establishes CONNECT tunnel through HTTP proxy
// Used for HTTPS/TLS connections needing end-to-end encryption
func setupHTTPTunnel(proxy net.Conn, host string, port int) error {
	connectReq := fmt.Sprintf("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n",
		host, port, host, port)

	if _, err := proxy.Write([]byte(connectReq)); err != nil {
		return fmt.Errorf("CONNECT write failed: %v", err)
	}

	resp := bufPool1K.Get().([]byte)
	defer bufPool1K.Put(resp)

	n, err := proxy.Read(resp)
	if err != nil {
		return fmt.Errorf("CONNECT response read failed: %v", err)
	}

	if !bytes.Contains(resp[:n], []byte("200")) {
		return fmt.Errorf("CONNECT rejected: %s", strings.TrimSpace(string(resp[:n])))
	}

	debugf("HTTP tunnel established to %s:%d", host, port)
	return nil
}

// setupHTTPDirect forwards plain HTTP request through proxy
// Rewrites relative URL to absolute URL per RFC 7230
// BUG 6 FIX: Removed duplicate blacklist check (now only in handleHTTP)
func setupHTTPDirect(proxy net.Conn, firstData []byte, host string, port int) error {
	// Rewrite request with absolute URL
	rewritten := rewriteHTTPAbsolute(firstData, host, port)

	if _, err := proxy.Write(rewritten); err != nil {
		return fmt.Errorf("HTTP request write failed: %v", err)
	}

	debugf("HTTP request forwarded to proxy for %s:%d", host, port)
	return nil
}

// rewriteHTTPAbsolute converts relative URL to absolute URL for proxy
// "GET /path HTTP/1.1" -> "GET http://host:port/path HTTP/1.1"
func rewriteHTTPAbsolute(data []byte, host string, port int) []byte {
	lineEnd := bytes.Index(data, []byte("\r\n"))
	if lineEnd == -1 {
		return data
	}

	parts := bytes.SplitN(data[:lineEnd], []byte(" "), 3)
	if len(parts) < 3 {
		return data
	}

	method := parts[0]
	path := parts[1]
	version := parts[2]

	// Skip if already absolute URL
	lowerPath := bytes.ToLower(path)
	if bytes.HasPrefix(lowerPath, []byte("http://")) ||
		bytes.HasPrefix(lowerPath, []byte("https://")) {
		return data
	}

	// Build absolute URL
	var absoluteURL string
	if port == 80 {
		absoluteURL = fmt.Sprintf("http://%s%s", host, path)
	} else {
		absoluteURL = fmt.Sprintf("http://%s:%d%s", host, port, path)
	}

	// Reconstruct request
	newLine := fmt.Sprintf("%s %s %s\r\n", method, absoluteURL, version)
	return append([]byte(newLine), data[lineEnd+2:]...)
}

// setupSOCKS5Proxy establishes SOCKS5 connection to target
// BUG 5 FIX: Check blacklist BEFORE handshake
// BUG 7 FIX: Removed redundant blacklist check
func setupSOCKS5Proxy(proxy net.Conn, host string, port int) error {
	// BUG 5 FIX: Check blacklist first, before any network I/O
	if isBlacklisted(host) {
		return fmt.Errorf("blocked: %s", host)
	}

	// Handshake: version 5, 1 method, no auth
	if _, err := proxy.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return err
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(proxy, resp); err != nil {
		return err
	}

	if resp[0] != 0x05 || resp[1] != 0x00 {
		return fmt.Errorf("SOCKS5 handshake failed")
	}

	// Build connect request
	req := []byte{0x05, 0x01, 0x00} // version, connect, reserved

	ip := net.ParseIP(host)
	if ip != nil && ip.To4() != nil {
		req = append(req, 0x01)       // IPv4
		req = append(req, ip.To4()...)
	} else if ip != nil {
		req = append(req, 0x04)        // IPv6
		req = append(req, ip.To16()...)
	} else {
		req = append(req, 0x03)        // Domain
		req = append(req, byte(len(host)))
		req = append(req, []byte(host)...)
	}

	// Append port (big endian)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))
	req = append(req, portBytes...)

	if _, err := proxy.Write(req); err != nil {
		return err
	}

	// Read response header
	resp = make([]byte, 4)
	if _, err := io.ReadFull(proxy, resp); err != nil {
		return err
	}

	if resp[1] != 0x00 {
		return fmt.Errorf("SOCKS5 connect failed: %d", resp[1])
	}

	// Skip bind address based on type
	switch resp[3] {
	case 0x01: // IPv4
		io.ReadFull(proxy, make([]byte, 4+2))
	case 0x03: // Domain
		var length byte
		binary.Read(proxy, binary.BigEndian, &length)
		io.ReadFull(proxy, make([]byte, int(length)+2))
	case 0x04: // IPv6
		io.ReadFull(proxy, make([]byte, 16+2))
	}

	debugf("SOCKS5 tunnel established to %s:%d", host, port)
	return nil
}

// runProxy starts the local transparent proxy listener
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

// parseProxyAddr parses proxy address and sets config type
func parseProxyAddr() {
	if config.ProxyAddr == "" && config.SaveDB != "" {
		config.ProxyType = "capture"
		return
	}
	if config.ProxyAddr == "" {
		return
	}

	addr := config.ProxyAddr

	switch {
	case strings.HasPrefix(addr, "http://"):
		config.ProxyType = "http"
		addr = strings.TrimPrefix(addr, "http://")
	case strings.HasPrefix(addr, "socks5://"):
		config.ProxyType = "socks5"
		addr = strings.TrimPrefix(addr, "socks5://")
	case !strings.Contains(addr, "://"):
		config.ProxyType = "redirect"
	default:
		fatal("Unknown proxy type")
	}

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
