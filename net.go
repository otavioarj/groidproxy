package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

func (d *debugConn) Read(b []byte) (n int, err error) {
	n, err = d.Conn.Read(b)
	if n > 0 {
		debugf("%s READ: %d bytes [%02x %02x %02x %02x...]", d.name, n,
			safeByteAt(b, 0), safeByteAt(b, 1), safeByteAt(b, 2), safeByteAt(b, 3))
	} else {
		debugf("%s READ: %d bytes, err: %v", d.name, n, err)
	}
	return
}

type prefixedConn struct {
	net.Conn
	prefixData []byte
	prefixRead bool
}

// Need this as the client-tls conn we read it before-hand to grab if its a COONECT ou ClientHello
func (p *prefixedConn) Read(b []byte) (n int, err error) {
	if !p.prefixRead {
		// First read: returns data already read
		p.prefixRead = true
		n = copy(b, p.prefixData)
		return n, nil
	}
	// Reads normally
	return p.Conn.Read(b)
}

func (d *debugConn) Write(b []byte) (n int, err error) {
	debugf("%s WRITE: attempting %d bytes [%02x %02x %02x %02x...]", d.name, len(b),
		safeByteAt(b, 0), safeByteAt(b, 1), safeByteAt(b, 2), safeByteAt(b, 3))

	n, err = d.Conn.Write(b)

	if err != nil {
		debugf("%s WRITE: %d bytes written, err: %v", d.name, n, err)
	} else {
		debugf("%s WRITE: %d bytes written successfully", d.name, n)
	}
	return
}

func safeByteAt(b []byte, index int) byte {
	if index < len(b) {
		return b[index]
	}
	return 0x00
}

func handleClient(client net.Conn) {
	defer client.Close()

	// Get original destination
	host, port, err := getOriginalDst(client)
	if err != nil {
		debugf("Failed to get original destination: %v", err)
		return
	}

	debugf("New connection to %s:%d", host, port)

	// For capture/save mode
	if config.SaveDB != "" {
		handleClientWithCapture(client, host, port)
		return
	}

	// Normal proxy flow (no capture-save)
	var proxy net.Conn
	proxy, err = net.DialTimeout("tcp",
		fmt.Sprintf("%s:%d", config.ProxyHost, config.ProxyPort),
		time.Duration(config.Timeout)*time.Second)
	if err != nil {
		debugf("Failed to connect to proxy: %v", err)
		return
	}
	defer proxy.Close()

	// Read first data from client
	buf := make([]byte, 4096)
	n, err := client.Read(buf)
	if err != nil {
		return
	}
	firstData := buf[:n]

	// Handle based on proxy type
	switch config.ProxyType {
	case "http":
		if err := setupHTTPProxy(proxy, firstData, host, port); err != nil {
			logf("HTTP setup failed: %v", err)
			return
		}
	case "socks5":
		if err := setupSOCKS5Proxy(proxy, host, port); err != nil {
			logf("SOCKS5 setup failed: %v", err)
			return
		}
		proxy.Write(firstData)
	}

	// Relay data
	if config.Stats {
		relayWithStats(client, proxy, fmt.Sprintf("%s:%d", host, port))
	} else {
		go io.Copy(proxy, client)
		io.Copy(client, proxy)
	}
}

func handleClientWithCapture(client net.Conn, host string, port int) {
	// Read first data
	buf := make([]byte, 4096)
	n, err := client.Read(buf)
	if err != nil {
		return
	}
	firstData := buf[:n]

	// 1. CONNECT request (proxy mode)
	// 2. TLS handshake

	if bytes.HasPrefix(firstData, []byte("CONNECT ")) || isTLSHandshake(firstData) && config.TLSCert != "" {
		// Handle TLS with unified function
		handleTLSConnection(client, host, port, firstData)
		return
	}

	// For HTTP or direct capture
	var proxy net.Conn

	if config.ProxyType == "capture" {
		// Direct connection
		proxy, err = net.DialTimeout("tcp",
			fmt.Sprintf("%s:%d", host, port),
			time.Duration(config.Timeout)*time.Second)
	} else {
		// Through proxy
		proxy, err = net.DialTimeout("tcp",
			fmt.Sprintf("%s:%d", config.ProxyHost, config.ProxyPort),
			time.Duration(config.Timeout)*time.Second)
	}

	if err != nil {
		debugf("Failed to connect: %v", err)
		return
	}
	defer proxy.Close()

	switch config.ProxyType {
	case "http":
		if err := setupHTTPProxy(proxy, firstData, host, port); err != nil {
			return
		}
	case "socks5":
		if err := setupSOCKS5Proxy(proxy, host, port); err != nil {
			return
		}
		proxy.Write(firstData)
	case "capture":
		// Direct connection - just forward the data
		proxy.Write(firstData)
	}
	// Capture HTTP data
	captureHTTP(client, proxy, firstData, host, port)
}

func getOriginalDst(conn net.Conn) (string, int, error) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return "", 0, fmt.Errorf("not TCP connection")
	}

	file, err := tcpConn.File()
	if err != nil {
		return "", 0, err
	}
	defer file.Close()

	fd := int(file.Fd())

	// Get original destination using SO_ORIGINAL_DST
	var addr syscall.RawSockaddrInet4
	size := uint32(syscall.SizeofSockaddrInet4)

	_, _, errno := syscall.RawSyscall6(
		syscall.SYS_GETSOCKOPT,
		uintptr(fd),
		uintptr(syscall.IPPROTO_IP),
		uintptr(SO_ORIGINAL_DST),
		uintptr(unsafe.Pointer(&addr)),
		uintptr(unsafe.Pointer(&size)),
		0,
	)

	if errno != 0 {
		return "", 0, fmt.Errorf("getsockopt failed: %v", errno)
	}

	// Convert to IP and port
	ip := net.IPv4(addr.Addr[0], addr.Addr[1], addr.Addr[2], addr.Addr[3])
	port := int(addr.Port>>8) | int(addr.Port&0xff)<<8

	return ip.String(), port, nil
}

func parseConnectTarget(connectData []byte) string {
	lines := strings.Split(string(connectData), "\r\n")
	if len(lines) < 1 {
		return ""
	}

	// Parse "CONNECT api.example.com:443 HTTP/1.1"
	parts := strings.Fields(lines[0])
	if len(parts) < 2 || !strings.HasPrefix(parts[0], "CONNECT") {
		return ""
	}

	// Extrair hostname da parte "host:port"
	hostPort := parts[1]
	if idx := strings.LastIndex(hostPort, ":"); idx != -1 {
		return hostPort[:idx]
	}

	return hostPort
}

func determineTargetHostname(host string, port int, connectData []byte, isConnectRequest bool) string {
	if isConnectRequest {
		// Modo proxy HTTP - extrair do CONNECT
		return parseConnectTarget(connectData)
	} else {
		// Modo TLS direto - extrair SNI do ClientHello
		if sni := extractSNIFromClientHello(connectData); sni != "" {
			return sni
		}
		// Fallback para IP (não ideal)
		return host
	}
}

func handleTLSConnection(client net.Conn, host string, port int, connectData []byte) {
	var isConnectRequest bool

	// Parse target host
	if connectData != nil && bytes.HasPrefix(connectData, []byte("CONNECT ")) {
		// CONNECT request
		isConnectRequest = true
	}

	if len(connectData) > 0 {
		client = &prefixedConn{
			Conn:       client,
			prefixData: connectData,
		}
		debugf("Wrapped connection with %d bytes of prefix data", len(connectData))
	}
	realHostname := determineTargetHostname(host, port, connectData, isConnectRequest)
	debugf("Handling TLS - Original: %s:%d, Real hostname: %s", host, port, realHostname)
	// 2. Setup client TLS
	tlsClient, err := setupClientTLSConnection(client, realHostname, isConnectRequest)
	if err != nil {
		debugf("Failed to setup client TLS: %v", err)
		return
	}
	defer tlsClient.Close()

	// 1. Setup server connection
	tlsServer, err := setupServerTLSConnection(realHostname, host, port)
	if err != nil {
		debugf("Failed to setup server TLS: %v", err)
		return
	}
	defer tlsServer.Close()

	// 3. Capture traffic
	captureTLS(tlsClient, tlsServer, fmt.Sprintf("%s:%d", realHostname, port))
}
