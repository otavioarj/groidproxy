package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// ConnType represents detected connection protocol
type ConnType int

const (
	ConnHTTP    ConnType = iota // Plain HTTP (GET, POST, etc.)
	ConnCONNECT                 // HTTP CONNECT tunnel request
	ConnTLS                     // Direct TLS handshake
	ConnUnknown                 // Unknown/binary protocol
)

// Pre-allocated HTTP method prefixes for efficient protocol detection
var httpMethods = [][]byte{
	[]byte("GET "),
	[]byte("POST "),
	[]byte("PUT "),
	[]byte("DELETE "),
	[]byte("HEAD "),
	[]byte("OPTIONS "),
	[]byte("PATCH "),
	[]byte("TRACE "),
}

// Buffer pools to reduce allocations in hot paths
var (
	bufPool4K = sync.Pool{New: func() interface{} { return make([]byte, 4*1024) }}
	bufPool1K = sync.Pool{New: func() interface{} { return make([]byte, 1024) }}
)

func (c ConnType) String() string {
	return [...]string{"HTTP", "CONNECT", "TLS", "Unknown"}[c]
}

// detectConnType analyzes first bytes to determine connection type
func detectConnType(data []byte) ConnType {
	if len(data) == 0 {
		return ConnUnknown
	}

	if isTLSHandshake(data) {
		return ConnTLS
	}

	if bytes.HasPrefix(data, []byte("CONNECT ")) {
		return ConnCONNECT
	}

	// Check HTTP methods using pre-allocated slices
	for _, m := range httpMethods {
		if bytes.HasPrefix(data, m) {
			return ConnHTTP
		}
	}

	return ConnUnknown
}

// handleClient handles incoming transparent proxy connections
// Unified handler - integrates previous handleClientWithCapture
func handleClient(client net.Conn) {
	defer client.Close()

	host, port, err := getOriginalDst(client)
	if err != nil {
		debugf("Failed to get original destination: %v", err)
		return
	}
	debugf("New connection to %s:%d", host, port)

	buf := bufPool4K.Get().([]byte)
	n, err := client.Read(buf)
	if err != nil {
		bufPool4K.Put(buf)
		return
	}
	firstData := make([]byte, n)
	copy(firstData, buf[:n])
	bufPool4K.Put(buf)

	connType := detectConnType(firstData)
	debugf("Detected connection type: %s", connType)

	switch connType {
	case ConnTLS, ConnCONNECT:
		handleHTTPS(client, firstData, host, port, connType)
	case ConnHTTP:
		handleHTTP(client, firstData, host, port)
	default:
		handleTunnel(client, firstData, host, port, true)
	}
}

// handleHTTPS handles TLS and CONNECT requests
// Routes to interception or tunneling based on config
func handleHTTPS(client net.Conn, firstData []byte, host string, port int, connType ConnType) {
	// TLS interception if capture mode with certificate
	if config.SaveDB != "" && config.TLSCert != "" {
		handleTLSIntercept(client, host, port, firstData)
		return
	}

	// For explicit CONNECT requests (client using us as HTTP proxy),
	// we must acknowledge the tunnel before client sends TLS handshake
	if connType == ConnCONNECT {
		if _, err := client.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
			debugf("Failed to send CONNECT response: %v", err)
			return
		}
		// Now read the actual TLS ClientHello that follows
		buf := bufPool4K.Get().([]byte)
		n, err := client.Read(buf)
		if err != nil {
			bufPool4K.Put(buf)
			debugf("Failed to read post-CONNECT data: %v", err)
			return
		}
		firstData = make([]byte, n)
		copy(firstData, buf[:n])
		bufPool4K.Put(buf)
	}

	handleTunnel(client, firstData, host, port, true)
}

// handleHTTP handles plain HTTP requests
// Supports capture mode and proxy forwarding
func handleHTTP(client net.Conn, firstData []byte, host string, port int) {
	// Single blacklist check point for HTTP traffic
	targetHost := extractHTTPHost(firstData, host)
	if isBlacklisted(targetHost) || isBlacklisted(host) {
		debugf("Blocked connection to %s", targetHost)
		return
	}

	if config.ProxyType == "capture" {
		handleDirectHTTP(client, firstData, host, port)
		return
	}

	handleTunnel(client, firstData, host, port, false)
}

// handleDirectHTTP connects directly to target for HTTP capture
func handleDirectHTTP(client net.Conn, firstData []byte, host string, port int) {
	server, err := net.DialTimeout("tcp",
		fmt.Sprintf("%s:%d", host, port),
		time.Duration(config.Timeout)*time.Second)
	if err != nil {
		debugf("Direct connection failed: %v", err)
		return
	}
	defer server.Close()

	server.Write(firstData)

	if config.SaveDB != "" {
		captureHTTP(client, server, firstData, host, port)
	} else {
		relayBidirectional(client, server, fmt.Sprintf("%s:%d", host, port), config.Stats)
	}
}

// handleTunnel establishes tunnel through upstream proxy
// isTunnel: true for CONNECT-based tunnel, false for plain HTTP
func handleTunnel(client net.Conn, firstData []byte, host string, port int, isTunnel bool) {
	for {
		proxy, err := net.DialTimeout("tcp",
			fmt.Sprintf("%s:%d", config.ProxyHost, config.ProxyPort),
			time.Duration(config.Timeout)*time.Second)
		if err != nil {
			debugf("Proxy connection failed: %v", err)
			return
		}

		err = setupUpstreamConn(proxy, firstData, host, port, isTunnel)
		if err != nil {
			debugf("Upstream setup failed: %v", err)
			proxy.Close()
			return
		}

		if config.SaveDB != "" && !isTunnel {
			captureHTTP(client, proxy, firstData, host, port)
			proxy.Close()
			return
		}

		proxyDied := relayBidirectional(client, proxy, fmt.Sprintf("%s:%d", host, port), config.Stats)
		proxy.Close()

		if !proxyDied || !isClientAlive(client) {
			break
		}

		debugf("Proxy died, client alive - reconnecting...")
		firstData = nil
	}
}

// setupUpstreamConn configures upstream proxy connection
// Handles both HTTP and SOCKS5 proxy types with tunnel/direct modes
func setupUpstreamConn(proxy net.Conn, firstData []byte, host string, port int, isTunnel bool) error {
	switch config.ProxyType {
	case "http":
		if isTunnel {
			if err := setupHTTPTunnel(proxy, host, port); err != nil {
				return err
			}
		} else {
			if err := setupHTTPDirect(proxy, firstData, host, port); err != nil {
				return err
			}
		}
		// Forward original data through established tunnel
		if isTunnel && firstData != nil {
			_, err := proxy.Write(firstData)
			return err
		}
		return nil

	case "socks5":
		if err := setupSOCKS5Proxy(proxy, host, port); err != nil {
			return err
		}
		if firstData != nil {
			_, err := proxy.Write(firstData)
			return err
		}
		return nil

	default:
		return fmt.Errorf("unsupported proxy type: %s", config.ProxyType)
	}
}

// extractHTTPHost extracts hostname from HTTP Host header
// Uses byte operations to avoid string allocations
func extractHTTPHost(data []byte, fallback string) string {
	// Case-insensitive search for Host header
	lower := bytes.ToLower(data)
	idx := bytes.Index(lower, []byte("\r\nhost:"))
	if idx == -1 {
		if bytes.HasPrefix(lower, []byte("host:")) {
			idx = -2 // Header at start (no preceding \r\n)
		} else {
			return fallback
		}
	}

	// Calculate value start position
	start := idx + 7
	if idx == -2 {
		start = 5
	}

	// Find end of header value
	end := bytes.Index(data[start:], []byte("\r\n"))
	if end == -1 {
		end = len(data) - start
	}

	// Extract host, stripping port if present
	hostVal := bytes.TrimSpace(data[start : start+end])
	if colonIdx := bytes.LastIndexByte(hostVal, ':'); colonIdx != -1 {
		hostVal = hostVal[:colonIdx]
	}

	if len(hostVal) == 0 {
		return fallback
	}
	return string(hostVal)
}

// getOriginalDst retrieves original destination from iptables REDIRECT
// Uses SO_ORIGINAL_DST socket option to get the pre-NAT destination
// Required for transparent proxy operation on Android/Linux
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

	// Query kernel for original destination address
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

	// Convert network byte order to host byte order
	ip := net.IPv4(addr.Addr[0], addr.Addr[1], addr.Addr[2], addr.Addr[3])
	port := int(addr.Port>>8) | int(addr.Port&0xff)<<8

	return ip.String(), port, nil
}

// isClientAlive checks if client connection is still active
// Uses zero-byte write followed by deadline-based read check
func isClientAlive(client net.Conn) bool {
	// Zero-byte write fails immediately if connection is closed
	client.SetWriteDeadline(time.Now().Add(1 * time.Millisecond))
	_, err := client.Write([]byte{})
	client.SetWriteDeadline(time.Time{})

	if err != nil {
		return false
	}

	// Check readability with short timeout
	client.SetReadDeadline(time.Now().Add(1 * time.Millisecond))
	var peek [1]byte
	n, err := client.Read(peek[:])
	client.SetReadDeadline(time.Time{})

	if n > 0 {
		debugf("Warning: isClientAlive consumed 1 byte during check")
		return true
	}
	if err == io.EOF {
		return false
	}
	// Timeout indicates alive connection with no pending data
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return true
	}

	return false
}

// relayBidirectional performs bidirectional data relay between connections
// Returns true if proxy died first (enables reconnection), false if client died
// Uses channel coordination to detect which side failed and enable early exit
func relayBidirectional(client, proxy net.Conn, target string, showStats bool) bool {
	done := make(chan bool, 2)           // Signals goroutine completion
	proxyDiedChan := make(chan struct{}) // Coordinates early exit on proxy failure
	var clientToProxy, proxyToClient int64
	var proxyDied, clientDied bool

	// Client to Proxy goroutine
	go func() {
		defer func() { done <- true }()
		buf := bufPool4K.Get().([]byte)
		defer bufPool4K.Put(buf)

		for {
			// Check if proxy already died (early exit)
			select {
			case <-proxyDiedChan:
				return
			default:
			}

			n, err := client.Read(buf)
			if err != nil {
				clientDied = true
				break
			}

			if _, err := proxy.Write(buf[:n]); err != nil {
				proxyDied = true
				close(proxyDiedChan)
				break
			}

			clientToProxy += int64(n)
			if showStats {
				printStats(target, clientToProxy, proxyToClient)
			}
		}
	}()

	// Proxy to Client goroutine
	go func() {
		defer func() { done <- true }()
		buf := bufPool4K.Get().([]byte)
		defer bufPool4K.Put(buf)

		for {
			// Check if proxy already died (early exit)
			select {
			case <-proxyDiedChan:
				return
			default:
			}

			n, err := proxy.Read(buf)
			if err != nil {
				proxyDied = true
				// Safe close - check if already closed
				select {
				case <-proxyDiedChan:
				default:
					close(proxyDiedChan)
				}
				break
			}

			if _, err := client.Write(buf[:n]); err != nil {
				clientDied = true
				break
			}

			proxyToClient += int64(n)
			if showStats {
				printStats(target, clientToProxy, proxyToClient)
			}
		}
	}()

	// Wait for both goroutines to complete
	<-done
	<-done

	if showStats {
		status := "CLOSED"
		if proxyDied {
			status = "PROXY DIED"
		} else if clientDied {
			status = "CLIENT DIED"
		}
		fmt.Printf("\r[%s] %s - TX: %s, RX: %s [%s]\n",
			time.Now().Format("15:04:05"), target,
			formatBytes(clientToProxy), formatBytes(proxyToClient), status)
	}

	return proxyDied
}

// prefixedConn wraps connection with pre-read data buffer
// Supports partial reads by tracking offset into prefix data
type prefixedConn struct {
	net.Conn
	prefix []byte
	offset int
}

func (p *prefixedConn) Read(b []byte) (int, error) {
	// Drain remaining prefix data first
	if p.offset < len(p.prefix) {
		n := copy(b, p.prefix[p.offset:])
		p.offset += n
		return n, nil
	}
	return p.Conn.Read(b)
}

// debugConn wraps connection with I/O logging
type debugConn struct {
	net.Conn
	name string
}

func (d *debugConn) Read(b []byte) (int, error) {
	n, err := d.Conn.Read(b)
	if n > 0 {
		debugf("%s READ: %d bytes", d.name, n)
	}
	return n, err
}

func (d *debugConn) Write(b []byte) (int, error) {
	n, err := d.Conn.Write(b)
	debugf("%s WRITE: %d bytes", d.name, n)
	return n, err
}

// parseConnectTarget extracts host from CONNECT request
func parseConnectTarget(data []byte) string {
	lineEnd := bytes.Index(data, []byte("\r\n"))
	if lineEnd == -1 {
		lineEnd = len(data)
	}

	parts := bytes.Fields(data[:lineEnd])
	if len(parts) < 2 || !bytes.Equal(parts[0], []byte("CONNECT")) {
		return ""
	}

	hostPort := parts[1]
	if idx := bytes.LastIndexByte(hostPort, ':'); idx != -1 {
		return string(hostPort[:idx])
	}
	return string(hostPort)
}

// determineTargetHostname resolves actual hostname from connection data
func determineTargetHostname(host string, data []byte, isConnect bool) string {
	if isConnect {
		return parseConnectTarget(data)
	}
	if sni := extractSNIFromClientHello(data); sni != "" {
		return sni
	}
	debugf("No hostname from TLS context, using IP")
	return host
}

// handleTLSIntercept performs MITM TLS interception for traffic capture
// Flow: Client <-> [GroidProxy with generated cert] <-> Server
// Decrypts traffic to capture cleartext HTTP inside TLS
func handleTLSIntercept(client net.Conn, host string, port int, data []byte) {
	isConnect := bytes.HasPrefix(data, []byte("CONNECT "))

	// Wrap client with prefixed data to replay initial bytes during TLS handshake
	if len(data) > 0 {
		client = &prefixedConn{Conn: client, prefix: data, offset: 0}
	}

	// Determine actual hostname from CONNECT request or SNI extension
	realHost := determineTargetHostname(host, data, isConnect)
	debugf("TLS interception - Host: %s, Real: %s", host, realHost)

	// Setup TLS with client using dynamically generated certificate
	tlsClient, err := setupClientTLSConnection(client, realHost, isConnect)
	if err != nil {
		debugf("Client TLS setup failed: %v", err)
		return
	}
	defer tlsClient.Close()

	// Connect to real server (directly or through upstream proxy)
	tlsServer, err := setupServerTLSConnection(realHost, host, port)
	if err != nil {
		debugf("Server TLS setup failed: %v", err)
		return
	}
	defer tlsServer.Close()

	// Relay and capture decrypted traffic
	captureTLS(tlsClient, tlsServer, fmt.Sprintf("%s:%d", realHost, port))
}
