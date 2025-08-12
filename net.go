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

	// Read first data from client (only once)
	buf := make([]byte, 4096)
	n, err := client.Read(buf)
	if err != nil {
		return
	}
	firstData := buf[:n]

	// Main reconnection loop
	for {
		debugf("Establishing proxy connection to %s:%d", config.ProxyHost, config.ProxyPort)

		// Create proxy connection
		proxy, err := net.DialTimeout("tcp",
			fmt.Sprintf("%s:%d", config.ProxyHost, config.ProxyPort),
			time.Duration(config.Timeout)*time.Second)
		if err != nil {
			debugf("Failed to connect to proxy: %v", err)
			return
		}

		// Setup proxy connection based on type
		err = setupProxyConnection(proxy, client, firstData, host, port)
		if err != nil {
			debugf("Proxy setup failed: %v", err)
			proxy.Close()
			return
		}

		// Start relay - returns when proxy connection dies
		proxyDied := relayBidirectional(client, proxy, fmt.Sprintf("%s:%d", host, port), config.Stats)

		proxy.Close()

		if !proxyDied {
			// Client closed, normal termination
			debugf("Client connection closed - ending relay")
			break
		}

		// Proxy died but client still alive - check if client has more data
		if !isClientAlive(client) {
			debugf("Client connection also closed after proxy death")
			break
		}

		debugf("Proxy died but client still alive - attempting reconnection...")

		// For reconnection, firstData is nil (already sent)
		firstData = nil
	}
}

// setupProxyConnection handles proxy setup for both HTTP and SOCKS5
func setupProxyConnection(proxy, client net.Conn, firstData []byte, host string, port int) error {
	switch config.ProxyType {
	case "http":
		return setupHTTPProxy(proxy, client, firstData, host, port)
	case "socks5":
		if err := setupSOCKS5Proxy(proxy, host, port); err != nil {
			return err
		}
		// Send first data if we have it
		if firstData != nil {
			_, err := proxy.Write(firstData)
			return err
		}
		return nil
	default:
		return fmt.Errorf("unsupported proxy type: %s", config.ProxyType)
	}
}

func isClientAlive(client net.Conn) bool {
	// Set very short read timeout to test connection
	client.SetReadDeadline(time.Now().Add(1 * time.Millisecond))
	buf := make([]byte, 1)
	_, err := client.Read(buf)
	client.SetReadDeadline(time.Time{}) // Clear deadline

	if err == nil {
		// Data available - client is alive and has more data
		return true
	}

	// Check error type
	if err == io.EOF {
		return false // Client closed
	}

	if strings.Contains(err.Error(), "timeout") {
		return true // Timeout = no data but connection alive
	}

	return false // Other errors = connection dead
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
		if err := setupHTTPProxy(proxy, client, firstData, host, port); err != nil {
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

	// Extract hostname from "host:port"
	hostPort := parts[1]
	if idx := strings.LastIndex(hostPort, ":"); idx != -1 {
		return hostPort[:idx]
	}

	return hostPort
}

func determineTargetHostname(host string, connectData []byte, isConnectRequest bool) string {
	if isConnectRequest {
		// Proxy HTTP - extract from CONNECT
		return parseConnectTarget(connectData)
	} else {
		// Direct TLS handshake - extract SNI from ClientHello
		if sni := extractSNIFromClientHello(connectData); sni != "" {
			return sni
		}
		// Fallback to IP - add a fatal() here?
		debugf("No hostName from TLS context!")
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
	realHostname := determineTargetHostname(host, connectData, isConnectRequest)
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

// relayBidirectional performs bidirectional relay with immediate reconnect on proxy death
// Returns true if proxy died first, false if client died first
func relayBidirectional(client, proxy net.Conn, target string, showStats bool) bool {
	done := make(chan bool, 2)
	proxyDiedChan := make(chan bool, 1) // New: Communication between goroutines
	var clientToProxy, proxyToClient int64
	var proxyDied, clientDied bool

	// Client to Proxy
	go func() {
		defer func() { done <- true }()

		buf := make([]byte, 4*1024)
		for {
			// Check if proxy died before trying to read from client
			select {
			case <-proxyDiedChan:
				debugf("Client→Proxy: Proxy died, terminating client relay for reconnection")
				return // Exit immediately to allow reconnection
			default:
				// Continue with normal read
			}

			n, err := client.Read(buf)
			if err != nil {
				if err == io.EOF || isConnectionClosed(err) {
					debugf("Client read ended: %v", err)
					clientDied = true
				} else {
					debugf("Client read error: %v", err)
					clientDied = true
				}
				break
			}

			written, err := proxy.Write(buf[:n])
			if err != nil {
				debugf("Proxy write error (proxy died): %v", err)
				proxyDied = true
				// Signal proxy death to other goroutine
				select {
				case proxyDiedChan <- true:
				default:
				}
				break
			}

			clientToProxy += int64(written)
			if showStats {
				printStats(target, clientToProxy, proxyToClient)
			} else {
				debugf("Client→Proxy: %d bytes", written)
			}
		}
	}()

	// Proxy to Client
	go func() {
		defer func() { done <- true }()

		buf := make([]byte, 4*1024)
		for {
			// Check if we should terminate due to proxy death signal
			select {
			case <-proxyDiedChan:
				debugf("Proxy→Client: Received proxy death signal, terminating")
				return
			default:
				// Continue with normal read
			}

			n, err := proxy.Read(buf)
			if err != nil {
				if err == io.EOF || isConnectionClosed(err) {
					debugf("Proxy read ended: %v", err)
					proxyDied = true
				} else {
					debugf("Proxy read error: %v", err)
					proxyDied = true
				}

				// Signal proxy death to client goroutine for immediate termination
				select {
				case proxyDiedChan <- true:
					debugf("Signaled proxy death for immediate reconnection")
				default:
				}
				break
			}

			written, err := client.Write(buf[:n])
			if err != nil {
				debugf("Client write error (client died): %v", err)
				clientDied = true
				break
			}

			proxyToClient += int64(written)
			if showStats {
				printStats(target, clientToProxy, proxyToClient)
			} else {
				debugf("Proxy→Client: %d bytes", written)
			}
		}
	}()

	// Wait for both directions to complete
	<-done
	<-done

	// Print final stats if enabled
	if showStats {
		fmt.Printf("\r[%s] %s - TX: %s, RX: %s [%s]\n",
			time.Now().Format("15:04:05"),
			target,
			formatBytes(clientToProxy),
			formatBytes(proxyToClient),
			func() string {
				if proxyDied {
					return "PROXY DIED"
				}
				if clientDied {
					return "CLIENT DIED"
				}
				return "CLOSED"
			}())
	}

	debugf("Relay ended - ProxyDied: %v, ClientDied: %v", proxyDied, clientDied)
	return proxyDied
}
