package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"syscall"
	"time"
	"unsafe"
)

func isTLSHandshake(data []byte) bool {
	// TLS handshake começa com:
	// - byte 0: 0x16 (Handshake)
	// - byte 1-2: TLS version (0x03 0x01 para TLS 1.0, 0x03 0x03 para TLS 1.2)
	return len(data) > 3 && data[0] == 0x16 && data[1] == 0x03
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

	isHTTPS := false

	if bytes.HasPrefix(firstData, []byte("CONNECT ")) || isTLSHandshake(firstData) {
		isHTTPS = true
	}

	if isHTTPS && config.TLSCert != "" {
		//
		if !bytes.HasPrefix(firstData, []byte("CONNECT ")) {
			// Client sent ClientHello, time for ServerHello
			handleDirectTLS(client, host, port)
		} else {
			// // Check if it's HTTPS CONNECT
			handleHTTPS(client, firstData)
		}
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

func handleDirectTLS(client net.Conn, host string, port int) {
	// Generate cert - use a generic one for IP connections
	certHost := host
	if net.ParseIP(host) != nil {
		// It's an IP, use a generic cert
		certHost = "localhost"
	}
	debugf("CertHost: %s", certHost)
	cert, err := generateCertForHost(certHost)
	if err != nil {
		debugf("Failed to generate certificate: %v", err)
		return
	}

	// TLS config with GetConfigForClient to handle SNI
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
			debugf("Client SNI: %s", info.ServerName)
			if info.ServerName != "" && info.ServerName != host {
				// Client provided SNI, generate cert for that
				newCert, err := generateCertForHost(info.ServerName)
				if err != nil {
					return nil, err
				}
				return &tls.Config{
					Certificates: []tls.Certificate{*newCert},
				}, nil
			}
			return nil, nil
		},
	}

	// TLS handshake with client
	tlsClient := tls.Server(client, tlsConfig)

	// Connect to server FIRST (before client handshake)
	var serverConn net.Conn
	var tlsServer *tls.Conn

	if config.ProxyType == "capture" {
		// Direct connection
		tlsServer, err = tls.Dial("tcp", fmt.Sprintf("%s:%d", host, port), &tls.Config{
			InsecureSkipVerify: true,
		})
		if err != nil {
			debugf("Failed to connect to server directly: %v", err)
			return
		}
	} else {
		// Through proxy
		serverConn, err = net.DialTimeout("tcp",
			fmt.Sprintf("%s:%d", config.ProxyHost, config.ProxyPort),
			time.Duration(config.Timeout)*time.Second)
		if err != nil {
			debugf("Failed to connect to proxy: %v", err)
			return
		}

		if config.ProxyType == "http" {
			// Send CONNECT
			connectReq := fmt.Sprintf("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n", host, port, host, port)
			serverConn.Write([]byte(connectReq))

			// Read response
			resp := make([]byte, 1024)
			n, _ := serverConn.Read(resp)
			if !bytes.Contains(resp[:n], []byte("200")) {
				debugf("Proxy CONNECT failed: %s", string(resp[:n]))
				serverConn.Close()
				return
			}
		}
		// ... handle SOCKS5 needed!!

		// Upgrade to TLS
		tlsServer = tls.Client(serverConn, &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: true,
		})
	}
	defer tlsServer.Close()

	// NOW do client handshake (after server is connected)
	if err := tlsClient.Handshake(); err != nil {
		debugf("Client TLS handshake failed: %v", err)
		return
	}
	defer tlsClient.Close()

	// Capture decrypted traffic
	captureTLS(tlsClient, tlsServer, fmt.Sprintf("%s:%d", host, port))
}
