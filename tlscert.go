package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

func isTLSHandshake(data []byte) bool {
	// TLS handshake começa com:
	// - byte 0: 0x16 (Handshake)
	// - byte 1-2: TLS version (0x03 0x01 para TLS 1.0, 0x03 0x03 para TLS 1.2)
	return len(data) > 3 && data[0] == 0x16 && data[1] == 0x03
}

func loadP12Certificate(certPath, password string) error {
	p12Data, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("failed to read P12 file: %v", err)
	}

	blocks, err := pkcs12.ToPEM(p12Data, password)
	if err != nil {
		return fmt.Errorf("failed to parse P12: %v", err)
	}

	var pemData []byte
	for _, b := range blocks {
		pemData = append(pemData, pem.EncodeToMemory(b)...)
	}

	// Parse certificate and key
	for _, block := range blocks {
		switch block.Type {
		case "CERTIFICATE":
			cert, err := x509.ParseCertificate(block.Bytes)
			if err == nil && cert.IsCA {
				caCert = cert
			}
		case "PRIVATE KEY":
			if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
				caKey = key
			} else if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
				caKey = key
			}
		}
	}

	if caCert == nil || caKey == nil {
		return fmt.Errorf("failed to extract CA certificate and key from P12")
	}
	return nil
}

func generateCertForHost(host string) (*tls.Certificate, error) {
	// Check cache first
	certCache.mu.RLock()
	if cert, ok := certCache.certs[host]; ok {
		certCache.mu.RUnlock()
		return cert, nil
	}
	certCache.mu.RUnlock()

	// Strip port if present
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		host = host[:idx]
	}

	// Generate new certificate per host
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore:   time.Now().Add(-24 * time.Hour),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{host},
	}

	// Add wildcard if it's a domain
	if net.ParseIP(host) == nil {
		template.DNSNames = append(template.DNSNames, "*."+host)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &priv.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	cert := &tls.Certificate{
		Certificate: [][]byte{certDER, caCert.Raw},
		PrivateKey:  priv,
	}
	// Cache it
	certCache.mu.Lock()
	certCache.certs[host] = cert
	certCache.mu.Unlock()

	return cert, nil
}

func setupServerTLSConnection(hostName, hostIP string, port int) (*tls.Conn, error) {
	if config.ProxyType == "capture" {
		// Direct connection with DNS fallback
		tlsConn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", hostName, port), &tls.Config{
			ServerName:         hostName,
			InsecureSkipVerify: true,
		})

		if err != nil {
			debugf("DNS/Connect failed for hostname %s: %v", hostName, err)
			debugf("Trying fallback to original IP %s", hostIP)

			// Fallback: usar IP original mas manter SNI correto
			tlsConn, err = tls.Dial("tcp", fmt.Sprintf("%s:%d", hostIP, port), &tls.Config{
				ServerName:         hostName, // SNI correto (hostname)
				InsecureSkipVerify: true,
			})

			if err != nil {
				return nil, fmt.Errorf("both hostname and IP connection failed: %v", err)
			}

			debugf("Fallback connection successful using IP %s with SNI %s", hostIP, hostName)
		} else {
			debugf("Direct hostname connection successful to %s", hostName)
		}

		return tlsConn, nil
	}

	// Through proxy
	serverConn, err := net.DialTimeout("tcp",
		fmt.Sprintf("%s:%d", config.ProxyHost, config.ProxyPort),
		time.Duration(config.Timeout)*time.Second)
	if err != nil {
		return nil, fmt.Errorf("proxy connection failed: %v", err)
	}

	// Setup proxy tunnel
	switch config.ProxyType {
	case "http":
		connectReq := fmt.Sprintf("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n",
			hostName, port, hostName, port)
		serverConn.Write([]byte(connectReq))

		// Read proxy response
		resp := make([]byte, 1024)
		n, err := serverConn.Read(resp)
		if err != nil || !bytes.Contains(resp[:n], []byte("200")) {
			serverConn.Close()
			return nil, fmt.Errorf("proxy CONNECT failed: %s", string(resp[:n]))
		}

	case "socks5":
		if err := setupSOCKS5Proxy(serverConn, hostName, port); err != nil {
			serverConn.Close()
			return nil, fmt.Errorf("SOCKS5 setup failed: %v", err)
		}
	}

	// Upgrade to TLS and do handshake
	tlsServer := tls.Client(serverConn, &tls.Config{
		ServerName:         hostName,
		InsecureSkipVerify: true,
	})

	// CRITICAL: Do the handshake now!
	if err := tlsServer.Handshake(); err != nil {
		tlsServer.Close()
		return nil, fmt.Errorf("server TLS handshake failed: %v", err)
	}

	return tlsServer, nil
}

func setupClientTLSConnection(client net.Conn, targetHost string, isConnectRequest bool) (*tls.Conn, error) {
	debugf("Setting up client TLS connection for: %s", targetHost)

	// Wrap with debug logging only if verbose mode is enabled
	var connToUse net.Conn = client
	if config.Verbose {
		connToUse = &debugConn{
			Conn: client,
			name: "CLIENT",
		}
		debugf("Debug I/O logging enabled for client connection")
	}

	// Send 200 Connection established if it was a CONNECT request
	if isConnectRequest {
		debugf("Sending HTTP 200 Connection established response")
		response := []byte("HTTP/1.1 200 Connection established\r\n\r\n")
		_, err := connToUse.Write(response)
		if err != nil {
			logf("Failed to write CONNECT response: %v", err)
			return nil, fmt.Errorf("failed to write CONNECT response: %v", err)
		}
	}

	// Generate certificate for target host
	cert, err := generateCertForHost(targetHost)
	if err != nil {
		logf("Certificate generation failed for %s: %v", targetHost, err)
		return nil, fmt.Errorf("cert generation failed: %v", err)
	}
	debugf("Certificate generated successfully for: %s", targetHost)

	// TLS config with comprehensive options
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		NextProtos:   []string{"http/1.1"},
		MinVersion:   tls.VersionTLS10,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		},
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			sniHost := info.ServerName
			if sniHost == "" {
				sniHost = targetHost
			}
			debugf("Client requested SNI: %s", sniHost)

			// Use existing certificate if SNI matches
			if sniHost == targetHost {
				return cert, nil
			}

			// Generate new certificate for different SNI
			debugf("Generating new certificate for SNI: %s", sniHost)
			newCert, err := generateCertForHost(sniHost)
			if err != nil {
				logf("Failed to generate certificate for SNI %s: %v", sniHost, err)
				return cert, nil // Fallback to original certificate
			}
			return newCert, nil
		},
	}

	// Create TLS server connection with client
	tlsClient := tls.Server(connToUse, tlsConfig)

	// Set reasonable deadline to prevent infinite hang
	deadline := time.Now().Add(15 * time.Second)
	if err := tlsClient.SetDeadline(deadline); err != nil {
		debugf("Warning: failed to set deadline: %v", err)
	}

	// Attempt handshake
	debugf("Starting TLS handshake with client...")
	handshakeStart := time.Now()
	err = tlsClient.Handshake()
	handshakeDuration := time.Since(handshakeStart)

	if err != nil {
		logf("Client TLS handshake failed after %v: %v", handshakeDuration, err)
		return nil, fmt.Errorf("client TLS handshake failed: %v", err)
	}

	debugf("Client TLS handshake completed successfully in %v", handshakeDuration)

	// Log connection details in verbose mode
	if config.Verbose {
		state := tlsClient.ConnectionState()
		debugf("TLS Version: 0x%x, Cipher: 0x%x", state.Version, state.CipherSuite)
	}

	// Clear deadline after successful handshake
	tlsClient.SetDeadline(time.Time{})

	return tlsClient, nil
}

func extractSNIFromClientHello(data []byte) string {
	if len(data) < 43 {
		return "" // too small 4 ClientHello
	}

	//  TLS Handshake (0x16) or ClientHello (0x01)
	if data[0] != 0x16 || data[5] != 0x01 {
		return ""
	}

	// Skip headers TLS and Handshake
	pos := 43 //

	// Pular Session ID
	if pos >= len(data) {
		return ""
	}
	sessionIDLen := int(data[pos])
	pos += 1 + sessionIDLen

	// skip Cipher Suites
	if pos+1 >= len(data) {
		return ""
	}
	cipherSuitesLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2 + cipherSuitesLen

	// skip Compression Methods
	if pos >= len(data) {
		return ""
	}
	compressionMethodsLen := int(data[pos])
	pos += 1 + compressionMethodsLen

	// extensions?
	if pos+1 >= len(data) {
		return ""
	}
	extensionsLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2

	// Parse extensions
	extensionsEnd := pos + extensionsLen
	for pos < extensionsEnd && pos+3 < len(data) {
		// Extension type (2 bytes) + length (2 bytes)
		extType := int(data[pos])<<8 | int(data[pos+1])
		extLen := int(data[pos+2])<<8 | int(data[pos+3])
		pos += 4

		// check if SNI extension (type 0x0000)
		if extType == 0x0000 && pos+extLen <= len(data) {
			return parseSNIExtension(data[pos : pos+extLen])
		}

		pos += extLen
	}

	return ""
}

func parseSNIExtension(data []byte) string {
	if len(data) < 5 {
		return ""
	}

	// SNI extension format:
	// 2 bytes: server name list length
	// 1 byte: name type (0x00 para hostname)
	// 2 bytes: hostname length
	// N bytes: hostname

	pos := 2 // skip server name list length

	for pos < len(data) {
		if pos+2 >= len(data) {
			break
		}

		nameType := data[pos]
		nameLen := int(data[pos+1])<<8 | int(data[pos+2])
		pos += 3

		if nameType == 0x00 && pos+nameLen <= len(data) {
			// found host
			hostname := string(data[pos : pos+nameLen])
			if len(hostname) > 0 && strings.Contains(hostname, ".") {
				return hostname
			}
		}

		pos += nameLen
	}

	return ""
}
