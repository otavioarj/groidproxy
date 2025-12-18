package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// captureHTTP captures plain HTTP traffic for database storage
func captureHTTP(client, server net.Conn, firstReq []byte, host string, port int) {
	capture := &CaptureData{
		Timestamp: time.Now().UnixNano(),
	}

	// Parse first request for metadata
	if lines := strings.Split(string(firstReq), "\r\n"); len(lines) > 0 {
		parts := strings.Fields(lines[0])
		if len(parts) >= 2 {
			capture.Method = parts[0]
			capture.URL = fmt.Sprintf("http://%s:%d%s", host, port, parts[1])
		}
	}

	// Include firstReq in capture (already sent to server, needed for DB)
	var requestBuf bytes.Buffer
	requestBuf.Write(firstReq)

	done := make(chan bool, 2)

	// Client to Server with capture
	go func() {
		buf := bufPool4K.Get().([]byte)
		defer bufPool4K.Put(buf)

		for requestBuf.Len() < MAX_CAPTURE_SIZE {
			n, err := client.Read(buf)
			if err != nil {
				break
			}
			requestBuf.Write(buf[:n])
			server.Write(buf[:n])
		}
		// Continue forwarding without capturing if over limit
		io.Copy(server, client)
		done <- true
	}()

	// Server to Client with capture
	var responseBuf bytes.Buffer
	go func() {
		buf := bufPool4K.Get().([]byte)
		defer bufPool4K.Put(buf)

		for responseBuf.Len() < MAX_CAPTURE_SIZE {
			n, err := server.Read(buf)
			if err != nil {
				break
			}
			responseBuf.Write(buf[:n])
			client.Write(buf[:n])
		}
		// Continue forwarding without capturing if over limit
		io.Copy(client, server)
		done <- true
	}()

	<-done
	<-done

	capture.Request = requestBuf.Bytes()
	capture.Response = responseBuf.Bytes()

	select {
	case captureChan <- capture:
	default:
		debugf("Capture channel full")
	}
}

// captureTLS captures decrypted TLS traffic using HTTP pairing
// Enforces memory limits and validates pairer initialization
func captureTLS(client, server *tls.Conn, targetHost string) {
	debugf("Starting TLS capture for %s", targetHost)

	// Safety check - fall back to simple relay if pairer unavailable
	if httpPairer == nil {
		debugf("Warning: httpPairer not initialized, falling back to relay")
		relayTLS(client, server, targetHost)
		return
	}

	done := make(chan bool, 2)

	// Client to Server (Request capture)
	go func() {
		defer func() { done <- true }()

		buf := bufPool4K.Get().([]byte)
		defer bufPool4K.Put(buf)

		var requestBuffer bytes.Buffer

		for {
			n, err := client.Read(buf)
			if err != nil {
				break
			}

			// Forward to server immediately (relay is priority)
			server.Write(buf[:n])

			// Enforce memory limit - stop capturing if exceeded
			if requestBuffer.Len()+n > MAX_CAPTURE_SIZE {
				debugf("Request buffer exceeds limit, skipping capture")
				io.Copy(server, client)
				break
			}

			requestBuffer.Write(buf[:n])

			// Check if we have a complete HTTP request
			if isCompleteHTTPMessage(requestBuffer.Bytes()) {
				httpPairer.addRequest(requestBuffer.Bytes(), targetHost)
				requestBuffer.Reset()
			}
		}

		if requestBuffer.Len() > 0 {
			debugf("Partial request data: %d bytes for %s", requestBuffer.Len(), targetHost)
		}
	}()

	// Server to Client (Response capture)
	go func() {
		defer func() { done <- true }()

		buf := bufPool4K.Get().([]byte)
		defer bufPool4K.Put(buf)

		var responseBuffer bytes.Buffer

		for {
			n, err := server.Read(buf)
			if err != nil {
				break
			}

			// Forward to client immediately (relay is priority)
			client.Write(buf[:n])

			// Enforce memory limit - stop capturing if exceeded
			if responseBuffer.Len()+n > MAX_CAPTURE_SIZE {
				debugf("Response buffer exceeds limit, skipping capture")
				io.Copy(client, server)
				break
			}

			responseBuffer.Write(buf[:n])

			// Check if we have a complete HTTP response
			if isCompleteHTTPMessage(responseBuffer.Bytes()) {
				httpPairer.addResponse(responseBuffer.Bytes(), targetHost)
				responseBuffer.Reset()
			}
		}

		if responseBuffer.Len() > 0 {
			debugf("Partial response data: %d bytes for %s", responseBuffer.Len(), targetHost)
		}
	}()

	<-done
	<-done

	debugf("TLS capture ended for %s", targetHost)
}

// relayTLS performs simple TLS relay without capture (fallback)
func relayTLS(client, server *tls.Conn, target string) {
	done := make(chan bool, 2)

	go func() {
		buf := bufPool4K.Get().([]byte)
		defer bufPool4K.Put(buf)
		io.CopyBuffer(server, client, buf)
		done <- true
	}()

	go func() {
		buf := bufPool4K.Get().([]byte)
		defer bufPool4K.Put(buf)
		io.CopyBuffer(client, server, buf)
		done <- true
	}()

	<-done
	<-done

	debugf("TLS relay ended for %s", target)
}
