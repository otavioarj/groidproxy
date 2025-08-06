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

func captureHTTP(client, server net.Conn, firstReq []byte, host string, port int) {
	capture := &CaptureData{
		Timestamp: time.Now().UnixNano(),
	}

	// Parse first request
	if lines := strings.Split(string(firstReq), "\r\n"); len(lines) > 0 {
		parts := strings.Fields(lines[0])
		if len(parts) >= 2 {
			capture.Method = parts[0]
			capture.URL = fmt.Sprintf("http://%s:%d%s", host, port, parts[1])
		}
	}

	// Accumulate request
	var requestBuf bytes.Buffer
	requestBuf.Write(firstReq)

	// Forward and capture request
	done := make(chan bool)
	go func() {
		buf := make([]byte, 4096)
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

	// Capture response
	var responseBuf bytes.Buffer
	go func() {
		buf := make([]byte, 4096)
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

	// Wait for completion
	<-done
	<-done

	// Save capture
	capture.Request = requestBuf.Bytes()
	capture.Response = responseBuf.Bytes()

	select {
	case captureChan <- capture:
	default:
		debugf("Capture channel full")
	}
}

func captureTLS(client, server *tls.Conn, targetHost string) {
	debugf("Starting TLS capture with HTTP pairing for %s", targetHost)

	done := make(chan bool, 2)

	// Client to Server (Request capture)
	go func() {
		defer func() { done <- true }()

		buf := make([]byte, 4096)
		var requestBuffer bytes.Buffer

		for {
			n, err := client.Read(buf)
			if err != nil {
				break
			}

			// Forward to server immediately (relay is priority)
			server.Write(buf[:n])

			// Accumulate request data for capture
			requestBuffer.Write(buf[:n])

			// Check if we have a complete HTTP request
			if isCompleteHTTPMessage(requestBuffer.Bytes()) {
				// Add complete request to pairing queue
				httpPairer.addRequest(requestBuffer.Bytes(), targetHost)
				requestBuffer.Reset()
			}
		}

		// Handle any remaining partial request data
		if requestBuffer.Len() > 0 {
			debugf("Partial request data remaining: %d bytes for %s", requestBuffer.Len(), targetHost)
		}
	}()

	// Server to Client (Response capture)
	go func() {
		defer func() { done <- true }()

		buf := make([]byte, 4096)
		var responseBuffer bytes.Buffer

		for {
			n, err := server.Read(buf)
			if err != nil {
				break
			}

			// Forward to client immediately (relay is priority)
			client.Write(buf[:n])

			// Accumulate response data for capture
			responseBuffer.Write(buf[:n])

			// Check if we have a complete HTTP response
			if isCompleteHTTPMessage(responseBuffer.Bytes()) {
				// Add complete response to pairing system
				httpPairer.addResponse(responseBuffer.Bytes(), targetHost)
				responseBuffer.Reset()
			}
		}

		// Handle any remaining partial response data
		if responseBuffer.Len() > 0 {
			debugf("Partial response data remaining: %d bytes for %s", responseBuffer.Len(), targetHost)
		}
	}()

	// Wait for both directions to complete
	<-done
	<-done

	debugf("TLS capture ended for %s", targetHost)
}
