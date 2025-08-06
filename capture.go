package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
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
	debugf("Starting TLS capture for %s", targetHost)

	done := make(chan bool, 2)
	var requestBuffer bytes.Buffer
	var mu sync.Mutex

	// Client -> Server (Request capture)
	go func() {
		defer func() { done <- true }()

		buf := make([]byte, 4096)
		for {
			n, err := client.Read(buf)
			if err != nil {
				break
			}

			// Forward to server
			server.Write(buf[:n])

			// Capture request data
			mu.Lock()
			requestBuffer.Write(buf[:n])

			// Check if we have a complete HTTP request
			if isCompleteHTTPMessage(requestBuffer.Bytes()) {
				go captureAndSaveHTTPMessage(requestBuffer.Bytes(), nil, targetHost, "request")
				requestBuffer.Reset()
			}
			mu.Unlock()
		}
	}()

	// Server -> Client (Response capture)
	go func() {
		defer func() { done <- true }()

		buf := make([]byte, 4096)
		var responseBuffer bytes.Buffer

		for {
			n, err := server.Read(buf)
			if err != nil {
				break
			}

			// Forward to client
			client.Write(buf[:n])

			// Capture response data
			responseBuffer.Write(buf[:n])

			// Check if we have a complete HTTP response
			if isCompleteHTTPMessage(responseBuffer.Bytes()) {
				mu.Lock()
				if requestBuffer.Len() > 0 {
					go captureAndSaveHTTPMessage(requestBuffer.Bytes(), responseBuffer.Bytes(), targetHost, "pair")
					requestBuffer.Reset()
				}
				mu.Unlock()
				responseBuffer.Reset()
			}
		}
	}()

	// Wait for both directions
	<-done
	<-done
}

func captureAndSaveHTTPMessage(request, response []byte, targetHost, msgType string) {
	capture := &CaptureData{
		Timestamp: time.Now().UnixNano(),
	}

	// Parse request
	if len(request) > 0 {
		if lines := strings.Split(string(request), "\r\n"); len(lines) > 0 {
			parts := strings.Fields(lines[0])
			if len(parts) >= 2 {
				capture.Method = parts[0]
				capture.URL = fmt.Sprintf("https://%s%s", targetHost, parts[1])
			}
		}
		capture.Request = request
	}

	if response != nil {
		capture.Response = response
	}

	// Send to save channel
	select {
	case captureChan <- capture:
	default:
		debugf("Capture channel full, dropping message")
	}
}
