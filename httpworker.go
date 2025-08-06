package main

import (
	"bytes"
	"fmt"
	"strings"
	"time"
)

// initHTTPPairer initializes the HTTP request/response pairing system
func initHTTPPairer() {
	httpPairer = &HTTPPairer{
		pending:     make([]HTTPPair, 0),
		saveChannel: make(chan HTTPPair, 100), // Buffered channel
	}

	// Start the save worker
	go httpPairSaveWorker()
	debugf("HTTP pairing system initialized")
}

// addRequest adds a complete HTTP request to pending queue
func (hp *HTTPPairer) addRequest(data []byte, host string) {
	method, url := parseHTTPRequestLine(data)
	if method == "" {
		debugf("Failed to parse HTTP request line")
		return
	}

	hp.mu.Lock()
	defer hp.mu.Unlock()

	pair := HTTPPair{
		Request:   append([]byte(nil), data...), // Copy data to avoid buffer reuse issues
		Timestamp: time.Now().UnixNano(),
		Host:      host,
		Method:    method,
		URL:       url,
	}

	hp.pending = append(hp.pending, pair)
	debugf("Added request to queue: %s %s (queue size: %d)", method, url, len(hp.pending))

	// Cleanup old orphaned requests (older than 30 seconds)
	cutoff := time.Now().Add(-30 * time.Second).UnixNano()
	originalSize := len(hp.pending)

	// Remove old requests from front of queue
	for len(hp.pending) > 0 && hp.pending[0].Timestamp < cutoff {
		debugf("Removing orphaned request: %s %s", hp.pending[0].Method, hp.pending[0].URL)
		hp.pending = hp.pending[1:]
	}

	if len(hp.pending) != originalSize {
		debugf("Cleaned up %d orphaned requests", originalSize-len(hp.pending))
	}
}

// addResponse pairs a complete HTTP response with pending request
func (hp *HTTPPairer) addResponse(data []byte, host string) {
	hp.mu.Lock()
	defer hp.mu.Unlock()

	// Find first pending request for this host (FIFO order)
	for i := range hp.pending {
		if hp.pending[i].Host == host {
			// Complete the pair with response data (modify original in slice)
			hp.pending[i].Response = append([]byte(nil), data...) // Copy response data

			// Get the completed pair (now with both request and response)
			completedPair := hp.pending[i]

			// Remove from pending queue
			hp.pending = append(hp.pending[:i], hp.pending[i+1:]...)

			debugf("Paired response with request: %s %s (queue size: %d)",
				completedPair.Method, completedPair.URL, len(hp.pending))

			// Send completed pair to save worker (non-blocking)
			select {
			case hp.saveChannel <- completedPair:
			default:
				debugf("Save channel full, dropping HTTP pair: %s %s",
					completedPair.Method, completedPair.URL)
			}
			return
		}
	}

	debugf("No pending request found for response to host: %s", host)
}

func httpPairSaveWorker() {
	debugf("HTTP pair save worker started")
	for pair := range httpPairer.saveChannel {
		// Process pair in separate goroutine to avoid blocking worker
		go savePairAsync(pair)
	}

	debugf("HTTP pair save worker stopped")
}

// savePairAsync saves a completed HTTP pair to database
func savePairAsync(pair HTTPPair) {
	// Function to extract Content-Encoding from HTTP data
	extractContentEncoding := func(httpData []byte) string {
		headerEnd := bytes.Index(httpData, []byte("\r\n\r\n"))
		if headerEnd == -1 {
			return ""
		}
		headers := string(httpData[:headerEnd])
		return extractHeaderValue(strings.ToLower(headers), "content-encoding")
	}
	// Start with original data
	requestBody := pair.Request
	responseBody := pair.Response

	// Decompress request if needed
	if reqEncoding := extractContentEncoding(pair.Request); reqEncoding != "" {
		if reqBodyData := getHTTPBody(pair.Request); len(reqBodyData) > 0 {
			if decompressed, err := decompressHTTPBody(reqBodyData, reqEncoding); err == nil {
				requestBody = replaceHTTPBody(pair.Request, decompressed)
				debugf("Decompressed request body (%s): %d → %d bytes",
					reqEncoding, len(reqBodyData), len(decompressed))
			} else {
				debugf("Failed to decompress request (%s): %v", reqEncoding, err)
			}
		}
	}

	// Decompress response if needed
	if respEncoding := extractContentEncoding(pair.Response); respEncoding != "" {
		if respBodyData := getHTTPBody(pair.Response); len(respBodyData) > 0 {
			if decompressed, err := decompressHTTPBody(respBodyData, respEncoding); err == nil {
				responseBody = replaceHTTPBody(pair.Response, decompressed)
				debugf("Decompressed response body (%s): %d → %d bytes",
					respEncoding, len(respBodyData), len(decompressed))
			} else {
				debugf("Failed to decompress response (%s): %v", respEncoding, err)
			}
		}
	}

	// Create capture data structure with potentially decompressed data
	capture := &CaptureData{
		Timestamp: pair.Timestamp,
		Method:    pair.Method,
		URL:       fmt.Sprintf("https://%s%s", pair.Host, pair.URL),
		Request:   requestBody,
		Response:  responseBody,
	}

	// Send to existing capture channel (non-blocking)
	select {
	case captureChan <- capture:
		debugf("HTTP pair saved to database: %s %s", pair.Method, pair.URL)
	default:
		debugf("Capture channel full, dropping HTTP pair: %s %s", pair.Method, pair.URL)
	}
}
