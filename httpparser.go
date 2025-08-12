package main

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// isCompleteHTTPMessage checks if HTTP message (request or response) is complete
func isCompleteHTTPMessage(data []byte) bool {
	if len(data) < 4 {
		return false
	}

	// Find end of headers
	headerEnd := bytes.Index(data, []byte("\r\n\r\n"))
	if headerEnd == -1 {
		return false // Headers not complete yet
	}

	headers := string(data[:headerEnd])
	bodyStart := headerEnd + 4

	// Check for Transfer-Encoding: chunked
	if isChunkedEncoding(headers) {
		return isChunkedMessageComplete(data[bodyStart:])
	}

	// Check Content-Length
	contentLength := getContentLength(headers)
	if contentLength >= 0 {
		// Has Content-Length header
		expectedTotal := bodyStart + contentLength
		return len(data) >= expectedTotal
	}

	// For HTTP responses without Content-Length or chunked encoding
	if isHTTPResponse(headers) {
		// Some responses (like 204, 304) have no body
		statusCode := getStatusCode(headers)
		if statusCode == 204 || statusCode == 304 ||
			(statusCode >= 100 && statusCode < 200) {
			return true // No body expected
		}

		// For responses without Content-Length, we can't determine completion
		// This is a limitation - might need connection close detection
		return false
	}

	// For requests without Content-Length (like GET), headers are enough
	if isHTTPRequest(headers) {
		method := getHTTPMethod(headers)
		if method == "GET" || method == "HEAD" || method == "DELETE" {
			return true // These methods typically don't have body
		}
		// POST, PUT without Content-Length is incomplete
		return false
	}

	return false
}

// isChunkedEncoding checks if message uses chunked transfer encoding
func isChunkedEncoding(headers string) bool {
	lowerHeaders := strings.ToLower(headers)
	transferEncoding := extractHeaderValue(lowerHeaders, "transfer-encoding")
	return strings.Contains(transferEncoding, "chunked")
}

// isChunkedMessageComplete checks if chunked message is complete
func isChunkedMessageComplete(body []byte) bool {
	pos := 0
	for pos < len(body) {
		// Find chunk size line
		chunkSizeEnd := bytes.Index(body[pos:], []byte("\r\n"))
		if chunkSizeEnd == -1 {
			return false // Incomplete chunk size line
		}

		// Parse chunk size (hex)
		chunkSizeLine := string(body[pos : pos+chunkSizeEnd])
		chunkSize := parseChunkSize(chunkSizeLine)
		if chunkSize < 0 {
			return false // Invalid chunk size
		}

		// Move past chunk size line
		pos += chunkSizeEnd + 2

		// Check if we have the full chunk data + trailing CRLF
		if pos+chunkSize+2 > len(body) {
			return false // Incomplete chunk data
		}

		// If chunk size is 0, this is the last chunk
		if chunkSize == 0 {
			// Check for optional trailing headers and final CRLF
			remainingData := body[pos:]
			finalCRLF := bytes.Index(remainingData, []byte("\r\n"))
			return finalCRLF != -1 // Missing final CRLF (false) or Chunked message complete (true)
		}

		// Move past chunk data and trailing CRLF
		pos += chunkSize + 2
	}

	return false // Reached end without finding terminal chunk
}

// getContentLength extracts Content-Length header value
func getContentLength(headers string) int {
	value := extractHeaderValue(strings.ToLower(headers), "content-length")
	if value == "" {
		return -1 // No Content-Length header
	}

	length, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return -1 // Invalid Content-Length value
	}

	return length
}

// extractHeaderValue extracts header value from headers string
func extractHeaderValue(headers, headerName string) string {
	headerName = strings.ToLower(headerName) + ":"
	lines := strings.Split(headers, "\r\n")

	for _, line := range lines {
		lowerLine := strings.ToLower(line)
		if strings.HasPrefix(lowerLine, headerName) {
			return strings.TrimSpace(line[len(headerName):])
		}
	}

	return ""
}

// isHTTPResponse checks if headers represent HTTP response
func isHTTPResponse(headers string) bool {
	firstLine := strings.Split(headers, "\r\n")[0]
	return strings.HasPrefix(firstLine, "HTTP/")
}

// isHTTPRequest checks if headers represent HTTP request
func isHTTPRequest(headers string) bool {
	firstLine := strings.Split(headers, "\r\n")[0]
	methods := []string{"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE"}

	for _, method := range methods {
		if strings.HasPrefix(firstLine, method+" ") {
			return true
		}
	}
	return false
}

// getStatusCode extracts status code from HTTP response
func getStatusCode(headers string) int {
	firstLine := strings.Split(headers, "\r\n")[0]
	parts := strings.Fields(firstLine)
	if len(parts) < 2 {
		return 0
	}

	code, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0
	}

	return code
}

// getHTTPMethod extracts HTTP method from request
func getHTTPMethod(headers string) string {
	firstLine := strings.Split(headers, "\r\n")[0]
	parts := strings.Fields(firstLine)
	if len(parts) < 1 {
		return ""
	}

	return strings.ToUpper(parts[0])
}

// parseChunkSize parses hex chunk size from chunk size line
func parseChunkSize(line string) int {
	// Chunk size line format: "1a3f" or "1a3f;chunk-extension"
	parts := strings.Split(line, ";")
	hexSize := strings.TrimSpace(parts[0])

	size, err := strconv.ParseInt(hexSize, 16, 32)
	if err != nil {
		return -1
	}

	return int(size)
}

func parseHTTPRequestLine(data []byte) (method, url string) {
	// Find first line (until \r\n)
	firstLineEnd := bytes.Index(data, []byte("\r\n"))
	if firstLineEnd == -1 {
		return "", ""
	}

	firstLine := string(data[:firstLineEnd])
	parts := strings.Fields(firstLine)

	if len(parts) < 2 {
		return "", ""
	}

	return strings.ToUpper(parts[0]), parts[1]
}

// decompressHTTPBody decompresses HTTP body based on Content-Encoding
func decompressHTTPBody(body []byte, encoding string) ([]byte, error) {
	var decodedBody bytes.Buffer
	bodyReader := bytes.NewReader(body)

	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "", "identity":
		return body, nil // No compression

	case "gzip":
		gzipReader, err := gzip.NewReader(bodyReader)
		if err != nil {
			return body, fmt.Errorf("failed to create gzip reader: %v", err)
		}
		defer gzipReader.Close()

		_, err = io.Copy(&decodedBody, gzipReader)
		if err != nil {
			return body, fmt.Errorf("failed to decompress gzip: %v", err)
		}

	case "deflate":
		deflateReader := flate.NewReader(bodyReader)
		defer deflateReader.Close()

		_, err := io.Copy(&decodedBody, deflateReader)
		if err != nil {
			return body, fmt.Errorf("failed to decompress deflate: %v", err)
		}

	default:
		debugf("Unsupported encoding: %s, saving compressed", encoding)
		return body, nil // Return compressed data
	}

	return decodedBody.Bytes(), nil
}

// getHTTPBody extracts the body portion from complete HTTP message
func getHTTPBody(httpData []byte) []byte {
	headerEnd := bytes.Index(httpData, []byte("\r\n\r\n"))
	if headerEnd == -1 {
		return nil // No body found
	}
	return httpData[headerEnd+4:]
}

// replaceHTTPBody replaces the body in HTTP message with new body
func replaceHTTPBody(httpData []byte, newBody []byte) []byte {
	headerEnd := bytes.Index(httpData, []byte("\r\n\r\n"))
	if headerEnd == -1 {
		return httpData // Return original if no body separator found
	}

	headers := httpData[:headerEnd+4] // Include \r\n\r\n
	return append(headers, newBody...)
}
