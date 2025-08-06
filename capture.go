package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"strconv"
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

func captureTLS(client, server net.Conn, targetHost string) {
	done := make(chan bool, 2)

	// Buffer para acumular requisições parciais
	var pendingRequest bytes.Buffer

	// Client to Server
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := client.Read(buf)
			if err != nil {
				break
			}

			data := buf[:n]
			server.Write(data)

			// Acumula dados
			pendingRequest.Write(data)

			// Verifica se é início de requisição HTTP
			reqData := pendingRequest.Bytes()
			if isHTTPRequest(reqData) {
				// Verifica se a requisição está completa
				if req, complete := extractCompleteRequest(reqData); complete {
					capture := &CaptureData{
						Timestamp: time.Now().UnixNano(),
					}

					// Parse método e URL
					if lines := strings.Split(string(req), "\r\n"); len(lines) > 0 {
						parts := strings.Fields(lines[0])
						if len(parts) >= 2 {
							capture.Method = parts[0]
							capture.URL = fmt.Sprintf("https://%s%s", targetHost, parts[1])
						}
					}

					capture.Request = req

					// Captura a resposta correspondente
					go captureResponse(server, client, capture)

					// Limpa buffer para próxima requisição
					pendingRequest.Reset()
				}
			}
		}
		done <- true
	}()

	// Server to Client - apenas encaminha
	go func() {
		io.Copy(client, server)
		done <- true
	}()

	<-done
	<-done
}

func isHTTPRequest(data []byte) bool {
	str := string(data)
	return strings.HasPrefix(str, "GET ") ||
		strings.HasPrefix(str, "POST ") ||
		strings.HasPrefix(str, "PUT ") ||
		strings.HasPrefix(str, "DELETE ") ||
		strings.HasPrefix(str, "HEAD ") ||
		strings.HasPrefix(str, "OPTIONS ") ||
		strings.HasPrefix(str, "PATCH ")
}

func extractCompleteRequest(data []byte) ([]byte, bool) {
	// Encontra fim dos headers
	headerEnd := bytes.Index(data, []byte("\r\n\r\n"))
	if headerEnd == -1 {
		return nil, false
	}

	headers := string(data[:headerEnd])
	headerEndPos := headerEnd + 4

	// Verifica Content-Length
	if idx := strings.Index(strings.ToLower(headers), "content-length:"); idx != -1 {
		// Extrai valor do Content-Length
		start := idx + 15
		end := strings.Index(headers[start:], "\r\n")
		if end == -1 {
			end = len(headers) - start
		} else {
			end += start
		}

		lengthStr := strings.TrimSpace(headers[start:end])
		if contentLen, err := strconv.Atoi(lengthStr); err == nil {
			// Verifica se temos o body completo
			if len(data) >= headerEndPos+contentLen {
				return data[:headerEndPos+contentLen], true
			}
			return nil, false
		}
	}

	// Se não tem Content-Length, assume que não tem body
	return data[:headerEndPos], true
}

func captureResponse(server, client net.Conn, capture *CaptureData) {
	var respBuf bytes.Buffer
	buf := make([]byte, 4096)

	for respBuf.Len() < MAX_CAPTURE_SIZE {
		n, err := server.Read(buf)
		if err != nil {
			break
		}

		respBuf.Write(buf[:n])
		client.Write(buf[:n])

		// Verifica se a resposta está completa
		if resp, complete := extractCompleteRequest(respBuf.Bytes()); complete {
			capture.Response = resp

			// Envia para salvar
			select {
			case captureChan <- capture:
			default:
				debugf("Capture channel full")
			}

			// Continua encaminhando o resto sem capturar
			io.Copy(client, server)
			return
		}
	}

	// Se chegou ao limite, salva o que tem
	capture.Response = respBuf.Bytes()
	select {
	case captureChan <- capture:
	default:
		debugf("Capture channel full")
	}
}
