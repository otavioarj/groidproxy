package main

import (
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
