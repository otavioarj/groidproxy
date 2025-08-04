package main

import (
	"fmt"
	"io"
	"net"
	"syscall"
	"time"
	"unsafe"
)

func handleClient(client net.Conn) {
	defer client.Close()

	// Get original destination
	host, port, err := getOriginalDst(client)
	if err != nil {
		debugf("Failed to get original destination: %v", err)
		return
	}

	debugf("New connection to %s:%d", host, port)

	// Connect to proxy
	proxy, err := net.DialTimeout("tcp",
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
	if config.ProxyType == "http" {
		if err := setupHTTPProxy(proxy, firstData, host, port); err != nil {
			logf("HTTP setup failed: %v", err)
			return
		}
	} else if config.ProxyType == "socks5" {
		if err := setupSOCKS5Proxy(proxy, host, port); err != nil {
			logf("SOCKS5 setup failed: %v", err)
			return
		}
		proxy.Write(firstData)
	}

	// Relay data with stats if enabled
	if config.Stats {
		relayWithStats(client, proxy, fmt.Sprintf("%s:%d", host, port))
	} else {
		go io.Copy(proxy, client)
		io.Copy(client, proxy)
	}
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
