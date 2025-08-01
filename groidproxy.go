package main

import (	
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	CHAIN_NAME = "GROID_OUT"
	VERSION    = "1.0.0"
	SO_ORIGINAL_DST = 80
)

type Config struct {
	Packages    []string
	ProxyAddr   string
	ProxyType   string // "redirect", "http", "socks5"
	ProxyHost   string
	ProxyPort   int
	LocalPort   int
	Daemon      bool
	UseGlobal   bool
	DNSRedirect bool
	Verbose     bool
	Stats       bool
	Timeout     int
}

var config Config

func main() {
	var flush, list bool
	var remove string
	// Parse flags
	flag.StringVar(&config.ProxyAddr, "p", "", "Proxy address (host:port or http://host:port or socks5://host:port)")
	flag.IntVar(&config.LocalPort, "local-port", 8123, "Local port for transparent proxy")
	flag.BoolVar(&config.Daemon, "d", false, "Run as daemon")
	flag.BoolVar(&config.UseGlobal, "global", false, "Redirect all traffic")
	flag.BoolVar(&config.DNSRedirect, "dns", false, "Also redirect DNS (port 53)")
	flag.BoolVar(&config.Verbose, "v", false, "Verbose output")
	flag.BoolVar(&config.Stats, "stats", false, "Show I/O statistics")
	flag.IntVar(&config.Timeout, "timeout", 10, "Connection timeout in seconds")
	flag.BoolVar(&flush, "flush", false, "Remove all GROID rules")
	flag.BoolVar(&list, "list", false, "List current rules")
	flag.StringVar(&remove, "remove", "", "Remove rules for package")
	
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Groid v%s - Golang Android Proxier\n\n", VERSION)
		fmt.Fprintf(os.Stderr, "Usage: %s [options] [packages...]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nModes:\n")
		fmt.Fprintf(os.Stderr, "  host:port          - Redirect to a transparent proxy\n")
		fmt.Fprintf(os.Stderr, "  http://host:port   - Local transparent to HTTP proxy \n")
		fmt.Fprintf(os.Stderr, "  socks5://host:port - Local transparent to SOCKS5 proxy\n")
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s -p 192.168.1.100:8888 com.example.app\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -p http://192.168.1.100:8080 com.example.app com.android.chrome\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -p socks5://192.168.1.100:1080 -global\n", os.Args[0])
	}
	
	flag.Parse()
	
	// Check root
	if os.Geteuid() != 0 {
		fatal("Must run as root")
	}	
	// Handle special commands
	if flush {
		flushRules()
		return
	}	
	if list {
		listRules()
		return
	}	
	if remove != "" {
		removePackageRules(remove)
		return
	}
	
	// Parse proxy address
	if config.ProxyAddr == "" {
		flag.Usage()
		os.Exit(1)
	}	
	parseProxyAddr()	
	// Get packages
	if !config.UseGlobal {
		config.Packages = flag.Args()
		if len(config.Packages) == 0 {
			flag.Usage()
			os.Exit(1)
		}
	}
	
	// Enable IPv4 forwarding
	exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run()
	
	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	
	// Initialize iptables chain
	initChain()	
	// Apply rules
	if config.UseGlobal {
		applyGlobalRules()
	} else {
		for _, pkg := range config.Packages {
			uid := getPackageUID(pkg)
			if uid > 0 {
				logf("Found package %s with UID %d", pkg, uid)
				applyPackageRules(pkg, uid)
			}
		}
	}
	
	// For redirect mode, just wait for signal
	// this mode demands a upstream transparent proxy
	if config.ProxyType == "redirect" {
		logf("Direct redirect mode active to %s:%d", config.ProxyHost, config.ProxyPort)
		if config.Daemon {
			daemonize()
		}
		
		// If stats enabled, show iptables stats
		if config.Stats {
			go showIptablesStats()
		}
		
		<-sigChan
	} else {
		// Start local proxy for http/socks5 modes
		if config.Daemon {
			daemonize()
		}
		
		go runProxy()
		logf("Started %s proxy on port %d", config.ProxyType, config.LocalPort)
		<-sigChan
	}
	
	// Cleanup
	logf("Shutting down...")
	if config.UseGlobal {
		removeGlobalRules()
	} else {
		for _, pkg := range config.Packages {
			removePackageRules(pkg)
		}
	}
}

func parseProxyAddr() {
	addr := config.ProxyAddr
	
	// Determine proxy type
	if strings.HasPrefix(addr, "http://") {
		config.ProxyType = "http"
		addr = strings.TrimPrefix(addr, "http://")
	} else if strings.HasPrefix(addr, "socks5://") {
		config.ProxyType = "socks5"
		addr = strings.TrimPrefix(addr, "socks5://")
	} else if !strings.Contains(addr, "://") {
		config.ProxyType = "redirect"
	} else {
		fatal("Unknown proxy type")
	}
	
	// Parse host:port
	parts := strings.Split(addr, ":")
	if len(parts) != 2 {
		fatal("Invalid proxy address format")
	}
	
	config.ProxyHost = parts[0]
	port, err := strconv.Atoi(parts[1])
	if err != nil {
		fatal("Invalid proxy port")
	}
	config.ProxyPort = port
}

func getPackageUID(pkg string) int {
	// Try pm command
	out, err := exec.Command("pm", "list", "packages", "-U", pkg).Output()
	if err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, pkg) && strings.Contains(line, "uid:") {
				parts := strings.Fields(line)
				for _, part := range parts {
					if strings.HasPrefix(part, "uid:") {
						uid, _ := strconv.Atoi(strings.TrimPrefix(part, "uid:"))
						return uid
					}
				}
			}
		}
	}
	
	// Try stat /data/data/package
	info, err := os.Stat("/data/data/" + pkg)
	if err == nil {
		if stat, ok := info.Sys().(*syscall.Stat_t); ok {
			return int(stat.Uid)
		}
	}
	
	fatal("Could not find UID for package %s", pkg)
	return 0
}

func initChain() {
	// Create custom chain
	exec.Command("iptables", "-t", "nat", "-N", CHAIN_NAME).Run()
	
	// Add to OUTPUT
	if err := exec.Command("iptables", "-t", "nat", "-C", "OUTPUT", "-j", CHAIN_NAME).Run(); err != nil {
		exec.Command("iptables", "-t", "nat", "-A", "OUTPUT", "-j", CHAIN_NAME).Run()
	}
}

func applyPackageRules(pkg string, uid int) {
	comment := fmt.Sprintf("GROID:%s", pkg)
	
	if config.ProxyType == "redirect" {
		// Direct DNAT redirect
		runCmd("iptables", "-t", "nat", "-A", CHAIN_NAME,
			"-m", "owner", "--uid-owner", strconv.Itoa(uid),
			"-p", "tcp", "!", "-d", "127.0.0.1",
			"-j", "DNAT", "--to-destination", fmt.Sprintf("%s:%d", config.ProxyHost, config.ProxyPort),
			"-m", "comment", "--comment", comment)
		
		// MASQUERADE for return traffic
		runCmd("iptables", "-t", "nat", "-A", "POSTROUTING",
			"-m", "owner", "--uid-owner", strconv.Itoa(uid),
			"-p", "tcp", "!", "-d", "127.0.0.1",
			"-j", "MASQUERADE",
			"-m", "comment", "--comment", comment)
	} else {
		// Local REDIRECT for http/socks5
		runCmd("iptables", "-t", "nat", "-A", CHAIN_NAME,
			"-m", "owner", "--uid-owner", strconv.Itoa(uid),
			"-p", "tcp", "!", "-d", "127.0.0.1",
			"-j", "REDIRECT", "--to-ports", strconv.Itoa(config.LocalPort),
			"-m", "comment", "--comment", comment)
		
		// Accept on local port
		runCmd("iptables", "-A", "INPUT",
			"-p", "tcp", "--dport", strconv.Itoa(config.LocalPort),
			"-j", "ACCEPT",
			"-m", "comment", "--comment", comment)
	}
	
	// DNS redirect if enabled
	if config.DNSRedirect {
		if config.ProxyType == "redirect" {
			runCmd("iptables", "-t", "nat", "-A", CHAIN_NAME,
				"-m", "owner", "--uid-owner", strconv.Itoa(uid),
				"-p", "udp", "--dport", "53",
				"-j", "DNAT", "--to-destination", fmt.Sprintf("%s:53", config.ProxyHost),
				"-m", "comment", "--comment", comment)
		}
	}
}

func applyGlobalRules() {
	comment := "GROID:global"
	
	if config.ProxyType == "redirect" {
		// Direct DNAT redirect
		runCmd("iptables", "-t", "nat", "-A", CHAIN_NAME,
			"-p", "tcp", "!", "-d", "127.0.0.1",
			"-j", "DNAT", "--to-destination", fmt.Sprintf("%s:%d", config.ProxyHost, config.ProxyPort),
			"-m", "comment", "--comment", comment)
		
		// MASQUERADE for return traffic
		runCmd("iptables", "-t", "nat", "-A", "POSTROUTING",
			"-p", "tcp", "!", "-d", "127.0.0.1",
			"-j", "MASQUERADE",
			"-m", "comment", "--comment", comment)
	} else {
		// Local REDIRECT for http/socks5
		runCmd("iptables", "-t", "nat", "-A", CHAIN_NAME,
			"-p", "tcp", "!", "-d", "127.0.0.1",
			"-j", "REDIRECT", "--to-ports", strconv.Itoa(config.LocalPort),
			"-m", "comment", "--comment", comment)
		
		// Accept on local port
		runCmd("iptables", "-A", "INPUT",
			"-p", "tcp", "--dport", strconv.Itoa(config.LocalPort),
			"-j", "ACCEPT",
			"-m", "comment", "--comment", comment)
	}
}

func removePackageRules(pkg string) {
	comment := fmt.Sprintf("GROID:%s", pkg)
	removeRulesWithComment("nat", CHAIN_NAME, comment)
	removeRulesWithComment("nat", "POSTROUTING", comment)
	removeRulesWithComment("filter", "INPUT", comment)
}

func removeGlobalRules() {
	comment := "GROID:global"
	removeRulesWithComment("nat", CHAIN_NAME, comment)
	removeRulesWithComment("nat", "POSTROUTING", comment)
	removeRulesWithComment("filter", "INPUT", comment)
}

func removeRulesWithComment(table, chain, comment string) {
	for {
		out, _ := exec.Command("iptables", "-t", table, "-L", chain, "--line-numbers", "-n").Output()
		lines := strings.Split(string(out), "\n")
		
		removed := false
		for i := len(lines) - 1; i >= 0; i-- {
			if strings.Contains(lines[i], comment) {
				parts := strings.Fields(lines[i])
				if len(parts) > 0 {
					if num, err := strconv.Atoi(parts[0]); err == nil {
						exec.Command("iptables", "-t", table, "-D", chain, strconv.Itoa(num)).Run()
						removed = true
						break
					}
				}
			}
		}
		
		if !removed {
			break
		}
	}
}

func flushRules() {
	exec.Command("iptables", "-t", "nat", "-F", CHAIN_NAME).Run()
	removeRulesWithComment("nat", "OUTPUT", "GROID:")
	removeRulesWithComment("nat", "POSTROUTING", "GROID:")
	removeRulesWithComment("filter", "INPUT", "GROID:")
	logf("All GROID rules flushed")
}

func listRules() {
	fmt.Println("=== GROID Rules ===")
	
	tables := []struct{ table, chain string }{
		{"nat", CHAIN_NAME},
		{"nat", "OUTPUT"},
		{"nat", "POSTROUTING"},
		{"filter", "INPUT"},
	}
	
	for _, tc := range tables {
		out, _ := exec.Command("sh", "-c", 
			fmt.Sprintf("iptables -t %s -L %s -n -v | grep GROID", tc.table, tc.chain)).Output()
		if len(out) > 0 {
			fmt.Printf("\n%s table - %s chain:\n%s", tc.table, tc.chain, out)
		}
	}
}

func runProxy() {
	listener, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", config.LocalPort))
	if err != nil {
		fatal("Failed to start proxy: %v", err)
	}
	defer listener.Close()
	
	for {
		client, err := listener.Accept()
		if err != nil {
			continue
		}
		
		go handleClient(client)
	}
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

func setupHTTPProxy(proxy net.Conn, firstData []byte, host string, port int) error {
	// Check if it's HTTP request
	data := string(firstData)
	
	if strings.HasPrefix(data, "CONNECT ") {
		// HTTPS CONNECT - forward as-is
		proxy.Write(firstData)
	} else if strings.Contains(data, " HTTP/") {
		// HTTP request - convert to absolute URL
		lines := strings.Split(data, "\r\n")
		if len(lines) > 0 {
			parts := strings.Fields(lines[0])
			if len(parts) >= 3 {
				// Keep original port, not proxy port!
				scheme := "http"
				if port == 443 {
					scheme = "https"
				}
				absoluteURL := fmt.Sprintf("%s://%s:%d%s", scheme, host, port, parts[1])
				lines[0] = fmt.Sprintf("%s %s %s", parts[0], absoluteURL, parts[2])
				
				proxy.Write([]byte(strings.Join(lines, "\r\n")))
				return nil
			}
		}
		// Fallback - send as-is
		proxy.Write(firstData)
	} else {
		// Not HTTP - send as-is
		proxy.Write(firstData)
	}
	
	return nil
}

func setupSOCKS5Proxy(proxy net.Conn, host string, port int) error {
	// SOCKS5 handshake
	proxy.Write([]byte{0x05, 0x01, 0x00}) // Version 5, 1 method, no auth
	
	resp := make([]byte, 2)
	if _, err := io.ReadFull(proxy, resp); err != nil {
		return err
	}
	
	if resp[0] != 0x05 || resp[1] != 0x00 {
		return fmt.Errorf("SOCKS5 handshake failed")
	}
	
	// Build connect request
	req := []byte{0x05, 0x01, 0x00} // Version 5, connect, reserved
	
	// Add destination
	ip := net.ParseIP(host)
	if ip != nil && ip.To4() != nil {
		req = append(req, 0x01) // IPv4
		req = append(req, ip.To4()...)
	} else if ip != nil {
		req = append(req, 0x04) // IPv6
		req = append(req, ip.To16()...)
	} else {
		req = append(req, 0x03) // Domain
		req = append(req, byte(len(host)))
		req = append(req, []byte(host)...)
	}
	
	// Add port
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))
	req = append(req, portBytes...)
	
	// Send connect
	if _, err := proxy.Write(req); err != nil {
		return err
	}
	
	// Read response
	resp = make([]byte, 4)
	if _, err := io.ReadFull(proxy, resp); err != nil {
		return err
	}
	
	if resp[1] != 0x00 {
		return fmt.Errorf("SOCKS5 connect failed: %d", resp[1])
	}
	
	// Skip bind address
	switch resp[3] {
	case 0x01: // IPv4
		io.ReadFull(proxy, make([]byte, 4+2))
	case 0x03: // Domain
		var len byte
		binary.Read(proxy, binary.BigEndian, &len)
		io.ReadFull(proxy, make([]byte, int(len)+2))
	case 0x04: // IPv6
		io.ReadFull(proxy, make([]byte, 16+2))
	}
	
	return nil
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

func relayWithStats(client, proxy net.Conn, target string) {
	done := make(chan bool, 2)
	var clientToProxy, proxyToClient int64
	
	// Client to Proxy
	go func() {
		buf := make([]byte, 4*1024)
		for {
			n, err := client.Read(buf)
			if err != nil {
				break
			}
			
			written, err := proxy.Write(buf[:n])
			if err != nil {
				break
			}
			
			clientToProxy += int64(written)
			printStats(target, clientToProxy, proxyToClient)
		}
		done <- true
	}()
	
	// Proxy to Client
	go func() {
		buf := make([]byte, 4*1024)
		for {
			n, err := proxy.Read(buf)
			if err != nil {
				break
			}
			
			written, err := client.Write(buf[:n])
			if err != nil {
				break
			}
			
			proxyToClient += int64(written)
			go printStats(target, clientToProxy, proxyToClient)
		}
		done <- true
	}()
	
	// Wait for both directions to complete
	<-done
	<-done
	
	// Print final stats with newline
	fmt.Printf("\r[%s] %s - TX: %s, RX: %s [CLOSED]\n", 
		time.Now().Format("15:04:05"), 
		target,
		formatBytes(clientToProxy), 
		formatBytes(proxyToClient))
}

func printStats(target string, tx, rx int64) {
	fmt.Printf("\r[%s] %s - TX: %s, RX: %s", 
		time.Now().Format("15:04:05"), 
		target,
		formatBytes(tx), 
		formatBytes(rx))
}

func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

func showIptablesStats() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	
	for range ticker.C {
		// Get stats from GROID_OUT chain
		out, err := exec.Command("iptables", "-t", "nat", "-L", CHAIN_NAME, "-n", "-v", "-x").Output()
		if err != nil {
			continue
		}
		
		lines := strings.Split(string(out), "\n")
		var totalPackets, totalBytes int64
		
		for _, line := range lines {
			if strings.Contains(line, "DNAT") || strings.Contains(line, "REDIRECT") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					packets, _ := strconv.ParseInt(fields[0], 10, 64)
					bytes, _ := strconv.ParseInt(fields[1], 10, 64)
					totalPackets += packets
					totalBytes += bytes
				}
			}
		}
		
		fmt.Printf("\r[%s] Chain %s - Packets: %d, Data: %s", 
			time.Now().Format("15:04:05"),
			CHAIN_NAME,
			totalPackets,
			formatBytes(totalBytes))
	}
}

func daemonize() {
	if os.Getppid() != 1 {
		cmd := exec.Command(os.Args[0], os.Args[1:]...)
		cmd.Stdout = nil
		cmd.Stderr = nil
		cmd.Stdin = nil
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		
		if err := cmd.Start(); err != nil {
			fatal("Failed to daemonize: %v", err)
		}
		
		fmt.Printf("Started daemon with PID %d\n", cmd.Process.Pid)
		os.Exit(0)
	}
}

func runCmd(name string, args ...string) {
	if err := exec.Command(name, args...).Run(); err != nil {
		logf("Command failed: %s %v", name, args)
	}
}

func logf(format string, args ...interface{}) {
	fmt.Printf("[%s] %s\n", time.Now().Format("15:04:05"), fmt.Sprintf(format, args...))
}

func debugf(format string, args ...interface{}) {
	if config.Verbose {
		logf("DEBUG: "+format, args...)
	}
}

func fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "ERROR: "+format+"\n", args...)
	os.Exit(1)
}
