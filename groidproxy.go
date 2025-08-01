package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

const (
	CHAIN_NAME = "PDROID_OUT"
	NAT_TABLE  = "nat"
	VERSION    = "2.0.0"
	SO_ORIGINAL_DST = 80
)

type Config struct {
	Packages    []string
	ProxyAddr   string
	ProxyType   string // "http", "socks5", "redirect"
	ProxyHost   string
	ProxyPort   int
	ProxyAuth   *ProxyAuth
	Daemon      bool
	PidFile     string
	Verbose     bool
	JSONLog     bool
	Once        bool
	DNSRedirect bool
	LocalPort   int
	UseGlobal   bool
	ConfigFile  string
	PoolSize    int // Connection pool size
}

type ProxyAuth struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type FileConfig struct {
	Proxy struct {
		Address  string     `json:"address"`
		Auth     *ProxyAuth `json:"auth,omitempty"`
		PoolSize int        `json:"pool_size,omitempty"`
	} `json:"proxy"`
	Apps   []string `json:"apps,omitempty"`
	Global bool     `json:"global,omitempty"`
	DNS    bool     `json:"dns_redirect,omitempty"`
	Port   int      `json:"local_port,omitempty"`
}

type Logger struct {
	verbose bool
	jsonLog bool
	mu      sync.Mutex
}

type ProxyPool struct {
	mu       sync.Mutex
	conns    chan net.Conn
	addr     string
	auth     *ProxyAuth
	proxyType string
}

type TrafficStats struct {
	BytesSent     uint64
	BytesReceived uint64
	Connections   uint64
	mu            sync.RWMutex
}

var (
	logger      = &Logger{}
	proxyPool   *ProxyPool
	bufferPool  = sync.Pool{
		New: func() interface{} {
			return make([]byte, 32*1024) // 32KB buffers
		},
	}
	stats = &TrafficStats{}
)

func (l *Logger) log(level, msg string, fields map[string]interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.verbose && level == "DEBUG" {
		return
	}

	if l.jsonLog {
		entry := map[string]interface{}{
			"time":  time.Now().Format(time.RFC3339),
			"level": level,
			"msg":   msg,
		}
		for k, v := range fields {
			entry[k] = v
		}
		data, _ := json.Marshal(entry)
		fmt.Println(string(data))
	} else {
		fmt.Printf("[%s] %s: %s", time.Now().Format("15:04:05"), level, msg)
		if len(fields) > 0 {
			fmt.Printf(" %+v", fields)
		}
		fmt.Println()
	}
}

func main() {
	var config Config

	flag.StringVar(&config.ProxyAddr, "p", "", "Proxy address (format: [user:pass@]ip:port, http://[user:pass@]ip:port, socks5://[user:pass@]ip:port)")
	flag.BoolVar(&config.Daemon, "d", false, "Run as daemon")
	flag.StringVar(&config.PidFile, "pid", "/data/local/tmp/pdroid.pid", "PID file location")
	flag.BoolVar(&config.Verbose, "v", false, "Verbose logging")
	flag.BoolVar(&config.JSONLog, "json", false, "Output logs in JSON format")
	flag.BoolVar(&config.Once, "once", false, "Apply rules and exit (no daemon)")
	flag.BoolVar(&config.DNSRedirect, "dns", false, "Also redirect DNS (UDP port 53)")
	flag.IntVar(&config.LocalPort, "local-port", 8123, "Local port for transparent proxy")
	flag.BoolVar(&config.UseGlobal, "global", false, "Redirect all traffic (not app-specific)")
	flag.StringVar(&config.ConfigFile, "config", "", "Configuration file path")
	flag.IntVar(&config.PoolSize, "pool-size", 10, "Connection pool size")

	var flush bool
	var remove string
	var list bool

	flag.BoolVar(&flush, "flush", false, "Flush all PDROID rules")
	flag.StringVar(&remove, "remove", "", "Remove rules for specific package")
	flag.BoolVar(&list, "list", false, "List current rules")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "GO Droid Proxy v%s - Android Transparent Proxy\n\n", VERSION)
		fmt.Fprintf(os.Stderr, "Usage: %s [options] [package1] [package2] ...\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nProxy Modes:\n")
		fmt.Fprintf(os.Stderr, "  - Direct redirect (no protocol): Redirects directly to external transparent proxy\n")
		fmt.Fprintf(os.Stderr, "  - HTTP proxy (http://): Creates local transparent proxy that forwards to HTTP proxy\n")
		fmt.Fprintf(os.Stderr, "  - SOCKS5 proxy (socks5://): Creates local transparent proxy that forwards to SOCKS5 proxy\n")
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  # Direct redirect to external transparent proxy\n")
		fmt.Fprintf(os.Stderr, "  %s -p 192.168.1.100:8888 com.example.app\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  # Local transparent proxy to HTTP proxy\n")
		fmt.Fprintf(os.Stderr, "  %s -p http://192.168.1.100:8080 com.example.app\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  # Local transparent proxy to SOCKS5 with auth\n")
		fmt.Fprintf(os.Stderr, "  %s -p user:pass@socks5://192.168.0.1:1080 -d com.app1 com.app2\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  # Configuration file\n")
		fmt.Fprintf(os.Stderr, "  %s -config /data/local/tmp/pdroid.json\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  # Redirect all traffic\n")
		fmt.Fprintf(os.Stderr, "  %s -p 192.168.1.100:8888 -global\n", os.Args[0])
	}

	flag.Parse()

	logger.verbose = config.Verbose
	logger.jsonLog = config.JSONLog

	// Check root
	if os.Geteuid() != 0 {
		logger.log("ERROR", "Must run as root", nil)
		os.Exit(1)
	}

	// Enable IP forwarding
	enableIPForwarding()

	// Handle special commands
	if flush {
		flushAllRules()
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

	// Load config file if specified
	if config.ConfigFile != "" {
		if err := loadConfigFile(&config); err != nil {
			logger.log("ERROR", "Failed to load config file", map[string]interface{}{
				"file":  config.ConfigFile,
				"error": err.Error(),
			})
			os.Exit(1)
		}
	}

	// Parse proxy address
	if config.ProxyAddr == "" {
		logger.log("ERROR", "Proxy address required (-p)", nil)
		os.Exit(1)
	}

	parseProxyAddr(&config)

	// For global mode, we don't need packages
	if !config.UseGlobal {
		if len(config.Packages) == 0 {
			config.Packages = flag.Args()
		}
		if len(config.Packages) == 0 {
			flag.Usage()
			os.Exit(1)
		}
	}

	// Initialize proxy pool only if not in redirect mode
	if config.ProxyType != "redirect" {
		proxyPool = NewProxyPool(
			fmt.Sprintf("%s:%d", config.ProxyHost, config.ProxyPort),
			config.ProxyType,
			config.ProxyAuth,
			config.PoolSize,
		)
	}

	// Setup signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Initialize chain
	initChain()

	// Apply rules
	if config.UseGlobal {
		applyGlobalRules(&config)
	} else {
		// Apply rules for each package
		for _, pkg := range config.Packages {
			uid, err := getPackageUID(pkg)
			if err != nil {
				logger.log("ERROR", "Failed to get UID", map[string]interface{}{
					"package": pkg,
					"error":   err.Error(),
				})
				continue
			}

			logger.log("INFO", "Found package", map[string]interface{}{
				"package": pkg,
				"uid":     uid,
			})

			applyPackageRules(&config, pkg, uid)
		}
	}

	if config.Once {
		logger.log("INFO", "Rules applied, exiting (once mode)", nil)
		return
	}

	// Only start local proxy if not in redirect mode
	if config.ProxyType != "redirect" {
		// Daemonize if requested
		if config.Daemon {
			daemonize(&config)
		}

		// Start transparent proxy
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			runTransparentProxy(ctx, &config)
		}()

		// Write PID file
		writePidFile(config.PidFile)
		defer os.Remove(config.PidFile)

		logger.log("INFO", "GO Droid Proxy started", map[string]interface{}{
			"version": VERSION,
			"mode":    config.ProxyType,
			"port":    config.LocalPort,
			"pool":    config.PoolSize,
		})

		// Start health check routine
		wg.Add(1)
		go func() {
			defer wg.Done()
			runHealthCheck(ctx, &config)
		}()

		// Wait for signal
		sig := <-sigChan
		logger.log("INFO", "Received signal", map[string]interface{}{
			"signal": sig.String(),
		})

		// Cancel context first
		cancel()

		// Wait for all goroutines to finish with timeout
		done := make(chan struct{})
		go func() {
			wg.Wait()
			close(done)
		}()

		select {
		case <-done:
			logger.log("INFO", "Clean shutdown completed", nil)
		case <-time.After(10 * time.Second):
			logger.log("WARN", "Forced shutdown after timeout", nil)
		}

		// Log final statistics
		stats.mu.RLock()
		logger.log("INFO", "Final statistics", map[string]interface{}{
			"connections": stats.Connections,
			"sent":        stats.BytesSent,
			"received":    stats.BytesReceived,
		})
		stats.mu.RUnlock()
	} else {
		// Redirect mode - just wait for signal
		logger.log("INFO", "Direct redirect mode active", map[string]interface{}{
			"target": fmt.Sprintf("%s:%d", config.ProxyHost, config.ProxyPort),
		})

		if config.Daemon {
			daemonize(&config)
		}

		// Write PID file
		writePidFile(config.PidFile)
		defer os.Remove(config.PidFile)

		// Wait for signal
		<-sigChan
		logger.log("INFO", "Shutting down redirect mode", nil)
	}

	// Cleanup rules
	if config.UseGlobal {
		removeGlobalRules()
	} else {
		for _, pkg := range config.Packages {
			removePackageRules(pkg)
		}
	}
}

func loadConfigFile(config *Config) error {
	data, err := os.ReadFile(config.ConfigFile)
	if err != nil {
		return err
	}

	var fc FileConfig
	if err := json.Unmarshal(data, &fc); err != nil {
		return err
	}

	// Apply file config to main config
	if fc.Proxy.Address != "" {
		config.ProxyAddr = fc.Proxy.Address
	}
	if fc.Proxy.Auth != nil {
		config.ProxyAuth = fc.Proxy.Auth
	}
	if fc.Proxy.PoolSize > 0 {
		config.PoolSize = fc.Proxy.PoolSize
	}
	if len(fc.Apps) > 0 {
		config.Packages = fc.Apps
	}
	if fc.Global {
		config.UseGlobal = true
	}
	if fc.DNS {
		config.DNSRedirect = true
	}
	if fc.Port > 0 {
		config.LocalPort = fc.Port
	}

	return nil
}

func parseProxyAddr(config *Config) {
	addr := config.ProxyAddr

	// Check for authentication
	if strings.Contains(addr, "@") {
		parts := strings.SplitN(addr, "@", 2)
		authPart := parts[0]
		addr = parts[1]

		// Remove protocol prefix from auth part if present
		authPart = strings.TrimPrefix(authPart, "http://")
		authPart = strings.TrimPrefix(authPart, "socks5://")
		authPart = strings.TrimPrefix(authPart, "socks://")

		authParts := strings.SplitN(authPart, ":", 2)
		if len(authParts) == 2 {
			config.ProxyAuth = &ProxyAuth{
				Username: authParts[0],
				Password: authParts[1],
			}
		}
	}

	// Parse protocol
	if !strings.Contains(addr, "://") {
		// No protocol specified - use redirect mode (direct iptables redirect)
		config.ProxyType = "redirect"
	} else if strings.HasPrefix(addr, "http://") {
		config.ProxyType = "http"
		addr = strings.TrimPrefix(addr, "http://")
	} else if strings.HasPrefix(addr, "socks5://") {
		config.ProxyType = "socks5"
		addr = strings.TrimPrefix(addr, "socks5://")
	} else if strings.HasPrefix(addr, "socks://") {
		config.ProxyType = "socks5"
		addr = strings.TrimPrefix(addr, "socks://")
	}

	parts := strings.Split(addr, ":")
	if len(parts) != 2 {
		logger.log("ERROR", "Invalid proxy address format", nil)
		os.Exit(1)
	}

	config.ProxyHost = parts[0]
	port, err := strconv.Atoi(parts[1])
	if err != nil {
		logger.log("ERROR", "Invalid proxy port", nil)
		os.Exit(1)
	}
	config.ProxyPort = port

	logger.log("DEBUG", "Parsed proxy configuration", map[string]interface{}{
		"type": config.ProxyType,
		"host": config.ProxyHost,
		"port": config.ProxyPort,
		"auth": config.ProxyAuth != nil,
	})
}

func enableIPForwarding() {
	// Check current value
	data, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if err != nil {
		logger.log("WARN", "Failed to read ip_forward", map[string]interface{}{
			"error": err.Error(),
		})
		return
	}

	current := strings.TrimSpace(string(data))
	if current == "0" {
		cmd := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1")
		if err := cmd.Run(); err != nil {
			logger.log("ERROR", "Failed to enable IP forwarding", map[string]interface{}{
				"error": err.Error(),
			})
		} else {
			logger.log("INFO", "Enabled IP forwarding", nil)
		}
	}
}

func getPackageUID(pkg string) (int, error) {
	// Method 1: Try using pm command
	cmd := exec.Command("pm", "list", "packages", "-U", pkg)
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, pkg) && strings.Contains(line, "uid:") {
				parts := strings.Fields(line)
				for _, part := range parts {
					if strings.HasPrefix(part, "uid:") {
						uidStr := strings.TrimPrefix(part, "uid:")
						return strconv.Atoi(uidStr)
					}
				}
			}
		}
	}

	// Method 2: Check /data/data directory
	dataPath := filepath.Join("/data/data", pkg)
	info, err := os.Stat(dataPath)
	if err == nil {
		if stat, ok := info.Sys().(*syscall.Stat_t); ok {
			return int(stat.Uid), nil
		}
	}

	// Method 3: Try dumpsys
	cmd = exec.Command("dumpsys", "package", pkg)
	output, err = cmd.Output()
	if err == nil {
		scanner := bufio.NewScanner(strings.NewReader(string(output)))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "userId=") {
				parts := strings.Fields(line)
				for _, part := range parts {
					if strings.HasPrefix(part, "userId=") {
						uidStr := strings.TrimPrefix(part, "userId=")
						return strconv.Atoi(uidStr)
					}
				}
			}
		}
	}

	return 0, fmt.Errorf("unable to determine UID for package: %s", pkg)
}

func initChain() {
	// Create custom chain if it doesn't exist
	cmd := exec.Command("iptables", "-t", NAT_TABLE, "-N", CHAIN_NAME)
	if err := cmd.Run(); err != nil {
		// Chain might already exist, that's ok
		logger.log("DEBUG", "Chain creation", map[string]interface{}{
			"chain": CHAIN_NAME,
			"note":  "might already exist",
		})
	}

	// Ensure chain is in OUTPUT (for locally generated packets)
	cmd = exec.Command("iptables", "-t", NAT_TABLE, "-C", "OUTPUT", "-j", CHAIN_NAME)
	if err := cmd.Run(); err != nil {
		cmd = exec.Command("iptables", "-t", NAT_TABLE, "-A", "OUTPUT", "-j", CHAIN_NAME)
		if err := cmd.Run(); err != nil {
			logger.log("ERROR", "Failed to add chain to OUTPUT", map[string]interface{}{
				"error": err.Error(),
			})
		} else {
			logger.log("INFO", "Added chain to OUTPUT", map[string]interface{}{
				"chain": CHAIN_NAME,
			})
		}
	}
}

func applyPackageRules(config *Config, pkg string, uid int) {
	comment := fmt.Sprintf("pdroid:%s", pkg)

	if config.ProxyType == "redirect" {
		// Direct redirect mode - redirect to external transparent proxy
		// Redirect TCP traffic directly to the external proxy
		cmd := exec.Command("iptables", "-t", NAT_TABLE, "-A", CHAIN_NAME,
			"-m", "owner", "--uid-owner", strconv.Itoa(uid),
			"-p", "tcp", "!", "-d", "127.0.0.1",
			"-j", "DNAT", "--to-destination", fmt.Sprintf("%s:%d", config.ProxyHost, config.ProxyPort),
			"-m", "comment", "--comment", comment)

		if err := cmd.Run(); err != nil {
			logger.log("ERROR", "Failed to add DNAT rule", map[string]interface{}{
				"package": pkg,
				"error":   err.Error(),
			})
		} else {
			logger.log("INFO", "Added DNAT rule for direct redirect", map[string]interface{}{
				"package": pkg,
				"uid":     uid,
				"dest":    fmt.Sprintf("%s:%d", config.ProxyHost, config.ProxyPort),
			})
		}

		// Also need SNAT for return traffic
		cmd = exec.Command("iptables", "-t", NAT_TABLE, "-A", "POSTROUTING",
			"-m", "owner", "--uid-owner", strconv.Itoa(uid),
			"-p", "tcp", "!", "-d", "127.0.0.1",
			"-j", "MASQUERADE",
			"-m", "comment", "--comment", comment)

		if err := cmd.Run(); err != nil {
			logger.log("WARN", "Failed to add MASQUERADE rule", map[string]interface{}{
				"error": err.Error(),
			})
		}
	} else {
		// Local transparent proxy mode (http:// or socks5://)
		// Mark packets in mangle table
		cmd := exec.Command("iptables", "-t", "mangle", "-A", "OUTPUT",
			"-m", "owner", "--uid-owner", strconv.Itoa(uid),
			"-j", "MARK", "--set-mark", strconv.Itoa(uid),
			"-m", "comment", "--comment", comment)

		if err := cmd.Run(); err != nil {
			logger.log("WARN", "Failed to add mangle rule", map[string]interface{}{
				"package": pkg,
				"error":   err.Error(),
			})
		} else {
			logger.log("DEBUG", "Added mangle rule", map[string]interface{}{
				"package": pkg,
				"uid":     uid,
			})
		}

		// Redirect TCP traffic in custom chain
		cmd = exec.Command("iptables", "-t", NAT_TABLE, "-A", CHAIN_NAME,
			"-p", "tcp", "-m", "mark", "--mark", strconv.Itoa(uid),
			"!", "-d", "127.0.0.1",
			"-j", "REDIRECT", "--to-ports", strconv.Itoa(config.LocalPort),
			"-m", "comment", "--comment", comment)

		if err := cmd.Run(); err != nil {
			// If mark-based redirect fails, try uid-owner in custom chain
			logger.log("WARN", "Mark-based redirect failed, trying uid-owner method", nil)

			cmd = exec.Command("iptables", "-t", NAT_TABLE, "-A", CHAIN_NAME,
				"-m", "owner", "--uid-owner", strconv.Itoa(uid),
				"-p", "tcp", "!", "-d", "127.0.0.1",
				"-j", "REDIRECT", "--to-ports", strconv.Itoa(config.LocalPort),
				"-m", "comment", "--comment", comment)

			if err := cmd.Run(); err != nil {
				logger.log("ERROR", "Failed to add redirect rule", map[string]interface{}{
					"package": pkg,
					"error":   err.Error(),
				})
			} else {
				logger.log("INFO", "Added redirect rule (uid-owner method)", map[string]interface{}{
					"package": pkg,
					"uid":     uid,
				})
			}
		} else {
			logger.log("INFO", "Added redirect rule (mark method)", map[string]interface{}{
				"package": pkg,
				"uid":     uid,
			})
		}

		// Add ACCEPT rule for the proxy port
		cmd = exec.Command("iptables", "-A", "INPUT",
			"-p", "tcp", "--dport", strconv.Itoa(config.LocalPort),
			"-j", "ACCEPT",
			"-m", "comment", "--comment", comment)

		if err := cmd.Run(); err != nil {
			logger.log("WARN", "Failed to add INPUT ACCEPT rule", map[string]interface{}{
				"error": err.Error(),
			})
		}
	}

	// DNS redirect if enabled
	if config.DNSRedirect {
		if config.ProxyType == "redirect" {
			// Direct DNS redirect to external proxy
			cmd := exec.Command("iptables", "-t", NAT_TABLE, "-A", CHAIN_NAME,
				"-m", "owner", "--uid-owner", strconv.Itoa(uid),
				"-p", "udp", "--dport", "53",
				"-j", "DNAT", "--to-destination", fmt.Sprintf("%s:53", config.ProxyHost),
				"-m", "comment", "--comment", comment)
			
			if err := cmd.Run(); err != nil {
				logger.log("WARN", "Failed to add DNS DNAT rule", map[string]interface{}{
					"package": pkg,
					"error":   err.Error(),
				})
			}
		} else {
			// Local DNS redirect
			cmd := exec.Command("iptables", "-t", NAT_TABLE, "-A", CHAIN_NAME,
				"-m", "owner", "--uid-owner", strconv.Itoa(uid),
				"-p", "udp", "--dport", "53",
				"-j", "REDIRECT", "--to-ports", "5353",
				"-m", "comment", "--comment", comment)

			if err := cmd.Run(); err != nil {
				logger.log("WARN", "Failed to add DNS rule", map[string]interface{}{
					"package": pkg,
					"error":   err.Error(),
				})
			} else {
				logger.log("INFO", "Added DNS redirect rule", map[string]interface{}{
					"package": pkg,
				})
			}
		}
	}

	logger.log("INFO", "Rules applied", map[string]interface{}{
		"package": pkg,
		"uid":     uid,
		"mode":    config.ProxyType,
		"target":  fmt.Sprintf("%s:%d", config.ProxyHost, config.ProxyPort),
	})
}

func applyGlobalRules(config *Config) {
	comment := "pdroid:global"

	if config.ProxyType == "redirect" {
		// Direct redirect mode - redirect all traffic to external transparent proxy
		cmd := exec.Command("iptables", "-t", NAT_TABLE, "-A", CHAIN_NAME,
			"-p", "tcp", "!", "-d", "127.0.0.1",
			"-j", "DNAT", "--to-destination", fmt.Sprintf("%s:%d", config.ProxyHost, config.ProxyPort),
			"-m", "comment", "--comment", comment)

		if err := cmd.Run(); err != nil {
			logger.log("ERROR", "Failed to add global DNAT rule", map[string]interface{}{
				"error": err.Error(),
			})
		} else {
			logger.log("INFO", "Added global DNAT rule", map[string]interface{}{
				"dest": fmt.Sprintf("%s:%d", config.ProxyHost, config.ProxyPort),
			})
		}

		// SNAT for return traffic
		cmd = exec.Command("iptables", "-t", NAT_TABLE, "-A", "POSTROUTING",
			"-p", "tcp", "!", "-d", "127.0.0.1",
			"-j", "MASQUERADE",
			"-m", "comment", "--comment", comment)

		if err := cmd.Run(); err != nil {
			logger.log("WARN", "Failed to add MASQUERADE rule", map[string]interface{}{
				"error": err.Error(),
			})
		}
	} else {
		// Local transparent proxy mode
		// Redirect all TCP traffic in custom chain
		cmd := exec.Command("iptables", "-t", NAT_TABLE, "-A", CHAIN_NAME,
			"-p", "tcp", "!", "-d", "127.0.0.1",
			"-j", "REDIRECT", "--to-ports", strconv.Itoa(config.LocalPort),
			"-m", "comment", "--comment", comment)

		if err := cmd.Run(); err != nil {
			logger.log("ERROR", "Failed to add global TCP redirect rule", map[string]interface{}{
				"error": err.Error(),
			})
		} else {
			logger.log("INFO", "Added global TCP redirect rule", nil)
		}

		// Add ACCEPT rule for the proxy port
		cmd = exec.Command("iptables", "-A", "INPUT",
			"-p", "tcp", "--dport", strconv.Itoa(config.LocalPort),
			"-j", "ACCEPT",
			"-m", "comment", "--comment", comment)

		if err := cmd.Run(); err != nil {
			logger.log("WARN", "Failed to add INPUT ACCEPT rule", map[string]interface{}{
				"error": err.Error(),
			})
		}
	}

	// DNS redirect if enabled
	if config.DNSRedirect {
		if config.ProxyType == "redirect" {
			// Direct DNS redirect to external proxy
			cmd := exec.Command("iptables", "-t", NAT_TABLE, "-A", CHAIN_NAME,
				"-p", "udp", "--dport", "53",
				"-j", "DNAT", "--to-destination", fmt.Sprintf("%s:53", config.ProxyHost),
				"-m", "comment", "--comment", comment)
			
			if err := cmd.Run(); err != nil {
				logger.log("WARN", "Failed to add global DNS DNAT rule", map[string]interface{}{
					"error": err.Error(),
				})
			}
		} else {
			// Local DNS redirect
			cmd := exec.Command("iptables", "-t", NAT_TABLE, "-A", CHAIN_NAME,
				"-p", "udp", "--dport", "53",
				"-j", "REDIRECT", "--to-ports", "5353",
				"-m", "comment", "--comment", comment)

			if err := cmd.Run(); err != nil {
				logger.log("WARN", "Failed to add global DNS rule", map[string]interface{}{
					"error": err.Error(),
				})
			} else {
				logger.log("INFO", "Added global DNS redirect rule", nil)
			}
		}
	}

	logger.log("INFO", "Global rules applied", map[string]interface{}{
		"mode":   config.ProxyType,
		"target": fmt.Sprintf("%s:%d", config.ProxyHost, config.ProxyPort),
	})
}

func removePackageRules(pkg string) {
	comment := fmt.Sprintf("pdroid:%s", pkg)

	// Remove from all tables
	removeRulesFromChain("mangle", "OUTPUT", comment)
	removeRulesFromChain("nat", CHAIN_NAME, comment)
	removeRulesFromChain("nat", "POSTROUTING", comment) // For MASQUERADE rules
	removeRulesFromChain("filter", "INPUT", comment)

	logger.log("INFO", "Rules removed", map[string]interface{}{
		"package": pkg,
	})
}

func removeGlobalRules() {
	comment := "pdroid:global"

	removeRulesFromChain("nat", CHAIN_NAME, comment)
	removeRulesFromChain("nat", "POSTROUTING", comment) // For MASQUERADE rules
	removeRulesFromChain("filter", "INPUT", comment)

	logger.log("INFO", "Global rules removed", nil)
}

func removeRulesFromChain(table, chain, comment string) {
	for {
		cmd := exec.Command("iptables", "-t", table, "-L", chain,
			"--line-numbers", "-n")
		output, err := cmd.Output()
		if err != nil {
			logger.log("WARN", "Failed to list rules", map[string]interface{}{
				"table": table,
				"chain": chain,
				"error": err.Error(),
			})
			break
		}

		removed := false
		lines := strings.Split(string(output), "\n")
		for i := len(lines) - 1; i >= 0; i-- {
			if strings.Contains(lines[i], comment) {
				parts := strings.Fields(lines[i])
				if len(parts) > 0 {
					if num, err := strconv.Atoi(parts[0]); err == nil {
						cmd = exec.Command("iptables", "-t", table, "-D",
							chain, strconv.Itoa(num))
						if err := cmd.Run(); err != nil {
							logger.log("WARN", "Failed to delete rule", map[string]interface{}{
								"table": table,
								"chain": chain,
								"rule":  num,
								"error": err.Error(),
							})
						}
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

func flushAllRules() {
	// Flush custom chain
	cmd := exec.Command("iptables", "-t", NAT_TABLE, "-F", CHAIN_NAME)
	if err := cmd.Run(); err != nil {
		logger.log("ERROR", "Failed to flush custom chain", map[string]interface{}{
			"error": err.Error(),
		})
	} else {
		logger.log("INFO", "Flushed custom chain", nil)
	}

	// Remove all pdroid rules from other chains
	tables := []struct {
		table string
		chain string
	}{
		{"mangle", "OUTPUT"},
		{"nat", "OUTPUT"},
		{"nat", "POSTROUTING"},
		{"filter", "INPUT"},
	}

	for _, tc := range tables {
		removeRulesFromChain(tc.table, tc.chain, "pdroid:")
	}

	logger.log("INFO", "All PDROID rules flushed", nil)
}

func listRules() {
	fmt.Println("=== NAT Table - PDROID_OUT Chain ===")
	cmd := exec.Command("iptables", "-t", NAT_TABLE, "-L", CHAIN_NAME, "-n", "-v")
	output, err := cmd.Output()
	if err == nil {
		fmt.Print(string(output))
	}

	fmt.Println("\n=== NAT Table - OUTPUT Chain (pdroid rules) ===")
	cmd = exec.Command("sh", "-c", "iptables -t nat -L OUTPUT -n -v | grep pdroid")
	output, err = cmd.Output()
	if err == nil && len(output) > 0 {
		fmt.Print(string(output))
	}

	fmt.Println("\n=== NAT Table - POSTROUTING Chain (pdroid rules) ===")
	cmd = exec.Command("sh", "-c", "iptables -t nat -L POSTROUTING -n -v | grep pdroid")
	output, err = cmd.Output()
	if err == nil && len(output) > 0 {
		fmt.Print(string(output))
	}

	fmt.Println("\n=== Mangle Table - OUTPUT Chain (pdroid marks) ===")
	cmd = exec.Command("sh", "-c", "iptables -t mangle -L OUTPUT -n -v | grep pdroid")
	output, err = cmd.Output()
	if err == nil && len(output) > 0 {
		fmt.Print(string(output))
	}

	fmt.Println("\n=== Filter Table - INPUT Chain (pdroid accept) ===")
	cmd = exec.Command("sh", "-c", "iptables -L INPUT -n -v | grep pdroid")
	output, err = cmd.Output()
	if err == nil && len(output) > 0 {
		fmt.Print(string(output))
	}
}

func daemonize(config *Config) {
	if os.Getppid() != 1 {
		// Filter sensitive args
		args := []string{os.Args[0]}
		for i := 1; i < len(os.Args); i++ {
			// Skip proxy address with auth
			if (os.Args[i] == "-p" || os.Args[i] == "--proxy") && i+1 < len(os.Args) {
				if strings.Contains(os.Args[i+1], "@") {
					// Replace auth with placeholder
					parts := strings.SplitN(os.Args[i+1], "@", 2)
					args = append(args, os.Args[i], "***:***@"+parts[1])
					i++ // Skip next arg
					continue
				}
			}
			args = append(args, os.Args[i])
		}

		cmd := exec.Command(args[0], args[1:]...)
		cmd.Stdout = nil
		cmd.Stderr = nil
		cmd.Stdin = nil
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Setsid: true,
		}

		// Pass auth via environment if present
		if config.ProxyAuth != nil {
			cmd.Env = append(os.Environ(),
				fmt.Sprintf("PDROID_PROXY_USER=%s", config.ProxyAuth.Username),
				fmt.Sprintf("PDROID_PROXY_PASS=%s", config.ProxyAuth.Password),
			)
		}

		if err := cmd.Start(); err != nil {
			logger.log("ERROR", "Failed to daemonize", map[string]interface{}{
				"error": err.Error(),
			})
			os.Exit(1)
		}

		logger.log("INFO", "Started daemon", map[string]interface{}{
			"pid": cmd.Process.Pid,
		})
		os.Exit(0)
	}

	// Check for auth in environment (from parent daemon)
	if user := os.Getenv("PDROID_PROXY_USER"); user != "" {
		if pass := os.Getenv("PDROID_PROXY_PASS"); pass != "" {
			config.ProxyAuth = &ProxyAuth{
				Username: user,
				Password: pass,
			}
		}
	}
}

func writePidFile(path string) {
	file, err := os.Create(path)
	if err != nil {
		logger.log("WARN", "Failed to create PID file", map[string]interface{}{
			"error": err.Error(),
		})
		return
	}
	defer file.Close()

	fmt.Fprintf(file, "%d\n", os.Getpid())
}

func NewProxyPool(addr, proxyType string, auth *ProxyAuth, size int) *ProxyPool {
	return &ProxyPool{
		conns:     make(chan net.Conn, size),
		addr:      addr,
		proxyType: proxyType,
		auth:      auth,
	}
}

func (p *ProxyPool) Get(ctx context.Context) (net.Conn, error) {
	select {
	case conn := <-p.conns:
		// Check if connection is still alive
		if err := conn.SetDeadline(time.Now().Add(time.Millisecond)); err != nil {
			conn.Close()
			return p.createNewConnection(ctx)
		}
		conn.SetDeadline(time.Time{})
		return conn, nil
	default:
		return p.createNewConnection(ctx)
	}
}

func (p *ProxyPool) createNewConnection(ctx context.Context) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
	}
	
	conn, err := dialer.DialContext(ctx, "tcp", p.addr)
	if err != nil {
		return nil, err
	}

	// For SOCKS5, perform handshake
	if p.proxyType == "socks5" {
		if err := p.socks5Handshake(conn); err != nil {
			conn.Close()
			return nil, err
		}
	}

	return conn, nil
}

func (p *ProxyPool) socks5Handshake(conn net.Conn) error {
	// Send greeting
	if p.auth != nil {
		// With username/password auth
		conn.Write([]byte{0x05, 0x01, 0x02})
	} else {
		// No auth
		conn.Write([]byte{0x05, 0x01, 0x00})
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("socks5 handshake failed: %w", err)
	}

	if resp[0] != 0x05 {
		return fmt.Errorf("invalid SOCKS version: %d", resp[0])
	}

	// Handle authentication if required
	if resp[1] == 0x02 && p.auth != nil {
		// Username/password authentication
		authMsg := []byte{0x01}
		authMsg = append(authMsg, byte(len(p.auth.Username)))
		authMsg = append(authMsg, []byte(p.auth.Username)...)
		authMsg = append(authMsg, byte(len(p.auth.Password)))
		authMsg = append(authMsg, []byte(p.auth.Password)...)

		if _, err := conn.Write(authMsg); err != nil {
			return fmt.Errorf("failed to send auth: %w", err)
		}

		authResp := make([]byte, 2)
		if _, err := io.ReadFull(conn, authResp); err != nil {
			return fmt.Errorf("failed to read auth response: %w", err)
		}

		if authResp[1] != 0x00 {
			return fmt.Errorf("authentication failed")
		}
	} else if resp[1] == 0xFF {
		return fmt.Errorf("no acceptable authentication methods")
	}

	return nil
}

func (p *ProxyPool) Put(conn net.Conn) {
	select {
	case p.conns <- conn:
		// Connection returned to pool
	default:
		// Pool is full, close the connection
		conn.Close()
	}
}

func runTransparentProxy(ctx context.Context, config *Config) {
	listener, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", config.LocalPort))
	if err != nil {
		logger.log("ERROR", "Failed to start transparent proxy", map[string]interface{}{
			"error": err.Error(),
		})
		return
	}
	defer listener.Close()

	logger.log("INFO", "Transparent proxy listening", map[string]interface{}{
		"port": config.LocalPort,
		"type": config.ProxyType,
	})

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				logger.log("ERROR", "Accept error", map[string]interface{}{
					"error": err.Error(),
				})
				continue
			}
		}

		atomic.AddUint64(&stats.Connections, 1)
		go handleConnection(ctx, conn, config)
	}
}

func handleConnection(ctx context.Context, client net.Conn, config *Config) {
	defer client.Close()

	// Get original destination
	host, port, err := getOriginalDst(client)
	if err != nil {
		logger.log("ERROR", "Failed to get original destination", map[string]interface{}{
			"error": err.Error(),
		})
		return
	}

	logger.log("DEBUG", "New connection", map[string]interface{}{
		"client": client.RemoteAddr().String(),
		"dest":   fmt.Sprintf("%s:%d", host, port),
	})

	// Read the first bytes to determine the protocol
	buf := make([]byte, 1024)
	n, err := client.Read(buf)
	if err != nil {
		return
	}

	// Check if it's HTTP
	if isHTTPRequest(buf[:n]) {
		handleHTTPTransparent(ctx, client, buf[:n], host, port, config)
	} else {
		// Assume it's a regular TCP connection, use SOCKS5
		handleSOCKS5Transparent(ctx, client, buf[:n], host, port, config)
	}
}

func getOriginalDst(conn net.Conn) (string, int, error) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return "", 0, fmt.Errorf("not a TCP connection")
	}

	file, err := tcpConn.File()
	if err != nil {
		return "", 0, err
	}
	defer file.Close()

	fd := int(file.Fd())
	
	// Get original destination using SO_ORIGINAL_DST
	// We need to use RawSyscall to get the full sockaddr structure
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
		// Try IPv6
		var addr6 syscall.RawSockaddrInet6
		size6 := uint32(syscall.SizeofSockaddrInet6)
		
		_, _, errno := syscall.RawSyscall6(
			syscall.SYS_GETSOCKOPT,
			uintptr(fd),
			uintptr(syscall.IPPROTO_IPV6),
			uintptr(SO_ORIGINAL_DST),
			uintptr(unsafe.Pointer(&addr6)),
			uintptr(unsafe.Pointer(&size6)),
			0,
		)
		
		if errno != 0 {
			return "", 0, fmt.Errorf("failed to get original destination: %v", errno)
		}
		
		// Convert IPv6 address
		ip := net.IP(addr6.Addr[:])
		port := int(addr6.Port>>8) | int(addr6.Port&0xff)<<8
		return ip.String(), port, nil
	}
	
	// Convert IPv4 address
	ip := net.IPv4(addr.Addr[0], addr.Addr[1], addr.Addr[2], addr.Addr[3])
	port := int(addr.Port>>8) | int(addr.Port&0xff)<<8
	
	return ip.String(), port, nil
}

func isHTTPRequest(data []byte) bool {
	methods := []string{"GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "CONNECT ", "OPTIONS ", "TRACE ", "PATCH "}
	str := string(data)
	for _, method := range methods {
		if strings.HasPrefix(str, method) {
			return true
		}
	}
	return false
}

func handleHTTPTransparent(ctx context.Context, client net.Conn, firstData []byte, host string, port int, config *Config) {
	// Get proxy connection from pool
	proxy, err := proxyPool.Get(ctx)
	if err != nil {
		logger.log("ERROR", "Failed to connect to proxy", map[string]interface{}{
			"error": err.Error(),
		})
		return
	}
	defer func() {
		if config.ProxyType == "http" {
			proxyPool.Put(proxy)
		} else {
			proxy.Close()
		}
	}()

	// For HTTP proxy, modify the request
	if config.ProxyType == "http" {
		// Check if it's a CONNECT request
		str := string(firstData)
		if strings.HasPrefix(str, "CONNECT ") {
			// Forward as-is
			proxy.Write(firstData)
		} else {
			// Convert to absolute URL
			lines := strings.Split(str, "\r\n")
			if len(lines) > 0 {
				parts := strings.Fields(lines[0])
				if len(parts) >= 3 {
					// Reconstruct first line with absolute URL
					absoluteURL := fmt.Sprintf("http://%s:%d%s", host, port, parts[1])
					lines[0] = fmt.Sprintf("%s %s %s", parts[0], absoluteURL, parts[2])
					
					// Add Proxy-Authorization header if auth is configured
					if config.ProxyAuth != nil {
						authStr := fmt.Sprintf("%s:%s", config.ProxyAuth.Username, config.ProxyAuth.Password)
						authHeader := fmt.Sprintf("Proxy-Authorization: Basic %s", 
							base64.StdEncoding.EncodeToString([]byte(authStr)))
						
						// Insert after first line
						lines = append(lines[:1], append([]string{authHeader}, lines[1:]...)...)
					}
					
					modifiedRequest := strings.Join(lines, "\r\n")
					proxy.Write([]byte(modifiedRequest))
				} else {
					proxy.Write(firstData)
				}
			}
		}
	} else {
		// For SOCKS5, we need to send CONNECT command first
		if err := socks5Connect(proxy, host, port); err != nil {
			logger.log("ERROR", "SOCKS5 connect failed", map[string]interface{}{
				"error": err.Error(),
			})
			return
		}
		proxy.Write(firstData)
	}

	// Proxy the rest
	proxyData(client, proxy)
}

func handleSOCKS5Transparent(ctx context.Context, client net.Conn, firstData []byte, host string, port int, config *Config) {
	// For SOCKS5 proxy
	proxy, err := proxyPool.Get(ctx)
	if err != nil {
		logger.log("ERROR", "Failed to connect to SOCKS5 proxy", map[string]interface{}{
			"error": err.Error(),
		})
		return
	}
	defer proxy.Close()

	// Send CONNECT request
	if err := socks5Connect(proxy, host, port); err != nil {
		logger.log("ERROR", "SOCKS5 connect failed", map[string]interface{}{
			"error": err.Error(),
			"dest":  fmt.Sprintf("%s:%d", host, port),
		})
		return
	}

	// Send the initial data
	proxy.Write(firstData)

	// Proxy the rest
	proxyData(client, proxy)
}

func socks5Connect(conn net.Conn, host string, port int) error {
	// Build SOCKS5 connect request
	req := buildSocks5Request(host, port)
	if _, err := conn.Write(req); err != nil {
		return err
	}

	// Read response
	resp := make([]byte, 4)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}

	if resp[1] != 0x00 {
		return fmt.Errorf("SOCKS5 connect failed with reply: %d", resp[1])
	}

	// Skip bind address
	return skipSocks5Address(conn, resp[3])
}

func buildSocks5Request(host string, port int) []byte {
	req := []byte{0x05, 0x01, 0x00} // Version 5, connect, reserved

	// Try to parse as IP
	ip := net.ParseIP(host)
	if ip != nil {
		if ip.To4() != nil {
			req = append(req, 0x01) // IPv4
			req = append(req, ip.To4()...)
		} else {
			req = append(req, 0x04) // IPv6
			req = append(req, ip.To16()...)
		}
	} else {
		req = append(req, 0x03) // Domain
		req = append(req, byte(len(host)))
		req = append(req, []byte(host)...)
	}

	// Port (big endian)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))
	req = append(req, portBytes...)

	return req
}

func skipSocks5Address(conn net.Conn, addrType byte) error {
	switch addrType {
	case 0x01: // IPv4
		_, err := io.ReadFull(conn, make([]byte, 4))
		if err != nil {
			return err
		}
	case 0x03: // Domain
		var domainLen byte
		if err := binary.Read(conn, binary.BigEndian, &domainLen); err != nil {
			return err
		}
		_, err := io.ReadFull(conn, make([]byte, domainLen))
		if err != nil {
			return err
		}
	case 0x04: // IPv6
		_, err := io.ReadFull(conn, make([]byte, 16))
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown address type: %d", addrType)
	}
	
	// Read port
	_, err := io.ReadFull(conn, make([]byte, 2))
	return err
}

func proxyData(client, proxy net.Conn) {
	done := make(chan struct{}, 2)

	transfer := func(dst, src net.Conn, direction string) {
		defer func() {
			dst.Close()
			src.Close()
			done <- struct{}{}
		}()

		buf := bufferPool.Get().([]byte)
		defer bufferPool.Put(buf)

		var total int64
		for {
			n, err := src.Read(buf)
			if err != nil {
				if err != io.EOF {
					logger.log("DEBUG", "Read error", map[string]interface{}{
						"direction": direction,
						"error":     err.Error(),
					})
				}
				break
			}

			if n > 0 {
				if _, err := dst.Write(buf[:n]); err != nil {
					logger.log("DEBUG", "Write error", map[string]interface{}{
						"direction": direction,
						"error":     err.Error(),
					})
					break
				}
				total += int64(n)
			}
		}

		// Update statistics
		if direction == "client->proxy" {
			atomic.AddUint64(&stats.BytesSent, uint64(total))
		} else {
			atomic.AddUint64(&stats.BytesReceived, uint64(total))
		}
	}

	go transfer(proxy, client, "client->proxy")
	go transfer(client, proxy, "proxy->client")

	// Wait for both directions to complete
	<-done
	<-done
}

func runHealthCheck(ctx context.Context, config *Config) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			checkProxyHealth(config)
		}
	}
}

func checkProxyHealth(config *Config) {
	conn, err := net.DialTimeout("tcp",
		fmt.Sprintf("%s:%d", config.ProxyHost, config.ProxyPort),
		5*time.Second)
	
	if err != nil {
		logger.log("WARN", "Proxy health check failed", map[string]interface{}{
			"proxy": fmt.Sprintf("%s:%d", config.ProxyHost, config.ProxyPort),
			"error": err.Error(),
		})
		return
	}
	conn.Close()
	
	logger.log("DEBUG", "Proxy health check OK", nil)
}
