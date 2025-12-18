package main

import (
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
)

const (
	CHAIN_NAME      = "GROID_OUT"
	VERSION         = "1.3.1"
	SO_ORIGINAL_DST = 80
	SESS_FILE       = ".groidf" // Session file, used to verify clean shutdown
)

// HTTPPair represents a complete HTTP request/response pair
type HTTPPair struct {
	Request   []byte // Complete HTTP request data
	Response  []byte // Complete HTTP response data
	Timestamp int64  // Request timestamp in nanoseconds
	Host      string // Target hostname
	Method    string // HTTP method (GET, POST, etc.)
	URL       string // Request URL path
}

// HTTPPairer manages HTTP request/response pairing with FIFO queue
type HTTPPairer struct {
	mu          sync.Mutex    // Protects pending queue
	pending     []HTTPPair    // FIFO queue of pending requests
	saveChannel chan HTTPPair // Channel for completed pairs
}

// Global HTTP pairer instance
var httpPairer *HTTPPairer

type CaptureData struct {
	Timestamp int64
	Method    string
	URL       string
	Request   []byte
	Response  []byte
}

type CertCache struct {
	mu    sync.RWMutex
	certs map[string]*tls.Certificate
}

var (
	db          *sql.DB
	captureChan chan *CaptureData
	saveWg      sync.WaitGroup
	caCert      *x509.Certificate
	caKey       interface{}
	certCache   = &CertCache{certs: make(map[string]*tls.Certificate)}
)

const MAX_CAPTURE_SIZE = 10 * 1024 * 1024 // 10MB

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
	Blacklist   string
	SaveDB      string
	TLSCert     string
	TLSPass     string
}

var config Config
var blacklistMap map[string]bool

func main() {
	var flush, list bool
	var remove string
	// Parse flags
	flag.StringVar(&config.ProxyAddr, "p", "", "Proxy address (host:port or http://host:port or socks5://host:port)")
	flag.IntVar(&config.LocalPort, "local-port", 8123, "Local port for transparent proxy")
	flag.BoolVar(&config.Daemon, "d", false, "Run as daemon")
	flag.BoolVar(&config.UseGlobal, "global", false, "Redirect all user traffic")
	flag.BoolVar(&config.DNSRedirect, "dns", false, "Also redirect DNS (port 53)")
	flag.BoolVar(&config.Verbose, "v", false, "Verbose output")
	flag.BoolVar(&config.Stats, "stats", false, "Show I/O statistics")
	flag.IntVar(&config.Timeout, "timeout", 10, "Connection timeout in seconds")
	flag.BoolVar(&flush, "flush", false, "Remove all GROID rules")
	flag.BoolVar(&list, "list", false, "List current rules")
	flag.StringVar(&remove, "remove", "", "Remove rules for package")
	flag.StringVar(&config.Blacklist, "blacklist", "", "Comma-separated list of blocked hosts/IPs (use .domain.com for wildcards)\n[!] Doesn't work on raw redirect")
	flag.StringVar(&config.SaveDB, "save", "", "Save traffic to a SQLite database, i.e., /data/local/tmp/Groid.db\n[!] Doesn't work on raw redirect\n[*] Can work without external proxy, only saving app(s) traffic locally.")
	flag.StringVar(&config.TLSCert, "tlscert", "", "PKCS12 certificate for TLS interception AND CA per-host!")
	flag.StringVar(&config.TLSPass, "tlspass", "", "Password for PKCS12 certificate")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] [packages...]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nModes:\n")
		fmt.Fprintf(os.Stderr, "  host:port          - Redirect TCP package (raw redirect) to an external transparent proxy\n")
		fmt.Fprintf(os.Stderr, "  http://host:port   - Local transparent to HTTP proxy \n")
		fmt.Fprintf(os.Stderr, "  socks5://host:port - Local transparent to SOCKS5 proxy\n")
		fmt.Fprintf(os.Stderr, "  save /path/base.db - Save all HTTP traffic app <=> server to base.db\n")
		fmt.Fprintf(os.Stderr, "   |-> Can work without upstream-proxy \n")
		fmt.Fprintf(os.Stderr, "   |-> With TLS (PKS12) certificate saves clear data\n")
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s -p 192.168.1.100:8888 com.example.app\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -p http://192.168.1.100:8080 com.example.app com.android.chrome\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -p socks5://192.168.1.100:1080 -global\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -p socks5://192.168.1.100:1080 -blacklist \"facebook.com,.youtube.com\" com.example.app\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -p http://192.168.1.100:1080 -save /data/local/tmp/Example.db -tlscert burp.pk12 -tlspass pass com.example.app\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -save /data/local/tmp/Example.db -tlscert burp.pk12 -tlspass pass com.example.app\n", os.Args[0])
	}
	fmt.Fprintf(os.Stderr, "<=[Groid v%s - Golang Android Proxier]=>\n", VERSION)
	flag.Parse()
	if len(os.Args) == 1 {
		flag.Usage()
		os.Exit(1)
	}

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
	if config.ProxyAddr == "" && config.SaveDB == "" {
		flag.Usage()
		os.Exit(1)
	}
	parseProxyAddr()

	// Initialize database if save flag is set
	if config.SaveDB != "" {
		if err := initDatabase(config.SaveDB); err != nil {
			fatal("Failed to initialize database: %v", err)
		}
		defer closeDatabase()
		logf("Saving traffic to %s", config.SaveDB)
		initHTTPPairer()

		// Load TLS certificate if provided
		if config.TLSCert != "" {
			if err := loadPkcs12Certificate(config.TLSCert, config.TLSPass); err != nil {
				fatal("Failed to load TLS certificate: %v", err)
			}
			logf("TLS interception enabled")
		} else {
			logf("TLS interception is NOT configured, saving encrypted (TLS) data!!")
		}
	}

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

	// Parse blacklist (not available in raw redirect mode)
	if config.Blacklist != "" {
		if config.ProxyType == "redirect" {
			fatal("Blacklist not available in redirect mode")
		}
		blacklistMap = make(map[string]bool)
		for _, host := range strings.Split(config.Blacklist, ",") {
			host = strings.TrimSpace(host)
			if host != "" {
				blacklistMap[host] = true
				debugf("Blacklisted: %s", host)
			}
		}
	}

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Check for unclean shutdown from previous session
	if _, err := os.Stat(SESS_FILE); err == nil {
		logf("Last session died? Flushing rules")
		flushRules()
	}

	// Inits iptable rules etc.
	initChain()
	// Session file removed at cleanup stage
	os.WriteFile(SESS_FILE, []byte{}, 0644)

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
		if config.SaveDB != "" {
			logf("Warning: -save flag is ignored in redirect mode")
		}
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
		// Start local proxy for http/socks5/capture modes
		if config.Daemon {
			daemonize()
		}
		go runProxy()
		if config.ProxyType == "capture" {
			logf("Started capture mode on port %d", config.LocalPort)
		} else {
			logf("Started %s proxy on port %d", config.ProxyType, config.LocalPort)
		}
		if len(blacklistMap) > 0 {
			logf("Blacklist active with %d entries", len(blacklistMap))
		}
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
	os.Remove(SESS_FILE) // Cleanup completed :)
}
