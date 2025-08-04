package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
)

const (
	CHAIN_NAME      = "GROID_OUT"
	VERSION         = "1.0.2"
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
	Blacklist   string
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
	flag.BoolVar(&config.UseGlobal, "global", false, "Redirect all traffic")
	flag.BoolVar(&config.DNSRedirect, "dns", false, "Also redirect DNS (port 53)")
	flag.BoolVar(&config.Verbose, "v", false, "Verbose output")
	flag.BoolVar(&config.Stats, "stats", false, "Show I/O statistics")
	flag.IntVar(&config.Timeout, "timeout", 10, "Connection timeout in seconds")
	flag.BoolVar(&flush, "flush", false, "Remove all GROID rules")
	flag.BoolVar(&list, "list", false, "List current rules")
	flag.StringVar(&remove, "remove", "", "Remove rules for package")
	flag.StringVar(&config.Blacklist, "blacklist", "", "Comma-separated list of blocked hosts/IPs (use .domain.com for wildcards)")

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
		fmt.Fprintf(os.Stderr, "  %s -p socks5://192.168.1.100:1080 -blacklist \"facebook.com,.youtube.com\" com.example.app\n", os.Args[0])
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

	// Parse blacklist
	if config.Blacklist != "" && config.ProxyType != "redirect" {
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
