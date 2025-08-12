package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

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

// isConnectionClosed checks if error indicates a real connection close
func isConnectionClosed(err error) bool {
	if err == nil {
		return false
	}

	errStr := strings.ToLower(err.Error())
	connectionClosedPatterns := []string{
		"connection reset by peer",
		"broken pipe",
		"use of closed network connection",
	}
	for _, pattern := range connectionClosedPatterns {
		if strings.Contains(errStr, pattern) {
			return true
		}
	}

	return false
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

func isBlacklisted(host string) bool {
	if len(blacklistMap) == 0 {
		return false
	}
	// Check exact match
	if blacklistMap[host] {
		return true
	}
	// Check wildcard domains (e.g., .facebook.com blocks *.facebook.com)
	for blocked := range blacklistMap {
		if strings.HasPrefix(blocked, ".") && strings.HasSuffix(host, blocked) {
			return true
		}
	}
	return false
}

func debugCapturedData(capture *CaptureData) {
	fmt.Printf("=== CAPTURE DEBUG ===\n")
	fmt.Printf("Method: %s\n", capture.Method)
	fmt.Printf("URL: %s\n", capture.URL)
	fmt.Printf("Request (first 200 chars):\n%s\n", string(capture.Request[:min(200, len(capture.Request))]))
	fmt.Printf("Response (first 200 chars):\n%s\n", string(capture.Response[:min(200, len(capture.Response))]))
	fmt.Printf("==================\n")
}
