package main

import (
	"fmt"
	"net"
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
	if blacklistMap == nil || len(blacklistMap) == 0 {
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
