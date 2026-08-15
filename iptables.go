package main

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

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

func initChain() {
	// Create custom chain
	exec.Command("iptables", "-t", "nat", "-N", CHAIN_NAME).Run()

	// Exclude traffic from local proxy port to avoid redirect loop
	// Only needed for http/socks5 modes that use the local listener
	if config.ProxyType != "redirect" {
		exec.Command("iptables", "-t", "nat", "-A", CHAIN_NAME,
			"-p", "tcp", "--sport", strconv.Itoa(config.LocalPort),
			"-j", "RETURN").Run()
	}

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

	// Block IPv6 for this UID to force IPv4 fallback
	// iptables covers v4 only; REJECT makes dual-stack apps switch to v4 at once
	// this avoid Happy Eyeballs (RFC 8305)!!
	runCmd("ip6tables", "-A", "OUTPUT",
		"-m", "owner", "--uid-owner", strconv.Itoa(uid),
		"-j", "REJECT",
		"-m", "comment", "--comment", comment)

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
	removeRulesWithComment("iptables", "nat", CHAIN_NAME, comment)
	removeRulesWithComment("iptables", "nat", "POSTROUTING", comment)
	removeRulesWithComment("iptables", "filter", "INPUT", comment)
	removeRulesWithComment("ip6tables", "filter", "OUTPUT", comment)
}

func removeGlobalRules() {
	comment := "GROID:global"
	removeRulesWithComment("iptables", "nat", CHAIN_NAME, comment)
	removeRulesWithComment("iptables", "nat", "POSTROUTING", comment)
	removeRulesWithComment("iptables", "filter", "INPUT", comment)
}

// removeRulesWithComment deletes tagged rules; cmd is iptables or ip6tables
func removeRulesWithComment(cmd, table, chain, comment string) {
	for {
		out, _ := exec.Command(cmd, "-t", table, "-L", chain, "--line-numbers", "-n").Output()
		lines := strings.Split(string(out), "\n")

		removed := false
		for i := len(lines) - 1; i >= 0; i-- {
			if strings.Contains(lines[i], comment) {
				parts := strings.Fields(lines[i])
				if len(parts) > 0 {
					if num, err := strconv.Atoi(parts[0]); err == nil {
						exec.Command(cmd, "-t", table, "-D", chain, strconv.Itoa(num)).Run()
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
	removeRulesWithComment("iptables", "nat", "OUTPUT", "GROID:")
	removeRulesWithComment("iptables", "nat", "POSTROUTING", "GROID:")
	removeRulesWithComment("iptables", "filter", "INPUT", "GROID:")
	removeRulesWithComment("ip6tables", "filter", "OUTPUT", "GROID:")
	logf("All GROID rules flushed")
}

func listRules() {
	fmt.Println("=== GROID Rules ===")

	tables := []struct{ cmd, table, chain string }{
		{"iptables", "nat", CHAIN_NAME},
		{"iptables", "nat", "OUTPUT"},
		{"iptables", "nat", "POSTROUTING"},
		{"iptables", "filter", "INPUT"},
		{"ip6tables", "filter", "OUTPUT"},
	}

	for _, tc := range tables {
		out, _ := exec.Command("sh", "-c",
			fmt.Sprintf("%s -t %s -L %s -n -v | grep GROID", tc.cmd, tc.table, tc.chain)).Output()
		if len(out) > 0 {
			fmt.Printf("\n%s %s table - %s chain:\n%s", tc.cmd, tc.table, tc.chain, out)
		}
	}
}
