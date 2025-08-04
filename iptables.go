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
