package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

const (
	modeSingle = "single"
	modeMulti  = "multi"
)

// resolveScanMode returns the effective scan mode.
// Priority: explicit --mode flag > interactive prompt (TTY) > default single.
func resolveScanMode(explicitMode string) (string, error) {
	mode := strings.ToLower(strings.TrimSpace(explicitMode))
	if mode != "" {
		if mode != modeSingle && mode != modeMulti {
			return "", fmt.Errorf("invalid mode %q (use single or multi)", explicitMode)
		}
		return mode, nil
	}

	if isInteractive() {
		return promptScanMode()
	}

	return modeSingle, nil
}

func isInteractive() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

func promptScanMode() (string, error) {
	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════╗")
	fmt.Println("║           [Mode] Scan Mode Select        ║")
	fmt.Println("╠══════════════════════════════════════════╣")
	fmt.Println("║  1) single  - scan one domain/company    ║")
	fmt.Println("║  2) multi   - scan domains from a list   ║")
	fmt.Println("╚══════════════════════════════════════════╝")
	fmt.Print("Select mode [1/single, 2/multi] (default: 1): ")

	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil && len(strings.TrimSpace(line)) == 0 {
		return modeSingle, nil
	}

	choice := strings.ToLower(strings.TrimSpace(line))
	switch choice {
	case "", "1", "single", "s":
		return modeSingle, nil
	case "2", "multi", "m", "batch", "list":
		return modeMulti, nil
	default:
		return "", fmt.Errorf("invalid mode selection %q (use 1/single or 2/multi)", choice)
	}
}

// loadDomainList reads domains from a text file (one domain per line).
// Lines starting with # and blank lines are ignored.
func loadDomainList(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open domain list %s: %w", path, err)
	}
	defer f.Close()

	seen := make(map[string]bool)
	var domains []string
	scanner := bufio.NewScanner(f)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Allow optional "domain,company" or whitespace-separated company notes; first token is domain.
		fields := strings.FieldsFunc(line, func(r rune) bool {
			return r == ',' || r == ';' || r == '\t' || r == ' '
		})
		if len(fields) == 0 {
			continue
		}
		domain := strings.ToLower(strings.TrimSpace(fields[0]))
		domain = strings.TrimPrefix(domain, "http://")
		domain = strings.TrimPrefix(domain, "https://")
		domain = strings.Trim(domain, "/")
		if domain == "" {
			continue
		}
		if !isDomain(domain) {
			fmt.Printf("[!] Skipping invalid domain on line %d: %s\n", lineNo, domain)
			continue
		}
		if seen[domain] {
			continue
		}
		seen[domain] = true
		domains = append(domains, domain)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed reading domain list: %w", err)
	}
	if len(domains) == 0 {
		return nil, fmt.Errorf("no valid domains found in list file: %s", path)
	}
	return domains, nil
}
