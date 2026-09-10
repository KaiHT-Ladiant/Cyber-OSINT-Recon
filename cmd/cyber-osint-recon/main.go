package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var (
	company           string
	output            string
	save              string
	subdomains        bool
	maxDepth          int
	workers           int
	shodanAPIKey      string
	censysToken       string
	virustotalAPIKey  string
	githubToken       string
	scanMode          string
	domainListPath    string
)

var rootCmd = &cobra.Command{
	Use:   "cyber-osint-recon",
	Short: "CyRecon - Cyber OSINT Recon",
	Long: `CyRecon (Cyber OSINT Recon) - Domain and Company Intelligence Gathering Tool

  - Domain WHOIS information collection
  - DNS record lookup (A, AAAA, MX, NS, TXT, CNAME)
  - Subdomain discovery
  - IP address and geolocation information
  - Email address collection
  - Web technology stack analysis
  - Report generation in JSON, HTML, Markdown, or DOCX formats
  - Real-time progress tracking with estimated remaining time
  - [Mode] single domain scan or multi-domain list scan

You can scan by domain name (e.g., example.com) or company name (e.g., "Example Corp").
When scanning by company name, the tool will automatically search for associated domains.

Developer: Kai_HT (redsec.kaiht.kr) | Team: RedSec (redsec.co.kr)`,
}

var scanCmd = &cobra.Command{
	Use:   "scan [domain|company|list-file]",
	Short: "Collect OSINT information for a domain, company, or domain list",
	Long: `Collect OSINT (Open Source Intelligence) information for a specified domain or company.

[Mode]
  single - Scan one domain or resolve domains from a company name (default)
  multi  - Scan many confirmed domains from a list file (one domain per line)

If you provide a domain (e.g., example.com), it will scan that domain directly.
If you provide a company name (e.g., "Example Corp"), it will search for associated domains and scan them.
In multi mode, pass --list domains.txt (or a list file as the positional argument).`,
	Example: `  # [Mode: single] Scan a domain
  cyber-osint-recon scan example.com

  # [Mode: single] Scan by company name (auto-searches for domains)
  cyber-osint-recon scan "Example Corp"

  # Scan domain with company name specified
  cyber-osint-recon scan example.com --company "Example Corp"

  # [Mode: multi] Scan domains from a list file
  cyber-osint-recon scan --mode multi --list domains.txt
  cyber-osint-recon scan --mode multi domains.txt

  # Specify output format
  cyber-osint-recon scan example.com --output json
  cyber-osint-recon scan example.com --output html
  cyber-osint-recon scan example.com --output markdown
  cyber-osint-recon scan example.com --output html --save report.html

  # Adjust email collection depth and worker count
  cyber-osint-recon scan example.com --subdomains=false
  cyber-osint-recon scan example.com --depth 3 --workers 20`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		mode, err := resolveScanMode(scanMode)
		if err != nil {
			return err
		}

		targets, resolvedCompany, err := resolveTargets(mode, args, company, domainListPath)
		if err != nil {
			return err
		}

		shodan, censys, vt := loadMergedAPIKeys(shodanAPIKey, censysToken, virustotalAPIKey)
		return runScan(targets, resolvedCompany, mode, subdomains, workers, maxDepth, output, save, shodan, censys, vt, githubToken)
	},
}

func init() {
	scanCmd.Flags().StringVar(&scanMode, "mode", "", "[Mode] Scan mode: single | multi (interactive prompt if omitted on TTY)")
	scanCmd.Flags().StringVarP(&domainListPath, "list", "L", "", "[Mode: multi] Path to domain list file (one domain per line)")
	scanCmd.Flags().StringVar(&company, "company", "", "Company name (optional)")
	scanCmd.Flags().StringVarP(&output, "output", "o", "markdown", "Output format (json, html, markdown, docx, excel)")
	scanCmd.Flags().StringVarP(&save, "save", "s", "", "Save report to file path")
	scanCmd.Flags().BoolVar(&subdomains, "subdomains", true, "Enable subdomain search")
	scanCmd.Flags().IntVarP(&maxDepth, "depth", "d", 2, "Maximum depth for email collection")
	scanCmd.Flags().IntVarP(&workers, "workers", "w", 10, "Number of workers for subdomain search")
	scanCmd.Flags().StringVar(&shodanAPIKey, "shodan-key", "", "Shodan API key (optional, for enhanced IP scanning)")
	scanCmd.Flags().StringVar(&censysToken, "censys-key", "", "Censys API token (optional, for enhanced IP scanning)")
	scanCmd.Flags().StringVar(&virustotalAPIKey, "virustotal-key", "", "VirusTotal API key (optional, for malware detection)")
	scanCmd.Flags().StringVar(&githubToken, "github-token", "", "GitHub API token (optional, for enhanced code search)")

	rootCmd.AddCommand(scanCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		msg := err.Error()
		if !strings.HasPrefix(msg, "[") {
			fmt.Fprintln(os.Stderr, "[!]", msg)
		} else {
			fmt.Fprintln(os.Stderr, msg)
		}
		os.Exit(1)
	}
}
