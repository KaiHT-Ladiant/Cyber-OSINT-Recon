package reporter

import (
	"cyber-osint-recon/internal/models"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nguyenthenguyen/docx"
)

// GenerateDOCXReport Generate DOCX format report using template
func GenerateDOCXReport(report *models.Report, filename string) error {
	if filename == "" {
		return fmt.Errorf("filename is required for DOCX output")
	}

	// Template file path
	templatePath := filepath.Join("Report", "template.docx")
	
	// Check if template exists, if not, create a simple one
	if _, err := os.Stat(templatePath); os.IsNotExist(err) {
		// Try to use the reference file as template
		refTemplate := filepath.Join("Report", "[대교] OSINT 추출정보 보고서.docx")
		if _, err := os.Stat(refTemplate); err == nil {
			templatePath = refTemplate
		} else {
			return fmt.Errorf("template file not found: %s. Please ensure template.docx exists in Report directory", templatePath)
		}
	}

	// Read template file
	r, err := docx.ReadDocxFile(templatePath)
	if err != nil {
		return fmt.Errorf("failed to read template file: %v", err)
	}
	defer r.Close()

	// Create editable document
	doc := r.Editable()

	// Build report content
	var content strings.Builder

	// Report title
	var title string
	if len(report.Domains) > 0 {
		domainList := make([]string, len(report.Domains))
		for i, d := range report.Domains {
			domainList[i] = d.Domain
		}
		title = fmt.Sprintf("Cyber OSINT Recon Report: %s", strings.Join(domainList, ", "))
	} else {
		title = fmt.Sprintf("Cyber OSINT Recon Report: %s", report.Domain)
	}
	content.WriteString(title + "\n\n")

	// Metadata
	content.WriteString("Generated: " + report.Timestamp.Format("2006-01-02 15:04:05") + "\n")
	content.WriteString("Developer: Kai_HT (redsec.kaiht.kr) | Team: RedSec (redsec.co.kr)\n\n")

	if report.Company != "" {
		content.WriteString("Company: " + report.Company + "\n\n")
	}

	content.WriteString("─────────────────────────────────────────────────────────────\n\n")

	// All Domains Information - Grouped by TLD
	if len(report.Domains) > 0 {
		content.WriteString(fmt.Sprintf("All Domains Information (%d domain(s))\n\n", len(report.Domains)))

		// Group domains by TLD
		domainsByTLD := make(map[string][]models.DomainReport)
		for _, domainReport := range report.Domains {
			tld := extractTLD(domainReport.Domain)
			domainsByTLD[tld] = append(domainsByTLD[tld], domainReport)
		}

		// Sort TLDs for consistent output
		tldOrder := []string{".kr", ".co.kr", ".com", ".net", ".org", ".io", ".co", ".other"}
		processedTLDs := make(map[string]bool)

		// Process known TLDs in order
		for _, tld := range tldOrder {
			if tld == ".other" {
				// Process remaining TLDs
				for t, domains := range domainsByTLD {
					if !processedTLDs[t] {
						content.WriteString(fmt.Sprintf("[%s] Domain Group (%d domain(s))\n\n", t, len(domains)))
						for _, domainReport := range domains {
							writeDomainReportContent(&content, &domainReport)
						}
						content.WriteString("─────────────────────────────────────────────────────────────\n\n")
					}
				}
			} else {
				if domains, exists := domainsByTLD[tld]; exists {
					processedTLDs[tld] = true
					content.WriteString(fmt.Sprintf("[%s] Domain Group (%d domain(s))\n\n", tld, len(domains)))
					for _, domainReport := range domains {
						writeDomainReportContent(&content, &domainReport)
					}
					content.WriteString("─────────────────────────────────────────────────────────────\n\n")
				}
			}
		}
	}

	// Primary Domain Information (for backward compatibility)
	if report.DomainInfo != nil {
		content.WriteString("Domain Information (WHOIS) - Primary Domain\n\n")
		if report.DomainInfo.Registrar != "" {
			content.WriteString("Registrar: " + report.DomainInfo.Registrar + "\n")
		}
		if !report.DomainInfo.CreatedDate.IsZero() {
			content.WriteString("Created Date: " + report.DomainInfo.CreatedDate.Format("2006-01-02") + "\n")
		}
		if !report.DomainInfo.UpdatedDate.IsZero() {
			content.WriteString("Updated Date: " + report.DomainInfo.UpdatedDate.Format("2006-01-02") + "\n")
		}
		if !report.DomainInfo.ExpiryDate.IsZero() {
			content.WriteString("Expiry Date: " + report.DomainInfo.ExpiryDate.Format("2006-01-02") + "\n")
		}
		if report.DomainInfo.Registrant != "" {
			content.WriteString("Registrant: " + report.DomainInfo.Registrant + "\n")
		}
		content.WriteString("\n")
	}

	// DNS records
	if report.DNSRecords != nil {
		content.WriteString("DNS Records\n\n")
		if len(report.DNSRecords.A) > 0 {
			content.WriteString("A Records:\n")
			for _, ip := range report.DNSRecords.A {
				content.WriteString("  • " + ip + "\n")
			}
			content.WriteString("\n")
		}
		if len(report.DNSRecords.MX) > 0 {
			content.WriteString("MX Records:\n")
			for _, mx := range report.DNSRecords.MX {
				content.WriteString(fmt.Sprintf("  • %s (Priority: %d)\n", mx.Host, mx.Pref))
			}
			content.WriteString("\n")
		}
		if len(report.DNSRecords.NS) > 0 {
			content.WriteString("NS Records:\n")
			for _, ns := range report.DNSRecords.NS {
				content.WriteString("  • " + ns + "\n")
			}
			content.WriteString("\n")
		}
		if len(report.DNSRecords.TXT) > 0 {
			content.WriteString("TXT Records:\n")
			for _, txt := range report.DNSRecords.TXT {
				content.WriteString("  • " + txt + "\n")
			}
			content.WriteString("\n")
		}
	}

	// Subdomains
	if len(report.Subdomains) > 0 {
		content.WriteString(fmt.Sprintf("Subdomains (%d found)\n\n", len(report.Subdomains)))
		for _, subdomain := range report.Subdomains {
			content.WriteString("  • " + subdomain + "\n")
		}
		content.WriteString("\n")
	}

	// IP addresses
	if len(report.IPAddresses) > 0 {
		content.WriteString("IP Address Information\n\n")
		for _, ip := range report.IPAddresses {
			content.WriteString(fmt.Sprintf("IP: %s | Reverse DNS: %s | Country: %s | Region: %s | City: %s | ISP: %s\n",
				ip.IP, ip.ReverseDNS, ip.Country, ip.Region, ip.City, ip.ISP))
		}
		content.WriteString("\n")
	}

	// Emails
	if len(report.Emails) > 0 {
		content.WriteString(fmt.Sprintf("Email Addresses (%d found)\n\n", len(report.Emails)))
		for _, email := range report.Emails {
			content.WriteString("  • " + email + "\n")
		}
		content.WriteString("\n")
	}

	// Shodan/Censys Results
	if len(report.ShodanCensys) > 0 {
		content.WriteString(fmt.Sprintf("Shodan/Censys Scan Results (%d found)\n\n", len(report.ShodanCensys)))
		for _, result := range report.ShodanCensys {
			content.WriteString(fmt.Sprintf("IP: %s | Port: %d | Service: %s | Version: %s | Hostname: %s | Source: %s\n",
				result.IP, result.Port, result.Service, result.Version, result.Hostname, result.Source))
			if len(result.SecurityIssues) > 0 {
				content.WriteString(fmt.Sprintf("  Security Issues: %s\n", strings.Join(result.SecurityIssues, ", ")))
			}
		}
		content.WriteString("\n")
	}

	// Web Archive Results
	if len(report.WebArchive) > 0 {
		content.WriteString(fmt.Sprintf("Web Archive Results (%d found)\n\n", len(report.WebArchive)))
		for _, result := range report.WebArchive {
			timestamp := result.Timestamp.Format("2006-01-02 15:04:05")
			content.WriteString(fmt.Sprintf("URL: %s | Timestamp: %s | Type: %s\n", result.URL, timestamp, result.Type))
			content.WriteString("  Snapshot: " + result.SnapshotURL + "\n")
		}
		content.WriteString("\n")
	}

	// GitHub Code Trace Results
	if len(report.GitHubCodeTrace) > 0 {
		content.WriteString(fmt.Sprintf("GitHub Code Trace Results (%d found)\n\n", len(report.GitHubCodeTrace)))
		for _, result := range report.GitHubCodeTrace {
			lineStr := ""
			if result.Line > 0 {
				lineStr = fmt.Sprintf(" | Line: %d", result.Line)
			}
			content.WriteString(fmt.Sprintf("Repository: %s | File: %s%s | Type: %s\n", result.Repository, result.File, lineStr, result.Type))
			content.WriteString("  URL: " + result.URL + "\n")
		}
		content.WriteString("\n")
	}

	// VirusTotal Results
	if len(report.VirusTotal) > 0 {
		content.WriteString(fmt.Sprintf("VirusTotal Scan Results (%d found)\n\n", len(report.VirusTotal)))
		for _, result := range report.VirusTotal {
			content.WriteString(fmt.Sprintf("Resource: %s | Type: %s | Positives: %d/%d\n", result.Resource, result.Type, result.Positives, result.Total))
			if result.Permalink != "" {
				content.WriteString("  Permalink: " + result.Permalink + "\n")
			}
		}
		content.WriteString("\n")
	}

	// Footer
	content.WriteString("─────────────────────────────────────────────────────────────\n")
	content.WriteString(fmt.Sprintf("Report generated at: %s\n", time.Now().Format("2006-01-02 15:04:05")))

	// Replace all content in template with new report content
	reportContent := content.String()
	
	// 템플릿의 모든 내용을 새 리포트 내용으로 완전 교체
	// 템플릿에서 찾을 수 있는 주요 텍스트 패턴들을 모두 교체
	doc.Replace("{{REPORT_CONTENT}}", reportContent, -1)
	doc.Replace("{{TITLE}}", title, -1)
	doc.Replace("{{DOMAIN}}", report.Domain, -1)
	doc.Replace("{{COMPANY}}", report.Company, -1)
	doc.Replace("{{TIMESTAMP}}", report.Timestamp.Format("2006-01-02 15:04:05"), -1)
	
	// 한국어 템플릿 패턴 교체
	doc.Replace("OSINT 추출정보", title, -1)
	doc.Replace("대교", report.Company, -1)
	
	// 템플릿의 첫 번째 문단을 전체 리포트 내용으로 교체
	// 템플릿 파일의 첫 번째 주요 텍스트를 찾아서 교체
	templatePatterns := []string{
		"OSINT",
		"추출정보",
		"보고서",
		"Report",
	}
	
	// 각 패턴의 첫 번째 발생을 리포트 내용으로 교체
	for _, pattern := range templatePatterns {
		doc.Replace(pattern, reportContent, 1)
	}
	
	// 템플릿의 모든 텍스트를 리포트 내용으로 교체 (최후의 수단)
	// docx 라이브러리의 제한으로 인해 완전한 교체가 어려울 수 있음
	// 대신 여러 패턴을 교체하여 최대한 많은 내용을 교체

	// Save to file
	return doc.WriteToFile(filename)
}

// writeDomainReportContent writes a single domain report section to content builder
func writeDomainReportContent(content *strings.Builder, domainReport *models.DomainReport) {
	content.WriteString(domainReport.Domain + "\n\n")

	// Domain WHOIS
	if domainReport.DomainInfo != nil {
		content.WriteString("WHOIS Information\n")
		if domainReport.DomainInfo.Registrar != "" {
			content.WriteString("  Registrar: " + domainReport.DomainInfo.Registrar + "\n")
		}
		if !domainReport.DomainInfo.CreatedDate.IsZero() {
			content.WriteString("  Created Date: " + domainReport.DomainInfo.CreatedDate.Format("2006-01-02") + "\n")
		}
		if !domainReport.DomainInfo.UpdatedDate.IsZero() {
			content.WriteString("  Updated Date: " + domainReport.DomainInfo.UpdatedDate.Format("2006-01-02") + "\n")
		}
		if !domainReport.DomainInfo.ExpiryDate.IsZero() {
			content.WriteString("  Expiry Date: " + domainReport.DomainInfo.ExpiryDate.Format("2006-01-02") + "\n")
		}
		if domainReport.DomainInfo.Registrant != "" {
			content.WriteString("  Registrant: " + domainReport.DomainInfo.Registrant + "\n")
		}
		content.WriteString("\n")
	}

	// DNS Records
	if domainReport.DNSRecords != nil {
		content.WriteString("DNS Records\n")
		if len(domainReport.DNSRecords.A) > 0 {
			content.WriteString("  A Records:\n")
			for _, ip := range domainReport.DNSRecords.A {
				content.WriteString("    • " + ip + "\n")
			}
		}
		if len(domainReport.DNSRecords.MX) > 0 {
			content.WriteString("  MX Records:\n")
			for _, mx := range domainReport.DNSRecords.MX {
				content.WriteString(fmt.Sprintf("    • %s (Priority: %d)\n", mx.Host, mx.Pref))
			}
		}
		if len(domainReport.DNSRecords.NS) > 0 {
			content.WriteString("  NS Records:\n")
			for _, ns := range domainReport.DNSRecords.NS {
				content.WriteString("    • " + ns + "\n")
			}
		}
		content.WriteString("\n")
	}

	// Subdomains
	if len(domainReport.Subdomains) > 0 {
		content.WriteString(fmt.Sprintf("Subdomains (%d found)\n", len(domainReport.Subdomains)))
		for _, subdomain := range domainReport.Subdomains {
			content.WriteString("  • " + subdomain + "\n")
		}
		content.WriteString("\n")
	}

	// Emails
	if len(domainReport.Emails) > 0 {
		content.WriteString(fmt.Sprintf("Email Addresses (%d found)\n", len(domainReport.Emails)))
		for _, email := range domainReport.Emails {
			content.WriteString("  • " + email + "\n")
		}
		content.WriteString("\n")
	}

	// Shodan/Censys
	if len(domainReport.ShodanCensys) > 0 {
		content.WriteString(fmt.Sprintf("Shodan/Censys Results (%d found)\n", len(domainReport.ShodanCensys)))
		for _, result := range domainReport.ShodanCensys {
			content.WriteString(fmt.Sprintf("  IP: %s | Port: %d | Service: %s | Version: %s | Hostname: %s | Source: %s\n",
				result.IP, result.Port, result.Service, result.Version, result.Hostname, result.Source))
		}
		content.WriteString("\n")
	}

	// Web Archive
	if len(domainReport.WebArchive) > 0 {
		content.WriteString(fmt.Sprintf("Web Archive Results (%d found)\n", len(domainReport.WebArchive)))
		for _, result := range domainReport.WebArchive {
			timestamp := result.Timestamp.Format("2006-01-02 15:04:05")
			content.WriteString(fmt.Sprintf("  URL: %s | Timestamp: %s | Type: %s\n", result.URL, timestamp, result.Type))
		}
		content.WriteString("\n")
	}

	// VirusTotal
	if len(domainReport.VirusTotal) > 0 {
		content.WriteString(fmt.Sprintf("VirusTotal Scan Results (%d found)\n", len(domainReport.VirusTotal)))
		for _, result := range domainReport.VirusTotal {
			content.WriteString(fmt.Sprintf("  Resource: %s | Type: %s | Positives: %d/%d\n",
				result.Resource, result.Type, result.Positives, result.Total))
		}
		content.WriteString("\n")
	}
}
