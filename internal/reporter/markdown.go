package reporter

import (
	"cyber-osint-recon/internal/models"
	"fmt"
	"os"
	"strings"
	"time"
)

// extractTLD extracts the TLD from a domain (e.g., "example.co.kr" -> ".co.kr")
func extractTLD(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return ".other"
	}

	// Handle multi-part TLDs like .co.kr, .co.uk
	if len(parts) >= 3 {
		// Common multi-part TLDs
		multiPartTLDs := []string{".co.kr", ".co.uk", ".com.au", ".co.jp", ".com.br", ".com.mx"}
		for _, tld := range multiPartTLDs {
			if strings.HasSuffix(domain, tld) {
				return tld
			}
		}
	}

	return "." + parts[len(parts)-1]
}

// writeDomainReport writes a single domain report section
func writeDomainReport(md *strings.Builder, domainReport *models.DomainReport) {
	// Domain WHOIS
	if domainReport.DomainInfo != nil {
		md.WriteString("##### WHOIS Information\n\n")
		if domainReport.DomainInfo.Registrar != "" {
			md.WriteString(fmt.Sprintf("- **Registrar:** %s\n", domainReport.DomainInfo.Registrar))
		}
		if !domainReport.DomainInfo.CreatedDate.IsZero() {
			md.WriteString(fmt.Sprintf("- **Created Date:** %s\n", domainReport.DomainInfo.CreatedDate.Format("2006-01-02")))
		}
		if !domainReport.DomainInfo.UpdatedDate.IsZero() {
			md.WriteString(fmt.Sprintf("- **Updated Date:** %s\n", domainReport.DomainInfo.UpdatedDate.Format("2006-01-02")))
		}
		if !domainReport.DomainInfo.ExpiryDate.IsZero() {
			md.WriteString(fmt.Sprintf("- **Expiry Date:** %s\n", domainReport.DomainInfo.ExpiryDate.Format("2006-01-02")))
		}
		if domainReport.DomainInfo.Registrant != "" {
			md.WriteString(fmt.Sprintf("- **Registrant:** %s\n", domainReport.DomainInfo.Registrant))
		}
		md.WriteString("\n")
	}

	// DNS Records
	if domainReport.DNSRecords != nil {
		md.WriteString("##### DNS Records\n\n")
		if len(domainReport.DNSRecords.A) > 0 {
			md.WriteString("**A Records:**\n")
			for _, ip := range domainReport.DNSRecords.A {
				md.WriteString(fmt.Sprintf("- %s\n", ip))
			}
			md.WriteString("\n")
		}
		if len(domainReport.DNSRecords.MX) > 0 {
			md.WriteString("**MX Records:**\n")
			md.WriteString("| Host | Priority |\n")
			md.WriteString("|------|----------|\n")
			for _, mx := range domainReport.DNSRecords.MX {
				md.WriteString(fmt.Sprintf("| %s | %d |\n", mx.Host, mx.Pref))
			}
			md.WriteString("\n")
		}
		if len(domainReport.DNSRecords.NS) > 0 {
			md.WriteString("**NS Records:**\n")
			for _, ns := range domainReport.DNSRecords.NS {
				md.WriteString(fmt.Sprintf("- %s\n", ns))
			}
			md.WriteString("\n")
		}
		if len(domainReport.DNSRecords.TXT) > 0 {
			md.WriteString("**TXT Records:**\n")
			for _, txt := range domainReport.DNSRecords.TXT {
				md.WriteString(fmt.Sprintf("- `%s`\n", txt))
			}
			md.WriteString("\n")
		}
	}

	// Subdomains
	if len(domainReport.Subdomains) > 0 {
		md.WriteString(fmt.Sprintf("##### Subdomains (%d found)\n\n", len(domainReport.Subdomains)))
		for _, subdomain := range domainReport.Subdomains {
			md.WriteString(fmt.Sprintf("- %s\n", subdomain))
		}
		md.WriteString("\n")
	}

	// Emails
	if len(domainReport.Emails) > 0 {
		md.WriteString(fmt.Sprintf("##### Email Addresses (%d found)\n\n", len(domainReport.Emails)))
		for _, email := range domainReport.Emails {
			md.WriteString(fmt.Sprintf("- %s\n", email))
		}
		md.WriteString("\n")
	}

	// Shodan/Censys
	if len(domainReport.ShodanCensys) > 0 {
		md.WriteString(fmt.Sprintf("##### Shodan/Censys Results (%d found)\n\n", len(domainReport.ShodanCensys)))
		md.WriteString("| IP Address | Port | Service | Version | Hostname | Source |\n")
		md.WriteString("|------------|------|---------|---------|----------|--------|\n")
		for _, result := range domainReport.ShodanCensys {
			md.WriteString(fmt.Sprintf("| %-15s | %-4d | %-20s | %-10s | %-20s | %-10s |\n",
				truncateString(result.IP, 15), result.Port, truncateString(result.Service, 20),
				truncateString(result.Version, 10), truncateString(result.Hostname, 20), result.Source))
		}
		md.WriteString("\n")
	}

	// Web Archive
	if len(domainReport.WebArchive) > 0 {
		md.WriteString(fmt.Sprintf("##### Web Archive Results (%d found)\n\n", len(domainReport.WebArchive)))
		md.WriteString("| URL | Timestamp | Type | Snapshot URL |\n")
		md.WriteString("|-----|-----------|------|--------------|\n")
		for _, result := range domainReport.WebArchive {
			timestamp := result.Timestamp.Format("2006-01-02 15:04:05")
			md.WriteString(fmt.Sprintf("| %-40s | %-19s | %-15s | %s |\n",
				truncateString(result.URL, 40), timestamp, truncateString(result.Type, 15), result.SnapshotURL))
		}
		md.WriteString("\n")
	}

	// VirusTotal
	if len(domainReport.VirusTotal) > 0 {
		md.WriteString(fmt.Sprintf("##### VirusTotal Scan Results (%d found)\n\n", len(domainReport.VirusTotal)))
		md.WriteString("| Resource | Type | Positives | Total | Permalink |\n")
		md.WriteString("|----------|------|-----------|-------|-----------|\n")
		for _, result := range domainReport.VirusTotal {
			md.WriteString(fmt.Sprintf("| %-30s | %-10s | %-9d | %-5d | %s |\n",
				truncateString(result.Resource, 30), result.Type, result.Positives, result.Total, result.Permalink))
		}
		md.WriteString("\n")
	}
}

// truncateString truncates a string to maxLen and adds ellipsis if needed
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

// GenerateMarkdownReport Generate Markdown format report
func GenerateMarkdownReport(report *models.Report, filename string) error {
	var md strings.Builder

	// Report title - show all domains if multiple
	if len(report.Domains) > 0 {
		domainList := make([]string, len(report.Domains))
		for i, d := range report.Domains {
			domainList[i] = d.Domain
		}
		md.WriteString(fmt.Sprintf("# Cyber OSINT Recon Report: %s\n\n", strings.Join(domainList, ", ")))
	} else {
		md.WriteString(fmt.Sprintf("# Cyber OSINT Recon Report: %s\n\n", report.Domain))
	}
	md.WriteString("**Generated:** " + report.Timestamp.Format("2006-01-02 15:04:05") + "\n")
	md.WriteString(fmt.Sprintf("**Developer:** Kai_HT (redsec.kaiht.kr) | **Team:** RedSec (redsec.co.kr)\n\n"))

	if report.Company != "" {
		md.WriteString(fmt.Sprintf("**Company:** %s\n\n", report.Company))
	}

	md.WriteString("---\n\n")

	// All Domains Information - Grouped by TLD
	if len(report.Domains) > 0 {
		md.WriteString(fmt.Sprintf("## All Domains Information (%d domain(s))\n\n", len(report.Domains)))

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
						md.WriteString(fmt.Sprintf("### [%s] Domain Group (%d domain(s))\n\n", t, len(domains)))
						for _, domainReport := range domains {
							md.WriteString(fmt.Sprintf("#### %s\n\n", domainReport.Domain))
							writeDomainReport(&md, &domainReport)
						}
						md.WriteString("---\n\n")
					}
				}
			} else {
				if domains, exists := domainsByTLD[tld]; exists {
					processedTLDs[tld] = true
					md.WriteString(fmt.Sprintf("### [%s] Domain Group (%d domain(s))\n\n", tld, len(domains)))
					for _, domainReport := range domains {
						md.WriteString(fmt.Sprintf("#### %s\n\n", domainReport.Domain))
						writeDomainReport(&md, &domainReport)
					}
					md.WriteString("---\n\n")
				}
			}
		}
	}

	// Primary Domain Information (for backward compatibility)
	if report.DomainInfo != nil {
		md.WriteString("## Domain Information (WHOIS) - Primary Domain\n\n")

		if report.DomainInfo.Registrar != "" {
			md.WriteString(fmt.Sprintf("- **Registrar:** %s\n", report.DomainInfo.Registrar))
		}
		if !report.DomainInfo.CreatedDate.IsZero() {
			md.WriteString(fmt.Sprintf("- **Created Date:** %s\n", report.DomainInfo.CreatedDate.Format("2006-01-02")))
		}
		if !report.DomainInfo.UpdatedDate.IsZero() {
			md.WriteString(fmt.Sprintf("- **Updated Date:** %s\n", report.DomainInfo.UpdatedDate.Format("2006-01-02")))
		}
		if !report.DomainInfo.ExpiryDate.IsZero() {
			md.WriteString(fmt.Sprintf("- **Expiry Date:** %s\n", report.DomainInfo.ExpiryDate.Format("2006-01-02")))
		}
		if report.DomainInfo.Registrant != "" {
			md.WriteString(fmt.Sprintf("- **Registrant:** %s\n", report.DomainInfo.Registrant))
		}
		if report.DomainInfo.AdminContact != "" {
			md.WriteString(fmt.Sprintf("- **Admin Contact:** %s\n", report.DomainInfo.AdminContact))
		}
		if report.DomainInfo.TechContact != "" {
			md.WriteString(fmt.Sprintf("- **Tech Contact:** %s\n", report.DomainInfo.TechContact))
		}

		if len(report.DomainInfo.NameServers) > 0 {
			md.WriteString("\n**Name Servers:**\n")
			for _, ns := range report.DomainInfo.NameServers {
				md.WriteString(fmt.Sprintf("- %s\n", ns))
			}
		}

		md.WriteString("\n")
	}

	// DNS records
	if report.DNSRecords != nil {
		md.WriteString("## DNS Records\n\n")

		if len(report.DNSRecords.A) > 0 {
			md.WriteString("### A Records\n\n")
			for _, ip := range report.DNSRecords.A {
				md.WriteString(fmt.Sprintf("- %s\n", ip))
			}
			md.WriteString("\n")
		}

		if len(report.DNSRecords.AAAA) > 0 {
			md.WriteString("### AAAA Records\n\n")
			for _, ip := range report.DNSRecords.AAAA {
				md.WriteString(fmt.Sprintf("- %s\n", ip))
			}
			md.WriteString("\n")
		}

		if len(report.DNSRecords.MX) > 0 {
			md.WriteString("### MX Records\n\n")
			md.WriteString("| Host | Priority |\n")
			md.WriteString("|------|----------|\n")
			for _, mx := range report.DNSRecords.MX {
				md.WriteString(fmt.Sprintf("| %s | %d |\n", mx.Host, mx.Pref))
			}
			md.WriteString("\n")
		}

		if len(report.DNSRecords.NS) > 0 {
			md.WriteString("### NS Records\n\n")
			for _, ns := range report.DNSRecords.NS {
				md.WriteString(fmt.Sprintf("- %s\n", ns))
			}
			md.WriteString("\n")
		}

		if len(report.DNSRecords.TXT) > 0 {
			md.WriteString("### TXT Records\n\n")
			for _, txt := range report.DNSRecords.TXT {
				md.WriteString(fmt.Sprintf("- `%s`\n", txt))
			}
			md.WriteString("\n")
		}

		if len(report.DNSRecords.CNAME) > 0 {
			md.WriteString("### CNAME Records\n\n")
			for _, cname := range report.DNSRecords.CNAME {
				md.WriteString(fmt.Sprintf("- %s\n", cname))
			}
			md.WriteString("\n")
		}
	}

	// Subdomains
	if len(report.Subdomains) > 0 {
		md.WriteString(fmt.Sprintf("## Subdomains (%d found)\n\n", len(report.Subdomains)))
		for _, subdomain := range report.Subdomains {
			md.WriteString(fmt.Sprintf("- %s\n", subdomain))
		}
		md.WriteString("\n")
	}

	// IP addresses
	if len(report.IPAddresses) > 0 {
		md.WriteString("## IP Address Information\n\n")
		md.WriteString("| IP Address | Reverse DNS | Country | Region | City | ISP |\n")
		md.WriteString("|------------|-------------|---------|--------|------|-----|\n")
		for _, ip := range report.IPAddresses {
			md.WriteString(fmt.Sprintf("| %-15s | %-30s | %-10s | %-15s | %-15s | %-20s |\n",
				truncateString(ip.IP, 15), truncateString(ip.ReverseDNS, 30), truncateString(ip.Country, 10),
				truncateString(ip.Region, 15), truncateString(ip.City, 15), truncateString(ip.ISP, 20)))
		}
		md.WriteString("\n")
	}

	// Emails
	if len(report.Emails) > 0 {
		md.WriteString(fmt.Sprintf("## Email Addresses (%d found)\n\n", len(report.Emails)))
		for _, email := range report.Emails {
			md.WriteString(fmt.Sprintf("- %s\n", email))
		}
		md.WriteString("\n")
	}

	// Technology stack
	if report.TechStack != nil {
		md.WriteString("## Technology Stack\n\n")

		if len(report.TechStack.WebServer) > 0 {
			md.WriteString("### Web Server\n\n")
			for _, ws := range report.TechStack.WebServer {
				md.WriteString(fmt.Sprintf("- %s\n", ws))
			}
			md.WriteString("\n")
		}

		if len(report.TechStack.Frameworks) > 0 {
			md.WriteString("### Frameworks\n\n")
			for _, fw := range report.TechStack.Frameworks {
				md.WriteString(fmt.Sprintf("- %s\n", fw))
			}
			md.WriteString("\n")
		}

		if len(report.TechStack.CMS) > 0 {
			md.WriteString("### CMS\n\n")
			for _, cms := range report.TechStack.CMS {
				md.WriteString(fmt.Sprintf("- %s\n", cms))
			}
			md.WriteString("\n")
		}

		if len(report.TechStack.CDN) > 0 {
			md.WriteString("### CDN\n\n")
			for _, cdn := range report.TechStack.CDN {
				md.WriteString(fmt.Sprintf("- %s\n", cdn))
			}
			md.WriteString("\n")
		}

		if len(report.TechStack.Analytics) > 0 {
			md.WriteString("### Analytics\n\n")
			for _, analytics := range report.TechStack.Analytics {
				md.WriteString(fmt.Sprintf("- %s\n", analytics))
			}
			md.WriteString("\n")
		}

		if len(report.TechStack.JavaScript) > 0 {
			md.WriteString("### JavaScript Libraries\n\n")
			for _, js := range report.TechStack.JavaScript {
				md.WriteString(fmt.Sprintf("- %s\n", js))
			}
			md.WriteString("\n")
		}

		if len(report.TechStack.Headers) > 0 {
			md.WriteString("### HTTP Headers\n\n")
			md.WriteString("| Header | Value |\n")
			md.WriteString("|--------|-------|\n")
			for key, value := range report.TechStack.Headers {
				if len(value) > 100 {
					value = value[:100] + "..."
				}
				md.WriteString(fmt.Sprintf("| %s | `%s` |\n", key, value))
			}
			md.WriteString("\n")
		}
	}

	// Pivot Email/Domain (Email Search)
	md.WriteString("## Pivot Email/Domain (Email Search)\n\n")
	md.WriteString("**Category:** Pivot Email / Domain\n\n")
	md.WriteString("**Tools Used:**\n")
	md.WriteString("- **Hunter.io:** Email format and sample email extraction\n")
	md.WriteString("- **Holehe:** Email existence verification across sites\n")
	md.WriteString("- **HaveIBeenPwned:** Data breach verification\n\n")
	md.WriteString("**Note:** Detailed results (email formats, sample emails, holehe results, breach data) are saved in `./Findings/email_pivot_*.csv` and `./Findings/email_pivot_*.json`\n\n")

	if report.EmailPivot != nil {
		md.WriteString("### Email Pivot Results\n\n")
		md.WriteString(fmt.Sprintf("- **Email:** %s\n", report.EmailPivot.Email))
		if len(report.EmailPivot.RelatedDomains) > 0 {
			md.WriteString("\n**Related Domains:**\n")
			for _, domain := range report.EmailPivot.RelatedDomains {
				md.WriteString(fmt.Sprintf("- %s\n", domain))
			}
		}
		if len(report.EmailPivot.BreachData) > 0 {
			md.WriteString("\n**Breach Information:**\n")
			for _, breach := range report.EmailPivot.BreachData {
				md.WriteString(fmt.Sprintf("- **Source:** %s\n", breach.Source))
				if breach.Description != "" {
					md.WriteString(fmt.Sprintf("  - **Description:** %s\n", breach.Description))
				}
				if !breach.Date.IsZero() {
					md.WriteString(fmt.Sprintf("  - **Date:** %s\n", breach.Date.Format("2006-01-02")))
				}
			}
		}
		md.WriteString("\n")
	} else {
		md.WriteString("### Email Pivot Results\n\n")
		md.WriteString("No email pivot results found at this time. Check `./Findings/email_pivot_*.csv` and `./Findings/email_pivot_*.json` for detailed results.\n\n")
	}

	// Extended Username/Social (Username Check & Social Media Tools)
	md.WriteString("## Extended Username/Social (Username Check & Social Media Tools)\n\n")
	md.WriteString("**Category:** Extended Username/Social\n\n")
	md.WriteString("**Tools Used:**\n")
	md.WriteString("- **GitHub Sherlock:** Username search across 100+ sites\n")
	md.WriteString("- **What's My Name:** Username existence verification\n")
	md.WriteString("- **LinkedIn:** Company employee profiles and associated accounts\n\n")
	md.WriteString("**Note:** Detailed results are saved in `./Findings/username_extended_*.csv` and `./Findings/username_extended_*.json`\n\n")

	if report.Usernames != nil && len(report.Usernames.Usernames) > 0 {
		md.WriteString(fmt.Sprintf("### Username Search Results (%d found)\n\n", len(report.Usernames.Usernames)))
		md.WriteString("| Username | Platform | URL | Exists |\n")
		md.WriteString("|----------|----------|-----|--------|\n")
		for _, profile := range report.Usernames.Usernames {
			exists := "No"
			if profile.Exists {
				exists = "Yes"
			}
			md.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n",
				truncateString(profile.Username, 30), truncateString(profile.Platform, 20), truncateString(profile.URL, 50), exists))
		}
		md.WriteString("\n")
	} else {
		md.WriteString("### Username Search Results\n\n")
		md.WriteString("No username search results found at this time. Check `./Findings/username_extended_*.csv` and `./Findings/username_extended_*.json` for detailed results.\n\n")
	}

	// Social Media
	if report.SocialMedia != nil && len(report.SocialMedia.Profiles) > 0 {
		md.WriteString("## Social Media Information\n\n")
		md.WriteString("| Platform | Username | URL | Verified |\n")
		md.WriteString("|----------|----------|-----|----------|\n")
		for _, profile := range report.SocialMedia.Profiles {
			verified := "No"
			if profile.Verified {
				verified = "Yes"
			}
			md.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n",
				profile.Platform, profile.Username, profile.URL, verified))
		}
		md.WriteString("\n")
	}

	// Company Background
	if report.CompanyBackground != nil {
		md.WriteString("## Company Background\n\n")
		if report.CompanyBackground.Description != "" {
			md.WriteString(fmt.Sprintf("- **Description:** %s\n", report.CompanyBackground.Description))
		}
		if report.CompanyBackground.Founded != "" {
			md.WriteString(fmt.Sprintf("- **Founded:** %s\n", report.CompanyBackground.Founded))
		}
		if report.CompanyBackground.Industry != "" {
			md.WriteString(fmt.Sprintf("- **Industry:** %s\n", report.CompanyBackground.Industry))
		}
		if report.CompanyBackground.Location != "" {
			md.WriteString(fmt.Sprintf("- **Location:** %s\n", report.CompanyBackground.Location))
		}
		if report.CompanyBackground.Employees != "" {
			md.WriteString(fmt.Sprintf("- **Employees:** %s\n", report.CompanyBackground.Employees))
		}
		if report.CompanyBackground.Revenue != "" {
			md.WriteString(fmt.Sprintf("- **Revenue:** %s\n", report.CompanyBackground.Revenue))
		}
		if len(report.CompanyBackground.SocialLinks) > 0 {
			md.WriteString("\n**Social Links:**\n")
			for _, link := range report.CompanyBackground.SocialLinks {
				md.WriteString(fmt.Sprintf("- %s\n", link))
			}
		}
		md.WriteString("\n")
	}

	// Corporate Registration/Financial/Recruitment Information
	md.WriteString("## Corporate Registration/Financial/Recruitment Information\n\n")
	md.WriteString("**Category:** Corporate Registration/Financial/Recruitment\n\n")
	md.WriteString("**Note:** Detailed results are saved in `./Findings/corporate_info_*.csv` and `./Findings/corporate_info_*.json`\n\n")
	md.WriteString("This section includes information from:\n")
	md.WriteString("- **Crunchbase:** Company information, subsidiaries, acquisitions\n")
	md.WriteString("- **OpenCorporates:** Corporate registration, jurisdiction, company numbers\n")
	md.WriteString("- **Subsidiaries & Partners:** Related companies and domains\n")
	md.WriteString("- **Cloud Assets:** Cloud service usage indicators\n\n")

	// Related Assets (including subsidiaries and partners from corporate info)
	if len(report.RelatedAssets) > 0 {
		md.WriteString(fmt.Sprintf("### Related Assets (%d found)\n\n", len(report.RelatedAssets)))
		md.WriteString("| Type | Value | Relation | Source |\n")
		md.WriteString("|------|-------|----------|--------|\n")
		for _, asset := range report.RelatedAssets {
			md.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n",
				asset.Type, truncateString(asset.Value, 40), truncateString(asset.Relation, 20), truncateString(asset.Source, 20)))
		}
		md.WriteString("\n")
	}

	// Code Repositories
	if len(report.CodeRepos) > 0 {
		md.WriteString(fmt.Sprintf("## Code Repositories (%d found)\n\n", len(report.CodeRepos)))
		md.WriteString("| Platform | Username | Repository | URL | Public | Language |\n")
		md.WriteString("|----------|----------|------------|-----|--------|----------|\n")
		for _, repo := range report.CodeRepos {
			public := "No"
			if repo.Public {
				public = "Yes"
			}
			md.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s | %s |\n",
				repo.Platform, repo.Username, repo.Repository, repo.URL, public, repo.Language))
		}
		md.WriteString("\n")
	}

	// Documents
	if len(report.Documents) > 0 {
		md.WriteString(fmt.Sprintf("## Documents (%d found)\n\n", len(report.Documents)))
		md.WriteString("| Platform | Title | URL | Type | Public |\n")
		md.WriteString("|----------|-------|-----|------|--------|\n")
		for _, doc := range report.Documents {
			public := "No"
			if doc.Public {
				public = "Yes"
			}
			md.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s |\n",
				doc.Platform, doc.Title, doc.URL, doc.Type, public))
		}
		md.WriteString("\n")
	}

	// Public Code/Paste/File Leak Search
	md.WriteString("## Public Code/Paste/File Leak Search\n\n")
	md.WriteString("**Category:** Public Code/Paste/File Leak Search\n\n")
	md.WriteString("**Tools Used:**\n")
	md.WriteString("- **Grep.app:** GitHub 공개 리포지토리에서 API 키, 내부 URL, 구성 파일 검색 (`from:domain.co.kr` / `domain` 검색)\n")
	md.WriteString("- **Pastebin.com:** 페이스트 사이트에서 도메인 관련 정보 검색\n")
	md.WriteString("- **LeakCheck.io:** 도메인 유출 데이터베이스 검색\n\n")
	md.WriteString("**Note:** Detailed results are saved in `./Findings/leak_search_*.csv` and `./Findings/leak_search_*.json`\n\n")

	// Data Spillage (including leak search results)
	if len(report.DataSpillage) > 0 {
		md.WriteString(fmt.Sprintf("### Data Spillage / Risk Items (%d found)\n\n", len(report.DataSpillage)))
		md.WriteString("| Source | Type | URL | Severity | Date | Description |\n")
		md.WriteString("|--------|------|-----|----------|------|-------------|\n")
		for _, spill := range report.DataSpillage {
			date := ""
			if !spill.Date.IsZero() {
				date = spill.Date.Format("2006-01-02")
			}
			md.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s | %s |\n",
				truncateString(spill.Source, 20), truncateString(spill.Type, 15), truncateString(spill.URL, 50), spill.Severity, date, truncateString(spill.Description, 50)))
		}
		md.WriteString("\n")
		md.WriteString("**Risk Assessment:**\n")
		highCount := 0
		mediumCount := 0
		lowCount := 0
		for _, spillage := range report.DataSpillage {
			switch spillage.Severity {
			case "high":
				highCount++
			case "medium":
				mediumCount++
			case "low":
				lowCount++
			}
		}
		md.WriteString(fmt.Sprintf("- **High Severity:** %d (API 키, 비밀번호, DB 정보 노출 등)\n", highCount))
		md.WriteString(fmt.Sprintf("- **Medium Severity:** %d (내부 URL, 구성 파일 노출 등)\n", mediumCount))
		md.WriteString(fmt.Sprintf("- **Low Severity:** %d (일반 코드 노출 등)\n\n", lowCount))
	} else {
		md.WriteString("### Data Spillage / Risk Items\n\n")
		md.WriteString("No data spillage or risk items found at this time.\n\n")
	}

	// Security Threats
	if len(report.SecurityThreats) > 0 {
		md.WriteString(fmt.Sprintf("## Security Threats (%d found)\n\n", len(report.SecurityThreats)))
		md.WriteString("| Type | Title | Severity | Source | Date | Description |\n")
		md.WriteString("|------|-------|----------|--------|------|-------------|\n")
		for _, threat := range report.SecurityThreats {
			date := ""
			if !threat.Date.IsZero() {
				date = threat.Date.Format("2006-01-02")
			}
			md.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s | %s |\n",
				threat.Type, threat.Title, threat.Severity, threat.Source, date, threat.Description))
		}
		md.WriteString("\n")
	}

	// Asset Inventory with Risk Assessment
	if report.AssetInventory != nil {
		md.WriteString("## Asset Inventory\n\n")

		// Detailed Asset Inventory Table
		if len(report.AssetInventory.Assets) > 0 {
			md.WriteString("### 발견 자산표\n\n")
			md.WriteString("| 카테고리 | 자산 | 세부 | 증거URL | 리스크 |\n")
			md.WriteString("|----------|------|------|---------|--------|\n")
			for _, asset := range report.AssetInventory.Assets {
				md.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s |\n",
					truncateString(asset.Category, 15),
					truncateString(asset.Asset, 40),
					truncateString(asset.Details, 20),
					truncateString(asset.EvidenceURL, 30),
					asset.Risk))
			}
			md.WriteString("\n")
		}

		// Summary statistics
		if len(report.AssetInventory.Domains) > 0 {
			md.WriteString(fmt.Sprintf("### Domains (%d)\n\n", len(report.AssetInventory.Domains)))
			for _, domain := range report.AssetInventory.Domains {
				md.WriteString(fmt.Sprintf("- %s\n", domain))
			}
			md.WriteString("\n")
		}
		if len(report.AssetInventory.IPs) > 0 {
			md.WriteString(fmt.Sprintf("### IP Addresses (%d)\n\n", len(report.AssetInventory.IPs)))
			for _, ip := range report.AssetInventory.IPs {
				md.WriteString(fmt.Sprintf("- %s\n", ip))
			}
			md.WriteString("\n")
		}
		if len(report.AssetInventory.Subdomains) > 0 {
			md.WriteString(fmt.Sprintf("### Subdomains (%d)\n\n", len(report.AssetInventory.Subdomains)))
			for _, subdomain := range report.AssetInventory.Subdomains {
				md.WriteString(fmt.Sprintf("- %s\n", subdomain))
			}
			md.WriteString("\n")
		}
		if len(report.AssetInventory.Emails) > 0 {
			md.WriteString(fmt.Sprintf("### Emails (%d)\n\n", len(report.AssetInventory.Emails)))
			for _, email := range report.AssetInventory.Emails {
				md.WriteString(fmt.Sprintf("- %s\n", email))
			}
			md.WriteString("\n")
		}
		if len(report.AssetInventory.Services) > 0 {
			md.WriteString("### Services\n\n")
			md.WriteString("| Port | Protocol | Service | Version |\n")
			md.WriteString("|------|----------|---------|----------|\n")
			for _, service := range report.AssetInventory.Services {
				md.WriteString(fmt.Sprintf("| %d | %s | %s | %s |\n",
					service.Port, service.Protocol, service.Service, service.Version))
			}
			md.WriteString("\n")
		}
	}

	// Shodan/Censys Results
	if len(report.ShodanCensys) > 0 {
		md.WriteString(fmt.Sprintf("## Shodan/Censys Scan Results (%d found)\n\n", len(report.ShodanCensys)))
		md.WriteString("| IP | Port | Service | Version | Banner | Source |\n")
		md.WriteString("|----|------|---------|---------|--------|--------|\n")
		for _, result := range report.ShodanCensys {
			banner := result.Banner
			if len(banner) > 100 {
				banner = banner[:100] + "..."
			}
			md.WriteString(fmt.Sprintf("| %s | %d | %s | %s | `%s` | %s |\n",
				result.IP, result.Port, result.Service, result.Version, banner, result.Source))
		}
		md.WriteString("\n")
	}

	// Web Archive Results
	if len(report.WebArchive) > 0 {
		md.WriteString(fmt.Sprintf("## Web Archive Results (%d found)\n\n", len(report.WebArchive)))
		md.WriteString("| URL | Timestamp | Type | Snapshot URL |\n")
		md.WriteString("|-----|-----------|------|--------------|\n")
		for _, result := range report.WebArchive {
			timestamp := result.Timestamp.Format("2006-01-02 15:04:05")
			md.WriteString(fmt.Sprintf("| %-40s | %-19s | %-15s | %s |\n",
				truncateString(result.URL, 40), timestamp, truncateString(result.Type, 15), result.SnapshotURL))
		}
		md.WriteString("\n")
	}

	// GitHub Code Trace Results
	if len(report.GitHubCodeTrace) > 0 {
		md.WriteString(fmt.Sprintf("## GitHub Code Trace Results (%d found)\n\n", len(report.GitHubCodeTrace)))
		md.WriteString("| Repository | File | Line | Type | URL |\n")
		md.WriteString("|------------|------|------|------|-----|\n")
		for _, result := range report.GitHubCodeTrace {
			lineStr := ""
			if result.Line > 0 {
				lineStr = fmt.Sprintf("%d", result.Line)
			}
			md.WriteString(fmt.Sprintf("| %-30s | %-30s | %-4s | %-15s | %s |\n",
				truncateString(result.Repository, 30), truncateString(result.File, 30), lineStr,
				truncateString(result.Type, 15), result.URL))
		}
		md.WriteString("\n")
	}

	// Employee Profiles
	if len(report.EmployeeProfiles) > 0 {
		md.WriteString(fmt.Sprintf("## Employee Profiles (%d found)\n\n", len(report.EmployeeProfiles)))
		md.WriteString("| Name | Username | Platform | Role | Company | URL |\n")
		md.WriteString("|------|----------|----------|------|---------|-----|\n")
		for _, profile := range report.EmployeeProfiles {
			md.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s | %s |\n",
				profile.Name, profile.Username, profile.Platform, profile.Role, profile.Company, profile.URL))
		}
		md.WriteString("\n")
	}

	// Corporate Info
	if report.CorporateInfo != nil {
		md.WriteString("## Corporate Information\n\n")
		md.WriteString(fmt.Sprintf("- **Source:** %s\n", report.CorporateInfo.Source))
		if report.CorporateInfo.Founded != "" {
			md.WriteString(fmt.Sprintf("- **Founded:** %s\n", report.CorporateInfo.Founded))
		}
		if report.CorporateInfo.Employees != "" {
			md.WriteString(fmt.Sprintf("- **Employees:** %s\n", report.CorporateInfo.Employees))
		}
		if report.CorporateInfo.FinancialInfo != "" {
			md.WriteString(fmt.Sprintf("- **Financial Info:** %s\n", report.CorporateInfo.FinancialInfo))
		}
		if len(report.CorporateInfo.Subsidiaries) > 0 {
			md.WriteString("\n**Subsidiaries:**\n")
			for _, sub := range report.CorporateInfo.Subsidiaries {
				md.WriteString(fmt.Sprintf("- %s\n", sub))
			}
		}
		if len(report.CorporateInfo.Partners) > 0 {
			md.WriteString("\n**Partners:**\n")
			for _, partner := range report.CorporateInfo.Partners {
				md.WriteString(fmt.Sprintf("- %s\n", partner))
			}
		}
		if len(report.CorporateInfo.RelatedDomains) > 0 {
			md.WriteString("\n**Related Domains:**\n")
			for _, domain := range report.CorporateInfo.RelatedDomains {
				md.WriteString(fmt.Sprintf("- %s\n", domain))
			}
		}
		if len(report.CorporateInfo.CloudAssets) > 0 {
			md.WriteString("\n**Cloud Assets:**\n")
			for _, asset := range report.CorporateInfo.CloudAssets {
				md.WriteString(fmt.Sprintf("- %s\n", asset))
			}
		}
		md.WriteString("\n")
	}

	// VirusTotal Results
	if len(report.VirusTotal) > 0 {
		md.WriteString(fmt.Sprintf("## VirusTotal Scan Results (%d found)\n\n", len(report.VirusTotal)))
		md.WriteString("| Resource | Type | Positives | Total | Permalink |\n")
		md.WriteString("|----------|------|-----------|-------|-----------|\n")
		for _, result := range report.VirusTotal {
			permalinkStr := ""
			if result.Permalink != "" {
				permalinkStr = result.Permalink
			}
			md.WriteString(fmt.Sprintf("| %s | %s | %d | %d | %s |\n",
				result.Resource, result.Type, result.Positives, result.Total, permalinkStr))
		}
		md.WriteString("\n")
	}

	// Risk Priority Assessment
	md.WriteString("## 리스크 우선순위\n\n")

	// Collect risk items by severity
	highRiskItems := []models.DataSpillage{}
	mediumRiskItems := []models.DataSpillage{}
	lowRiskItems := []models.DataSpillage{}

	for _, spill := range report.DataSpillage {
		if spill.Severity == "high" {
			highRiskItems = append(highRiskItems, spill)
		} else if spill.Severity == "medium" {
			mediumRiskItems = append(mediumRiskItems, spill)
		} else {
			lowRiskItems = append(lowRiskItems, spill)
		}
	}

	md.WriteString("| 우선순위 | 리스크 | 자산 | 설명 | 조치사항 |\n")
	md.WriteString("|----------|--------|------|------|----------|\n")

	priority := 1
	// High risk items
	for _, item := range highRiskItems {
		md.WriteString(fmt.Sprintf("| %d | 고 | %s | %s | 즉시 조치 필요 |\n",
			priority, truncateString(item.URL, 40), truncateString(item.Description, 50)))
		priority++
	}
	// Medium risk items
	for _, item := range mediumRiskItems {
		md.WriteString(fmt.Sprintf("| %d | 중 | %s | %s | 조치 권장 |\n",
			priority, truncateString(item.URL, 40), truncateString(item.Description, 50)))
		priority++
	}
	// Low risk items
	for _, item := range lowRiskItems {
		md.WriteString(fmt.Sprintf("| %d | 저 | %s | %s | 모니터링 |\n",
			priority, truncateString(item.URL, 40), truncateString(item.Description, 50)))
		priority++
	}
	md.WriteString("\n")

	// Continuous Monitoring
	md.WriteString("## 지속적인 모니터링\n\n")
	md.WriteString("**Web Monitoring 카테고리 (예: Visualping)로 변화 감지 설정**\n\n")
	md.WriteString("| 자산 | 카테고리 | 모니터링 도구 | 설정 URL | 설명 |\n")
	md.WriteString("|------|----------|----------------|----------|------|\n")

	// Add monitoring suggestions
	if report.Domain != "" {
		md.WriteString(fmt.Sprintf("| %s | 도메인 | Visualping | https://visualping.io/?url=%s | 웹사이트 변화 감지 |\n",
			report.Domain, report.Domain))
		md.WriteString(fmt.Sprintf("| %s | 도메인 | Shodan Monitor | https://www.shodan.io/monitor?query=hostname:%s | Shodan 모니터링 |\n",
			report.Domain, report.Domain))
		md.WriteString(fmt.Sprintf("| %s | 도메인 | Censys Monitor | https://search.censys.io/hosts?q=dns.names:%s | Censys 모니터링 |\n",
			report.Domain, report.Domain))
	}

	// Add subdomain monitoring
	if len(report.Subdomains) > 0 {
		for i, subdomain := range report.Subdomains {
			if i < 5 { // Limit to first 5 subdomains
				md.WriteString(fmt.Sprintf("| %s | 서브도메인 | Visualping | https://visualping.io/?url=%s | 웹사이트 변화 감지 |\n",
					subdomain, subdomain))
			}
		}
	}
	md.WriteString("\n")

	md.WriteString("**모니터링 설정 방법:**\n")
	md.WriteString("1. Visualping.io에 접속하여 대상 URL을 입력\n")
	md.WriteString("2. 변화 감지 주기 설정 (일일/주간/월간)\n")
	md.WriteString("3. 알림 이메일 설정\n")
	md.WriteString("4. Shodan/Censys 모니터링은 API 키를 사용하여 자동화 가능\n\n")

	md.WriteString("---\n\n")
	md.WriteString(fmt.Sprintf("*Report generated at: %s*\n", time.Now().Format("2006-01-02 15:04:05")))

	content := md.String()
	if filename != "" {
		return os.WriteFile(filename, []byte(content), 0644)
	}

	_, err := os.Stdout.WriteString(content)
	return err
}
