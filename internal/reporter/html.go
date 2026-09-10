package reporter

import (
	"cyber-osint-recon/internal/models"
	"fmt"
	"os"
	"strings"
)

// GenerateHTMLReport Generate HTML format report
func GenerateHTMLReport(report *models.Report, filename string) error {
	var html strings.Builder

	html.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OSINT Report - ` + report.Domain + `</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }
        .container {
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        h1 {
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }
        h2 {
            color: #34495e;
            margin-top: 30px;
            border-left: 4px solid #3498db;
            padding-left: 15px;
        }
        h3 {
            color: #7f8c8d;
            margin-top: 20px;
        }
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }
        .info-card {
            background: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            border-left: 4px solid #3498db;
        }
        .info-card strong {
            color: #2c3e50;
            display: block;
            margin-bottom: 5px;
        }
        ul {
            list-style-type: none;
            padding-left: 0;
        }
        li {
            padding: 8px;
            margin: 5px 0;
            background: #f8f9fa;
            border-left: 3px solid #95a5a6;
            padding-left: 15px;
        }
        .badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 3px;
            font-size: 0.85em;
            margin: 2px;
            background: #3498db;
            color: white;
        }
        .timestamp {
            color: #7f8c8d;
            font-size: 0.9em;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background: #3498db;
            color: white;
        }
        tr:hover {
            background: #f5f5f5;
        }
        .developer-info {
            background: #e8f4f8;
            padding: 15px;
            border-radius: 5px;
            border-left: 4px solid #3498db;
            margin: 20px 0;
        }
    </style>
</head>
<body>
    <div class="container">
`)

	// Header
	html.WriteString(fmt.Sprintf(`
        <h1>🔍 Cyber OSINT Recon Report: %s</h1>
        <p class="timestamp">Generated: %s</p>
        <div class="developer-info">
            <strong>Developer:</strong> Kai_HT (redsec.kaiht.kr)<br>
            <strong>Team:</strong> RedSec (redsec.co.kr)
        </div>
`, report.Domain, report.Timestamp.Format("2006-01-02 15:04:05")))

	if report.Company != "" {
		html.WriteString(fmt.Sprintf(`<p><strong>Company:</strong> %s</p>`, report.Company))
	}

	// Domain information
	if report.DomainInfo != nil {
		html.WriteString(`<h2>📋 Domain Information (WHOIS)</h2>`)
		html.WriteString(`<div class="info-grid">`)
		
		if report.DomainInfo.Registrar != "" {
			html.WriteString(fmt.Sprintf(`<div class="info-card"><strong>Registrar:</strong> %s</div>`, report.DomainInfo.Registrar))
		}
		if !report.DomainInfo.CreatedDate.IsZero() {
			html.WriteString(fmt.Sprintf(`<div class="info-card"><strong>Created Date:</strong> %s</div>`, report.DomainInfo.CreatedDate.Format("2006-01-02")))
		}
		if !report.DomainInfo.UpdatedDate.IsZero() {
			html.WriteString(fmt.Sprintf(`<div class="info-card"><strong>Updated Date:</strong> %s</div>`, report.DomainInfo.UpdatedDate.Format("2006-01-02")))
		}
		if !report.DomainInfo.ExpiryDate.IsZero() {
			html.WriteString(fmt.Sprintf(`<div class="info-card"><strong>Expiry Date:</strong> %s</div>`, report.DomainInfo.ExpiryDate.Format("2006-01-02")))
		}
		if report.DomainInfo.Registrant != "" {
			html.WriteString(fmt.Sprintf(`<div class="info-card"><strong>Registrant:</strong> %s</div>`, report.DomainInfo.Registrant))
		}
		if report.DomainInfo.AdminContact != "" {
			html.WriteString(fmt.Sprintf(`<div class="info-card"><strong>Admin Contact:</strong> %s</div>`, report.DomainInfo.AdminContact))
		}
		if report.DomainInfo.TechContact != "" {
			html.WriteString(fmt.Sprintf(`<div class="info-card"><strong>Tech Contact:</strong> %s</div>`, report.DomainInfo.TechContact))
		}
		
		html.WriteString(`</div>`)
		
		if len(report.DomainInfo.NameServers) > 0 {
			html.WriteString(`<h3>Name Servers</h3><ul>`)
			for _, ns := range report.DomainInfo.NameServers {
				html.WriteString(fmt.Sprintf(`<li>%s</li>`, ns))
			}
			html.WriteString(`</ul>`)
		}
	}

	// DNS records
	if report.DNSRecords != nil {
		html.WriteString(`<h2>🌐 DNS Records</h2>`)
		
		if len(report.DNSRecords.A) > 0 {
			html.WriteString(`<h3>A Records</h3><ul>`)
			for _, ip := range report.DNSRecords.A {
				html.WriteString(fmt.Sprintf(`<li>%s</li>`, ip))
			}
			html.WriteString(`</ul>`)
		}
		
		if len(report.DNSRecords.AAAA) > 0 {
			html.WriteString(`<h3>AAAA Records</h3><ul>`)
			for _, ip := range report.DNSRecords.AAAA {
				html.WriteString(fmt.Sprintf(`<li>%s</li>`, ip))
			}
			html.WriteString(`</ul>`)
		}
		
		if len(report.DNSRecords.MX) > 0 {
			html.WriteString(`<h3>MX Records</h3><table><thead><tr><th>Host</th><th>Priority</th></tr></thead><tbody>`)
			for _, mx := range report.DNSRecords.MX {
				html.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%d</td></tr>`, mx.Host, mx.Pref))
			}
			html.WriteString(`</tbody></table>`)
		}
		
		if len(report.DNSRecords.NS) > 0 {
			html.WriteString(`<h3>NS Records</h3><ul>`)
			for _, ns := range report.DNSRecords.NS {
				html.WriteString(fmt.Sprintf(`<li>%s</li>`, ns))
			}
			html.WriteString(`</ul>`)
		}
		
		if len(report.DNSRecords.TXT) > 0 {
			html.WriteString(`<h3>TXT Records</h3><ul>`)
			for _, txt := range report.DNSRecords.TXT {
				html.WriteString(fmt.Sprintf(`<li><code>%s</code></li>`, txt))
			}
			html.WriteString(`</ul>`)
		}
		
		if len(report.DNSRecords.CNAME) > 0 {
			html.WriteString(`<h3>CNAME Records</h3><ul>`)
			for _, cname := range report.DNSRecords.CNAME {
				html.WriteString(fmt.Sprintf(`<li>%s</li>`, cname))
			}
			html.WriteString(`</ul>`)
		}
	}

	// Subdomains
	if len(report.Subdomains) > 0 {
		html.WriteString(fmt.Sprintf(`<h2>🔗 Subdomains (%d found)</h2>`, len(report.Subdomains)))
		html.WriteString(`<ul>`)
		for _, subdomain := range report.Subdomains {
			html.WriteString(fmt.Sprintf(`<li>%s</li>`, subdomain))
		}
		html.WriteString(`</ul>`)
	}

	// IP addresses
	if len(report.IPAddresses) > 0 {
		html.WriteString(`<h2>📍 IP Address Information</h2>`)
		html.WriteString(`<table><thead><tr><th>IP Address</th><th>Reverse DNS</th><th>Country</th><th>Region</th><th>City</th><th>ISP</th></tr></thead><tbody>`)
		for _, ip := range report.IPAddresses {
			html.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>`, 
				ip.IP, ip.ReverseDNS, ip.Country, ip.Region, ip.City, ip.ISP))
		}
		html.WriteString(`</tbody></table>`)
	}

	// Emails
	if len(report.Emails) > 0 {
		html.WriteString(fmt.Sprintf(`<h2>📧 Email Addresses (%d found)</h2>`, len(report.Emails)))
		html.WriteString(`<ul>`)
		for _, email := range report.Emails {
			html.WriteString(fmt.Sprintf(`<li>%s</li>`, email))
		}
		html.WriteString(`</ul>`)
	}

	// Technology stack
	if report.TechStack != nil {
		html.WriteString(`<h2>⚙️ Technology Stack</h2>`)
		
		if len(report.TechStack.WebServer) > 0 {
			html.WriteString(`<h3>Web Server</h3>`)
			for _, ws := range report.TechStack.WebServer {
				html.WriteString(fmt.Sprintf(`<span class="badge">%s</span>`, ws))
			}
			html.WriteString(`<br><br>`)
		}
		
		if len(report.TechStack.Frameworks) > 0 {
			html.WriteString(`<h3>Frameworks</h3>`)
			for _, fw := range report.TechStack.Frameworks {
				html.WriteString(fmt.Sprintf(`<span class="badge">%s</span>`, fw))
			}
			html.WriteString(`<br><br>`)
		}
		
		if len(report.TechStack.CMS) > 0 {
			html.WriteString(`<h3>CMS</h3>`)
			for _, cms := range report.TechStack.CMS {
				html.WriteString(fmt.Sprintf(`<span class="badge">%s</span>`, cms))
			}
			html.WriteString(`<br><br>`)
		}
		
		if len(report.TechStack.CDN) > 0 {
			html.WriteString(`<h3>CDN</h3>`)
			for _, cdn := range report.TechStack.CDN {
				html.WriteString(fmt.Sprintf(`<span class="badge">%s</span>`, cdn))
			}
			html.WriteString(`<br><br>`)
		}
		
		if len(report.TechStack.Analytics) > 0 {
			html.WriteString(`<h3>Analytics</h3>`)
			for _, analytics := range report.TechStack.Analytics {
				html.WriteString(fmt.Sprintf(`<span class="badge">%s</span>`, analytics))
			}
			html.WriteString(`<br><br>`)
		}
		
		if len(report.TechStack.JavaScript) > 0 {
			html.WriteString(`<h3>JavaScript Libraries</h3>`)
			for _, js := range report.TechStack.JavaScript {
				html.WriteString(fmt.Sprintf(`<span class="badge">%s</span>`, js))
			}
			html.WriteString(`<br><br>`)
		}
		
		if len(report.TechStack.Headers) > 0 {
			html.WriteString(`<h3>HTTP Headers</h3>`)
			html.WriteString(`<table><thead><tr><th>Header</th><th>Value</th></tr></thead><tbody>`)
			for key, value := range report.TechStack.Headers {
				if len(value) > 100 {
					value = value[:100] + "..."
				}
				html.WriteString(fmt.Sprintf(`<tr><td>%s</td><td><code>%s</code></td></tr>`, key, value))
			}
			html.WriteString(`</tbody></table>`)
		}
	}

	// Email Pivot
	if report.EmailPivot != nil {
		html.WriteString(`<h2>📧 Email Pivot Information</h2>`)
		html.WriteString(`<div class="info-grid">`)
		html.WriteString(fmt.Sprintf(`<div class="info-card"><strong>Email:</strong> %s</div>`, report.EmailPivot.Email))
		if len(report.EmailPivot.RelatedDomains) > 0 {
			html.WriteString(`<h3>Related Domains</h3><ul>`)
			for _, domain := range report.EmailPivot.RelatedDomains {
				html.WriteString(fmt.Sprintf(`<li>%s</li>`, domain))
			}
			html.WriteString(`</ul>`)
		}
		html.WriteString(`</div>`)
	}

	// Usernames
	if report.Usernames != nil && len(report.Usernames.Usernames) > 0 {
		html.WriteString(`<h2>👤 Extended Username Information</h2>`)
		html.WriteString(`<table><thead><tr><th>Username</th><th>Platform</th><th>URL</th><th>Exists</th></tr></thead><tbody>`)
		for _, profile := range report.Usernames.Usernames {
			existsStr := "No"
			if profile.Exists {
				existsStr = "Yes"
			}
			html.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%s</td><td><a href="%s" target="_blank">%s</a></td><td>%s</td></tr>`, 
				profile.Username, profile.Platform, profile.URL, profile.URL, existsStr))
		}
		html.WriteString(`</tbody></table>`)
	}

	// Social Media
	if report.SocialMedia != nil && len(report.SocialMedia.Profiles) > 0 {
		html.WriteString(`<h2>📱 Social Media Information</h2>`)
		html.WriteString(`<table><thead><tr><th>Platform</th><th>Username</th><th>URL</th><th>Verified</th></tr></thead><tbody>`)
		for _, profile := range report.SocialMedia.Profiles {
			verifiedStr := "No"
			if profile.Verified {
				verifiedStr = "Yes"
			}
			html.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%s</td><td><a href="%s" target="_blank">%s</a></td><td>%s</td></tr>`, 
				profile.Platform, profile.Username, profile.URL, profile.URL, verifiedStr))
		}
		html.WriteString(`</tbody></table>`)
	}

	// Company Background
	if report.CompanyBackground != nil {
		html.WriteString(`<h2>🏢 Company Background</h2>`)
		html.WriteString(`<div class="info-grid">`)
		if report.CompanyBackground.Description != "" {
			html.WriteString(fmt.Sprintf(`<div class="info-card"><strong>Description:</strong> %s</div>`, report.CompanyBackground.Description))
		}
		if report.CompanyBackground.Founded != "" {
			html.WriteString(fmt.Sprintf(`<div class="info-card"><strong>Founded:</strong> %s</div>`, report.CompanyBackground.Founded))
		}
		if report.CompanyBackground.Industry != "" {
			html.WriteString(fmt.Sprintf(`<div class="info-card"><strong>Industry:</strong> %s</div>`, report.CompanyBackground.Industry))
		}
		if report.CompanyBackground.Location != "" {
			html.WriteString(fmt.Sprintf(`<div class="info-card"><strong>Location:</strong> %s</div>`, report.CompanyBackground.Location))
		}
		if report.CompanyBackground.Employees != "" {
			html.WriteString(fmt.Sprintf(`<div class="info-card"><strong>Employees:</strong> %s</div>`, report.CompanyBackground.Employees))
		}
		if report.CompanyBackground.Revenue != "" {
			html.WriteString(fmt.Sprintf(`<div class="info-card"><strong>Revenue:</strong> %s</div>`, report.CompanyBackground.Revenue))
		}
		if len(report.CompanyBackground.SocialLinks) > 0 {
			html.WriteString(`<h3>Social Links</h3><ul>`)
			for _, link := range report.CompanyBackground.SocialLinks {
				html.WriteString(fmt.Sprintf(`<li><a href="%s" target="_blank">%s</a></li>`, link, link))
			}
			html.WriteString(`</ul>`)
		}
		html.WriteString(`</div>`)
	}

	// Related Assets
	if len(report.RelatedAssets) > 0 {
		html.WriteString(fmt.Sprintf(`<h2>🔗 Related Assets (%d found)</h2>`, len(report.RelatedAssets)))
		html.WriteString(`<table><thead><tr><th>Type</th><th>Value</th><th>Relation</th><th>Source</th></tr></thead><tbody>`)
		for _, asset := range report.RelatedAssets {
			html.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>`, 
				asset.Type, asset.Value, asset.Relation, asset.Source))
		}
		html.WriteString(`</tbody></table>`)
	}

	// Code Repositories
	if len(report.CodeRepos) > 0 {
		html.WriteString(fmt.Sprintf(`<h2>💻 Code Repositories (%d found)</h2>`, len(report.CodeRepos)))
		html.WriteString(`<table><thead><tr><th>Platform</th><th>Username</th><th>Repository</th><th>URL</th><th>Public</th><th>Language</th></tr></thead><tbody>`)
		for _, repo := range report.CodeRepos {
			publicStr := "No"
			if repo.Public {
				publicStr = "Yes"
			}
			html.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%s</td><td>%s</td><td><a href="%s" target="_blank">%s</a></td><td>%s</td><td>%s</td></tr>`, 
				repo.Platform, repo.Username, repo.Repository, repo.URL, repo.URL, publicStr, repo.Language))
		}
		html.WriteString(`</tbody></table>`)
	}

	// Documents
	if len(report.Documents) > 0 {
		html.WriteString(fmt.Sprintf(`<h2>📄 Documents (%d found)</h2>`, len(report.Documents)))
		html.WriteString(`<table><thead><tr><th>Platform</th><th>Title</th><th>URL</th><th>Type</th><th>Public</th></tr></thead><tbody>`)
		for _, doc := range report.Documents {
			publicStr := "No"
			if doc.Public {
				publicStr = "Yes"
			}
			html.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%s</td><td><a href="%s" target="_blank">%s</a></td><td>%s</td><td>%s</td></tr>`, 
				doc.Platform, doc.Title, doc.URL, doc.URL, doc.Type, publicStr))
		}
		html.WriteString(`</tbody></table>`)
	}

	// Data Spillage
	if len(report.DataSpillage) > 0 {
		html.WriteString(fmt.Sprintf(`<h2>🔓 Data Spillage (%d found)</h2>`, len(report.DataSpillage)))
		html.WriteString(`<table><thead><tr><th>Source</th><th>Type</th><th>URL</th><th>Severity</th><th>Date</th><th>Description</th></tr></thead><tbody>`)
		for _, spill := range report.DataSpillage {
			date := ""
			if !spill.Date.IsZero() {
				date = spill.Date.Format("2006-01-02")
			}
			html.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%s</td><td><a href="%s" target="_blank">%s</a></td><td>%s</td><td>%s</td><td>%s</td></tr>`, 
				spill.Source, spill.Type, spill.URL, spill.URL, spill.Severity, date, spill.Description))
		}
		html.WriteString(`</tbody></table>`)
	}

	// Security Threats
	if len(report.SecurityThreats) > 0 {
		html.WriteString(fmt.Sprintf(`<h2>🛡️ Security Threats (%d found)</h2>`, len(report.SecurityThreats)))
		html.WriteString(`<table><thead><tr><th>Type</th><th>Title</th><th>Severity</th><th>Source</th><th>Date</th><th>Description</th></tr></thead><tbody>`)
		for _, threat := range report.SecurityThreats {
			date := ""
			if !threat.Date.IsZero() {
				date = threat.Date.Format("2006-01-02")
			}
			html.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>`, 
				threat.Type, threat.Title, threat.Severity, threat.Source, date, threat.Description))
		}
		html.WriteString(`</tbody></table>`)
	}

	// Asset Inventory
	if report.AssetInventory != nil {
		html.WriteString(`<h2>📊 Asset Inventory</h2>`)
		if len(report.AssetInventory.Domains) > 0 {
			html.WriteString(fmt.Sprintf(`<h3>Domains (%d)</h3><ul>`, len(report.AssetInventory.Domains)))
			for _, domain := range report.AssetInventory.Domains {
				html.WriteString(fmt.Sprintf(`<li>%s</li>`, domain))
			}
			html.WriteString(`</ul>`)
		}
		if len(report.AssetInventory.IPs) > 0 {
			html.WriteString(fmt.Sprintf(`<h3>IP Addresses (%d)</h3><ul>`, len(report.AssetInventory.IPs)))
			for _, ip := range report.AssetInventory.IPs {
				html.WriteString(fmt.Sprintf(`<li>%s</li>`, ip))
			}
			html.WriteString(`</ul>`)
		}
		if len(report.AssetInventory.Subdomains) > 0 {
			html.WriteString(fmt.Sprintf(`<h3>Subdomains (%d)</h3><ul>`, len(report.AssetInventory.Subdomains)))
			for _, subdomain := range report.AssetInventory.Subdomains {
				html.WriteString(fmt.Sprintf(`<li>%s</li>`, subdomain))
			}
			html.WriteString(`</ul>`)
		}
		if len(report.AssetInventory.Emails) > 0 {
			html.WriteString(fmt.Sprintf(`<h3>Emails (%d)</h3><ul>`, len(report.AssetInventory.Emails)))
			for _, email := range report.AssetInventory.Emails {
				html.WriteString(fmt.Sprintf(`<li>%s</li>`, email))
			}
			html.WriteString(`</ul>`)
		}
		if len(report.AssetInventory.Services) > 0 {
			html.WriteString(`<h3>Services</h3>`)
			html.WriteString(`<table><thead><tr><th>Port</th><th>Protocol</th><th>Service</th><th>Version</th></tr></thead><tbody>`)
			for _, service := range report.AssetInventory.Services {
				html.WriteString(fmt.Sprintf(`<tr><td>%d</td><td>%s</td><td>%s</td><td>%s</td></tr>`, 
					service.Port, service.Protocol, service.Service, service.Version))
			}
			html.WriteString(`</tbody></table>`)
		}
	}

	// Shodan/Censys Results
	if len(report.ShodanCensys) > 0 {
		html.WriteString(fmt.Sprintf(`<h2>🔍 Shodan/Censys Scan Results (%d found)</h2>`, len(report.ShodanCensys)))
		html.WriteString(`<table><thead><tr><th>IP</th><th>Port</th><th>Service</th><th>Version</th><th>Banner</th><th>Source</th></tr></thead><tbody>`)
		for _, result := range report.ShodanCensys {
			banner := result.Banner
			if len(banner) > 100 {
				banner = banner[:100] + "..."
			}
			html.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%d</td><td>%s</td><td>%s</td><td><code>%s</code></td><td>%s</td></tr>`, 
				result.IP, result.Port, result.Service, result.Version, banner, result.Source))
		}
		html.WriteString(`</tbody></table>`)
	}

	// Web Archive Results
	if len(report.WebArchive) > 0 {
		html.WriteString(fmt.Sprintf(`<h2>📜 Web Archive Results (%d found)</h2>`, len(report.WebArchive)))
		html.WriteString(`<table><thead><tr><th>URL</th><th>Timestamp</th><th>Snapshot URL</th><th>Type</th></tr></thead><tbody>`)
		for _, result := range report.WebArchive {
			timestamp := result.Timestamp.Format("2006-01-02 15:04:05")
			html.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%s</td><td><a href="%s" target="_blank">%s</a></td><td>%s</td></tr>`, 
				result.URL, timestamp, result.SnapshotURL, result.SnapshotURL, result.Type))
		}
		html.WriteString(`</tbody></table>`)
	}

	// GitHub Code Trace Results
	if len(report.GitHubCodeTrace) > 0 {
		html.WriteString(fmt.Sprintf(`<h2>🔎 GitHub Code Trace Results (%d found)</h2>`, len(report.GitHubCodeTrace)))
		html.WriteString(`<table><thead><tr><th>Repository</th><th>File</th><th>Line</th><th>Type</th><th>URL</th></tr></thead><tbody>`)
		for _, result := range report.GitHubCodeTrace {
			lineStr := ""
			if result.Line > 0 {
				lineStr = fmt.Sprintf("%d", result.Line)
			}
			html.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td><a href="%s" target="_blank">%s</a></td></tr>`, 
				result.Repository, result.File, lineStr, result.Type, result.URL, result.URL))
		}
		html.WriteString(`</tbody></table>`)
	}

	// Employee Profiles
	if len(report.EmployeeProfiles) > 0 {
		html.WriteString(fmt.Sprintf(`<h2>👥 Employee Profiles (%d found)</h2>`, len(report.EmployeeProfiles)))
		html.WriteString(`<table><thead><tr><th>Name</th><th>Username</th><th>Platform</th><th>Role</th><th>Company</th><th>URL</th></tr></thead><tbody>`)
		for _, profile := range report.EmployeeProfiles {
			html.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td><a href="%s" target="_blank">%s</a></td></tr>`, 
				profile.Name, profile.Username, profile.Platform, profile.Role, profile.Company, profile.URL, profile.URL))
		}
		html.WriteString(`</tbody></table>`)
	}

	// Corporate Info
	if report.CorporateInfo != nil {
		html.WriteString(`<h2>🏛️ Corporate Information</h2>`)
		html.WriteString(`<div class="info-grid">`)
		html.WriteString(fmt.Sprintf(`<div class="info-card"><strong>Source:</strong> %s</div>`, report.CorporateInfo.Source))
		if report.CorporateInfo.Founded != "" {
			html.WriteString(fmt.Sprintf(`<div class="info-card"><strong>Founded:</strong> %s</div>`, report.CorporateInfo.Founded))
		}
		if report.CorporateInfo.Employees != "" {
			html.WriteString(fmt.Sprintf(`<div class="info-card"><strong>Employees:</strong> %s</div>`, report.CorporateInfo.Employees))
		}
		if report.CorporateInfo.FinancialInfo != "" {
			html.WriteString(fmt.Sprintf(`<div class="info-card"><strong>Financial Info:</strong> %s</div>`, report.CorporateInfo.FinancialInfo))
		}
		html.WriteString(`</div>`)
		if len(report.CorporateInfo.Subsidiaries) > 0 {
			html.WriteString(`<h3>Subsidiaries</h3><ul>`)
			for _, sub := range report.CorporateInfo.Subsidiaries {
				html.WriteString(fmt.Sprintf(`<li>%s</li>`, sub))
			}
			html.WriteString(`</ul>`)
		}
		if len(report.CorporateInfo.Partners) > 0 {
			html.WriteString(`<h3>Partners</h3><ul>`)
			for _, partner := range report.CorporateInfo.Partners {
				html.WriteString(fmt.Sprintf(`<li>%s</li>`, partner))
			}
			html.WriteString(`</ul>`)
		}
		if len(report.CorporateInfo.RelatedDomains) > 0 {
			html.WriteString(`<h3>Related Domains</h3><ul>`)
			for _, domain := range report.CorporateInfo.RelatedDomains {
				html.WriteString(fmt.Sprintf(`<li>%s</li>`, domain))
			}
			html.WriteString(`</ul>`)
		}
		if len(report.CorporateInfo.CloudAssets) > 0 {
			html.WriteString(`<h3>Cloud Assets</h3><ul>`)
			for _, asset := range report.CorporateInfo.CloudAssets {
				html.WriteString(fmt.Sprintf(`<li>%s</li>`, asset))
			}
			html.WriteString(`</ul>`)
		}
	}

	// VirusTotal Results
	if len(report.VirusTotal) > 0 {
		html.WriteString(fmt.Sprintf(`<h2>🛡️ VirusTotal Scan Results (%d found)</h2>`, len(report.VirusTotal)))
		html.WriteString(`<table><thead><tr><th>Resource</th><th>Type</th><th>Positives</th><th>Total</th><th>Permalink</th></tr></thead><tbody>`)
		for _, result := range report.VirusTotal {
			permalinkStr := ""
			if result.Permalink != "" {
				permalinkStr = fmt.Sprintf(`<a href="%s" target="_blank">View</a>`, result.Permalink)
			}
			html.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%s</td><td>%d</td><td>%d</td><td>%s</td></tr>`, 
				result.Resource, result.Type, result.Positives, result.Total, permalinkStr))
		}
		html.WriteString(`</tbody></table>`)
	}

	html.WriteString(`
        <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #eee; text-align: center; color: #7f8c8d; font-size: 0.85em;">
            <p>Generated by Cyber OSINT Recon</p>
        </div>
    </div>
</body>
</html>
`)

	content := html.String()
	if filename != "" {
		return os.WriteFile(filename, []byte(content), 0644)
	}

	_, err := os.Stdout.WriteString(content)
	return err
}
