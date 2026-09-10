package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"cyber-osint-recon/internal/collector"
	"cyber-osint-recon/internal/config"
	"cyber-osint-recon/internal/models"
	"cyber-osint-recon/internal/reporter"
)

func isDomain(input string) bool {
	input = strings.TrimSpace(strings.ToLower(input))
	input = strings.TrimPrefix(input, "http://")
	input = strings.TrimPrefix(input, "https://")
	input = strings.Trim(input, "/")
	if input == "" || strings.ContainsAny(input, " \t") {
		return false
	}
	if strings.Contains(input, "/") || strings.Contains(input, "@") {
		return false
	}
	parts := strings.Split(input, ".")
	if len(parts) < 2 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		for _, r := range p {
			if !(r == '-' || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')) {
				return false
			}
		}
	}
	return true
}

func uniqueStrings(items []string) []string {
	seen := make(map[string]bool)
	out := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" || seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	return out
}

func generateReportPath(domain, company, format string) string {
	reportDir := "Report"
	if err := os.MkdirAll(reportDir, 0755); err != nil {
		fmt.Printf("[!] Failed to create Report directory: %v, using current directory\n", err)
		reportDir = "."
	}

	label := domain
	if label == "" {
		label = company
	}
	if label == "" {
		label = "scan"
	}
	label = strings.ReplaceAll(label, " ", "_")
	label = strings.ReplaceAll(label, "/", "_")
	label = strings.ReplaceAll(label, "\\", "_")

	ts := time.Now().Format("20060102_150405")
	ext := format
	switch format {
	case "markdown":
		ext = "md"
	case "docx":
		ext = "docx"
	case "excel", "xlsx":
		ext = "xlsx"
		format = "excel"
	}
	_ = format
	return filepath.Join(reportDir, fmt.Sprintf("cyrecon_%s_%s.%s", label, ts, ext))
}

func collectDomainInfo(domain string, enableSubdomains bool, workers, depth int, shodanKey, censysToken, vtKey string, progress *progressTracker) models.DomainReport {
	_ = progress
	dr := models.DomainReport{Domain: domain}
	var mu sync.Mutex
	var wg sync.WaitGroup

	run := func(fn func()) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fn()
		}()
	}

	fmt.Printf("[*] Starting OSINT information collection (Domain): %s\n", domain)

	// Phase 1: independent collectors
	run(func() {
		fmt.Printf("[*] Collecting domain WHOIS information for %s...\n", domain)
		info, err := collector.CollectDomainInfo(domain)
		if err != nil {
			fmt.Printf("[!] domain information collection failed for %s: %v\n", domain, err)
			return
		}
		mu.Lock()
		dr.DomainInfo = info
		mu.Unlock()
	})

	run(func() {
		fmt.Printf("[*] Querying DNS records for %s...\n", domain)
		dns, err := collector.CollectDNSRecords(domain)
		if err != nil {
			fmt.Printf("[!] DNS collection failed for %s: %v\n", domain, err)
			return
		}
		ips := make([]models.IPInfo, 0)
		seen := map[string]bool{}
		if dns != nil {
			for _, ip := range append(append([]string{}, dns.A...), dns.AAAA...) {
				if seen[ip] {
					continue
				}
				seen[ip] = true
				if info, err := collector.GetIPInfo(ip); err == nil && info != nil {
					ips = append(ips, *info)
				} else {
					ips = append(ips, models.IPInfo{IP: ip})
				}
			}
		}
		mu.Lock()
		dr.DNSRecords = dns
		dr.IPAddresses = ips
		mu.Unlock()
	})

	run(func() {
		if !enableSubdomains {
			return
		}
		fmt.Printf("[*] Searching for subdomains for %s...\n", domain)
		subs := collector.EnumerateFromCert(domain)
		subs = append(subs, collector.DiscoverSubdomains(domain, nil, workers)...)
		mu.Lock()
		dr.Subdomains = uniqueStrings(subs)
		mu.Unlock()
	})

	run(func() {
		fmt.Printf("[*] Collecting email addresses for %s...\n", domain)
		emails := collector.ExtractEmailsFromWhois(domain)
		if crawled, err := collector.CollectEmails(domain, depth); err == nil {
			emails = append(emails, crawled...)
		}
		if harvested, err := collector.CollectEmailsTheHarvester(domain, ""); err == nil {
			emails = append(emails, harvested...)
		}
		emails = append(emails, collector.SearchEmailFromWeb(domain, "")...)
		mu.Lock()
		dr.Emails = uniqueStrings(emails)
		mu.Unlock()
	})

	run(func() {
		fmt.Printf("[*] Analyzing web technology stack for %s...\n", domain)
		tech, err := collector.CollectTechStack(domain)
		if err != nil {
			fmt.Printf("[!] technology stack analysis failed for %s: %v\n", domain, err)
			return
		}
		mu.Lock()
		dr.TechStack = tech
		mu.Unlock()
	})

	run(func() {
		results, err := collector.CollectWebArchive(domain)
		if err != nil {
			fmt.Printf("[!] Web archive search failed for %s: %v\n", domain, err)
			return
		}
		mu.Lock()
		dr.WebArchive = results
		mu.Unlock()
	})

	wg.Wait()

	// Phase 2: collectors that depend on IPs / subdomains
	wg = sync.WaitGroup{}
	run(func() {
		fmt.Printf("[*] Scanning with Shodan/Censys for %s...\n", domain)
		ips := make([]string, 0, len(dr.IPAddresses))
		for _, ip := range dr.IPAddresses {
			ips = append(ips, ip.IP)
		}
		results, err := collector.CollectShodanCensys(domain, ips, shodanKey, censysToken, dr.Subdomains, "")
		if err != nil {
			fmt.Printf("[!] Shodan/Censys scan failed for %s: %v\n", domain, err)
			return
		}
		if shodanKey != "" {
			if pivot, err := collector.PerformShodanPivotFromDNSDumpster(domain, shodanKey); err == nil {
				results = append(results, pivot...)
			}
		}
		mu.Lock()
		dr.ShodanCensys = results
		mu.Unlock()
	})

	run(func() {
		ips := make([]string, 0, len(dr.IPAddresses))
		for _, ip := range dr.IPAddresses {
			ips = append(ips, ip.IP)
		}
		results, err := collector.CollectVirusTotal(domain, ips, vtKey)
		if err != nil {
			fmt.Printf("[!] VirusTotal scan failed for %s: %v\n", domain, err)
			return
		}
		mu.Lock()
		dr.VirusTotal = results
		mu.Unlock()
	})

	wg.Wait()
	return dr
}

func mergeDomainIntoReport(report *models.Report, dr models.DomainReport) {
	report.Domains = append(report.Domains, dr)
	if report.Domain == "" {
		report.Domain = dr.Domain
		report.DomainInfo = dr.DomainInfo
		report.DNSRecords = dr.DNSRecords
		report.TechStack = dr.TechStack
	}
	report.Subdomains = uniqueStrings(append(report.Subdomains, dr.Subdomains...))
	report.Emails = uniqueStrings(append(report.Emails, dr.Emails...))
	report.IPAddresses = append(report.IPAddresses, dr.IPAddresses...)
	report.ShodanCensys = append(report.ShodanCensys, dr.ShodanCensys...)
	report.WebArchive = append(report.WebArchive, dr.WebArchive...)
	report.VirusTotal = append(report.VirusTotal, dr.VirusTotal...)
}

func collectExtendedOSINT(report *models.Report, primaryDomain, company, githubToken string, progress *progressTracker) {
	if progress != nil {
		progress.startStep("Pivot Email/Domain Search")
	}
	if pivot, err := collector.CollectEmailPivotDomain(primaryDomain); err != nil {
		fmt.Printf("[!] Pivot Email/Domain search failed: %v\n", err)
	} else if pivot != nil {
		ep := &models.EmailPivot{
			Email:          "",
			RelatedDomains: []string{primaryDomain},
		}
		if len(pivot.SampleEmails) > 0 {
			ep.Email = pivot.SampleEmails[0]
		}
		for _, b := range pivot.BreachResults {
			ep.BreachData = append(ep.BreachData, models.BreachInfo{
				Source:      strings.Join(b.Breaches, ", "),
				Description: fmt.Sprintf("breached=%v count=%d", b.Breached, b.Count),
			})
		}
		report.EmailPivot = ep
		report.Emails = uniqueStrings(append(report.Emails, pivot.SampleEmails...))
		_ = collector.SaveEmailPivotFindings(pivot)
	}
	if progress != nil {
		progress.completeStep()
	}

	if progress != nil {
		progress.startStep("Username & Social Media Search")
	}
	if ext, err := collector.CollectExtendedUsernameSocial(primaryDomain, company); err != nil {
		fmt.Printf("[!] Extended Username/Social search failed: %v\n", err)
	} else if ext != nil {
		ui := &models.UsernameInfo{}
		for _, u := range ext.Usernames {
			ui.Usernames = append(ui.Usernames, models.UsernameProfile{
				Username: u.Username,
				Platform: u.Platform,
				URL:      u.URL,
				Exists:   u.Exists,
			})
		}
		report.Usernames = ui
		_ = collector.SaveUsernameExtendedFindings(ext)
	}
	if social, err := collector.CollectSocialMediaInfo(company, primaryDomain); err == nil {
		report.SocialMedia = social
	}
	if progress != nil {
		progress.completeStep()
	}

	if progress != nil {
		progress.startStep("Company Background Research")
	}
	if company != "" {
		if bg, err := collector.CollectCompanyBackground(company); err == nil {
			report.CompanyBackground = bg
		}
	}
	if progress != nil {
		progress.completeStep()
	}

	if progress != nil {
		progress.startStep("Related Assets Discovery")
	}
	if assets, err := collector.CollectRelatedAssets(primaryDomain, company, report.Subdomains); err == nil {
		report.RelatedAssets = assets
	}
	if progress != nil {
		progress.completeStep()
	}

	if progress != nil {
		progress.startStep("Code Repository Search")
	}
	if repos, err := collector.CollectCodeRepositories(primaryDomain, company); err == nil {
		report.CodeRepos = repos
	}
	if progress != nil {
		progress.completeStep()
	}

	if progress != nil {
		progress.startStep("Document Repository Search")
	}
	if docs, err := collector.CollectDocuments(primaryDomain, company); err == nil {
		report.Documents = docs
	}
	if progress != nil {
		progress.completeStep()
	}

	if progress != nil {
		progress.startStep("Data Spillage Detection")
	}
	emailHint := ""
	if len(report.Emails) > 0 {
		emailHint = report.Emails[0]
	}
	if spills, err := collector.CollectDataSpillage(primaryDomain, company, emailHint); err == nil {
		report.DataSpillage = append(report.DataSpillage, spills...)
	}
	if progress != nil {
		progress.completeStep()
	}

	if progress != nil {
		progress.startStep("Security Threat Intelligence")
	}
	if threats, err := collector.CollectSecurityThreats(primaryDomain, company, report.IPAddresses); err == nil {
		report.SecurityThreats = threats
	}
	if progress != nil {
		progress.completeStep()
	}

	if progress != nil {
		progress.startStep("GitHub Code Trace")
	}
	gh := make([]models.GitHubCodeTraceResult, 0)
	if results, err := collector.CollectGitHubCodeTrace(primaryDomain, company); err == nil {
		gh = append(gh, results...)
	}
	if results, err := collector.CollectGrepAppCodeSearch(primaryDomain, company); err == nil {
		gh = append(gh, results...)
	}
	if githubToken != "" {
		if results, err := collector.CollectGitHubDorking(primaryDomain, company, githubToken); err == nil {
			gh = append(gh, results...)
		}
	}
	report.GitHubCodeTrace = gh
	if progress != nil {
		progress.completeStep()
	}

	if progress != nil {
		progress.startStep("Employee Profile Search")
	}
	if profiles, err := collector.CollectEmployeeProfiles(company, primaryDomain); err == nil {
		report.EmployeeProfiles = profiles
	}
	if progress != nil {
		progress.completeStep()
	}

	if progress != nil {
		progress.startStep("Corporate Information Search")
	}
	if corp, err := collector.CollectCorporateInfo(primaryDomain, company); err != nil {
		fmt.Printf("[!] Corporate Information search failed: %v\n", err)
	} else if corp != nil {
		ci := &models.CorporateInfo{
			Source:         "crunchbase/opencorporates",
			Employees:      "",
			Founded:        "",
			RelatedDomains: []string{},
		}
		for _, s := range corp.Subsidiaries {
			ci.Subsidiaries = append(ci.Subsidiaries, s.Name)
		}
		for _, p := range corp.Partners {
			ci.Partners = append(ci.Partners, p.Name)
		}
		for _, c := range corp.CloudAssets {
			ci.CloudAssets = append(ci.CloudAssets, c.Service+":"+c.Domain+c.Subdomain)
		}
		if len(corp.CrunchbaseResults) > 0 {
			ci.Employees = corp.CrunchbaseResults[0].Employees
			ci.Founded = corp.CrunchbaseResults[0].Founded
			ci.Source = "crunchbase"
		} else if len(corp.OpenCorporatesResults) > 0 {
			ci.Source = "opencorporates"
			ci.Founded = corp.OpenCorporatesResults[0].IncorporationDate
		}
		report.CorporateInfo = ci
		_ = collector.SaveCorporateInfoFindings(corp)
	}
	if progress != nil {
		progress.completeStep()
	}

	if progress != nil {
		progress.startStep("Leak Search")
	}
	if leak, err := collector.CollectLeakSearch(primaryDomain, company); err != nil {
		fmt.Printf("[!] Leak Search failed: %v\n", err)
	} else if leak != nil {
		for _, item := range leak.RiskItems {
			report.DataSpillage = append(report.DataSpillage, models.DataSpillage{
				Source:      item.Source,
				Type:        item.Type,
				URL:         item.Location,
				Description: item.Description,
				Severity:    item.Severity,
			})
		}
		_ = collector.SaveLeakSearchFindings(leak)
	}
	if progress != nil {
		progress.completeStep()
	}

	if progress != nil {
		progress.startStep("Asset Inventory Generation")
	}
	if inv, err := collector.CollectAssetInventory(report); err == nil {
		report.AssetInventory = inv
	}
	if progress != nil {
		progress.completeStep()
	}
}

func saveReport(report *models.Report, format, savePath string) (string, error) {
	format = strings.ToLower(strings.TrimSpace(format))
	if savePath == "" {
		savePath = generateReportPath(report.Domain, report.Company, format)
	}

	fmt.Printf("[*] Generating report... (elapsed time: %s)\n", formatDuration(time.Since(report.Timestamp)))

	var err error
	switch format {
	case "json":
		err = reporter.GenerateJSONReport(report, savePath)
	case "html":
		err = reporter.GenerateHTMLReport(report, savePath)
	case "markdown", "md":
		err = reporter.GenerateMarkdownReport(report, savePath)
	case "docx":
		err = reporter.GenerateDOCXReport(report, savePath)
	case "excel", "xlsx":
		fmt.Printf("[*] Generating Excel report: %s\n", savePath)
		err = reporter.GenerateExcelReport(report, savePath)
		if err == nil {
			fmt.Printf("[+] Excel report saved to '%s'\n", savePath)
		}
	default:
		return "", fmt.Errorf("unsupported output format: %s (use json, html, markdown, docx, excel)", format)
	}
	return savePath, err
}

func runScan(targets []string, company string, mode string, enableSubdomains bool, workers, depth int, outputFormat, savePath, shodanKey, censysToken, vtKey, githubToken string) error {
	fmt.Println()
	fmt.Printf("[Mode] %s\n", strings.ToUpper(mode))
	fmt.Printf("[*] Targets: %d domain(s)\n", len(targets))
	for i, t := range targets {
		fmt.Printf("   %d. %s\n", i+1, t)
	}
	if company != "" {
		fmt.Printf("[*] Company: %s\n", company)
	}
	fmt.Println()

	// Domain collection steps (1) + extended OSINT (~12) + report/cleanup (2)
	totalSteps := 1 + 12 + 2
	if len(targets) > 1 {
		totalSteps = len(targets) + 12 + 2
	}
	progress := newProgressTracker(totalSteps)

	report := &models.Report{
		Timestamp: time.Now(),
		Company:   company,
		Domains:   make([]models.DomainReport, 0, len(targets)),
	}

	for i, domain := range targets {
		stepName := fmt.Sprintf("Domain Collection (%d/%d): %s", i+1, len(targets), domain)
		progress.startStep(stepName)
		dr := collectDomainInfo(domain, enableSubdomains, workers, depth, shodanKey, censysToken, vtKey, progress)
		mergeDomainIntoReport(report, dr)
		progress.completeStep()
	}

	primary := report.Domain
	if company == "" && primary != "" {
		company = collector.ExtractCompanyNameFromDomain(primary)
		report.Company = company
	}

	collectExtendedOSINT(report, primary, company, githubToken, progress)

	// Integrate Findings directory artifacts then clean up
	progress.startStep("Findings Integration & Cleanup")
	if _, err := collector.LoadFindingsFromDirectory("Findings"); err == nil {
		fmt.Println("[INFO] Loaded findings from Findings directory")
	}
	fmt.Println("[*] Cleaning up Findings directory...")
	if err := collector.CleanupFindingsDirectory("Findings"); err != nil {
		fmt.Printf("[!] Failed to cleanup Findings directory: %v\n", err)
	} else {
		fmt.Println("[+] Findings directory cleaned up (data integrated into report)")
	}
	progress.completeStep()

	progress.startStep("Report Generation")
	savedTo, err := saveReport(report, outputFormat, savePath)
	if err != nil {
		progress.completeStep()
		return err
	}
	fmt.Printf("[+] Report saved to '%s'\n", savedTo)
	progress.completeStep()

	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════╗")
	fmt.Println("║            Scan Completed                ║")
	fmt.Printf("║  Total Time: %-28s║\n", formatDuration(progress.totalElapsed()))
	fmt.Printf("║  Domains: %-31d║\n", len(report.Domains))
	fmt.Println("╚══════════════════════════════════════════╝")
	return nil
}

func resolveTargets(mode string, args []string, companyFlag, listPath string) (targets []string, company string, err error) {
	company = companyFlag

	switch mode {
	case modeMulti:
		path := listPath
		if path == "" && len(args) > 0 {
			path = args[0]
		}
		if path == "" {
			return nil, "", fmt.Errorf("[Mode: multi] requires a domain list file via --list or positional argument")
		}
		targets, err = loadDomainList(path)
		if err != nil {
			return nil, "", err
		}
		fmt.Printf("[+] Loaded %d domain(s) from list: %s\n", len(targets), path)
		return targets, company, nil

	default: // single
		if listPath != "" {
			// Allow --list even in single if user mistakenly set it? Prefer multi semantics.
			return nil, "", fmt.Errorf("[Mode: single] does not use --list; switch to --mode multi")
		}
		if len(args) == 0 {
			return nil, "", fmt.Errorf("[Mode: single] requires a domain or company name argument")
		}
		input := strings.TrimSpace(args[0])
		if isDomain(input) {
			domain := strings.ToLower(input)
			domain = strings.TrimPrefix(domain, "http://")
			domain = strings.TrimPrefix(domain, "https://")
			domain = strings.Trim(domain, "/")
			targets = []string{domain}
			if company == "" {
				company = collector.ExtractCompanyNameFromDomain(domain)
			}
			return targets, company, nil
		}

		// Treat as company name
		company = input
		fmt.Printf("[*] Searching domains by company name: %s\n", company)
		fmt.Println("   Searching for domains...")
		found, searchErr := collector.SearchDomainsByCompany(company)
		if searchErr != nil {
			return nil, "", fmt.Errorf("%v\n   Please enter a domain directly or check the company name", searchErr)
		}
		fmt.Printf("[+] Found %d domain(s):\n", len(found))
		for i, d := range found {
			fmt.Printf("   %d. %s\n", i+1, d)
		}
		return found, company, nil
	}
}

func loadMergedAPIKeys(cmdShodan, cmdCensys, cmdVT string) (string, string, string) {
	cfg, err := config.LoadConfig()
	if err != nil || cfg == nil {
		cfg = &config.Config{}
	}
	return config.MergeConfig(cfg, cmdShodan, cmdCensys, cmdVT)
}
