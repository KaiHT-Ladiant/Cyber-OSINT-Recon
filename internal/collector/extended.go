package collector

import (
	"cyber-osint-recon/internal/models"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
)

// httpClient HTTP client with default timeout and headers
var httpClient = &http.Client{
	Timeout: 10 * time.Second,
}

// getUserAgent Returns a random user agent string
func getUserAgent() string {
	userAgents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
	}
	return userAgents[0] // Use first one for consistency
}

// fetchURL Fetches a URL and returns the response body as string
func fetchURL(url string) (string, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("User-Agent", getUserAgent())
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

// checkURLExists Checks if a URL exists (returns true if status code is 200)
func checkURLExists(url string) bool {
	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return false
	}

	req.Header.Set("User-Agent", getUserAgent())

	resp, err := httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusFound
}

// CollectEmailPivot Collect email pivot information
func CollectEmailPivot(email string) ([]*models.EmailPivot, error) {
	var pivots []*models.EmailPivot
	
	// Extract domain from email
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid email format: %s", email)
	}
	
	domain := parts[1]
	
	pivot := &models.EmailPivot{
		Email:        email,
		RelatedDomains: []string{domain},
	}
	
	// Try to find related domains based on email patterns
	// This is a simplified version - in production, you'd use APIs like Hunter.io, etc.
	
	// Check for breach data (simplified - in production use HaveIBeenPwned API)
	// For now, just return the domain
	
	pivots = append(pivots, pivot)
	
	return pivots, nil
}

// CollectUsernameInfo Collect extended username information
func CollectUsernameInfo(username, domain string) (*models.UsernameInfo, error) {
	info := &models.UsernameInfo{
		Usernames: []models.UsernameProfile{},
	}

	if username == "" {
		return info, nil
	}

	var wg sync.WaitGroup
	var mutex sync.Mutex

	// Platform-specific URL patterns
	platforms := map[string]string{
		"github":      fmt.Sprintf("https://github.com/%s", username),
		"gitlab":      fmt.Sprintf("https://gitlab.com/%s", username),
		"bitbucket":   fmt.Sprintf("https://bitbucket.org/%s", username),
		"stackoverflow": fmt.Sprintf("https://stackoverflow.com/users/%s", username),
		"reddit":      fmt.Sprintf("https://www.reddit.com/user/%s", username),
	}

	for platform, url := range platforms {
		wg.Add(1)
		go func(p, u string) {
			defer wg.Done()
			exists := checkURLExists(u)
			mutex.Lock()
			info.Usernames = append(info.Usernames, models.UsernameProfile{
				Username: username,
				Platform: p,
				URL:      u,
				Exists:   exists,
			})
			mutex.Unlock()
		}(platform, url)
	}

	wg.Wait()

	return info, nil
}

// CollectSocialMediaInfo Collect social media information
func CollectSocialMediaInfo(company, domain string) (*models.SocialMediaInfo, error) {
	info := &models.SocialMediaInfo{
		Profiles: []models.SocialProfile{},
	}

	// Generate search patterns
	patterns := []string{}
	if company != "" {
		cleanCompany := strings.ToLower(strings.ReplaceAll(company, " ", ""))
		patterns = append(patterns, cleanCompany, strings.ToLower(company))
	}
	if domain != "" {
		domainParts := strings.Split(domain, ".")
		if len(domainParts) > 0 {
			patterns = append(patterns, domainParts[0])
		}
	}

	// Remove duplicates
	seen := make(map[string]bool)
	uniquePatterns := []string{}
	for _, p := range patterns {
		if p != "" && !seen[p] {
			seen[p] = true
			uniquePatterns = append(uniquePatterns, p)
		}
	}

	if len(uniquePatterns) == 0 {
		return info, nil
	}

	var wg sync.WaitGroup
	var mutex sync.Mutex

	// Platform URL patterns
	platformURLs := map[string]func(string) string{
		"github": func(p string) string { return fmt.Sprintf("https://github.com/%s", p) },
		"linkedin": func(p string) string { return fmt.Sprintf("https://www.linkedin.com/company/%s", p) },
		"twitter": func(p string) string { return fmt.Sprintf("https://twitter.com/%s", p) },
		"medium": func(p string) string { return fmt.Sprintf("https://medium.com/@%s", p) },
	}

	// Check each platform for each pattern
	for platform, urlFunc := range platformURLs {
		for _, pattern := range uniquePatterns {
			wg.Add(1)
			go func(plat string, pat string, urlFn func(string) string) {
				defer wg.Done()
				url := urlFn(pat)
				// Check if profile exists (commented out to reduce requests)
				// exists := checkURLExists(url)
				
				mutex.Lock()
				info.Profiles = append(info.Profiles, models.SocialProfile{
					Platform: plat,
					Username: pat,
					URL:      url,
					Verified: false, // Would need to check verification badge
				})
				mutex.Unlock()
			}(platform, pattern, urlFunc)
		}
	}

	wg.Wait()

	return info, nil
}

// CollectCompanyBackground Collect company background information
func CollectCompanyBackground(company string) (*models.CompanyBackground, error) {
	bg := &models.CompanyBackground{}

	if company == "" {
		return bg, nil
	}

	// Try Wikipedia
	wikipediaURL := fmt.Sprintf("https://en.wikipedia.org/wiki/%s", strings.ReplaceAll(company, " ", "_"))
	body, err := fetchURL(wikipediaURL)
	if err == nil {
		doc, err := goquery.NewDocumentFromReader(strings.NewReader(body))
		if err == nil {
			// Extract description from first paragraph
			doc.Find("div.mw-parser-output > p").First().Each(func(i int, s *goquery.Selection) {
				text := strings.TrimSpace(s.Text())
				if len(text) > 100 && bg.Description == "" {
					if len(text) > 500 {
						text = text[:500] + "..."
					}
					bg.Description = text
				}
			})

			// Extract infobox data
			doc.Find("table.infobox tr").Each(func(i int, s *goquery.Selection) {
				th := s.Find("th").Text()
				td := strings.TrimSpace(s.Find("td").Text())

				thLower := strings.ToLower(th)
				if strings.Contains(thLower, "founded") && bg.Founded == "" {
					bg.Founded = td
				}
				if strings.Contains(thLower, "industry") && bg.Industry == "" {
					bg.Industry = td
				}
				if strings.Contains(thLower, "headquarters") && bg.Location == "" {
					bg.Location = td
				}
				if strings.Contains(thLower, "employees") && bg.Employees == "" {
					bg.Employees = td
				}
				if strings.Contains(thLower, "revenue") && bg.Revenue == "" {
					bg.Revenue = td
				}
			})
		}
	}

	if bg.Description == "" {
		bg.Description = fmt.Sprintf("Background information for %s", company)
	}

	return bg, nil
}

// CollectRelatedAssets Collect related assets
func CollectRelatedAssets(domain, company string, existingAssets []string) ([]models.RelatedAsset, error) {
	var assets []models.RelatedAsset
	
	// Find assets related to the domain/company
	// This would include:
	// - Similar domains
	// - Related IPs
	// - Related emails
	// - Associated organizations
	
	// Add existing subdomains as related assets
	// This is a simplified version
	
	return assets, nil
}

// CollectCodeRepositories Collect code repository information
func CollectCodeRepositories(domain, company string) ([]models.CodeRepository, error) {
	var repos []models.CodeRepository
	var mutex sync.Mutex
	var wg sync.WaitGroup

	// Search terms to try
	searchTerms := []string{}
	if company != "" {
		searchTerms = append(searchTerms, strings.ToLower(strings.ReplaceAll(company, " ", "")), company)
	}
	if domain != "" {
		domainParts := strings.Split(domain, ".")
		if len(domainParts) > 0 {
			searchTerms = append(searchTerms, domainParts[0], domain)
		}
	}

	// Remove duplicates
	seen := make(map[string]bool)
	uniqueTerms := []string{}
	for _, term := range searchTerms {
		if term != "" && !seen[term] {
			seen[term] = true
			uniqueTerms = append(uniqueTerms, term)
		}
	}

	// Check GitHub
	for _, term := range uniqueTerms {
		wg.Add(1)
		go func(term string) {
			defer wg.Done()
			url := fmt.Sprintf("https://github.com/%s", term)
			if checkURLExists(url) {
				mutex.Lock()
				repos = append(repos, models.CodeRepository{
					Platform:   "github",
					Username:   term,
					Repository: "",
					URL:        url,
					Public:     true,
				})
				mutex.Unlock()
			}
		}(term)
	}

	// Check GitLab
	for _, term := range uniqueTerms {
		wg.Add(1)
		go func(term string) {
			defer wg.Done()
			url := fmt.Sprintf("https://gitlab.com/%s", term)
			if checkURLExists(url) {
				mutex.Lock()
				repos = append(repos, models.CodeRepository{
					Platform:   "gitlab",
					Username:   term,
					Repository: "",
					URL:        url,
					Public:     true,
				})
				mutex.Unlock()
			}
		}(term)
	}

	// Search GitHub by domain/company name
	if company != "" || domain != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			searchQuery := ""
			if company != "" {
				searchQuery = company
			} else {
				searchQuery = domain
			}
			
			// GitHub search URL (limited, as it requires authentication for API)
			searchURL := fmt.Sprintf("https://github.com/search?q=%s&type=repositories", strings.ReplaceAll(searchQuery, " ", "+"))
			body, err := fetchURL(searchURL)
			if err == nil {
				doc, err := goquery.NewDocumentFromReader(strings.NewReader(body))
				if err == nil {
					doc.Find("a[data-hydro-click]").Each(func(i int, s *goquery.Selection) {
						if i < 5 { // Limit to first 5 results
							href, exists := s.Attr("href")
							if exists && strings.HasPrefix(href, "/") && strings.Count(href, "/") == 2 {
								parts := strings.Split(strings.TrimPrefix(href, "/"), "/")
								if len(parts) == 2 {
									repoURL := "https://github.com" + href
									mutex.Lock()
									repos = append(repos, models.CodeRepository{
										Platform:   "github",
										Username:   parts[0],
										Repository: parts[1],
										URL:        repoURL,
										Public:     true,
									})
									mutex.Unlock()
								}
							}
						}
					})
				}
			}
		}()
	}

	wg.Wait()

	return repos, nil
}

// CollectDocuments Collect document repository information
func CollectDocuments(domain, company string) ([]models.Document, error) {
	var docs []models.Document
	
	// Search for public documents
	// Common platforms: Google Drive, Dropbox, S3 buckets, etc.
	
	// This would require specific APIs or web scraping
	// For now, return empty
	
	return docs, nil
}

// CollectDataSpillage Collect data spillage information
func CollectDataSpillage(domain, company, email string) ([]models.DataSpillage, error) {
	var spillages []models.DataSpillage
	var mutex sync.Mutex
	var wg sync.WaitGroup

	// Search terms
	searchTerms := []string{}
	if domain != "" {
		searchTerms = append(searchTerms, domain)
	}
	if company != "" {
		searchTerms = append(searchTerms, company)
	}
	if email != "" {
		parts := strings.Split(email, "@")
		if len(parts) > 0 {
			searchTerms = append(searchTerms, parts[0])
		}
	}

	// Search Pastebin (via search engines or direct - limited without API)
	// Note: Actual Pastebin search requires API access
	// This is a simplified version that checks common patterns

	// Check GitHub for potential leaks
	for _, term := range searchTerms {
		if term == "" {
			continue
		}
		wg.Add(1)
		go func(searchTerm string) {
			defer wg.Done()
			
			// Search GitHub for potential leaks (limited - would need GitHub API for better results)
			searchURL := fmt.Sprintf("https://github.com/search?q=%s+password+OR+api_key+OR+secret&type=code", 
				strings.ReplaceAll(searchTerm, " ", "+"))
			
			body, err := fetchURL(searchURL)
			if err == nil {
				// Check if results exist
				if strings.Contains(body, "repository code results") || strings.Contains(body, "code results") {
					mutex.Lock()
					spillages = append(spillages, models.DataSpillage{
						Source:      "GitHub",
						Type:        "code_leak",
						URL:         searchURL,
						Description: fmt.Sprintf("Potential code leak found for %s on GitHub", searchTerm),
						Severity:    "medium",
					})
					mutex.Unlock()
				}
			}
		}(term)
	}

	wg.Wait()

	return spillages, nil
}

// CollectSecurityThreats Collect security threat information (includes VirusTotal)
func CollectSecurityThreats(domain, company string, ipAddresses []models.IPInfo) ([]models.SecurityThreat, error) {
	var threats []models.SecurityThreat
	
	// Extract IP addresses as strings
	ipStrings := make([]string, len(ipAddresses))
	for i, ipInfo := range ipAddresses {
		ipStrings[i] = ipInfo.IP
	}
	
	// Note: VirusTotal collection is now handled separately in main.go via enhanced.go
	
	// Simple Google search for vulnerabilities (placeholder)
	_ = domain
	_ = company
	_ = ipStrings
	
	return threats, nil
}

// CollectAssetInventory Collect asset inventory with detailed risk assessment
func CollectAssetInventory(report *models.Report) (*models.AssetInventory, error) {
	inventory := &models.AssetInventory{
		Domains:    []string{},
		IPs:        []string{},
		Subdomains: []string{},
		Emails:     []string{},
		Services:   []models.ServiceInfo{},
		Assets:     []models.AssetItem{},
	}
	
	// Collect all discovered assets
	if report.Domain != "" {
		inventory.Domains = append(inventory.Domains, report.Domain)
	}
	
	if len(report.Subdomains) > 0 {
		inventory.Subdomains = append(inventory.Subdomains, report.Subdomains...)
		inventory.Domains = append(inventory.Domains, report.Subdomains...)
	}
	
	for _, ipInfo := range report.IPAddresses {
		inventory.IPs = append(inventory.IPs, ipInfo.IP)
	}
	
	if len(report.Emails) > 0 {
		inventory.Emails = append(inventory.Emails, report.Emails...)
	}
	
	// Extract services from tech stack (if available)
	if report.TechStack != nil {
		for _, ws := range report.TechStack.WebServer {
			inventory.Services = append(inventory.Services, models.ServiceInfo{
				Port:     80,
				Protocol: "http",
				Service:  ws,
			})
			inventory.Services = append(inventory.Services, models.ServiceInfo{
				Port:     443,
				Protocol: "https",
				Service:  ws,
			})
		}
	}
	
	// Build detailed asset items with risk assessment
	// Subdomains
	for _, subdomain := range report.Subdomains {
		risk := "저"
		details := ""
		evidenceURL := "crt.sh"
		source := "crt.sh"
		
		// Check if it's an admin subdomain
		subdomainLower := strings.ToLower(subdomain)
		if strings.Contains(subdomainLower, "admin") ||
			strings.Contains(subdomainLower, "manage") ||
			strings.Contains(subdomainLower, "control") ||
			strings.Contains(subdomainLower, "dashboard") {
			risk = "중"
			details = "관리자 페이지"
		}
		
		// Find evidence from Shodan/Censys
		for _, sc := range report.ShodanCensys {
			if sc.Hostname == subdomain || strings.Contains(sc.Hostname, subdomain) {
				evidenceURL = fmt.Sprintf("Shodan/%s", sc.IP)
				if sc.Port == 443 {
					details = fmt.Sprintf("%d %s", sc.Port, sc.Service)
				}
				if len(sc.SecurityIssues) > 0 {
					risk = "중"
				}
				source = "Shodan"
				break
			}
		}
		
		inventory.Assets = append(inventory.Assets, models.AssetItem{
			Category:    "서브도메인",
			Asset:       subdomain,
			Details:     details,
			EvidenceURL: evidenceURL,
			Risk:        risk,
			Source:      source,
		})
	}
	
	// IP Addresses
	for _, ipInfo := range report.IPAddresses {
		risk := "저"
		details := ""
		evidenceURL := ""
		source := "DNS"
		
		// Check Shodan/Censys for this IP
		for _, sc := range report.ShodanCensys {
			if sc.IP == ipInfo.IP {
				evidenceURL = fmt.Sprintf("Shodan/%s", sc.IP)
				details = fmt.Sprintf("%d %s", sc.Port, sc.Service)
				if len(sc.SecurityIssues) > 0 {
					risk = "중"
				}
				source = "Shodan"
				break
			}
		}
		
		if details == "" {
			details = "NS 서버"
		}
		
		inventory.Assets = append(inventory.Assets, models.AssetItem{
			Category:    "IP",
			Asset:       ipInfo.IP,
			Details:     details,
			EvidenceURL: evidenceURL,
			Risk:        risk,
			Source:      source,
		})
	}
	
	// Emails
	for _, email := range report.Emails {
		inventory.Assets = append(inventory.Assets, models.AssetItem{
			Category:    "이메일",
			Asset:       email,
			Details:     "이메일 주소",
			EvidenceURL: "",
			Risk:        "저",
			Source:      "WHOIS",
		})
	}
	
	// Leak Search Results
	for _, leak := range report.DataSpillage {
		risk := leak.Severity
		if risk == "high" {
			risk = "고"
		} else if risk == "medium" {
			risk = "중"
		} else {
			risk = "저"
		}
		inventory.Assets = append(inventory.Assets, models.AssetItem{
			Category:    "유출정보",
			Asset:       leak.URL,
			Details:     leak.Type,
			EvidenceURL: leak.URL,
			Risk:        risk,
			Source:      leak.Source,
			Description: leak.Description,
		})
	}
	
	return inventory, nil
}

// Helper function to extract email from text
func extractEmailsFromText(text string) []string {
	var emails []string
	emailRegex := regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	matches := emailRegex.FindAllString(text, -1)
	
	seen := make(map[string]bool)
	for _, match := range matches {
		if !seen[match] {
			emails = append(emails, match)
			seen[match] = true
		}
	}
	
	return emails
}
