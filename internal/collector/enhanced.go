package collector

import (
	"context"
	"cyber-osint-recon/internal/models"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/VirusTotal/vt-go"
	"github.com/shadowscatcher/shodan"
	"github.com/shadowscatcher/shodan/search"
)

// httpClientEnhanced HTTP client for API calls
var httpClientEnhanced = &http.Client{
	Timeout: 15 * time.Second,
}

// fetchURLEnhanced Fetches a URL and returns the response body as string
func fetchURLEnhanced(url string) (string, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("User-Agent", "Cyber-OSINT-Recon/1.0")
	req.Header.Set("Accept", "application/json")

	resp, err := httpClientEnhanced.Do(req)
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

// checkURLExistsEnhanced Checks if a URL exists (returns true if status code is 200)
func checkURLExistsEnhanced(url string) bool {
	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return false
	}

	req.Header.Set("User-Agent", "Cyber-OSINT-Recon/1.0")

	resp, err := httpClientEnhanced.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusFound
}

// CollectShodanCensys Collects information from Shodan/Censys (requires API keys)
// For Censys, use Basic Auth with API ID and Secret (censysToken contains API ID, censysSecret contains Secret)
// subdomains: list of subdomains to search individually
// company: company name for SSL certificate-based search
func CollectShodanCensys(domain string, ipAddresses []string, shodanKey, censysToken string, subdomains []string, company string) ([]models.ShodanCensysResult, error) {
	var results []models.ShodanCensysResult
	var mutex sync.Mutex
	var wg sync.WaitGroup
	ctx := context.Background()

	// Initialize Shodan client
	var shodanClient *shodan.Client
	if shodanKey != "" {
		var err error
		shodanClient, err = shodan.GetClient(shodanKey, httpClientEnhanced, false)
		if err != nil {
			// If client initialization fails, log error but continue
			fmt.Printf("[!] Shodan client initialization failed: %v\n", err)
			shodanClient = nil
		} else {
			fmt.Printf("[+] Shodan client initialized successfully\n")
		}
	}

	// Shodan advanced search: hostname and SSL certificate based search
	if shodanClient != nil && domain != "" {
		// 1. Hostname-based search
		wg.Add(1)
		go func() {
			defer wg.Done()
			fmt.Printf("[*] Shodan: Searching for hostname:%s...\n", domain)
			query := fmt.Sprintf("hostname:%s", domain)
			shodanResults := performShodanSearch(shodanKey, query, domain, &mutex, &results)
			if len(shodanResults) > 0 {
				fmt.Printf("[+] Shodan: Found %d result(s) for hostname:%s\n", len(shodanResults), domain)
			}
		}()

		// 2. SSL certificate-based search (use company name if provided)
		if company != "" {
			wg.Add(1)
			go func() {
				defer wg.Done()
				fmt.Printf("[*] Shodan: Searching for SSL certificate with CN containing '%s'...\n", company)
				// Search by SSL certificate subject CN
				query := fmt.Sprintf("ssl.cert.subject.cn:*%s*", company)
				shodanResults := performShodanSearch(shodanKey, query, domain, &mutex, &results)
				if len(shodanResults) > 0 {
					fmt.Printf("[+] Shodan: Found %d result(s) for SSL certificate search\n", len(shodanResults))
				}
			}()
		}
		
		// 3. Search for each subdomain individually
		if len(subdomains) > 0 {
			fmt.Printf("[*] Shodan: Searching for %d subdomain(s)...\n", len(subdomains))
			for _, subdomain := range subdomains {
				wg.Add(1)
				go func(sub string) {
					defer wg.Done()
					query := fmt.Sprintf("hostname:%s", sub)
					shodanResults := performShodanSearch(shodanKey, query, sub, &mutex, &results)
					if len(shodanResults) > 0 {
						fmt.Printf("[+] Shodan: Found %d result(s) for subdomain %s\n", len(shodanResults), sub)
					}
				}(subdomain)
			}
		}
	}

	if len(ipAddresses) == 0 {
		fmt.Printf("[INFO] No IP addresses to scan with Shodan/Censys\n")
		// Wait for domain search to complete if no IPs
		if shodanClient != nil && domain != "" {
			time.Sleep(2 * time.Second)
		}
		return results, nil
	}

	for _, ip := range ipAddresses {
		// Shodan API using official library
		if shodanClient != nil {
			wg.Add(1)
			go func(ipAddr string) {
				defer wg.Done()
				fmt.Printf("[*] Shodan: Querying IP %s...\n", ipAddr)
				params := search.HostParams{
					IP:      ipAddr,
					Minify:  false,
					History: false,
				}
				host, err := shodanClient.Host(ctx, params)
				if err != nil {
					// Log detailed error information
					errMsg := err.Error()
					if strings.Contains(errMsg, "401") || strings.Contains(errMsg, "unauthorized") {
						fmt.Printf("[!] Shodan API error for IP %s: Invalid API key or unauthorized access\n", ipAddr)
					} else if strings.Contains(errMsg, "429") || strings.Contains(errMsg, "rate limit") {
						fmt.Printf("[!] Shodan API error for IP %s: Rate limit exceeded. Please wait and try again.\n", ipAddr)
					} else if strings.Contains(errMsg, "404") || strings.Contains(errMsg, "not found") || strings.Contains(errMsg, "No information available") {
						// IP에 대한 정보가 없음 (정상적인 경우)
						return
					} else {
						// 기타 오류는 조용히 처리
						return
					}
					return
				}
				// Extract detailed port and service information
				if host.Services != nil && len(host.Services) > 0 {
					fmt.Printf("[+] Shodan: Found %d service(s) for IP %s\n", len(host.Services), ipAddr)
					for _, service := range host.Services {
						if service == nil {
							continue
						}
						port := service.Port
						product := service.ProductString()
						banner := service.Data
						
						// Extract version from banner
						version := extractVersionFromBanner(banner, product)
						
						// Extract hostname
						hostname := ""
						if host.Hostnames != nil && len(host.Hostnames) > 0 {
							hostname = host.Hostnames[0]
						}
						
						// Extract SSL information
						sslInfo := ""
						certCN := ""
						isHTTPS := (port == 443 || port == 8443)
						if service.SSL != nil {
							// SSL information is available, extract CN if present
							if service.SSL.Cert.Subject.CN != "" {
								certCN = service.SSL.Cert.Subject.CN
								sslInfo = fmt.Sprintf("CN: %s", certCN)
							}
						}
						
						// Extract OS information
						osInfo := ""
						if host.OS != nil {
							osInfo = *host.OS
						}
						
						// Security assessment
						securityIssues := assessSecurityIssues(port, product, version, banner, hostname)
						
						mutex.Lock()
						results = append(results, models.ShodanCensysResult{
							IP:              ipAddr,
							Port:            port,
							Service:         product,
							Banner:          banner,
							Version:         version,
							Source:          "shodan",
							Hostname:        hostname,
							SSLInfo:         sslInfo,
							Product:         product,
							OS:              osInfo,
							SecurityIssues:  securityIssues,
							IsHTTPS:         isHTTPS,
							CertificateCN:   certCN,
						})
						mutex.Unlock()
					}
				} else {
					// No services found for this IP (this is normal for some IPs)
					fmt.Printf("[INFO] Shodan: No services found for IP %s (IP may not be in Shodan database or has no open ports)\n", ipAddr)
				}
			}(ip)
		}

		// Censys API (Basic Auth with API ID + Secret)
		// Note: If censysToken contains a token, try Bearer auth first, then fall back to Basic Auth
		if censysToken != "" {
			wg.Add(1)
			go func(ipAddr string) {
				defer wg.Done()
				censysURL := fmt.Sprintf("https://search.censys.io/api/v2/hosts/%s", ipAddr)
				req, err := http.NewRequest("GET", censysURL, nil)
				if err != nil {
					return
				}

			// Censys API supports both Bearer token and Basic Auth (API ID + Secret)
			// Try Bearer token first, then fall back to Basic Auth if needed
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", censysToken))
			req.Header.Set("User-Agent", "Cyber-OSINT-Recon/1.0")
			req.Header.Set("Accept", "application/json")
			resp, err := httpClientEnhanced.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			// If Bearer auth fails with 401, try Basic Auth (API ID:Secret format)
			if resp.StatusCode == http.StatusUnauthorized {
				resp.Body.Close()
				// Check if token contains colon (API ID:Secret format)
				if strings.Contains(censysToken, ":") {
					parts := strings.SplitN(censysToken, ":", 2)
					if len(parts) == 2 {
						// Use Basic Auth with API ID and Secret
						req, err = http.NewRequest("GET", censysURL, nil)
						if err != nil {
							return
						}
						req.SetBasicAuth(parts[0], parts[1])
						req.Header.Set("User-Agent", "Cyber-OSINT-Recon/1.0")
						req.Header.Set("Accept", "application/json")
						resp, err = httpClientEnhanced.Do(req)
						if err != nil {
							return
						}
						defer resp.Body.Close()
					}
				} else {
					// Token format doesn't support Basic Auth fallback
					return
				}
			}

				bodyBytes, err := io.ReadAll(resp.Body)
				if err != nil {
					return
				}
				if resp.StatusCode == http.StatusOK {
					var data map[string]interface{}
					if err := json.Unmarshal(bodyBytes, &data); err == nil {
						if result, ok := data["result"].(map[string]interface{}); ok {
							if services, ok := result["services"].([]interface{}); ok {
								for _, svc := range services {
									if svcMap, ok := svc.(map[string]interface{}); ok {
										port := 0
										if portFloat, ok := svcMap["port"].(float64); ok {
											port = int(portFloat)
										}
										serviceName := ""
										if s, ok := svcMap["service_name"].(string); ok {
											serviceName = s
										}

										mutex.Lock()
										results = append(results, models.ShodanCensysResult{
											IP:      ipAddr,
											Port:    port,
											Service: serviceName,
											Source:  "censys",
										})
										mutex.Unlock()
									}
								}
							}
						}
					}
				}
			}(ip)
		}
	}

	// Censys domain search using dns.names filter
	if censysToken != "" && domain != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fmt.Printf("[*] Censys: Searching for dns.names:%s...\n", domain)
			// Use Censys search API with dns.names filter
			query := fmt.Sprintf("dns.names:%s", domain)
			censysSearchURL := fmt.Sprintf("https://search.censys.io/api/v2/hosts/search?q=%s", url.QueryEscape(query))
			
			req, err := http.NewRequest("GET", censysSearchURL, nil)
			if err != nil {
				return
			}
		// Try Bearer token first
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", censysToken))
		req.Header.Set("User-Agent", "Cyber-OSINT-Recon/1.0")
		req.Header.Set("Accept", "application/json")
		
		resp, err := httpClientEnhanced.Do(req)
		if err != nil {
			fmt.Printf("[!] Censys domain search error: %v\n", err)
			return
		}
		defer resp.Body.Close()
		
		// If Bearer auth fails, try Basic Auth (API ID:Secret format)
		if resp.StatusCode == http.StatusUnauthorized {
			if strings.Contains(censysToken, ":") {
				parts := strings.SplitN(censysToken, ":", 2)
				if len(parts) == 2 {
					resp.Body.Close()
					req, err = http.NewRequest("GET", censysSearchURL, nil)
					if err != nil {
						fmt.Printf("[!] Censys domain search error: Invalid API key or unauthorized access\n")
						return
					}
					req.SetBasicAuth(parts[0], parts[1])
					req.Header.Set("User-Agent", "Cyber-OSINT-Recon/1.0")
					req.Header.Set("Accept", "application/json")
					resp, err = httpClientEnhanced.Do(req)
					if err != nil {
						fmt.Printf("[!] Censys domain search error: %v\n", err)
						return
					}
					defer resp.Body.Close()
				}
			}
			
			if resp.StatusCode == http.StatusUnauthorized {
				fmt.Printf("[!] Censys domain search error: Invalid API key or unauthorized access\n")
				return
			}
		}
		
		if resp.StatusCode != http.StatusOK {
			fmt.Printf("[!] Censys domain search error: HTTP %d\n", resp.StatusCode)
			return
		}
			
			bodyBytes, err := io.ReadAll(resp.Body)
			if err != nil {
				return
			}
			
			var searchResult struct {
				Result struct {
					Hits []struct {
						IP      string `json:"ip"`
						Services []struct {
							Port        int    `json:"port"`
							ServiceName string `json:"service_name"`
						} `json:"services"`
					} `json:"hits"`
					Total int `json:"total"`
				} `json:"result"`
			}
			
			if err := json.Unmarshal(bodyBytes, &searchResult); err == nil {
				if len(searchResult.Result.Hits) > 0 {
					fmt.Printf("[+] Censys: Found %d result(s) for dns.names:%s\n", len(searchResult.Result.Hits), domain)
					for _, hit := range searchResult.Result.Hits {
						for _, svc := range hit.Services {
							mutex.Lock()
							results = append(results, models.ShodanCensysResult{
								IP:      hit.IP,
								Port:    svc.Port,
								Service: svc.ServiceName,
								Source:  "censys",
							})
							mutex.Unlock()
						}
					}
				} else {
					fmt.Printf("[INFO] Censys: No results found for dns.names:%s\n", domain)
				}
			}
		}()
	}

	wg.Wait()
	return results, nil
}

// performShodanSearch performs a Shodan search with detailed result extraction
func performShodanSearch(shodanKey, query, domain string, mutex *sync.Mutex, results *[]models.ShodanCensysResult) []models.ShodanCensysResult {
	var searchResults []models.ShodanCensysResult
	
	shodanURL := fmt.Sprintf("https://api.shodan.io/shodan/host/search?key=%s&query=%s", shodanKey, url.QueryEscape(query))
	
	req, err := http.NewRequest("GET", shodanURL, nil)
	if err != nil {
		return searchResults
	}
	req.Header.Set("User-Agent", "Cyber-OSINT-Recon/1.0")
	
	resp, err := httpClientEnhanced.Do(req)
	if err != nil {
		return searchResults
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return searchResults
	}
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return searchResults
	}
	
	var searchResult struct {
		Matches []struct {
			IP        string   `json:"ip_str"`
			Port      int      `json:"port"`
			Product   string   `json:"product"`
			Data      string   `json:"data"`
			Hostnames []string `json:"hostnames"`
			SSL       struct {
				Cert struct {
					Subject struct {
						CN string `json:"cn"`
					} `json:"subject"`
				} `json:"cert"`
			} `json:"ssl"`
			Version   string `json:"version"`
			OS        string `json:"os"`
		} `json:"matches"`
		Total int `json:"total"`
	}
	
	if err := json.Unmarshal(body, &searchResult); err != nil {
		return searchResults
	}
	
	for _, match := range searchResult.Matches {
		hostname := ""
		if len(match.Hostnames) > 0 {
			hostname = match.Hostnames[0]
		}
		
		version := match.Version
		if version == "" {
			version = extractVersionFromBanner(match.Data, match.Product)
		}
		
		securityIssues := assessSecurityIssues(match.Port, match.Product, version, match.Data, hostname)
		
		result := models.ShodanCensysResult{
			IP:             match.IP,
			Port:           match.Port,
			Service:        match.Product,
			Banner:         match.Data,
			Version:        version,
			Source:         "shodan",
			Hostname:       hostname,
			Product:        match.Product,
			OS:             match.OS,
			SecurityIssues: securityIssues,
			IsHTTPS:        (match.Port == 443 || match.Port == 8443),
			CertificateCN:  match.SSL.Cert.Subject.CN,
		}
		
		if match.SSL.Cert.Subject.CN != "" {
			result.SSLInfo = fmt.Sprintf("CN: %s", match.SSL.Cert.Subject.CN)
		}
		
		searchResults = append(searchResults, result)
		
		mutex.Lock()
		*results = append(*results, result)
		mutex.Unlock()
	}
	
	return searchResults
}

// extractVersionFromBanner extracts product version from banner text
func extractVersionFromBanner(banner, product string) string {
	if banner == "" {
		return ""
	}
	
	// Common version patterns
	versionPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)(?:version|v|ver)[\s:]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)`),
		regexp.MustCompile(`(?i)([0-9]+\.[0-9]+\.[0-9]+)`),
		regexp.MustCompile(`(?i)(Apache[/\s]+[0-9]+\.[0-9]+)`),
		regexp.MustCompile(`(?i)(nginx[/\s]+[0-9]+\.[0-9]+)`),
		regexp.MustCompile(`(?i)(IIS[/\s]+[0-9]+\.[0-9]+)`),
		regexp.MustCompile(`(?i)(OpenSSH[_\s]+[0-9]+\.[0-9]+)`),
	}
	
	for _, pattern := range versionPatterns {
		matches := pattern.FindStringSubmatch(banner)
		if len(matches) > 1 {
			return strings.TrimSpace(matches[1])
		}
	}
	
	return ""
}

// assessSecurityIssues performs security assessment on discovered services
func assessSecurityIssues(port int, product, version, banner, hostname string) []string {
	var issues []string
	
	// Check for admin/management interfaces on common ports
	if port == 443 || port == 80 || port == 8080 || port == 8443 {
		bannerLower := strings.ToLower(banner)
		hostnameLower := strings.ToLower(hostname)
		
		// Admin page detection
		adminKeywords := []string{"admin", "management", "manager", "console", "control", "dashboard", "panel"}
		for _, keyword := range adminKeywords {
			if strings.Contains(bannerLower, keyword) || strings.Contains(hostnameLower, keyword) {
				issues = append(issues, fmt.Sprintf("Potential admin/management interface detected on port %d", port))
				break
			}
		}
		
		// Apache version check
		if strings.Contains(strings.ToLower(product), "apache") || strings.Contains(bannerLower, "apache") {
			if version != "" {
				// Check for old Apache versions
				if strings.HasPrefix(version, "2.2") || strings.HasPrefix(version, "2.0") || strings.HasPrefix(version, "1.") {
					issues = append(issues, fmt.Sprintf("Outdated Apache version detected: %s (potential security risk)", version))
				}
			}
			// Check for server-status or server-info exposure
			if strings.Contains(bannerLower, "server-status") || strings.Contains(bannerLower, "server-info") {
				issues = append(issues, "Apache server-status or server-info page may be exposed")
			}
		}
		
		// Check for default credentials or weak configurations
		if strings.Contains(bannerLower, "default") && (strings.Contains(bannerLower, "password") || strings.Contains(bannerLower, "login")) {
			issues = append(issues, "Potential default credentials or weak authentication detected")
		}
	}
	
	// Check for exposed database ports
	if port == 3306 || port == 5432 || port == 1433 || port == 27017 {
		issues = append(issues, fmt.Sprintf("Database service exposed on port %d (verify access controls)", port))
	}
	
	// Check for exposed RDP/SSH/VNC
	if port == 3389 {
		issues = append(issues, "RDP (Remote Desktop) service exposed (verify access controls and authentication)")
	}
	if port == 22 {
		// Check SSH version
		if strings.Contains(strings.ToLower(banner), "openssh") {
			if version != "" && (strings.HasPrefix(version, "6.") || strings.HasPrefix(version, "5.") || strings.HasPrefix(version, "4.")) {
				issues = append(issues, fmt.Sprintf("Outdated OpenSSH version detected: %s", version))
			}
		}
	}
	if port == 5900 || port == 5901 {
		issues = append(issues, "VNC service exposed (verify access controls and authentication)")
	}
	
	// Check for exposed FTP
	if port == 21 {
		issues = append(issues, "FTP service exposed (verify encryption and access controls)")
	}
	
	// Check for exposed SMB
	if port == 445 || port == 139 {
		issues = append(issues, "SMB service exposed (verify access controls and encryption)")
	}
	
	return issues
}

// PerformShodanPivotFromDNSDumpster performs Shodan pivot using IP addresses extracted from dnsdumpster.com
func PerformShodanPivotFromDNSDumpster(domain string, shodanKey string) ([]models.ShodanCensysResult, error) {
	var results []models.ShodanCensysResult

	if shodanKey == "" {
		return results, fmt.Errorf("Shodan API key is required for pivot")
	}

	// Collect data from dnsdumpster.com
	fmt.Printf("[*] Collecting data from dnsdumpster.com for Shodan pivot...\n")
	dnsdumpsterData, err := CollectDNSDumpsterData(domain)
	if err != nil {
		return results, fmt.Errorf("failed to collect dnsdumpster data: %w", err)
	}

	if len(dnsdumpsterData.IPAddresses) == 0 {
		fmt.Printf("[INFO] No IP addresses found from dnsdumpster.com for Shodan pivot\n")
		return results, nil
	}

	fmt.Printf("[+] Found %d IP address(es) from dnsdumpster.com\n", len(dnsdumpsterData.IPAddresses))
	fmt.Printf("[*] Performing Shodan pivot on %d IP address(es)...\n", len(dnsdumpsterData.IPAddresses))

	// Perform Shodan scan on extracted IPs
	shodanResults, err := CollectShodanCensys(domain, dnsdumpsterData.IPAddresses, shodanKey, "", nil, "")
	if err != nil {
		return results, fmt.Errorf("failed to perform Shodan pivot: %w", err)
	}

	// Mark results as from dnsdumpster pivot
	for i := range shodanResults {
		shodanResults[i].Source = "shodan-dnsdumpster-pivot"
	}

	fmt.Printf("[+] Shodan pivot completed: Found %d result(s)\n", len(shodanResults))
	return shodanResults, nil
}

// CollectWebArchive Collects web archive information from Wayback Machine
// Searches for historical snapshots including deleted paths like /admin, /upload, etc.
func CollectWebArchive(domain string) ([]models.WebArchiveResult, error) {
	var results []models.WebArchiveResult
	var mutex sync.Mutex
	var wg sync.WaitGroup
	
	// Common paths to search for in web archive
	paths := []string{
		"/admin", "/administrator", "/admin.php", "/admin.html",
		"/upload", "/uploads", "/upload.php",
		"/login", "/login.php", "/login.html", "/signin",
		"/config", "/config.php", "/config.json",
		"/backup", "/backups", "/backup.sql",
		"/test", "/test.php", "/testing",
		"/api", "/api.php", "/api.json",
		"/.env", "/.git", "/.svn",
		"/wp-admin", "/wp-login.php",
		"/phpmyadmin", "/phpinfo.php",
	}
	
	// Search for domain root and common paths
	searchURLs := []string{
		fmt.Sprintf("%s/*", domain),
	}
	
	// Add path-specific searches
	for _, path := range paths {
		searchURLs = append(searchURLs, fmt.Sprintf("%s%s", domain, path))
	}
	
	// Search each URL pattern
	for _, searchURL := range searchURLs {
		wg.Add(1)
		go func(urlPattern string) {
			defer wg.Done()
			
			// Wayback Machine CDX API
			waybackURL := fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=%s&output=json&limit=50&collapse=urlkey", url.QueryEscape(urlPattern))
			
			body, err := fetchURLEnhanced(waybackURL)
			if err != nil {
				return
			}
			
			var data [][]string
			if err := json.Unmarshal([]byte(body), &data); err != nil || len(data) <= 1 {
				return
			}
			
			for i, row := range data {
				if i == 0 { // Skip header
					continue
				}
				if len(row) >= 3 {
					timestamp := row[1]
					originalURL := row[2]
					
					// Parse timestamp
					var t time.Time
					if len(timestamp) >= 14 {
						year, _ := strconv.Atoi(timestamp[0:4])
						month, _ := strconv.Atoi(timestamp[4:6])
						day, _ := strconv.Atoi(timestamp[6:8])
						hour, _ := strconv.Atoi(timestamp[8:10])
						min, _ := strconv.Atoi(timestamp[10:12])
						sec, _ := strconv.Atoi(timestamp[12:14])
						t = time.Date(year, time.Month(month), day, hour, min, sec, 0, time.UTC)
					}
					
					snapshotURL := fmt.Sprintf("http://web.archive.org/web/%s/%s", timestamp, originalURL)
					
					// Determine type based on URL pattern
					archiveType := ""
					urlLower := strings.ToLower(originalURL)
					if strings.Contains(urlLower, "login") || strings.Contains(urlLower, "signin") {
						archiveType = "login_page"
					} else if strings.Contains(urlLower, ".js") {
						archiveType = "js_file"
					} else if strings.Contains(urlLower, "admin") || strings.Contains(urlLower, "administrator") {
						archiveType = "admin_page"
					} else if strings.Contains(urlLower, "upload") {
						archiveType = "upload_page"
					} else if strings.Contains(urlLower, "config") || strings.Contains(urlLower, ".env") {
						archiveType = "config_file"
					} else if strings.Contains(urlLower, "backup") {
						archiveType = "backup_file"
					} else if strings.Contains(urlLower, "api") {
						archiveType = "api_endpoint"
					}
					
					// Fetch first few lines of content for analysis
					content := ""
					if archiveType == "js_file" || archiveType == "config_file" {
						// Try to fetch content preview
						contentResp, err := httpClientEnhanced.Get(snapshotURL)
						if err == nil {
							defer contentResp.Body.Close()
							if contentResp.StatusCode == http.StatusOK {
								contentBytes, _ := io.ReadAll(io.LimitReader(contentResp.Body, 500))
								content = string(contentBytes)
							}
						}
					}
					
					mutex.Lock()
					results = append(results, models.WebArchiveResult{
						URL:         originalURL,
						Timestamp:   t,
						SnapshotURL: snapshotURL,
						Type:        archiveType,
						Content:     content,
					})
					mutex.Unlock()
				}
			}
		}(searchURL)
	}
	
	wg.Wait()
	return results, nil
}

// CollectGrepAppCodeSearch Searches for code traces using grep.app (emails, API keys, hardcoded keywords)
func CollectGrepAppCodeSearch(domain, company string) ([]models.GitHubCodeTraceResult, error) {
	var results []models.GitHubCodeTraceResult
	var mutex sync.Mutex
	var wg sync.WaitGroup
	
	searchTerms := []string{}
	if domain != "" {
		searchTerms = append(searchTerms, domain)
	}
	if company != "" {
		searchTerms = append(searchTerms, company)
	}
	
	if len(searchTerms) == 0 {
		return results, nil
	}
	
	// Search patterns for grep.app
	searchPatterns := []struct {
		pattern string
		typ     string
	}{
		{fmt.Sprintf("%s", domain), "domain_reference"},
		{fmt.Sprintf("@%s", domain), "email"},
		{fmt.Sprintf("api_key.*%s", domain), "api_key"},
		{fmt.Sprintf("apikey.*%s", domain), "api_key"},
		{fmt.Sprintf("secret.*%s", domain), "secret"},
		{fmt.Sprintf("password.*%s", domain), "password"},
		{fmt.Sprintf("%s.*login", domain), "login_page"},
		{fmt.Sprintf("%s.*admin", domain), "admin_page"},
		{fmt.Sprintf("https?://%s", domain), "internal_url"},
	}
	
	for _, term := range searchTerms {
		for _, pattern := range searchPatterns {
			wg.Add(1)
			go func(searchTerm string, searchPattern struct {
				pattern string
				typ     string
			}) {
				defer wg.Done()
				
				// grep.app search API (using web scraping as API may not be public)
				grepURL := fmt.Sprintf("https://grep.app/search?q=%s", url.QueryEscape(searchPattern.pattern))
				
				req, err := http.NewRequest("GET", grepURL, nil)
				if err != nil {
					return
				}
				req.Header.Set("User-Agent", "Cyber-OSINT-Recon/1.0")
				req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
				
				resp, err := httpClientEnhanced.Do(req)
				if err != nil {
					return
				}
				defer resp.Body.Close()
				
				if resp.StatusCode != http.StatusOK {
					return
				}
				
				// Parse HTML response to extract repository information
				doc, err := goquery.NewDocumentFromReader(resp.Body)
				if err != nil {
					return
				}
				
				// Extract repository links and code snippets
				doc.Find("a[href*='github.com']").Each(func(i int, s *goquery.Selection) {
					href, exists := s.Attr("href")
					if !exists {
						return
					}
					
					// Check if it's a GitHub repository link
					if strings.Contains(href, "github.com") {
						// Extract repository and file information
						parts := strings.Split(href, "/")
						if len(parts) >= 5 {
							repository := fmt.Sprintf("%s/%s", parts[3], parts[4])
							file := ""
							if len(parts) > 5 {
								file = strings.Join(parts[5:], "/")
							}
							
							// Extract line number if present
							line := 0
							if hashIndex := strings.Index(file, "#L"); hashIndex != -1 {
								lineStr := file[hashIndex+2:]
								if lineEnd := strings.Index(lineStr, "-"); lineEnd != -1 {
									lineStr = lineStr[:lineEnd]
								}
								line, _ = strconv.Atoi(lineStr)
								file = file[:hashIndex]
							}
							
							// Get code snippet
							codeSnippet := s.Parent().Text()
							if len(codeSnippet) > 200 {
								codeSnippet = codeSnippet[:200] + "..."
							}
							
							mutex.Lock()
							results = append(results, models.GitHubCodeTraceResult{
								Repository: repository,
								File:       file,
								URL:        fmt.Sprintf("https://github.com%s", href),
								Line:       line,
								Content:    codeSnippet,
								Type:       searchPattern.typ,
							})
							mutex.Unlock()
						}
					}
				})
			}(term, pattern)
		}
	}
	
	wg.Wait()
	return results, nil
}

// CollectGitHubCodeTrace Collects code traces from GitHub (emails, API keys, old login pages, hardcoded keywords)
func CollectGitHubCodeTrace(domain, company string) ([]models.GitHubCodeTraceResult, error) {
	var results []models.GitHubCodeTraceResult
	var mutex sync.Mutex
	var wg sync.WaitGroup
	
	searchTerms := []string{}
	if domain != "" {
		searchTerms = append(searchTerms, domain)
	}
	if company != "" {
		searchTerms = append(searchTerms, company)
	}
	
	// Keywords to search for
	keywords := []struct {
		keyword string
		typ     string
	}{
		{"email", "email"},
		{"api_key", "api_key"},
		{"apiKey", "api_key"},
		{"password", "password"},
		{"secret", "secret"},
		{"login", "old_login"},
		{"hardcoded", "js_hardcoded"},
	}
	
	for _, term := range searchTerms {
		for _, kw := range keywords {
			wg.Add(1)
			go func(searchTerm, keyword, resultType string) {
				defer wg.Done()
				
				// GitHub code search (limited without API)
				searchURL := fmt.Sprintf("https://github.com/search?q=%s+%s&type=code", 
					url.QueryEscape(searchTerm), url.QueryEscape(keyword))
				
				body, err := fetchURLEnhanced(searchURL)
				if err == nil {
					doc, err := goquery.NewDocumentFromReader(strings.NewReader(body))
					if err == nil {
						doc.Find("div.code-list-item").Each(func(i int, s *goquery.Selection) {
							if i < 3 { // Limit to 3 results per keyword
								repoLink, _ := s.Find("a").First().Attr("href")
								fileLink, _ := s.Find("a").Eq(1).Attr("href")
								codeText := strings.TrimSpace(s.Find("td.blob-code").Text())
								
								if repoLink != "" && fileLink != "" {
									repoParts := strings.Split(strings.TrimPrefix(repoLink, "/"), "/")
									if len(repoParts) >= 2 {
										fileParts := strings.Split(strings.TrimPrefix(fileLink, repoLink+"/blob/"), "/")
										fileName := ""
										if len(fileParts) > 0 {
											fileName = fileParts[len(fileParts)-1]
										}
										
										mutex.Lock()
										results = append(results, models.GitHubCodeTraceResult{
											Repository: repoLink,
											File:       fileName,
											URL:        "https://github.com" + fileLink,
											Content:    codeText[:min(200, len(codeText))], // First 200 chars
											Type:       resultType,
										})
										mutex.Unlock()
									}
								}
							}
						})
					}
				}
			}(term, kw.keyword, kw.typ)
		}
	}
	
	wg.Wait()
	
	return results, nil
}

// CollectEmployeeProfiles Collects employee profiles using sherlock/whatsmyname approach
func CollectEmployeeProfiles(company, domain string) ([]models.EmployeeProfile, error) {
	var profiles []models.EmployeeProfile
	var mutex sync.Mutex
	var wg sync.WaitGroup
	
	// Generate potential usernames
	usernames := []string{}
	if company != "" {
		cleanCompany := strings.ToLower(strings.ReplaceAll(company, " ", ""))
		usernames = append(usernames, cleanCompany, company)
	}
	if domain != "" {
		domainParts := strings.Split(domain, ".")
		if len(domainParts) > 0 {
			usernames = append(usernames, domainParts[0])
		}
	}
	
	// Common platforms (similar to sherlock/whatsmyname)
	platforms := map[string]func(string) string{
		"LinkedIn": func(u string) string { return fmt.Sprintf("https://www.linkedin.com/in/%s", u) },
		"GitHub":   func(u string) string { return fmt.Sprintf("https://github.com/%s", u) },
		"Twitter":  func(u string) string { return fmt.Sprintf("https://twitter.com/%s", u) },
		"Medium":   func(u string) string { return fmt.Sprintf("https://medium.com/@%s", u) },
	}
	
	for _, username := range usernames {
		for platform, urlFunc := range platforms {
			wg.Add(1)
			go func(uname, plat string, urlFn func(string) string) {
				defer wg.Done()
				
				profileURL := urlFn(uname)
				exists := checkURLExistsEnhanced(profileURL)
				
				if exists {
					mutex.Lock()
					profiles = append(profiles, models.EmployeeProfile{
						Username: uname,
						Platform: plat,
						URL:      profileURL,
						Company:  company,
					})
					mutex.Unlock()
				}
			}(username, platform, urlFunc)
		}
	}
	
	wg.Wait()
	
	return profiles, nil
}

// CollectCorporateInfoLegacy Collects corporate information from Crunchbase/OpenCorporates (legacy function, use corporate.go instead)
func CollectCorporateInfoLegacy(company string) (*models.CorporateInfo, error) {
	info := &models.CorporateInfo{}
	
	if company == "" {
		return info, nil
	}
	
	// Crunchbase scraping (limited without API)
	crunchbaseURL := fmt.Sprintf("https://www.crunchbase.com/organization/%s", 
		strings.ToLower(strings.ReplaceAll(company, " ", "-")))
	
	body, err := fetchURLEnhanced(crunchbaseURL)
	if err == nil {
		doc, err := goquery.NewDocumentFromReader(strings.NewReader(body))
		if err == nil {
			info.Source = "crunchbase"
			
			// Extract subsidiaries
			doc.Find("a[href*='/organization/']").Each(func(i int, s *goquery.Selection) {
				href, _ := s.Attr("href")
				if strings.Contains(href, "/organization/") {
					org := strings.TrimPrefix(href, "/organization/")
					if org != "" && org != strings.ToLower(strings.ReplaceAll(company, " ", "-")) {
						info.Subsidiaries = append(info.Subsidiaries, org)
					}
				}
			})
			
			// Extract employee count
			doc.Find("span.field-type").Each(func(i int, s *goquery.Selection) {
				text := strings.ToLower(s.Text())
				if strings.Contains(text, "employees") {
					employees := strings.TrimSpace(s.Next().Text())
					if info.Employees == "" {
						info.Employees = employees
					}
				}
			})
		}
	}
	
	// OpenCorporates (would require API key for full access)
	// Placeholder structure
	if info.Source == "" {
		info.Source = "opencorporates"
	}
	
	return info, nil
}

// CollectVirusTotal Collects VirusTotal verification results using official vt-go library (v3 API)
func CollectVirusTotal(domain string, ipAddresses []string, apiKey string) ([]models.VirusTotalResult, error) {
	var results []models.VirusTotalResult

	if apiKey == "" {
		// No API key provided, skip
		return results, nil
	}

	// Initialize VirusTotal client
	client := vt.NewClient(apiKey)

	var wg sync.WaitGroup
	var mutex sync.Mutex

	// Check domain
	if domain != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			obj, err := client.GetObject(vt.URL("domains/%s", domain))
			if err == nil && obj != nil {
				// Extract last analysis stats
				lastAnalysisStats, err := obj.Get("last_analysis_stats")
				if err == nil {
					if statsMap, ok := lastAnalysisStats.(map[string]interface{}); ok {
						positives := 0
						total := 0
						if p, ok := statsMap["malicious"].(float64); ok {
							positives = int(p)
						}
						if t, ok := statsMap["harmless"].(float64); ok {
							total += int(t)
						}
						if t, ok := statsMap["suspicious"].(float64); ok {
							total += int(t)
						}
						if t, ok := statsMap["malicious"].(float64); ok {
							total += int(t)
						}
						if t, ok := statsMap["undetected"].(float64); ok {
							total += int(t)
						}

						permalink := ""
						if links, err := obj.Get("links"); err == nil {
							if linksMap, ok := links.(map[string]interface{}); ok {
								if p, ok := linksMap["self"].(string); ok {
									permalink = p
								}
							}
						}

						mutex.Lock()
						results = append(results, models.VirusTotalResult{
							Resource:  domain,
							Type:      "domain",
							Positives: positives,
							Total:     total,
							Permalink: permalink,
						})
						mutex.Unlock()
					}
				}
			}
		}()
	}

	// Check IP addresses (with rate limiting - max 4 per minute for free tier)
	for i, ip := range ipAddresses {
		if i >= 4 { // Limit to 4 IPs per scan for free tier
			break
		}
		wg.Add(1)
		go func(ipAddr string, delay int) {
			defer wg.Done()
			time.Sleep(time.Duration(delay) * 15 * time.Second) // Rate limiting: 15 seconds between requests
			obj, err := client.GetObject(vt.URL("ip_addresses/%s", ipAddr))
			if err == nil && obj != nil {
				// Extract last analysis stats
				lastAnalysisStats, err := obj.Get("last_analysis_stats")
				if err == nil {
					if statsMap, ok := lastAnalysisStats.(map[string]interface{}); ok {
						positives := 0
						total := 0
						if p, ok := statsMap["malicious"].(float64); ok {
							positives = int(p)
						}
						if t, ok := statsMap["harmless"].(float64); ok {
							total += int(t)
						}
						if t, ok := statsMap["suspicious"].(float64); ok {
							total += int(t)
						}
						if t, ok := statsMap["malicious"].(float64); ok {
							total += int(t)
						}
						if t, ok := statsMap["undetected"].(float64); ok {
							total += int(t)
						}

						permalink := ""
						if links, err := obj.Get("links"); err == nil {
							if linksMap, ok := links.(map[string]interface{}); ok {
								if p, ok := linksMap["self"].(string); ok {
									permalink = p
								}
							}
						}

						mutex.Lock()
						results = append(results, models.VirusTotalResult{
							Resource:  ipAddr,
							Type:      "ip",
							Positives: positives,
							Total:     total,
							Permalink: permalink,
						})
						mutex.Unlock()
					}
				}
			}
		}(ip, i)
	}

	wg.Wait()
	return results, nil
}

// Helper function
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
