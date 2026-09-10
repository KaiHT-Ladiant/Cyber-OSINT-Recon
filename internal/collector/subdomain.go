package collector

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
)

// CommonSubdomains 일반적인 서브도메인 목록
var CommonSubdomains = []string{
	"www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
	"ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test",
	"ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn",
	"ns3", "mail2", "new", "mysql", "old", "lists", "support", "mobile", "mx",
	"static", "docs", "beta", "shop", "sql", "secure", "demo", "cp", "calendar",
	"wiki", "web", "media", "email", "images", "img", "www1", "intranet",
	"portal", "video", "sip", "dns2", "api", "cdn", "stats", "dns1", "ns4",
	"www3", "dns", "search", "staging", "server", "mx1", "chat", "wap", "my",
	"svn", "mail1", "sites", "proxy", "ads", "host", "crm", "cms", "backup",
	"mx2", "lyncdiscover", "info", "apps", "download", "remote", "db", "forums",
	"store", "relay", "files", "newsletter", "app", "live", "owa", "en",
	"start", "sms", "office", "exchange", "ipv4", "api2", "admin2", "wms",
	"edm", "smtp2", "smtp1", "vip", "test1", "mysql2", "mail3", "dns3", "dl",
	"cdn2", "img2", "img1", "crm2", "db1", "db2", "smtp3", "mail4", "mx3",
	"mx4", "monitor", "mssql", "help", "smtp4", "ftp2", "ftp1", "vpn2", "office2",
	"office1", "sql2", "sql1", "db3", "db4", "int", "int2", "ts", "ts2", "ts1",
	"ts3", "ts4", "qa", "qa1", "qa2", "qa3", "qa4", "prod", "prod1", "prod2",
	"prod3", "prod4", "dev1", "dev2", "dev3", "dev4", "stg", "stg1", "stg2",
	"stg3", "stg4", "uat", "uat1", "uat2", "uat3", "uat4",
}

// DiscoverSubdomains 서브도메인 발견
func DiscoverSubdomains(domain string, wordlist []string, workers int) []string {
	if wordlist == nil {
		wordlist = CommonSubdomains
	}

	var discovered []string
	var mutex sync.Mutex
	var wg sync.WaitGroup

	// 워커 풀 생성
	jobs := make(chan string, len(wordlist))
	
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for subdomain := range jobs {
				fullDomain := subdomain + "." + domain
				if checkSubdomain(fullDomain) {
					mutex.Lock()
					discovered = append(discovered, fullDomain)
					mutex.Unlock()
				}
			}
		}()
	}

	// 작업 전송
	for _, subdomain := range wordlist {
		jobs <- subdomain
	}
	close(jobs)

	wg.Wait()
	return discovered
}

// checkSubdomain 서브도메인 존재 여부 확인
func checkSubdomain(subdomain string) bool {
	// DNS 조회로 확인
	_, err := net.LookupHost(subdomain)
	return err == nil
}

// LoadWordlistFromFile 파일에서 단어 목록 로드
func LoadWordlistFromFile(filename string) ([]string, error) {
	var wordlist []string
	// 구현은 파일 읽기로 대체 가능
	return wordlist, fmt.Errorf("파일 로드 기능은 추후 구현 예정")
}

// BruteForceSubdomain 브루트포스 방식으로 서브도메인 발견
func BruteForceSubdomain(domain string, chars string, maxLen int) []string {
	var discovered []string
	
	// 간단한 브루트포스 (예: a.example.com, b.example.com, ...)
	if maxLen <= 0 {
		maxLen = 3
	}
	
	generateStrings(domain, chars, maxLen, "", &discovered)
	return discovered
}

func generateStrings(domain, chars string, maxLen int, current string, discovered *[]string) {
	if len(current) >= maxLen {
		subdomain := current + "." + domain
		if checkSubdomain(subdomain) {
			*discovered = append(*discovered, subdomain)
		}
		return
	}

	for _, char := range chars {
		generateStrings(domain, chars, maxLen, current+string(char), discovered)
	}
}

// httpClientSubdomain HTTP client for subdomain discovery
var httpClientSubdomain = &http.Client{
	Timeout: 30 * time.Second,
}

// EnumerateFromCert 인증서에서 서브도메인 목록 추출 (crt.sh 사용)
func EnumerateFromCert(domain string) []string {
	var subdomains []string
	var mutex sync.Mutex
	var wg sync.WaitGroup

	// crt.sh API를 사용하여 인증서에서 서브도메인 추출
	wg.Add(1)
	go func() {
		defer wg.Done()
		fmt.Printf("🔍 Searching subdomains from crt.sh for %s...\n", domain)
		crtSubdomains := searchCrtSh(domain)
		if len(crtSubdomains) > 0 {
			mutex.Lock()
			subdomains = append(subdomains, crtSubdomains...)
			mutex.Unlock()
			fmt.Printf("[+] crt.sh: Found %d subdomain(s)\n", len(crtSubdomains))
		}
	}()

	// dnsdumpster.com을 사용하여 서브도메인 검색
	wg.Add(1)
	go func() {
		defer wg.Done()
		fmt.Printf("🔍 Searching subdomains from dnsdumpster.com for %s...\n", domain)
		dnsdumpsterSubdomains := searchDNSDumpster(domain)
		if len(dnsdumpsterSubdomains) > 0 {
			mutex.Lock()
			subdomains = append(subdomains, dnsdumpsterSubdomains...)
			mutex.Unlock()
			fmt.Printf("[+] dnsdumpster.com: Found %d subdomain(s)\n", len(dnsdumpsterSubdomains))
		}
	}()

	wg.Wait()

	// 중복 제거
	uniqueSubdomains := make(map[string]bool)
	var result []string
	for _, subdomain := range subdomains {
		subdomain = strings.ToLower(strings.TrimSpace(subdomain))
		if subdomain != "" && !uniqueSubdomains[subdomain] {
			uniqueSubdomains[subdomain] = true
			result = append(result, subdomain)
		}
	}

	return result
}

// searchCrtSh crt.sh API를 사용하여 서브도메인 검색
func searchCrtSh(domain string) []string {
	var subdomains []string

	// crt.sh API: https://crt.sh/?q=%25.domain&output=json
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return subdomains
	}
	req.Header.Set("User-Agent", "Cyber-OSINT-Recon/1.0")
	req.Header.Set("Accept", "application/json")

	resp, err := httpClientSubdomain.Do(req)
	if err != nil {
		return subdomains
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return subdomains
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return subdomains
	}

	// Parse JSON response
	var certs []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.Unmarshal(body, &certs); err != nil {
		return subdomains
	}

	// Extract unique subdomains
	seen := make(map[string]bool)
	for _, cert := range certs {
		if cert.NameValue == "" {
			continue
		}
		// Split by newline and comma (crt.sh returns multiple domains per line)
		names := strings.FieldsFunc(cert.NameValue, func(c rune) bool {
			return c == '\n' || c == '\r' || c == ','
		})
		for _, name := range names {
			name = strings.ToLower(strings.TrimSpace(name))
			// Remove wildcard prefix
			if strings.HasPrefix(name, "*.") {
				name = name[2:]
			}
			// Only include subdomains of the target domain
			if strings.HasSuffix(name, "."+domain) || name == domain {
				if !seen[name] {
					seen[name] = true
					subdomains = append(subdomains, name)
				}
			}
		}
	}

	return subdomains
}

// searchDNSDumpster dnsdumpster.com을 사용하여 서브도메인 검색
func searchDNSDumpster(domain string) []string {
	var subdomains []string

	// dnsdumpster.com은 CSRF 토큰이 필요하므로 직접 HTML 파싱
	url := fmt.Sprintf("https://dnsdumpster.com/", domain)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return subdomains
	}
	req.Header.Set("User-Agent", "Cyber-OSINT-Recon/1.0")

	resp, err := httpClientSubdomain.Do(req)
	if err != nil {
		return subdomains
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return subdomains
	}

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return subdomains
	}

	// CSRF 토큰 추출
	csrfToken, exists := doc.Find("input[name='csrfmiddlewaretoken']").Attr("value")
	if !exists {
		return subdomains
	}

	// POST 요청으로 도메인 검색
	postURL := "https://dnsdumpster.com/"
	postData := fmt.Sprintf("csrfmiddlewaretoken=%s&targetip=%s&user=free", csrfToken, domain)
	postReq, err := http.NewRequest("POST", postURL, strings.NewReader(postData))
	if err != nil {
		return subdomains
	}
	postReq.Header.Set("User-Agent", "Cyber-OSINT-Recon/1.0")
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postReq.Header.Set("Referer", url)

	// 쿠키 설정
	for _, cookie := range resp.Cookies() {
		postReq.AddCookie(cookie)
	}

	postResp, err := httpClientSubdomain.Do(postReq)
	if err != nil {
		return subdomains
	}
	defer postResp.Body.Close()

	if postResp.StatusCode != http.StatusOK {
		return subdomains
	}

	postDoc, err := goquery.NewDocumentFromReader(postResp.Body)
	if err != nil {
		return subdomains
	}

	// 서브도메인 추출 (테이블에서)
	seen := make(map[string]bool)
	postDoc.Find("td.col-md-4").Each(func(i int, s *goquery.Selection) {
		text := strings.TrimSpace(s.Text())
		if text != "" && (strings.HasSuffix(text, "."+domain) || text == domain) {
			text = strings.ToLower(text)
			if !seen[text] {
				seen[text] = true
				subdomains = append(subdomains, text)
			}
		}
	})

	// SVG 이미지에서 서브도메인 추출 (dnsdumpster는 SVG로 DNS 맵을 제공)
	postDoc.Find("svg text").Each(func(i int, s *goquery.Selection) {
		text := strings.TrimSpace(s.Text())
		if text != "" {
			// 도메인 패턴 매칭
			domainPattern := regexp.MustCompile(`([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+` + regexp.QuoteMeta(domain))
			matches := domainPattern.FindAllString(text, -1)
			for _, match := range matches {
				match = strings.ToLower(strings.TrimSpace(match))
				if (strings.HasSuffix(match, "."+domain) || match == domain) && !seen[match] {
					seen[match] = true
					subdomains = append(subdomains, match)
				}
			}
		}
	})

	return subdomains
}

// 서브도메인 리스트를 스캐너로 읽기
func readWordlistFromScanner(scanner *bufio.Scanner) []string {
	var wordlist []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			wordlist = append(wordlist, line)
		}
	}
	return wordlist
}

// DNSDumpsterData contains IP addresses and hostnames extracted from dnsdumpster.com
type DNSDumpsterData struct {
	IPAddresses []string
	Hostnames   []string
	Subdomains  []string
}

// CollectDNSDumpsterData extracts IP addresses, hostnames, and subdomains from dnsdumpster.com CSV and images
func CollectDNSDumpsterData(domain string) (*DNSDumpsterData, error) {
	data := &DNSDumpsterData{
		IPAddresses: []string{},
		Hostnames:   []string{},
		Subdomains:  []string{},
	}

	// Get initial page to get CSRF token
	url := "https://dnsdumpster.com/"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return data, err
	}
	req.Header.Set("User-Agent", "Cyber-OSINT-Recon/1.0")

	resp, err := httpClientSubdomain.Do(req)
	if err != nil {
		return data, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return data, fmt.Errorf("failed to access dnsdumpster.com: status %d", resp.StatusCode)
	}

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return data, err
	}

	// Extract CSRF token
	csrfToken, exists := doc.Find("input[name='csrfmiddlewaretoken']").Attr("value")
	if !exists {
		return data, fmt.Errorf("CSRF token not found")
	}

	// POST request to search domain
	postURL := "https://dnsdumpster.com/"
	postData := fmt.Sprintf("csrfmiddlewaretoken=%s&targetip=%s&user=free", csrfToken, domain)
	postReq, err := http.NewRequest("POST", postURL, strings.NewReader(postData))
	if err != nil {
		return data, err
	}
	postReq.Header.Set("User-Agent", "Cyber-OSINT-Recon/1.0")
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postReq.Header.Set("Referer", url)

	// Set cookies
	for _, cookie := range resp.Cookies() {
		postReq.AddCookie(cookie)
	}

	postResp, err := httpClientSubdomain.Do(postReq)
	if err != nil {
		return data, err
	}
	defer postResp.Body.Close()

	if postResp.StatusCode != http.StatusOK {
		return data, fmt.Errorf("failed to search domain: status %d", postResp.StatusCode)
	}

	postDoc, err := goquery.NewDocumentFromReader(postResp.Body)
	if err != nil {
		return data, err
	}

	// Extract subdomains from table
	seen := make(map[string]bool)
	ipPattern := regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`)

	// Extract from table cells
	postDoc.Find("td.col-md-4").Each(func(i int, s *goquery.Selection) {
		text := strings.TrimSpace(s.Text())
		if text != "" {
			// Check if it's a subdomain
			if strings.HasSuffix(text, "."+domain) || text == domain {
				text = strings.ToLower(text)
				if !seen[text] {
					seen[text] = true
					data.Subdomains = append(data.Subdomains, text)
					data.Hostnames = append(data.Hostnames, text)
				}
			}
			// Check if it's an IP address
			if ipPattern.MatchString(text) {
				ips := ipPattern.FindAllString(text, -1)
				for _, ip := range ips {
					if !seen[ip] {
						seen[ip] = true
						data.IPAddresses = append(data.IPAddresses, ip)
					}
				}
			}
		}
	})

	// Extract from SVG image (DNS map)
	postDoc.Find("svg text").Each(func(i int, s *goquery.Selection) {
		text := strings.TrimSpace(s.Text())
		if text != "" {
			// Extract IP addresses
			ips := ipPattern.FindAllString(text, -1)
			for _, ip := range ips {
				if !seen[ip] {
					seen[ip] = true
					data.IPAddresses = append(data.IPAddresses, ip)
				}
			}
			// Extract subdomains
			domainPattern := regexp.MustCompile(`([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+` + regexp.QuoteMeta(domain))
			matches := domainPattern.FindAllString(text, -1)
			for _, match := range matches {
				match = strings.ToLower(strings.TrimSpace(match))
				if (strings.HasSuffix(match, "."+domain) || match == domain) && !seen[match] {
					seen[match] = true
					data.Subdomains = append(data.Subdomains, match)
					data.Hostnames = append(data.Hostnames, match)
				}
			}
		}
	})

	// Try to download CSV file
	csvURL := fmt.Sprintf("https://dnsdumpster.com/static/csv/%s.csv", domain)
	csvReq, err := http.NewRequest("GET", csvURL, nil)
	if err == nil {
		csvReq.Header.Set("User-Agent", "Cyber-OSINT-Recon/1.0")
		// Set cookies from previous response
		for _, cookie := range postResp.Cookies() {
			csvReq.AddCookie(cookie)
		}

		csvResp, err := httpClientSubdomain.Do(csvReq)
		if err == nil {
			defer csvResp.Body.Close()
			if csvResp.StatusCode == http.StatusOK {
				// Parse CSV
				reader := csv.NewReader(csvResp.Body)
				records, err := reader.ReadAll()
				if err == nil {
					for i, record := range records {
						if i == 0 {
							continue // Skip header
						}
						if len(record) >= 2 {
							hostname := strings.TrimSpace(record[0])
							ip := strings.TrimSpace(record[1])
							
							// Add hostname
							if hostname != "" && !seen[hostname] {
								seen[hostname] = true
								if strings.HasSuffix(hostname, "."+domain) || hostname == domain {
									data.Subdomains = append(data.Subdomains, hostname)
								}
								data.Hostnames = append(data.Hostnames, hostname)
							}
							
							// Add IP address
							if ip != "" && ipPattern.MatchString(ip) && !seen[ip] {
								seen[ip] = true
								data.IPAddresses = append(data.IPAddresses, ip)
							}
						}
					}
				}
			}
		}
	}

	return data, nil
}
