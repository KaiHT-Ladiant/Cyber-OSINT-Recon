package collector

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
)

// LeakSearchResult 공개 코드/페이스트/파일 노출 검색 결과
type LeakSearchResult struct {
	Domain          string                    `json:"domain"`
	Company         string                    `json:"company,omitempty"`
	GrepAppResults  []GrepAppFinding          `json:"grep_app_results,omitempty"`
	PastebinResults []PastebinFinding         `json:"pastebin_results,omitempty"`
	LeakCheckResults []LeakCheckFinding       `json:"leakcheck_results,omitempty"`
	RiskItems       []RiskItem                `json:"risk_items,omitempty"`
	Category        string                    `json:"category"` // "Public Code/Paste/File Leak Search"
	Command         string                    `json:"command,omitempty"`
	WebUsage        string                    `json:"web_usage,omitempty"`
	Theory          string                    `json:"theory,omitempty"`
}

// GrepAppFinding Grep.app 검색 결과
type GrepAppFinding struct {
	Repository    string   `json:"repository"`
	File          string   `json:"file"`
	URL           string   `json:"url"`
	Line          int      `json:"line,omitempty"`
	Content       string   `json:"content,omitempty"`
	Type          string   `json:"type"` // "api_key", "internal_url", "config", "password", "secret"
	Severity      string   `json:"severity"` // "high", "medium", "low"
	Description   string   `json:"description,omitempty"`
}

// PastebinFinding Pastebin 검색 결과
type PastebinFinding struct {
	PasteID      string   `json:"paste_id"`
	Title        string   `json:"title,omitempty"`
	URL          string   `json:"url"`
	Content      string   `json:"content,omitempty"`
	Type         string   `json:"type"` // "api_key", "internal_url", "config", "password", "secret"
	Severity     string   `json:"severity"`
	Date         time.Time `json:"date,omitempty"`
	Description  string   `json:"description,omitempty"`
}

// LeakCheckFinding LeakCheck.io 검색 결과
type LeakCheckFinding struct {
	Source        string   `json:"source"`
	Type          string   `json:"type"` // "breach", "paste", "leak"
	URL           string   `json:"url,omitempty"`
	Description   string   `json:"description,omitempty"`
	Date          time.Time `json:"date,omitempty"`
	LastBreach    string   `json:"last_breach,omitempty"` // "2016-10", "2019-05" 형식
	Severity      string   `json:"severity"`
	Records       int      `json:"records,omitempty"`
}

// RiskItem 리스크 항목
type RiskItem struct {
	Type          string   `json:"type"` // "api_key", "internal_url", "config", "password", "secret", "db_info"
	Source        string   `json:"source"` // "grep.app", "pastebin", "leakcheck"
	Location      string   `json:"location"` // 파일 경로 또는 URL
	Description   string   `json:"description"`
	Severity      string   `json:"severity"`
	Recommendation string  `json:"recommendation,omitempty"`
}

// CollectLeakSearch 공개 코드/페이스트/파일 노출 검색
// 1. grep.app에서 from:domain.co.kr / domain 검색
// 2. pastebin.com에서 domain 검색
// 3. leakcheck.io에서 domain.co.kr 도메인 유출 검색
func CollectLeakSearch(domain, company string) (*LeakSearchResult, error) {
	result := &LeakSearchResult{
		Domain:   domain,
		Company:  company,
		Category: "Public Code/Paste/File Leak Search",
		Command:  "Web search: https://grep.app, https://pastebin.com, https://leakcheck.io",
		WebUsage: "https://grep.app/search?q=from:" + domain + ", https://pastebin.com/search?q=" + domain + ", https://leakcheck.io/search?q=" + domain,
		Theory:   "공개 코드 저장소, 페이스트 사이트, 유출 데이터베이스에서 API 키, 내부 URL, 구성 파일 노출을 탐색하여 보안 리스크를 식별합니다.",
	}

	fmt.Printf("[*] Collecting leak search information for domain: %s, company: %s\n", domain, company)

	// 1. Grep.app 검색
	fmt.Printf("[*] Searching grep.app for domain: %s\n", domain)
	grepAppResults, err := searchGrepApp(domain, company)
	if err != nil {
		fmt.Printf("[!] Grep.app search failed: %v\n", err)
	} else {
		result.GrepAppResults = grepAppResults
		fmt.Printf("[+] Grep.app: Found %d result(s)\n", len(grepAppResults))
	}

	// 2. Pastebin 검색
	fmt.Printf("[*] Searching Pastebin for domain: %s\n", domain)
	pastebinResults, err := searchPastebin(domain, company)
	if err != nil {
		fmt.Printf("[!] Pastebin search failed: %v\n", err)
	} else {
		result.PastebinResults = pastebinResults
		fmt.Printf("[+] Pastebin: Found %d result(s)\n", len(pastebinResults))
	}

	// 3. LeakCheck.io 검색
	fmt.Printf("[*] Searching LeakCheck.io for domain: %s\n", domain)
	leakCheckResults, err := searchLeakCheck(domain)
	if err != nil {
		fmt.Printf("[!] LeakCheck.io search failed: %v\n", err)
	} else {
		result.LeakCheckResults = leakCheckResults
		fmt.Printf("[+] LeakCheck.io: Found %d result(s)\n", len(leakCheckResults))
	}

	// 4. 리스크 항목 추출
	result.RiskItems = extractRiskItems(result)

	return result, nil
}

// searchGrepApp Grep.app에서 코드 검색
func searchGrepApp(domain, company string) ([]GrepAppFinding, error) {
	var results []GrepAppFinding

	// Grep.app 검색 쿼리
	queries := []string{
		fmt.Sprintf("from:%s", domain),
		domain,
		fmt.Sprintf("%s api_key", domain),
		fmt.Sprintf("%s password", domain),
		fmt.Sprintf("%s secret", domain),
		fmt.Sprintf("%s config", domain),
		fmt.Sprintf("%s .env", domain),
		fmt.Sprintf("%s credentials", domain),
	}

	for _, query := range queries {
		url := fmt.Sprintf("https://grep.app/api/search?q=%s", strings.ReplaceAll(query, " ", "+"))
		
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", getUserAgent())
		req.Header.Set("Accept", "application/json")

		resp, err := httpClient.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			continue
		}

		var grepResult struct {
			Results []struct {
				Repository string `json:"repository"`
				File       string `json:"file"`
				URL        string `json:"url"`
				Line       int    `json:"line"`
				Content    string `json:"content"`
			} `json:"results"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&grepResult); err != nil {
			continue
		}

		for _, item := range grepResult.Results {
			// 타입 및 심각도 판단
			findingType, severity := classifyFinding(item.Content, item.File)
			
			results = append(results, GrepAppFinding{
				Repository:  item.Repository,
				File:        item.File,
				URL:         item.URL,
				Line:        item.Line,
				Content:     truncateString(item.Content, 200),
				Type:        findingType,
				Severity:    severity,
				Description: generateDescription(findingType, item.File),
			})
		}

		// API rate limit 방지
		time.Sleep(500 * time.Millisecond)
	}

	return results, nil
}

// searchPastebin Pastebin에서 검색
// Note: Pastebin의 공개 검색 기능은 제한적이거나 제거되었을 수 있습니다.
func searchPastebin(domain, company string) ([]PastebinFinding, error) {
	var results []PastebinFinding

	// Pastebin은 공개 검색 API를 제공하지 않으며, 웹 검색도 제한적입니다.
	// 대신 공개 paste ID를 확인하거나 다른 방법을 사용해야 합니다.
	// 현재는 기능을 비활성화하고 빈 결과를 반환합니다.
	// 사용자는 수동으로 https://pastebin.com/archive를 확인할 수 있습니다.
	
	// 참고: Pastebin의 공개 검색 기능이 제거되었거나 제한되어 있어
	// 403 오류가 발생할 수 있습니다. 이 기능은 유지되지만 실제로는
	// 작동하지 않을 수 있으므로, 사용자에게 수동 확인을 안내합니다.
	
	url := fmt.Sprintf("https://pastebin.com/archive")
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", getUserAgent())
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return nil, err
	}

	// Pastebin archive 페이지에서 도메인 관련 paste 찾기
	// Pastebin의 공개 검색이 제한적이므로 archive에서 최근 paste를 확인
	doc.Find("table.maintable tr").Each(func(i int, s *goquery.Selection) {
		if i == 0 {
			return // Skip header row
		}
		
		pasteLink := s.Find("td a").First()
		href := pasteLink.AttrOr("href", "")
		if href == "" {
			return
		}
		
		// Extract paste ID from href (format: /paste_id)
		if strings.HasPrefix(href, "/") {
			pasteID := strings.TrimPrefix(href, "/")
			
			// Paste 내용 확인 (도메인이 포함되어 있는지)
			pasteURL := fmt.Sprintf("https://pastebin.com/raw/%s", pasteID)
			content := fetchPasteContent(pasteURL)
			
			// 도메인이 포함되어 있는지 확인
			if strings.Contains(strings.ToLower(content), strings.ToLower(domain)) {
				title := strings.TrimSpace(pasteLink.Text())
				fullURL := fmt.Sprintf("https://pastebin.com%s", href)
				
				// 타입 및 심각도 판단
				findingType, severity := classifyFinding(content, title)
				
				results = append(results, PastebinFinding{
					PasteID:     pasteID,
					Title:       title,
					URL:         fullURL,
					Content:     truncateString(content, 500),
					Type:        findingType,
					Severity:    severity,
					Description: generateDescription(findingType, title),
				})
			}
		}
	})

	return results, nil
}

// searchLeakCheck LeakCheck.io에서 도메인 유출 검색
// LeakCheck.io는 웹 인터페이스를 통해 검색 결과를 제공합니다.
// 검색 결과는 모달 창에 테이블 형식으로 표시됩니다.
func searchLeakCheck(domain string) ([]LeakCheckFinding, error) {
	var results []LeakCheckFinding

	// LeakCheck.io 웹 검색 인터페이스 사용
	// 메인 페이지에서 검색 폼을 통해 검색하거나, 직접 검색 URL 사용
	searchURLs := []string{
		fmt.Sprintf("https://leakcheck.io/?q=%s", domain),
		fmt.Sprintf("https://leakcheck.io/search?q=%s", domain),
		fmt.Sprintf("https://leakcheck.io/api?key=public&check=%s", domain),
	}
	
	var resp *http.Response
	var err error
	var finalURL string
	
	for _, url := range searchURLs {
		req, reqErr := http.NewRequest("GET", url, nil)
		if reqErr != nil {
			continue
		}
		req.Header.Set("User-Agent", getUserAgent())
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
		req.Header.Set("Accept-Language", "en-US,en;q=0.5")
		req.Header.Set("Referer", "https://leakcheck.io/")
		
		resp, err = httpClient.Do(req)
		if err == nil && resp.StatusCode == http.StatusOK {
			finalURL = url
			break
		}
		if resp != nil {
			resp.Body.Close()
		}
		resp = nil // Reset for next iteration
	}
	
	if resp == nil || resp.StatusCode != http.StatusOK {
		statusCode := 0
		if resp != nil {
			statusCode = resp.StatusCode
		}
		return nil, fmt.Errorf("HTTP %d (service may be unavailable or URL changed)", statusCode)
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return nil, err
	}

	// LeakCheck.io 검색 결과 파싱
	// 스크린샷 기준: 테이블에 "@ Source"와 "@ Last breach" 컬럼이 있음
	// 결과는 모달 창이나 테이블 형식으로 표시됨
	
	// 방법 1: 테이블에서 결과 파싱 (검색 결과 모달)
	doc.Find("table tbody tr, .table tbody tr, #results-table tbody tr").Each(func(i int, s *goquery.Selection) {
		// "@ Source" 컬럼에서 소스 이름 추출
		sourceCell := s.Find("td").First()
		source := strings.TrimSpace(sourceCell.Text())
		
		// "@ Last breach" 컬럼에서 날짜 추출
		dateCell := s.Find("td").Eq(1)
		lastBreach := strings.TrimSpace(dateCell.Text())
		
		if source != "" && source != "@ Source" { // 헤더 행 제외
			// URL 추출 (링크가 있는 경우)
			urlText := ""
			link := sourceCell.Find("a").First()
			if link.Length() > 0 {
				urlText = link.AttrOr("href", "")
				if urlText != "" && !strings.HasPrefix(urlText, "http") {
					urlText = "https://leakcheck.io" + urlText
				}
			}
			if urlText == "" {
				urlText = finalURL
			}
			
			// 심각도 판단 (기본값: medium)
			severity := "medium"
			if strings.Contains(strings.ToLower(source), "stealer") || 
			   strings.Contains(strings.ToLower(source), "password") {
				severity = "high"
			}
			
			results = append(results, LeakCheckFinding{
				Source:      source,
				LastBreach:  lastBreach,
				URL:         urlText,
				Description: fmt.Sprintf("Data breach found in %s. Last breach: %s", source, lastBreach),
				Severity:    severity,
			})
		}
	})
	
	// 방법 2: 일반적인 결과 항목 파싱 (모달이나 리스트 형식)
	if len(results) == 0 {
		doc.Find(".leak-item, .result-item, .breach-item, .search-result").Each(func(i int, s *goquery.Selection) {
			source := strings.TrimSpace(s.Find(".source, .breach-name, .name").Text())
			description := strings.TrimSpace(s.Find(".description, .breach-description").Text())
			urlText := s.Find("a").AttrOr("href", "")
			recordsText := strings.TrimSpace(s.Find(".records, .count").Text())
			lastBreach := strings.TrimSpace(s.Find(".date, .last-breach").Text())
			
			if source != "" {
				// 전체 URL 생성
				if urlText != "" && !strings.HasPrefix(urlText, "http") {
					urlText = "https://leakcheck.io" + urlText
				}
				if urlText == "" {
					urlText = finalURL
				}
				
				// 레코드 수 파싱
				records := 0
				if recordsText != "" {
					fmt.Sscanf(recordsText, "%d", &records)
				}
			
			// 타입 및 심각도 판단
			findingType := "breach"
			severity := "high"
			if strings.Contains(strings.ToLower(source), "paste") {
				findingType = "paste"
			}
			
				// 날짜 파싱 시도
				var parsedDate time.Time
				if lastBreach != "" {
					// "2016-10", "2019-05" 형식 파싱
					if t, err := time.Parse("2006-01", lastBreach); err == nil {
						parsedDate = t
					} else if t, err := time.Parse("2006-01-02", lastBreach); err == nil {
						parsedDate = t
					}
				}
				
				results = append(results, LeakCheckFinding{
					Source:      source,
					Type:        findingType,
					URL:         urlText,
					Description: description,
					LastBreach:  lastBreach,
					Date:        parsedDate,
					Severity:    severity,
					Records:     records,
				})
			}
		})
	}

	return results, nil
}

// classifyFinding 발견된 내용의 타입과 심각도 분류
func classifyFinding(content, filename string) (string, string) {
	filenameLower := strings.ToLower(filename)
	
	// API 키 패턴
	apiKeyPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)(api[_-]?key|apikey)\s*[=:]\s*['"]?([a-zA-Z0-9_\-]{20,})['"]?`),
		regexp.MustCompile(`(?i)(aws[_-]?access[_-]?key|aws_secret)\s*[=:]\s*['"]?([a-zA-Z0-9_\-/+=]{20,})['"]?`),
		regexp.MustCompile(`(?i)(github[_-]?token|gh_token)\s*[=:]\s*['"]?([a-zA-Z0-9_\-]{20,})['"]?`),
		regexp.MustCompile(`(?i)(private[_-]?key|secret[_-]?key)\s*[=:]\s*['"]?([a-zA-Z0-9_\-/+=]{40,})['"]?`),
	}
	
	// 비밀번호 패턴
	passwordPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[=:]\s*['"]?([^'"]{8,})['"]?`),
		regexp.MustCompile(`(?i)(db[_-]?password|database[_-]?password)\s*[=:]\s*['"]?([^'"]{8,})['"]?`),
	}
	
	// DB 정보 패턴
	dbPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)(mysql|postgresql|mongodb)[^:]*:\/\/[^'"]+`),
		regexp.MustCompile(`(?i)(db[_-]?host|database[_-]?host)\s*[=:]\s*['"]?([^'"]+)['"]?`),
		regexp.MustCompile(`(?i)(db[_-]?name|database[_-]?name)\s*[=:]\s*['"]?([^'"]+)['"]?`),
	}
	
	// 내부 URL 패턴
	internalURLPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)(https?:\/\/)?(localhost|127\.0\.0\.1|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.)`),
		regexp.MustCompile(`(?i)(internal|private|dev|staging)[^'"]*\.(com|net|org|co\.kr)`),
	}
	
	// 구성 파일 패턴
	configPatterns := []string{".env", "config.php", "config.js", "config.json", "settings.py", "credentials", ".pem", ".key"}
	
	// API 키 검사
	for _, pattern := range apiKeyPatterns {
		if pattern.MatchString(content) {
			return "api_key", "high"
		}
	}
	
	// 비밀번호 검사
	for _, pattern := range passwordPatterns {
		if pattern.MatchString(content) {
			return "password", "high"
		}
	}
	
	// DB 정보 검사
	for _, pattern := range dbPatterns {
		if pattern.MatchString(content) {
			return "db_info", "high"
		}
	}
	
	// 내부 URL 검사
	for _, pattern := range internalURLPatterns {
		if pattern.MatchString(content) {
			return "internal_url", "medium"
		}
	}
	
	// 구성 파일 검사
	for _, configPattern := range configPatterns {
		if strings.Contains(filenameLower, configPattern) {
			return "config", "medium"
		}
	}
	
	// 기본값
	return "code", "low"
}

// generateDescription 발견 항목에 대한 설명 생성
func generateDescription(findingType, location string) string {
	descriptions := map[string]string{
		"api_key":    fmt.Sprintf("API 키가 %s에서 노출되었습니다.", location),
		"password":   fmt.Sprintf("비밀번호가 %s에서 노출되었습니다.", location),
		"db_info":    fmt.Sprintf("데이터베이스 정보가 %s에서 노출되었습니다.", location),
		"internal_url": fmt.Sprintf("내부 URL이 %s에서 노출되었습니다.", location),
		"config":     fmt.Sprintf("구성 파일 %s이(가) 노출되었습니다.", location),
		"secret":     fmt.Sprintf("비밀 정보가 %s에서 노출되었습니다.", location),
		"code":       fmt.Sprintf("코드가 %s에서 발견되었습니다.", location),
	}
	
	if desc, ok := descriptions[findingType]; ok {
		return desc
	}
	return fmt.Sprintf("정보가 %s에서 발견되었습니다.", location)
}

// fetchPasteContent Pastebin 원시 내용 가져오기
func fetchPasteContent(url string) string {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", getUserAgent())

	resp, err := httpClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ""
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}

	// 내용이 너무 길면 잘라내기
	content := string(body)
	if len(content) > 1000 {
		content = content[:1000] + "..."
	}

	return content
}

// extractRiskItems 리스크 항목 추출
func extractRiskItems(result *LeakSearchResult) []RiskItem {
	var riskItems []RiskItem
	
	// Grep.app 결과에서 리스크 항목 추출
	for _, finding := range result.GrepAppResults {
		if finding.Severity == "high" || finding.Severity == "medium" {
			riskItems = append(riskItems, RiskItem{
				Type:          finding.Type,
				Source:        "grep.app",
				Location:      finding.URL,
				Description:   finding.Description,
				Severity:      finding.Severity,
				Recommendation: generateRecommendation(finding.Type),
			})
		}
	}
	
	// Pastebin 결과에서 리스크 항목 추출
	for _, finding := range result.PastebinResults {
		if finding.Severity == "high" || finding.Severity == "medium" {
			riskItems = append(riskItems, RiskItem{
				Type:          finding.Type,
				Source:        "pastebin",
				Location:      finding.URL,
				Description:   finding.Description,
				Severity:      finding.Severity,
				Recommendation: generateRecommendation(finding.Type),
			})
		}
	}
	
	// LeakCheck 결과에서 리스크 항목 추출
	for _, finding := range result.LeakCheckResults {
		if finding.Severity == "high" {
			riskItems = append(riskItems, RiskItem{
				Type:          finding.Type,
				Source:        "leakcheck.io",
				Location:      finding.URL,
				Description:   finding.Description,
				Severity:      finding.Severity,
				Recommendation: "데이터 유출 확인 및 영향 범위 평가 필요",
			})
		}
	}
	
	return riskItems
}

// generateRecommendation 리스크 항목에 대한 권장사항 생성
func generateRecommendation(riskType string) string {
	recommendations := map[string]string{
		"api_key":    "API 키를 즉시 회전시키고, 노출된 키를 무효화하세요.",
		"password":   "비밀번호를 즉시 변경하고, 관련 계정의 보안을 확인하세요.",
		"db_info":    "데이터베이스 접근 권한을 재검토하고, 필요시 자격 증명을 변경하세요.",
		"internal_url": "내부 URL 접근을 제한하고, 방화벽 규칙을 확인하세요.",
		"config":     "구성 파일을 공개 저장소에서 제거하고, 환경 변수나 비밀 관리 시스템을 사용하세요.",
		"secret":     "노출된 비밀 정보를 즉시 회전시키고, 접근 로그를 확인하세요.",
	}
	
	if rec, ok := recommendations[riskType]; ok {
		return rec
	}
	return "노출된 정보를 확인하고 적절한 조치를 취하세요."
}

// truncateString 문자열을 지정된 길이로 자르기
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// SaveLeakSearchFindings Findings 디렉토리에 CSV 및 JSON 저장
func SaveLeakSearchFindings(result *LeakSearchResult) error {
	// Findings 디렉토리 생성
	findingsDir := "Findings"
	if err := os.MkdirAll(findingsDir, 0755); err != nil {
		return fmt.Errorf("failed to create Findings directory: %v", err)
	}

	// CSV 파일 저장
	csvPath := filepath.Join(findingsDir, fmt.Sprintf("leak_search_%s_%s.csv", result.Domain, time.Now().Format("20060102_150405")))
	if err := saveLeakSearchCSV(result, csvPath); err != nil {
		return fmt.Errorf("failed to save CSV: %v", err)
	}
	fmt.Printf("[+] Leak search CSV saved to: %s\n", csvPath)

	// JSON 파일도 저장
	jsonPath := filepath.Join(findingsDir, fmt.Sprintf("leak_search_%s_%s.json", result.Domain, time.Now().Format("20060102_150405")))
	if err := saveLeakSearchJSON(result, jsonPath); err != nil {
		return fmt.Errorf("failed to save JSON: %v", err)
	}
	fmt.Printf("[+] Leak search JSON saved to: %s\n", jsonPath)

	return nil
}

// saveLeakSearchCSV CSV 파일로 저장
func saveLeakSearchCSV(result *LeakSearchResult, filepath string) error {
	file, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// 헤더 작성
	headers := []string{"Domain", "Company", "Category", "Source", "Type", "Location", "Severity", "Description", "Recommendation"}
	if err := writer.Write(headers); err != nil {
		return err
	}

	// 리스크 항목 저장
	for _, risk := range result.RiskItems {
		row := []string{
			result.Domain,
			result.Company,
			result.Category,
			risk.Source,
			risk.Type,
			risk.Location,
			risk.Severity,
			risk.Description,
			risk.Recommendation,
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return nil
}

// saveLeakSearchJSON JSON 파일로 저장
func saveLeakSearchJSON(result *LeakSearchResult, filepath string) error {
	file, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}
