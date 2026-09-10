package collector

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
)

// UsernameExtendedResult Extended Username/Social 검색 결과
type UsernameExtendedResult struct {
	Domain          string                    `json:"domain"`
	Company         string                    `json:"company,omitempty"`
	Usernames       []UsernameSearchResult    `json:"usernames,omitempty"`
	SherlockResults []SherlockPlatformResult  `json:"sherlock_results,omitempty"`
	WhatsMyNameResults []WhatsMyNameResult    `json:"whatsmyname_results,omitempty"`
	LinkedInResults []LinkedInProfile         `json:"linkedin_results,omitempty"`
	Category        string                    `json:"category"` // "Extended Username/Social"
	Command         string                    `json:"command,omitempty"`
	WebUsage        string                    `json:"web_usage,omitempty"`
	Theory          string                    `json:"theory,omitempty"`
}

// UsernameSearchResult Username 검색 결과
type UsernameSearchResult struct {
	Username        string   `json:"username"`
	Source          string   `json:"source"` // "domain", "company", "email"
	Platform        string   `json:"platform"`
	URL             string   `json:"url"`
	Exists          bool     `json:"exists"`
	Verified        bool     `json:"verified,omitempty"`
	Official        bool     `json:"official,omitempty"` // 공식 계정 여부
}

// SherlockPlatformResult Sherlock 검색 결과
type SherlockPlatformResult struct {
	Username        string   `json:"username"`
	Platform        string   `json:"platform"`
	URL             string   `json:"url"`
	Exists          bool     `json:"exists"`
	Status          string   `json:"status,omitempty"`
}

// WhatsMyNameResult What's My Name 검색 결과
type WhatsMyNameResult struct {
	Username        string   `json:"username"`
	Site            string   `json:"site"`
	URL             string   `json:"url"`
	Exists          bool     `json:"exists"`
}

// LinkedInProfile LinkedIn 프로필 정보
type LinkedInProfile struct {
	Name            string   `json:"name"`
	Title            string   `json:"title,omitempty"`
	Company          string   `json:"company,omitempty"`
	URL              string   `json:"url"`
	Connection       string   `json:"connection,omitempty"` // "1st", "2nd", "3rd"
}

// CollectExtendedUsernameSocial Extended Username/Social 검색 수행
// 1. GitHub Sherlock 사용하여 username 검색
// 2. whatsmyname.app 검색
// 3. LinkedIn 회사 검색
func CollectExtendedUsernameSocial(domain, company string) (*UsernameExtendedResult, error) {
	result := &UsernameExtendedResult{
		Domain:   domain,
		Company:  company,
		Category: "Extended Username/Social",
		Command:  "python3 sherlock.py <username>",
		WebUsage: "https://whatsmyname.app/",
		Theory:   "이메일이나 브랜드에서 유도한 username을 100+ 사이트에서 검색하여 공식/비공식 계정을 매핑합니다.",
	}

	fmt.Printf("[*] Collecting extended username/social information for domain: %s, company: %s\n", domain, company)

	// Username 후보 생성
	usernames := generateUsernameCandidates(domain, company)
	fmt.Printf("[*] Generated %d username candidate(s)\n", len(usernames))

	// 1. GitHub Sherlock 검색
	fmt.Printf("[*] Searching with GitHub Sherlock...\n")
	for _, username := range usernames {
		sherlockResults, err := searchWithSherlock(username)
		if err != nil {
			// Sherlock이 설치되지 않은 경우 조용히 처리
			continue
		}
		result.SherlockResults = append(result.SherlockResults, sherlockResults...)
	}
	fmt.Printf("[+] Sherlock: Found %d platform result(s)\n", len(result.SherlockResults))

	// 2. What's My Name 검색
	fmt.Printf("[*] Searching with What's My Name...\n")
	for _, username := range usernames {
		whatsMyNameResults, err := searchWhatsMyName(username)
		if err != nil {
			// HTTP 403/404는 조용히 처리 (웹 스크래핑 차단)
			if !strings.Contains(err.Error(), "HTTP 403") && !strings.Contains(err.Error(), "HTTP 404") {
				fmt.Printf("[!] What's My Name search failed for %s: %v\n", username, err)
			}
			continue
		}
		if whatsMyNameResults != nil {
			result.WhatsMyNameResults = append(result.WhatsMyNameResults, whatsMyNameResults...)
		}
	}
		fmt.Printf("[+] What's My Name: Found %d site result(s)\n", len(result.WhatsMyNameResults))

	// 3. LinkedIn 검색
	if company != "" {
		fmt.Printf("[*] Searching LinkedIn for company: %s\n", company)
		linkedInResults, err := searchLinkedIn(company, domain)
		if err != nil {
			fmt.Printf("[!] LinkedIn search failed: %v\n", err)
		} else {
			result.LinkedInResults = linkedInResults
			fmt.Printf("[+] LinkedIn: Found %d profile(s)\n", len(linkedInResults))
		}
	}

	// 결과 통합
	result.Usernames = mergeUsernameResults(result)

	return result, nil
}

// generateUsernameCandidates 도메인과 회사명에서 username 후보 생성
func generateUsernameCandidates(domain, company string) []string {
	var usernames []string
	
	// 도메인에서 username 추출
	domainParts := strings.Split(domain, ".")
	if len(domainParts) > 0 {
		baseDomain := domainParts[0]
		usernames = append(usernames, baseDomain)
		usernames = append(usernames, baseDomain+"_official")
		usernames = append(usernames, baseDomain+"official")
		usernames = append(usernames, baseDomain+"-org")
		usernames = append(usernames, baseDomain+"org")
	}

	// 회사명에서 username 추출
	if company != "" {
		companyClean := strings.ToLower(strings.ReplaceAll(company, " ", ""))
		usernames = append(usernames, companyClean)
		usernames = append(usernames, companyClean+"_official")
		usernames = append(usernames, companyClean+"official")
		usernames = append(usernames, companyClean+"-org")
		usernames = append(usernames, companyClean+"org")
	}

	// 중복 제거
	seen := make(map[string]bool)
	var unique []string
	for _, u := range usernames {
		if !seen[u] {
			seen[u] = true
			unique = append(unique, u)
		}
	}

	return unique
}

// searchWithSherlock GitHub Sherlock을 사용하여 username 검색
func searchWithSherlock(username string) ([]SherlockPlatformResult, error) {
	var results []SherlockPlatformResult

	// Sherlock 경로 확인 (sherlock 디렉토리 또는 시스템에 설치된 경우)
	sherlockPaths := []string{
		"sherlock/sherlock.py",
		"../sherlock/sherlock.py",
		"~/sherlock/sherlock.py",
	}

	var sherlockPath string
	for _, path := range sherlockPaths {
		if _, err := os.Stat(path); err == nil {
			sherlockPath = path
			break
		}
	}

	if sherlockPath == "" {
		// Python3 또는 python으로 sherlock 실행 시도
		pythonCommands := []string{"python3", "python"}
		var cmd *exec.Cmd
		var output []byte
		var err error
		sherlockNotFound := true
		
		for _, pythonCmd := range pythonCommands {
			// 일반적인 sherlock 설치 경로 시도
			sherlockPaths := []string{
				filepath.Join(os.Getenv("HOME"), "sherlock", "sherlock.py"),
				filepath.Join(os.Getenv("USERPROFILE"), "sherlock", "sherlock.py"),
				"./sherlock/sherlock.py",
				"../sherlock/sherlock.py",
			}
			
			for _, path := range sherlockPaths {
				if _, statErr := os.Stat(path); statErr == nil {
					cmd = exec.Command(pythonCmd, path, username, "--json", "--print-found")
					output, err = cmd.CombinedOutput()
					if err == nil {
						sherlockNotFound = false
						break
					}
				}
			}
			if !sherlockNotFound {
				break
			}
		}
		
		if sherlockNotFound {
			// Sherlock을 찾을 수 없으면 빈 결과 반환 (조용히 실패)
			return results, nil
		}

		// JSON 출력 파싱
		var sherlockData map[string]interface{}
		if err := json.Unmarshal(output, &sherlockData); err == nil {
			for platform, data := range sherlockData {
				if platformData, ok := data.(map[string]interface{}); ok {
					if exists, ok := platformData["exists"].(bool); ok && exists {
						url, _ := platformData["url"].(string)
						status, _ := platformData["status"].(string)
						results = append(results, SherlockPlatformResult{
							Username: username,
							Platform: platform,
							URL:      url,
							Exists:   true,
							Status:   status,
						})
					}
				}
			}
		}
	} else {
		// 로컬 sherlock.py 실행
		cmd := exec.Command("python3", sherlockPath, username, "--json", "--print-found")
		output, err := cmd.CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("sherlock execution failed: %v (output: %s)", err, string(output))
		}

		// JSON 출력 파싱
		var sherlockData map[string]interface{}
		if err := json.Unmarshal(output, &sherlockData); err == nil {
			for platform, data := range sherlockData {
				if platformData, ok := data.(map[string]interface{}); ok {
					if exists, ok := platformData["exists"].(bool); ok && exists {
						url, _ := platformData["url"].(string)
						status, _ := platformData["status"].(string)
						results = append(results, SherlockPlatformResult{
							Username: username,
							Platform: platform,
							URL:      url,
							Exists:   true,
							Status:   status,
						})
					}
				}
			}
		}
	}

	return results, nil
}

// searchWhatsMyName What's My Name 웹 검색
func searchWhatsMyName(username string) ([]WhatsMyNameResult, error) {
	var results []WhatsMyNameResult

	// What's My Name API 또는 웹 검색
	url := fmt.Sprintf("https://whatsmyname.app/tools/username?q=%s", username)
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", getUserAgent())

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusNotFound {
		// What's My Name 웹 스크래핑이 차단된 경우 조용히 실패
		return nil, nil // 빈 결과 반환 (조용히 실패)
	}
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return nil, err
	}

	// 결과 파싱 (What's My Name 페이지 구조에 따라)
	doc.Find(".result-item, .site-result").Each(func(i int, s *goquery.Selection) {
		site := strings.TrimSpace(s.Find(".site-name, .site").Text())
		urlText := strings.TrimSpace(s.Find(".url, a").AttrOr("href", ""))
		
		if site != "" && urlText != "" {
			results = append(results, WhatsMyNameResult{
				Username: username,
				Site:     site,
				URL:      urlText,
				Exists:   true,
			})
		}
	})

	return results, nil
}

// searchLinkedIn LinkedIn에서 회사 검색
func searchLinkedIn(company, domain string) ([]LinkedInProfile, error) {
	var profiles []LinkedInProfile

	// LinkedIn 검색 URL
	url := fmt.Sprintf("https://www.linkedin.com/search/results/companies/?keywords=%s", company)
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", getUserAgent())

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

	// LinkedIn 프로필 파싱 (페이지 구조에 따라)
	doc.Find(".search-result, .entity-result").Each(func(i int, s *goquery.Selection) {
		name := strings.TrimSpace(s.Find(".entity-result__title-text a, .search-result__title a").Text())
		urlText := s.Find(".entity-result__title-text a, .search-result__title a").AttrOr("href", "")
		
		if name != "" && urlText != "" {
			// 전체 URL 생성
			if !strings.HasPrefix(urlText, "http") {
				urlText = "https://www.linkedin.com" + urlText
			}
			
			title := strings.TrimSpace(s.Find(".entity-result__primary-subtitle, .search-result__info").Text())
			
			profiles = append(profiles, LinkedInProfile{
				Name:    name,
				Title:   title,
				Company: company,
				URL:     urlText,
			})
		}
	})

	return profiles, nil
}

// mergeUsernameResults 검색 결과 통합
func mergeUsernameResults(result *UsernameExtendedResult) []UsernameSearchResult {
	var merged []UsernameSearchResult
	seen := make(map[string]bool)

	// Sherlock 결과 통합
	for _, sr := range result.SherlockResults {
		key := sr.Platform + ":" + sr.Username
		if !seen[key] {
			seen[key] = true
			merged = append(merged, UsernameSearchResult{
				Username: sr.Username,
				Source:   "sherlock",
				Platform: sr.Platform,
				URL:      sr.URL,
				Exists:   sr.Exists,
			})
		}
	}

	// What's My Name 결과 통합
	for _, wmn := range result.WhatsMyNameResults {
		key := wmn.Site + ":" + wmn.Username
		if !seen[key] {
			seen[key] = true
			merged = append(merged, UsernameSearchResult{
				Username: wmn.Username,
				Source:   "whatsmyname",
				Platform: wmn.Site,
				URL:      wmn.URL,
				Exists:   wmn.Exists,
			})
		}
	}

	return merged
}

// SaveUsernameExtendedFindings Findings 디렉토리에 CSV 및 JSON 저장
func SaveUsernameExtendedFindings(result *UsernameExtendedResult) error {
	// Findings 디렉토리 생성
	findingsDir := "Findings"
	if err := os.MkdirAll(findingsDir, 0755); err != nil {
		return fmt.Errorf("failed to create Findings directory: %v", err)
	}

	// CSV 파일 저장
	csvPath := filepath.Join(findingsDir, fmt.Sprintf("username_extended_%s_%s.csv", result.Domain, time.Now().Format("20060102_150405")))
	if err := saveUsernameExtendedCSV(result, csvPath); err != nil {
		return fmt.Errorf("failed to save CSV: %v", err)
	}
	fmt.Printf("[+] Username extended CSV saved to: %s\n", csvPath)

	// JSON 파일도 저장
	jsonPath := filepath.Join(findingsDir, fmt.Sprintf("username_extended_%s_%s.json", result.Domain, time.Now().Format("20060102_150405")))
	if err := saveUsernameExtendedJSON(result, jsonPath); err != nil {
		return fmt.Errorf("failed to save JSON: %v", err)
	}
	fmt.Printf("[+] Username extended JSON saved to: %s\n", jsonPath)

	return nil
}

// saveUsernameExtendedCSV CSV 파일로 저장
func saveUsernameExtendedCSV(result *UsernameExtendedResult, filepath string) error {
	file, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// 헤더 작성
	headers := []string{"Domain", "Company", "Category", "Username", "Source", "Platform", "URL", "Exists", "Verified", "Official"}
	if err := writer.Write(headers); err != nil {
		return err
	}

	// 데이터 작성
	for _, username := range result.Usernames {
		row := []string{
			result.Domain,
			result.Company,
			result.Category,
			username.Username,
			username.Source,
			username.Platform,
			username.URL,
			fmt.Sprintf("%t", username.Exists),
			fmt.Sprintf("%t", username.Verified),
			fmt.Sprintf("%t", username.Official),
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return nil
}

// saveUsernameExtendedJSON JSON 파일로 저장
func saveUsernameExtendedJSON(result *UsernameExtendedResult, filepath string) error {
	file, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}
