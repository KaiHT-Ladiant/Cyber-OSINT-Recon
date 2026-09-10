package collector

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
)

// EmailPivotResult Pivot Email/Domain 검색 결과
type EmailPivotResult struct {
	Domain           string                    `json:"domain"`
	EmailFormats     []EmailFormat             `json:"email_formats,omitempty"`
	SampleEmails     []string                  `json:"sample_emails,omitempty"`
	HoleheResults    []HoleheResult            `json:"holehe_results,omitempty"`
	BreachResults    []BreachResult            `json:"breach_results,omitempty"`
	Category         string                    `json:"category"` // "Pivot Email / Domain"
	Command          string                    `json:"command,omitempty"`
	WebUsage         string                    `json:"web_usage,omitempty"`
	Theory           string                    `json:"theory,omitempty"`
}

// EmailFormat 이메일 포맷 정보
type EmailFormat struct {
	Format      string  `json:"format"`      // 예: "{first}.{last}@domain.co.kr"
	Confidence  int     `json:"confidence"`  // 신뢰도 (0-100)
	Sources     int     `json:"sources"`     // 출처 수
}

// HoleheResult Holehe 검색 결과
type HoleheResult struct {
	Email       string   `json:"email"`
	Site        string   `json:"site"`
	Exists      bool     `json:"exists"`
	URL         string   `json:"url,omitempty"`
}

// BreachResult HaveIBeenPwned 검색 결과
type BreachResult struct {
	Email       string   `json:"email"`
	Breached    bool     `json:"breached"`
	Breaches    []string `json:"breaches,omitempty"` // 유출된 서비스 목록
	Count       int      `json:"count,omitempty"`    // 유출 횟수
}

// CollectEmailPivotDomain Pivot Email/Domain 검색 수행
// 1. hunter.io에서 도메인 검색하여 이메일 포맷 및 샘플 이메일 추출
// 2. holehe를 사용하여 이메일이 존재하는 사이트 확인
// 3. haveibeenpwned.com에서 회사 도메인 검색하여 Username Check 피벗 찾기
func CollectEmailPivotDomain(domain string) (*EmailPivotResult, error) {
	result := &EmailPivotResult{
		Domain:   domain,
		Category: "Pivot Email / Domain",
		Command:  "hunter.io API 또는 웹 검색",
		WebUsage: "https://hunter.io/search?domain=" + domain,
		Theory:   "이메일 포맷 추출을 통해 조직의 이메일 네이밍 규칙을 파악하고, 이를 기반으로 추가 이메일 주소를 생성하여 유출 여부를 확인합니다.",
	}

	fmt.Printf("[*] Collecting email pivot information for domain: %s\n", domain)

	// 1. Hunter.io에서 이메일 포맷 및 샘플 이메일 추출
	fmt.Printf("[*] Searching hunter.io for domain: %s\n", domain)
	formats, samples, err := searchHunterIO(domain)
	if err != nil {
		fmt.Printf("[!] Hunter.io search failed: %v\n", err)
	} else {
		result.EmailFormats = formats
		result.SampleEmails = samples
		fmt.Printf("[+] Hunter.io: Found %d email format(s) and %d sample email(s)\n", len(formats), len(samples))
	}

	// 2. Holehe를 사용하여 샘플 이메일이 존재하는 사이트 확인
	if len(result.SampleEmails) > 0 {
		fmt.Printf("[*] Checking email existence using holehe for %d email(s)\n", len(result.SampleEmails))
		// 처음 5개 이메일만 확인 (너무 많으면 시간이 오래 걸림)
		emailsToCheck := result.SampleEmails
		if len(emailsToCheck) > 5 {
			emailsToCheck = emailsToCheck[:5]
		}

		for _, email := range emailsToCheck {
			holeheResults, err := checkEmailWithHolehe(email)
			if err != nil {
				fmt.Printf("[!] Holehe check failed for %s: %v\n", email, err)
				continue
			}
			result.HoleheResults = append(result.HoleheResults, holeheResults...)
		}
		fmt.Printf("[+] Holehe: Checked %d email(s), found %d existing account(s)\n", len(emailsToCheck), len(result.HoleheResults))
	}

	// 3. HaveIBeenPwned에서 도메인 검색
	fmt.Printf("[*] Searching HaveIBeenPwned for domain: %s\n", domain)
	breachResults, err := searchHaveIBeenPwned(domain)
	if err != nil {
		fmt.Printf("[!] HaveIBeenPwned search failed: %v\n", err)
	} else {
		result.BreachResults = breachResults
		fmt.Printf("[+] HaveIBeenPwned: Found %d breach result(s)\n", len(breachResults))
	}

	return result, nil
}

// searchHunterIO Hunter.io에서 도메인 검색하여 이메일 포맷 및 샘플 이메일 추출
func searchHunterIO(domain string) ([]EmailFormat, []string, error) {
	var formats []EmailFormat
	var samples []string

	// Hunter.io 웹 검색 (API 키 없이도 기본 정보는 확인 가능)
	url := fmt.Sprintf("https://hunter.io/search?domain=%s", domain)
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", getUserAgent())

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return nil, nil, err
	}

	// Hunter.io 실제 HTML 구조에 맞춘 파싱
	// 이메일 포맷 추출 (다양한 선택자 시도)
	doc.Find(".email-format, .format, [data-format], .pattern").Each(func(i int, s *goquery.Selection) {
		format := strings.TrimSpace(s.Text())
		if format != "" && strings.Contains(format, "@") {
			// 포맷 예: "{first}.{last}@domain.co.kr"
			formats = append(formats, EmailFormat{
				Format:     format,
				Confidence: 80, // 기본값
				Sources:    1,
			})
		}
	})

	// 샘플 이메일 추출 (다양한 선택자 시도)
	emailSelectors := []string{
		".email", ".sample-email", ".email-address", 
		"[data-email]", ".result-email", "a[href^='mailto:']",
		".table-email", ".email-list .email-item",
	}
	
	for _, selector := range emailSelectors {
		doc.Find(selector).Each(func(i int, s *goquery.Selection) {
			email := ""
			// href 속성에서 이메일 추출
			if href := s.AttrOr("href", ""); strings.HasPrefix(href, "mailto:") {
				email = strings.TrimPrefix(href, "mailto:")
			} else {
				email = strings.TrimSpace(s.Text())
			}
			
			// 이메일 형식 검증
			if email != "" && strings.Contains(email, "@") && strings.Contains(email, ".") {
				// 중복 제거
				duplicate := false
				for _, existing := range samples {
					if existing == email {
						duplicate = true
						break
					}
				}
				if !duplicate {
					samples = append(samples, email)
				}
			}
		})
	}
	
	// JSON 데이터에서 이메일 추출 시도 (페이지에 JSON-LD 또는 인라인 JSON이 있는 경우)
	doc.Find("script[type='application/json'], script[type='application/ld+json']").Each(func(i int, s *goquery.Selection) {
		jsonText := strings.TrimSpace(s.Text())
		if strings.Contains(jsonText, "@") && strings.Contains(jsonText, domain) {
			// 간단한 이메일 패턴 추출
			emailRegex := regexp.MustCompile(`[a-zA-Z0-9._%+-]+@` + strings.ReplaceAll(domain, ".", `\.`) + `\b`)
			matches := emailRegex.FindAllString(jsonText, -1)
			for _, match := range matches {
				duplicate := false
				for _, existing := range samples {
					if existing == match {
						duplicate = true
						break
					}
				}
				if !duplicate {
					samples = append(samples, match)
				}
			}
		}
	})

	// 이메일 포맷이 없으면 기본 포맷 생성
	if len(formats) == 0 {
		// 일반적인 이메일 포맷 생성
		formats = []EmailFormat{
			{Format: "{first}.{last}@" + domain, Confidence: 50, Sources: 0},
			{Format: "{first}{last}@" + domain, Confidence: 50, Sources: 0},
			{Format: "{first}@" + domain, Confidence: 40, Sources: 0},
			{Format: "{last}.{first}@" + domain, Confidence: 40, Sources: 0},
		}
	}

	return formats, samples, nil
}

// checkEmailWithHolehe Holehe를 사용하여 이메일이 존재하는 사이트 확인
func checkEmailWithHolehe(email string) ([]HoleheResult, error) {
	var results []HoleheResult

	// Holehe Python 모듈 실행
	cmd := exec.Command("python", "-m", "holehe", email, "--only-used")
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Holehe가 설치되지 않았을 수 있음
		return nil, fmt.Errorf("holehe execution failed: %v (output: %s)", err, string(output))
	}

	// Holehe 출력 파싱 (JSON 형식)
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}

		var result map[string]interface{}
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			continue
		}

		exists, ok := result["exists"].(bool)
		if !ok {
			continue
		}

		if exists {
			site, _ := result["name"].(string)
			url, _ := result["url"].(string)
			
			results = append(results, HoleheResult{
				Email:  email,
				Site:   site,
				Exists: true,
				URL:    url,
			})
		}
	}

	return results, nil
}

// searchHaveIBeenPwned HaveIBeenPwned에서 도메인 검색
func searchHaveIBeenPwned(domain string) ([]BreachResult, error) {
	var results []BreachResult

	// HaveIBeenPwned API v3 사용 (도메인 검색)
	url := fmt.Sprintf("https://haveibeenpwned.com/api/v3/breacheddomain/%s", domain)
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", getUserAgent())
	req.Header.Set("hibp-api-key", "") // API 키가 있으면 설정

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		// 유출된 정보 없음
		return results, nil
	}

	if resp.StatusCode == http.StatusUnauthorized {
		// API 키가 필요함 (무료 버전은 제한적)
		return results, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	var breaches []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&breaches); err != nil {
		return nil, err
	}

	breachNames := make([]string, 0, len(breaches))
	for _, breach := range breaches {
		if name, ok := breach["Name"].(string); ok {
			breachNames = append(breachNames, name)
		}
	}

	if len(breachNames) > 0 {
		results = append(results, BreachResult{
			Email:    "*@" + domain,
			Breached: true,
			Breaches: breachNames,
			Count:    len(breachNames),
		})
	}

	return results, nil
}

// SaveEmailPivotFindings Findings 디렉토리에 CSV 및 스크린샷 저장
func SaveEmailPivotFindings(result *EmailPivotResult) error {
	// Findings 디렉토리 생성
	findingsDir := "Findings"
	if err := os.MkdirAll(findingsDir, 0755); err != nil {
		return fmt.Errorf("failed to create Findings directory: %v", err)
	}

	// CSV 파일 저장
	csvPath := filepath.Join(findingsDir, fmt.Sprintf("email_pivot_%s_%s.csv", result.Domain, time.Now().Format("20060102_150405")))
	if err := saveEmailPivotCSV(result, csvPath); err != nil {
		return fmt.Errorf("failed to save CSV: %v", err)
	}
	fmt.Printf("[+] Email pivot CSV saved to: %s\n", csvPath)

	// JSON 파일도 저장 (상세 정보)
	jsonPath := filepath.Join(findingsDir, fmt.Sprintf("email_pivot_%s_%s.json", result.Domain, time.Now().Format("20060102_150405")))
	if err := saveEmailPivotJSON(result, jsonPath); err != nil {
		return fmt.Errorf("failed to save JSON: %v", err)
	}
	fmt.Printf("[+] Email pivot JSON saved to: %s\n", jsonPath)

	// 스크린샷은 별도로 구현 필요 (selenium 등 사용)
	// 여기서는 일단 스킵

	return nil
}

// saveEmailPivotCSV CSV 파일로 저장
func saveEmailPivotCSV(result *EmailPivotResult, filepath string) error {
	file, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// 헤더 작성
	headers := []string{"Domain", "Category", "Email Format", "Confidence", "Sample Email", "Holehe Site", "Holehe URL", "Breached", "Breaches"}
	if err := writer.Write(headers); err != nil {
		return err
	}

	// 데이터 작성
	// Email Formats가 있으면 각 포맷별로 저장
	if len(result.EmailFormats) > 0 {
		for _, format := range result.EmailFormats {
			// Sample emails가 있으면 각 샘플별로 저장
			if len(result.SampleEmails) > 0 {
				for _, sample := range result.SampleEmails {
					// Holehe 결과 찾기
					holeheSite := ""
					holeheURL := ""
					for _, hr := range result.HoleheResults {
						if hr.Email == sample {
							holeheSite = hr.Site
							holeheURL = hr.URL
							break
						}
					}

					// Breach 결과 찾기
					breached := "No"
					breaches := ""
					for _, br := range result.BreachResults {
						if strings.HasSuffix(sample, "@"+result.Domain) {
							breached = "Yes"
							breaches = strings.Join(br.Breaches, "; ")
							break
						}
					}

					row := []string{
						result.Domain,
						result.Category,
						format.Format,
						fmt.Sprintf("%d", format.Confidence),
						sample,
						holeheSite,
						holeheURL,
						breached,
						breaches,
					}
					if err := writer.Write(row); err != nil {
						return err
					}
				}
			} else {
				// Sample emails가 없으면 포맷만 저장
				row := []string{
					result.Domain,
					result.Category,
					format.Format,
					fmt.Sprintf("%d", format.Confidence),
					"", // Sample Email
					"", // Holehe Site
					"", // Holehe URL
					"", // Breached
					"", // Breaches
				}
				if err := writer.Write(row); err != nil {
					return err
				}
			}
		}
	} else {
		// Email Formats가 없으면 Sample Emails만 저장
		if len(result.SampleEmails) > 0 {
			for _, sample := range result.SampleEmails {
				// Holehe 결과 찾기
				holeheSite := ""
				holeheURL := ""
				for _, hr := range result.HoleheResults {
					if hr.Email == sample {
						holeheSite = hr.Site
						holeheURL = hr.URL
						break
					}
				}

				// Breach 결과 찾기
				breached := "No"
				breaches := ""
				for _, br := range result.BreachResults {
					if strings.HasSuffix(sample, "@"+result.Domain) {
						breached = "Yes"
						breaches = strings.Join(br.Breaches, "; ")
						break
					}
				}

				row := []string{
					result.Domain,
					result.Category,
					"", // Email Format
					"", // Confidence
					sample,
					holeheSite,
					holeheURL,
					breached,
					breaches,
				}
				if err := writer.Write(row); err != nil {
					return err
				}
			}
		} else {
			// Holehe Results만 저장
			for _, hr := range result.HoleheResults {
				row := []string{
					result.Domain,
					result.Category,
					"", // Email Format
					"", // Confidence
					hr.Email,
					hr.Site,
					hr.URL,
					"", // Breached
					"", // Breaches
				}
				if err := writer.Write(row); err != nil {
					return err
				}
			}
			// Breach Results만 저장
			for _, br := range result.BreachResults {
				row := []string{
					result.Domain,
					result.Category,
					"", // Email Format
					"", // Confidence
					br.Email,
					"", // Holehe Site
					"", // Holehe URL
					"Yes", // Breached
					strings.Join(br.Breaches, "; "), // Breaches
				}
				if err := writer.Write(row); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// saveEmailPivotJSON JSON 파일로 저장
func saveEmailPivotJSON(result *EmailPivotResult, filepath string) error {
	file, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}
