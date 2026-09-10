package collector

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
)

// CorporateInfoResult 법인 등록/재무/채용 정보 검색 결과
type CorporateInfoResult struct {
	Domain          string                    `json:"domain"`
	Company         string                    `json:"company,omitempty"`
	CrunchbaseResults []CrunchbaseCompany    `json:"crunchbase_results,omitempty"`
	OpenCorporatesResults []OpenCorporatesCompany `json:"opencorporates_results,omitempty"`
	Subsidiaries    []SubsidiaryInfo         `json:"subsidiaries,omitempty"`
	Partners        []PartnerInfo            `json:"partners,omitempty"`
	CloudAssets     []CloudAsset             `json:"cloud_assets,omitempty"`
	Category        string                    `json:"category"` // "Corporate Registration/Financial/Recruitment"
	Command         string                    `json:"command,omitempty"`
	WebUsage        string                    `json:"web_usage,omitempty"`
	Theory          string                    `json:"theory,omitempty"`
}

// CrunchbaseCompany Crunchbase 회사 정보
type CrunchbaseCompany struct {
	Name            string   `json:"name"`
	URL             string   `json:"url"`
	Description     string   `json:"description,omitempty"`
	Founded         string   `json:"founded,omitempty"`
	Industry        string   `json:"industry,omitempty"`
	Location        string   `json:"location,omitempty"`
	Employees       string   `json:"employees,omitempty"`
	Funding         string   `json:"funding,omitempty"`
	Subsidiaries    []string `json:"subsidiaries,omitempty"`
	Acquisitions    []string `json:"acquisitions,omitempty"`
}

// OpenCorporatesCompany OpenCorporates 회사 정보
type OpenCorporatesCompany struct {
	Name            string   `json:"name"`
	URL             string   `json:"url"`
	Jurisdiction    string   `json:"jurisdiction,omitempty"`
	CompanyNumber   string   `json:"company_number,omitempty"`
	Status          string   `json:"status,omitempty"`
	IncorporationDate string `json:"incorporation_date,omitempty"`
	DissolutionDate string   `json:"dissolution_date,omitempty"`
	Address         string   `json:"address,omitempty"`
}

// SubsidiaryInfo 자회사 정보
type SubsidiaryInfo struct {
	Name            string   `json:"name"`
	Domain          string   `json:"domain,omitempty"`
	Type            string   `json:"type,omitempty"` // "subsidiary", "partner", "acquisition"
	Source          string   `json:"source"` // "crunchbase", "opencorporates"
	URL             string   `json:"url,omitempty"`
}

// PartnerInfo 파트너 정보
type PartnerInfo struct {
	Name            string   `json:"name"`
	Domain          string   `json:"domain,omitempty"`
	Type            string   `json:"type,omitempty"` // "partner", "investor", "customer"
	Source          string   `json:"source"`
	URL             string   `json:"url,omitempty"`
}

// CloudAsset 클라우드 자산 정보
type CloudAsset struct {
	Service         string   `json:"service"` // "AWS", "Azure", "GCP", etc.
	Domain          string   `json:"domain,omitempty"`
	Subdomain       string   `json:"subdomain,omitempty"`
	Type            string   `json:"type,omitempty"` // "S3", "CloudFront", "App Engine", etc.
	Source          string   `json:"source"`
}

// CollectCorporateInfo 법인 등록/재무/채용 정보 수집
// 1. Crunchbase에서 회사 검색
// 2. OpenCorporates에서 회사 검색
// 3. 자회사/파트너 도메인 및 클라우드 자산 추출
func CollectCorporateInfo(domain, company string) (*CorporateInfoResult, error) {
	result := &CorporateInfoResult{
		Domain:   domain,
		Company:  company,
		Category: "Corporate Registration/Financial/Recruitment",
		Command:  "Web search: https://www.crunchbase.com, https://opencorporates.com",
		WebUsage: "https://www.crunchbase.com/discover/organizations, https://opencorporates.com",
		Theory:   "법인 등록/재무/채용 정보를 통해 자회사, 파트너 도메인 및 클라우드 사용 단서를 확보합니다.",
	}

	fmt.Printf("[*] Collecting corporate information for domain: %s, company: %s\n", domain, company)

	// 1. Crunchbase 검색
	if company != "" {
		fmt.Printf("[*] Searching Crunchbase for company: %s\n", company)
		crunchbaseResults, err := searchCrunchbase(company, domain)
		if err != nil {
			fmt.Printf("[!] Crunchbase search failed: %v\n", err)
		} else {
			result.CrunchbaseResults = crunchbaseResults
			fmt.Printf("[+] Crunchbase: Found %d company result(s)\n", len(crunchbaseResults))
		}
	}

	// 2. OpenCorporates 검색
	if company != "" {
		fmt.Printf("[*] Searching OpenCorporates for company: %s\n", company)
		openCorporatesResults, err := searchOpenCorporates(company, domain)
		if err != nil {
			fmt.Printf("[!] OpenCorporates search failed: %v\n", err)
		} else {
			result.OpenCorporatesResults = openCorporatesResults
			fmt.Printf("[+] OpenCorporates: Found %d company result(s)\n", len(openCorporatesResults))
		}
	}

	// 3. 자회사/파트너 도메인 및 클라우드 자산 추출
	result.Subsidiaries = extractSubsidiaries(result)
	result.Partners = extractPartners(result)
	result.CloudAssets = extractCloudAssets(result, domain)

	return result, nil
}

// searchCrunchbase Crunchbase에서 회사 검색
func searchCrunchbase(company, domain string) ([]CrunchbaseCompany, error) {
	var results []CrunchbaseCompany

	// Crunchbase 검색 URL - 여러 URL 패턴 시도
	// Note: Crunchbase는 웹 스크래핑을 제한할 수 있음 (403 오류 가능)
	urls := []string{
		fmt.Sprintf("https://www.crunchbase.com/discover/organizations?q=%s", strings.ReplaceAll(company, " ", "+")),
		fmt.Sprintf("https://www.crunchbase.com/search/organizations?query=%s", strings.ReplaceAll(company, " ", "%20")),
		fmt.Sprintf("https://www.crunchbase.com/organization/%s", strings.ToLower(strings.ReplaceAll(company, " ", "-"))),
	}
	
	var resp *http.Response
	var err error
	
	for _, testURL := range urls {
		req, reqErr := http.NewRequest("GET", testURL, nil)
		if reqErr != nil {
			continue
		}
		req.Header.Set("User-Agent", getUserAgent())
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
		req.Header.Set("Accept-Language", "en-US,en;q=0.5")
		req.Header.Set("Referer", "https://www.crunchbase.com/")
		
			resp, err = httpClient.Do(req)
		if err == nil && resp.StatusCode == http.StatusOK {
			break
		}
		if resp != nil {
			resp.Body.Close()
		}
		resp = nil // Reset for next iteration
	}
	
	if resp == nil {
		// Crunchbase 웹 스크래핑이 차단된 경우 조용히 실패
		// Note: Crunchbase API를 사용하려면 API 키가 필요합니다
		return nil, fmt.Errorf("Crunchbase web scraping blocked (403/404). API key required for programmatic access")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return nil, err
	}

	// Crunchbase 결과 파싱
	// Crunchbase는 동적 콘텐츠를 사용할 수 있으므로 여러 선택자 패턴 시도
	selectors := []string{
		".result-item", ".organization-card", ".entity-result",
		".search-result", ".grid-card", ".card",
		"div[data-test='result-item']", "div[class*='result']",
		"div[class*='organization']", "div[class*='entity']",
	}
	
	found := false
	for _, selector := range selectors {
		doc.Find(selector).Each(func(i int, s *goquery.Selection) {
			name := strings.TrimSpace(s.Find(".name, .organization-name, .entity-name, h3, h4, [class*='name']").First().Text())
			
			// 이름이 비어있으면 링크 텍스트 사용
			if name == "" {
				name = strings.TrimSpace(s.Find("a").First().Text())
			}
			
			urlText := s.Find("a").First().AttrOr("href", "")
			
			if name != "" && name != "Name" { // 헤더 행 제외
				found = true
				
				// 전체 URL 생성
				if urlText != "" && !strings.HasPrefix(urlText, "http") {
					urlText = "https://www.crunchbase.com" + urlText
				}
				if urlText == "" {
					urlText = fmt.Sprintf("https://www.crunchbase.com/organization/%s", strings.ToLower(strings.ReplaceAll(name, " ", "-")))
				}
				
				description := strings.TrimSpace(s.Find(".description, .short-description, [class*='description']").Text())
				founded := strings.TrimSpace(s.Find(".founded, .founded-date, [class*='founded']").Text())
				industry := strings.TrimSpace(s.Find(".industry, .category, [class*='industry'], [class*='category']").Text())
				location := strings.TrimSpace(s.Find(".location, .headquarters, [class*='location'], [class*='headquarters']").Text())
				employees := strings.TrimSpace(s.Find(".employees, .employee-count, [class*='employee']").Text())
				funding := strings.TrimSpace(s.Find(".funding, .total-funding, [class*='funding']").Text())
				
				results = append(results, CrunchbaseCompany{
					Name:        name,
					URL:         urlText,
					Description: description,
					Founded:     founded,
					Industry:    industry,
					Location:    location,
					Employees:   employees,
					Funding:     funding,
				})
			}
		})
		
		if found {
			break // 결과를 찾았으면 다른 선택자 시도 중단
		}
	}
	
	// 결과를 찾지 못한 경우, 페이지 내용에서 회사명이 포함되어 있는지 확인
	if len(results) == 0 {
		bodyText := doc.Text()
		if strings.Contains(strings.ToLower(bodyText), strings.ToLower(company)) {
			// 회사명이 페이지에 있지만 구조화된 데이터가 없는 경우
			// 기본 정보만 반환
			results = append(results, CrunchbaseCompany{
				Name:        company,
				URL:         fmt.Sprintf("https://www.crunchbase.com/organization/%s", strings.ToLower(strings.ReplaceAll(company, " ", "-"))),
				Description: "Company found on Crunchbase but detailed information requires API access or login",
			})
		}
	}

	return results, nil
}

// searchOpenCorporates OpenCorporates에서 회사 검색
func searchOpenCorporates(company, domain string) ([]OpenCorporatesCompany, error) {
	var results []OpenCorporatesCompany

	// OpenCorporates 검색 URL
	url := fmt.Sprintf("https://opencorporates.com/companies?q=%s", strings.ReplaceAll(company, " ", "+"))
	
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

	// OpenCorporates 결과 파싱
	doc.Find(".company, .result-item, .search-result").Each(func(i int, s *goquery.Selection) {
		name := strings.TrimSpace(s.Find(".company-name, .name").Text())
		urlText := s.Find("a").AttrOr("href", "")
		
		if name != "" {
			// 전체 URL 생성
			if urlText != "" && !strings.HasPrefix(urlText, "http") {
				urlText = "https://opencorporates.com" + urlText
			}
			
			jurisdiction := strings.TrimSpace(s.Find(".jurisdiction, .jurisdiction-name").Text())
			companyNumber := strings.TrimSpace(s.Find(".company-number, .number").Text())
			status := strings.TrimSpace(s.Find(".status, .company-status").Text())
			incorporationDate := strings.TrimSpace(s.Find(".incorporation-date, .date-incorporated").Text())
			dissolutionDate := strings.TrimSpace(s.Find(".dissolution-date, .date-dissolved").Text())
			address := strings.TrimSpace(s.Find(".address, .registered-address").Text())
			
			results = append(results, OpenCorporatesCompany{
				Name:            name,
				URL:             urlText,
				Jurisdiction:    jurisdiction,
				CompanyNumber:   companyNumber,
				Status:          status,
				IncorporationDate: incorporationDate,
				DissolutionDate: dissolutionDate,
				Address:         address,
			})
		}
	})

	return results, nil
}

// extractSubsidiaries 자회사 정보 추출
func extractSubsidiaries(result *CorporateInfoResult) []SubsidiaryInfo {
	var subsidiaries []SubsidiaryInfo
	
	// Crunchbase에서 자회사 추출
	for _, cb := range result.CrunchbaseResults {
		for _, sub := range cb.Subsidiaries {
			subsidiaries = append(subsidiaries, SubsidiaryInfo{
				Name:   sub,
				Type:   "subsidiary",
				Source: "crunchbase",
			})
		}
		for _, acq := range cb.Acquisitions {
			subsidiaries = append(subsidiaries, SubsidiaryInfo{
				Name:   acq,
				Type:   "acquisition",
				Source: "crunchbase",
			})
		}
	}
	
	return subsidiaries
}

// extractPartners 파트너 정보 추출
func extractPartners(result *CorporateInfoResult) []PartnerInfo {
	var partners []PartnerInfo
	
	// Crunchbase에서 파트너 정보 추출 (추가 구현 필요)
	// 여기서는 기본 구조만 제공
	
	return partners
}

// extractCloudAssets 클라우드 자산 추출
func extractCloudAssets(result *CorporateInfoResult, domain string) []CloudAsset {
	var assets []CloudAsset
	
	// 자회사 도메인에서 클라우드 자산 추출
	// 일반적인 클라우드 서비스 패턴 검색
	cloudPatterns := []struct {
		Service string
		Patterns []string
	}{
		{"AWS", []string{"s3", "cloudfront", "amazonaws"}},
		{"Azure", []string{"azure", "azurewebsites", "blob.core.windows.net"}},
		{"GCP", []string{"googleapis", "appspot.com", "cloud.google"}},
		{"Cloudflare", []string{"cloudflare", "cf-cdn"}},
	}
	
	// 도메인에서 클라우드 패턴 검색
	for _, pattern := range cloudPatterns {
		for _, p := range pattern.Patterns {
			if strings.Contains(domain, p) {
				assets = append(assets, CloudAsset{
					Service: pattern.Service,
					Domain:  domain,
					Type:    p,
					Source:  "domain_analysis",
				})
			}
		}
	}
	
	return assets
}

// SaveCorporateInfoFindings Findings 디렉토리에 CSV 및 JSON 저장
func SaveCorporateInfoFindings(result *CorporateInfoResult) error {
	// Findings 디렉토리 생성
	findingsDir := "Findings"
	if err := os.MkdirAll(findingsDir, 0755); err != nil {
		return fmt.Errorf("failed to create Findings directory: %v", err)
	}

	// CSV 파일 저장
	csvPath := filepath.Join(findingsDir, fmt.Sprintf("corporate_info_%s_%s.csv", result.Domain, time.Now().Format("20060102_150405")))
	if err := saveCorporateInfoCSV(result, csvPath); err != nil {
		return fmt.Errorf("failed to save CSV: %v", err)
	}
	fmt.Printf("[+] Corporate info CSV saved to: %s\n", csvPath)

	// JSON 파일도 저장
	jsonPath := filepath.Join(findingsDir, fmt.Sprintf("corporate_info_%s_%s.json", result.Domain, time.Now().Format("20060102_150405")))
	if err := saveCorporateInfoJSON(result, jsonPath); err != nil {
		return fmt.Errorf("failed to save JSON: %v", err)
	}
	fmt.Printf("[+] Corporate info JSON saved to: %s\n", jsonPath)

	return nil
}

// saveCorporateInfoCSV CSV 파일로 저장
func saveCorporateInfoCSV(result *CorporateInfoResult, filepath string) error {
	file, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// 헤더 작성
	headers := []string{"Domain", "Company", "Category", "Type", "Name", "Source", "URL", "Details"}
	if err := writer.Write(headers); err != nil {
		return err
	}

	// Crunchbase 결과
	for _, cb := range result.CrunchbaseResults {
		row := []string{
			result.Domain,
			result.Company,
			result.Category,
			"Crunchbase Company",
			cb.Name,
			"crunchbase",
			cb.URL,
			fmt.Sprintf("Founded: %s, Industry: %s, Location: %s, Employees: %s, Funding: %s", cb.Founded, cb.Industry, cb.Location, cb.Employees, cb.Funding),
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	// OpenCorporates 결과
	for _, oc := range result.OpenCorporatesResults {
		row := []string{
			result.Domain,
			result.Company,
			result.Category,
			"OpenCorporates Company",
			oc.Name,
			"opencorporates",
			oc.URL,
			fmt.Sprintf("Jurisdiction: %s, Company Number: %s, Status: %s", oc.Jurisdiction, oc.CompanyNumber, oc.Status),
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	// 자회사
	for _, sub := range result.Subsidiaries {
		row := []string{
			result.Domain,
			result.Company,
			result.Category,
			"Subsidiary",
			sub.Name,
			sub.Source,
			sub.URL,
			sub.Type,
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	// 파트너
	for _, partner := range result.Partners {
		row := []string{
			result.Domain,
			result.Company,
			result.Category,
			"Partner",
			partner.Name,
			partner.Source,
			partner.URL,
			partner.Type,
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	// 클라우드 자산
	for _, asset := range result.CloudAssets {
		row := []string{
			result.Domain,
			result.Company,
			result.Category,
			"Cloud Asset",
			asset.Service,
			asset.Source,
			asset.Domain,
			asset.Type,
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return nil
}

// saveCorporateInfoJSON JSON 파일로 저장
func saveCorporateInfoJSON(result *CorporateInfoResult, filepath string) error {
	file, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}
