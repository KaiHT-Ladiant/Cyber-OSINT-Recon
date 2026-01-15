package collector

import (
	"fmt"
	"net"
	"strings"
	"sync"
)

// SearchDomainsByCompany 회사명으로 도메인 검색
func SearchDomainsByCompany(companyName string) ([]string, error) {
	var domains []string
	var mutex sync.Mutex
	var wg sync.WaitGroup

	// 회사명 정규화 (소문자, 공백 제거 등)
	normalized := normalizeCompanyName(companyName)
	
	// 가능한 도메인 후보 생성
	candidates := generateDomainCandidates(normalized)

	// 각 후보에 대해 DNS 조회로 확인
	jobs := make(chan string, len(candidates))
	
	for w := 0; w < 10; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for candidate := range jobs {
				if isValidDomain(candidate) {
					mutex.Lock()
					domains = append(domains, candidate)
					mutex.Unlock()
				}
			}
		}()
	}

	// 작업 전송
	for _, candidate := range candidates {
		jobs <- candidate
	}
	close(jobs)

	wg.Wait()

	if len(domains) == 0 {
		return nil, fmt.Errorf("could not find domains for company name '%s'. Please try with a domain directly or check the company name", companyName)
	}

	return domains, nil
}

// containsKorean checks if string contains Korean characters
func containsKorean(s string) bool {
	for _, r := range s {
		if r >= 0xAC00 && r <= 0xD7A3 {
			return true
		}
	}
	return false
}

// normalizeCompanyName normalizes company name
func normalizeCompanyName(name string) string {
	name = strings.TrimSpace(name)
	
	// If contains Korean, keep as-is for .kr domain search
	// Remove common suffixes for English company names
	if !containsKorean(name) {
		name = strings.ToLower(name)
		name = strings.ReplaceAll(name, " inc.", "")
		name = strings.ReplaceAll(name, " inc", "")
		name = strings.ReplaceAll(name, " ltd.", "")
		name = strings.ReplaceAll(name, " ltd", "")
		name = strings.ReplaceAll(name, " corp.", "")
		name = strings.ReplaceAll(name, " corp", "")
		name = strings.ReplaceAll(name, " co.", "")
		name = strings.ReplaceAll(name, " co", "")
		name = strings.ReplaceAll(name, " llc", "")
		name = strings.ReplaceAll(name, " limited", "")
		
		// Remove spaces and special characters for English names
		name = strings.ReplaceAll(name, " ", "")
		name = strings.ReplaceAll(name, "-", "")
		name = strings.ReplaceAll(name, "_", "")
	}
	
	return name
}

// generateDomainCandidates generates possible domain candidates from company name
func generateDomainCandidates(normalizedName string) []string {
	var candidates []string
	hasKorean := containsKorean(normalizedName)
	
	// For Korean company names, try .kr and .co.kr TLDs with the name as-is
	// For English company names, try various TLDs
	if hasKorean {
		tlds := []string{"kr", "co.kr"}
		// Try with company name as-is for Korean domains
		for _, tld := range tlds {
			// Korean domains often use the company name directly
			candidates = append(candidates, fmt.Sprintf("%s.%s", normalizedName, tld))
		}
		// Also try common patterns for Korean companies
		englishPatterns := []string{
			"company", "corp", "group", "tech", "systems", "solutions",
		}
		for _, pattern := range englishPatterns {
			for _, tld := range tlds {
				candidates = append(candidates, fmt.Sprintf("%s%s.%s", normalizedName, pattern, tld))
			}
		}
	} else {
		// English company names
		tlds := []string{"com", "net", "org", "co.kr", "kr", "io", "tech", "ai"}
		
		// Basic patterns
		patterns := []string{
			normalizedName,
			normalizedName + "corp",
			normalizedName + "corp",
		}
		
		// Hyphen variations
		if len(normalizedName) > 3 {
			patterns = append(patterns, addHyphenVariations(normalizedName)...)
		}

		// Remove duplicates
		patternMap := make(map[string]bool)
		var uniquePatterns []string
		for _, pattern := range patterns {
			if !patternMap[pattern] && len(pattern) > 0 {
				patternMap[pattern] = true
				uniquePatterns = append(uniquePatterns, pattern)
			}
		}

		// Combine with TLDs
		for _, pattern := range uniquePatterns {
			for _, tld := range tlds {
				candidates = append(candidates, fmt.Sprintf("%s.%s", pattern, tld))
			}
		}
	}

	return candidates
}

// addHyphenVariations 하이픈 변형 추가 (간단한 버전)
func addHyphenVariations(name string) []string {
	var variations []string
	
	// 3자 이상일 때만 하이픈 추가 시도
	if len(name) >= 4 {
		// 간단히 중간에 하이픈 하나 추가
		if len(name) > 6 {
			mid := len(name) / 2
			variations = append(variations, name[:mid]+"-"+name[mid:])
		}
	}
	
	return variations
}

// isValidDomain 도메인이 유효한지 확인 (DNS 조회)
func isValidDomain(domain string) bool {
	// 간단한 도메인 형식 체크
	if !strings.Contains(domain, ".") {
		return false
	}
	
	// DNS 조회
	_, err := net.LookupHost(domain)
	return err == nil
}

// ExtractCompanyNameFromDomain 도메인에서 회사명 추출 (역방향 검색에 사용)
func ExtractCompanyNameFromDomain(domain string) string {
	// www. 제거
	domain = strings.TrimPrefix(domain, "www.")
	
	// TLD 제거
	parts := strings.Split(domain, ".")
	if len(parts) > 1 {
		domain = strings.Join(parts[:len(parts)-1], ".")
	}
	
	return domain
}
