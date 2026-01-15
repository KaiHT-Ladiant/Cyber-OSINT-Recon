package collector

import (
	"cyber-osint-recon/internal/models"
	"fmt"
	"strings"
	"time"

	"github.com/likexian/whois"
)

// CollectDomainInfo 도메인 WHOIS 정보 수집
func CollectDomainInfo(domain string) (*models.DomainInfo, error) {
	result, err := whois.Whois(domain)
	if err != nil {
		return nil, fmt.Errorf("WHOIS lookup failed: %w", err)
	}

	info := &models.DomainInfo{}

	// WHOIS 결과 파싱 (간단한 키워드 기반 파싱)
	whoisData := parseWhois(result)
	info.Registrar = whoisData["registrar"]
	
	if nsStr := whoisData["name_servers"]; nsStr != "" {
		info.NameServers = strings.Split(nsStr, ",")
		for i := range info.NameServers {
			info.NameServers[i] = strings.TrimSpace(info.NameServers[i])
		}
	}

	if whoisData["created"] != "" {
		if t, err := parseDate(whoisData["created"]); err == nil {
			info.CreatedDate = t
		}
	}
	if whoisData["updated"] != "" {
		if t, err := parseDate(whoisData["updated"]); err == nil {
			info.UpdatedDate = t
		}
	}
	if whoisData["expiry"] != "" {
		if t, err := parseDate(whoisData["expiry"]); err == nil {
			info.ExpiryDate = t
		}
	}

	info.Registrant = whoisData["registrant"]
	info.AdminContact = whoisData["admin"]
	info.TechContact = whoisData["tech"]

	return info, nil
}

// parseWhois WHOIS 결과 파싱
func parseWhois(data string) map[string]string {
	result := make(map[string]string)
	var nameServers []string

	lines := splitLines(data)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// 다양한 WHOIS 포맷 지원
		if strings.Contains(line, "Registrar:") {
			result["registrar"] = extractValue(line, "Registrar:")
		}
		if strings.Contains(line, "Creation Date:") || strings.Contains(line, "Created:") {
			result["created"] = extractValue(line, "Creation Date:", "Created:")
		}
		if strings.Contains(line, "Updated Date:") || strings.Contains(line, "Updated:") {
			result["updated"] = extractValue(line, "Updated Date:", "Updated:")
		}
		if strings.Contains(line, "Expiry Date:") || strings.Contains(line, "Expires:") {
			result["expiry"] = extractValue(line, "Expiry Date:", "Expires:")
		}
		if strings.Contains(line, "Name Server:") || strings.Contains(line, "nserver:") {
			ns := extractValue(line, "Name Server:", "nserver:")
			if ns != "" {
				nameServers = append(nameServers, ns)
			}
		}
		if strings.Contains(line, "Registrant:") {
			result["registrant"] = extractValue(line, "Registrant:")
		}
		if strings.Contains(line, "Admin Contact:") || strings.Contains(line, "admin-c:") {
			result["admin"] = extractValue(line, "Admin Contact:", "admin-c:")
		}
		if strings.Contains(line, "Tech Contact:") || strings.Contains(line, "tech-c:") {
			result["tech"] = extractValue(line, "Tech Contact:", "tech-c:")
		}
	}

	if len(nameServers) > 0 {
		result["name_servers"] = strings.Join(nameServers, ",")
	}

	return result
}

// 간단한 헬퍼 함수들
func splitLines(s string) []string {
	return strings.Split(s, "\n")
}

func extractValue(line string, prefixes ...string) string {
	for _, prefix := range prefixes {
		if strings.Contains(line, prefix) {
			idx := strings.Index(line, prefix)
			if idx >= 0 {
				val := strings.TrimSpace(line[idx+len(prefix):])
				// 콜론이나 공백 제거
				val = strings.TrimPrefix(val, ":")
				val = strings.TrimSpace(val)
				return val
			}
		}
	}
	return ""
}

func parseDate(dateStr string) (time.Time, error) {
	formats := []string{
		"2006-01-02",
		"2006-01-02 15:04:05",
		"02-Jan-2006",
		"2006-01-02T15:04:05Z",
		time.RFC3339,
		time.RFC1123,
	}

	for _, format := range formats {
		if t, err := time.Parse(format, dateStr); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("날짜 파싱 실패: %s", dateStr)
}

