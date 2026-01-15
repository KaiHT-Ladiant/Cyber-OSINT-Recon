package collector

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"golang.org/x/net/html"
)

var emailRegex = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)

// CollectEmails 도메인에서 이메일 주소 수집
func CollectEmails(domain string, maxDepth int) ([]string, error) {
	var emails []string
	visited := make(map[string]bool)
	
	baseURL := "https://" + domain
	if !strings.HasPrefix(domain, "http") {
		baseURL = "https://" + domain
	}
	
	return collectEmailsRecursive(baseURL, domain, maxDepth, 0, visited, emails)
}

// collectEmailsRecursive 재귀적으로 이메일 수집
func collectEmailsRecursive(url, domain string, maxDepth, currentDepth int, visited map[string]bool, emails []string) ([]string, error) {
	if currentDepth > maxDepth || visited[url] {
		return emails, nil
	}
	visited[url] = true

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		return emails, nil // 에러는 무시하고 계속 진행
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return emails, nil
	}

	// HTML 파싱
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return emails, nil
	}

	// 텍스트에서 이메일 추출
	text := doc.Text()
	foundEmails := emailRegex.FindAllString(text, -1)
	
	emailSet := make(map[string]bool)
	for _, email := range foundEmails {
		email = strings.ToLower(strings.TrimSpace(email))
		if strings.Contains(email, "@"+domain) && !emailSet[email] {
			emailSet[email] = true
			emails = append(emails, email)
		}
	}

	// 링크에서도 이메일 찾기
	doc.Find("a[href^='mailto:']").Each(func(i int, s *goquery.Selection) {
		href, exists := s.Attr("href")
		if exists {
			email := strings.TrimPrefix(href, "mailto:")
			email = strings.Split(email, "?")[0] // 쿼리 파라미터 제거
			email = strings.ToLower(strings.TrimSpace(email))
			if strings.Contains(email, "@"+domain) && !emailSet[email] {
				emailSet[email] = true
				emails = append(emails, email)
			}
		}
	})

	// 같은 도메인의 링크 따라가기
	if currentDepth < maxDepth {
		doc.Find("a[href]").Each(func(i int, s *goquery.Selection) {
			href, exists := s.Attr("href")
			if exists {
				absoluteURL := resolveURL(url, href)
				if isSameDomain(absoluteURL, domain) && !visited[absoluteURL] {
					newEmails, _ := collectEmailsRecursive(absoluteURL, domain, maxDepth, currentDepth+1, visited, emails)
					emails = newEmails
				}
			}
		})
	}

	return emails, nil
}

// resolveURL 상대 URL을 절대 URL로 변환
func resolveURL(base, relative string) string {
	if strings.HasPrefix(relative, "http://") || strings.HasPrefix(relative, "https://") {
		return relative
	}
	if strings.HasPrefix(relative, "//") {
		return "https:" + relative
	}
	if strings.HasPrefix(relative, "/") {
		// base URL에서 도메인 추출
		if strings.HasPrefix(base, "http://") || strings.HasPrefix(base, "https://") {
			parts := strings.Split(base, "/")
			if len(parts) >= 3 {
				return parts[0] + "//" + parts[2] + relative
			}
		}
		return base + relative
	}
	// 상대 경로
	lastSlash := strings.LastIndex(base, "/")
	if lastSlash >= 0 {
		return base[:lastSlash+1] + relative
	}
	return base + "/" + relative
}

// isSameDomain URL이 같은 도메인인지 확인
func isSameDomain(url, domain string) bool {
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		return false
	}
	
	url = strings.TrimPrefix(url, "http://")
	url = strings.TrimPrefix(url, "https://")
	
	parts := strings.Split(url, "/")
	if len(parts) > 0 {
		urlDomain := parts[0]
		return strings.HasSuffix(urlDomain, domain) || urlDomain == domain
	}
	return false
}

// ExtractEmailsFromText 텍스트에서 이메일 주소 추출
func ExtractEmailsFromText(text string) []string {
	emails := emailRegex.FindAllString(text, -1)
	
	emailSet := make(map[string]bool)
	var uniqueEmails []string
	
	for _, email := range emails {
		email = strings.ToLower(strings.TrimSpace(email))
		if !emailSet[email] {
			emailSet[email] = true
			uniqueEmails = append(uniqueEmails, email)
		}
	}
	
	return uniqueEmails
}

// SearchEmailFromWeb 웹에서 이메일 주소 검색 (Google Dorking 등)
func SearchEmailFromWeb(domain string, company string) []string {
	var emails []string
	
	// Google Dorking 패턴들
	patterns := []string{
		fmt.Sprintf("site:%s \"@%s\"", domain, domain),
		fmt.Sprintf("site:%s \"contact\" \"email\"", domain),
	}
	
	if company != "" {
		patterns = append(patterns, fmt.Sprintf("\"%s\" \"@%s\"", company, domain))
	}
	
	// 실제 구현은 검색 API 사용 필요 (Google Custom Search API 등)
	// 여기서는 기본적인 패턴만 반환
	
	return emails
}

// 이메일 유효성 검증
func isValidEmail(email string) bool {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return false
	}
	
	local := parts[0]
	domain := parts[1]
	
	if len(local) == 0 || len(local) > 64 {
		return false
	}
	
	if len(domain) == 0 || len(domain) > 255 {
		return false
	}
	
	return emailRegex.MatchString(email)
}

// HTML 노드에서 텍스트 추출 헬퍼
func extractTextFromNode(n *html.Node) string {
	var text strings.Builder
	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.TextNode {
			text.WriteString(n.Data)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(n)
	return text.String()
}
