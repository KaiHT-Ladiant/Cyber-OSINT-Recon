package collector

import (
	"cyber-osint-recon/internal/models"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
)

// 웹 서버 시그니처
var webServerSignatures = map[string]string{
	"nginx":      "nginx",
	"apache":     "apache",
	"iis":        "microsoft-iis",
	"cloudflare": "cloudflare",
	"litespeed":  "litespeed",
	"caddy":      "caddy",
}

// 프레임워크 시그니처
var frameworkSignatures = map[string]string{
	"wordpress":  "wp-content",
	"drupal":     "drupal",
	"joomla":     "joomla",
	"react":      "react",
	"vue":        "vue.js",
	"angular":    "angular",
	"laravel":    "laravel",
	"django":     "django",
	"rails":      "rails",
	".net":       "asp.net",
}

// CDN 시그니처
var cdnSignatures = map[string]string{
	"cloudflare": "cloudflare",
	"akamai":     "akamai",
	"amazon":     "amazonaws",
	"cloudfront": "cloudfront",
	"maxcdn":     "maxcdn",
	"keycdn":     "keycdn",
	"fastly":     "fastly",
	"incapsula":  "incapsula",
}

// Analytics 시그니처
var analyticsSignatures = map[string]string{
	"google-analytics": "google-analytics.com",
	"gtag":            "googletagmanager.com",
	"facebook-pixel":  "facebook.net",
	"mixpanel":        "mixpanel.com",
	"segment":         "segment.com",
	"hotjar":          "hotjar.com",
}

// CollectTechStack 웹 기술 스택 정보 수집
func CollectTechStack(domain string) (*models.TechStack, error) {
	techStack := &models.TechStack{
		Headers: make(map[string]string),
	}

	url := "https://" + domain
	if !strings.HasPrefix(domain, "http") {
		url = "https://" + domain
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return nil
		},
	}

	resp, err := client.Get(url)
	if err != nil {
		return techStack, fmt.Errorf("failed to access website: %w", err)
	}
	defer resp.Body.Close()

	// HTTP 헤더 분석
	techStack.Headers = make(map[string]string)
	for key, values := range resp.Header {
		if len(values) > 0 {
			techStack.Headers[strings.ToLower(key)] = strings.Join(values, ", ")
		}
	}

	// 웹 서버 감지
	server := resp.Header.Get("Server")
	if server != "" {
		serverLower := strings.ToLower(server)
		for name, sig := range webServerSignatures {
			if strings.Contains(serverLower, sig) {
				techStack.WebServer = append(techStack.WebServer, name)
				break
			}
		}
	}

	// X-Powered-By 헤더 확인
	poweredBy := resp.Header.Get("X-Powered-By")
	if poweredBy != "" {
		poweredByLower := strings.ToLower(poweredBy)
		for name, sig := range frameworkSignatures {
			if strings.Contains(poweredByLower, sig) {
				techStack.Frameworks = append(techStack.Frameworks, name)
				break
			}
		}
	}

	// CDN 감지
	cdnHeaders := []string{"CF-Ray", "X-Cache", "X-CDN", "Server"}
	for _, header := range cdnHeaders {
		value := resp.Header.Get(header)
		if value != "" {
			valueLower := strings.ToLower(value)
			for name, sig := range cdnSignatures {
				if strings.Contains(valueLower, sig) {
					techStack.CDN = append(techStack.CDN, name)
					break
				}
			}
		}
	}

	// HTML 본문 분석
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err == nil {
		htmlContent, _ := doc.Html()
		htmlLower := strings.ToLower(htmlContent)

		// 프레임워크 감지 (HTML 내용 기반)
		for name, sig := range frameworkSignatures {
			if strings.Contains(htmlLower, sig) {
				found := false
				for _, fw := range techStack.Frameworks {
					if fw == name {
						found = true
						break
					}
				}
				if !found {
					techStack.Frameworks = append(techStack.Frameworks, name)
				}
			}
		}

		// CMS 감지
		cmsSignatures := map[string]string{
			"wordpress": "/wp-content/",
			"drupal":    "/sites/default/",
			"joomla":    "/joomla/",
			"magento":   "/magento/",
			"shopify":   "shopify",
		}
		for name, sig := range cmsSignatures {
			if strings.Contains(htmlLower, sig) {
				techStack.CMS = append(techStack.CMS, name)
			}
		}

		// JavaScript 라이브러리 감지
		doc.Find("script[src]").Each(func(i int, s *goquery.Selection) {
			src, exists := s.Attr("src")
			if exists {
				srcLower := strings.ToLower(src)
				if strings.Contains(srcLower, "jquery") {
					techStack.JavaScript = appendIfNotExists(techStack.JavaScript, "jquery")
				}
				if strings.Contains(srcLower, "react") {
					techStack.JavaScript = appendIfNotExists(techStack.JavaScript, "react")
				}
				if strings.Contains(srcLower, "vue") {
					techStack.JavaScript = appendIfNotExists(techStack.JavaScript, "vue.js")
				}
				if strings.Contains(srcLower, "angular") {
					techStack.JavaScript = appendIfNotExists(techStack.JavaScript, "angular")
				}
				if strings.Contains(srcLower, "bootstrap") {
					techStack.JavaScript = appendIfNotExists(techStack.JavaScript, "bootstrap")
				}
			}
		})

		// Analytics 감지
		doc.Find("script").Each(func(i int, s *goquery.Selection) {
			scriptContent, _ := s.Html()
			scriptLower := strings.ToLower(scriptContent)
			for name, sig := range analyticsSignatures {
				if strings.Contains(scriptLower, sig) {
					techStack.Analytics = appendIfNotExists(techStack.Analytics, name)
				}
			}
		})

		// 스크립트 src에서 Analytics 감지
		doc.Find("script[src]").Each(func(i int, s *goquery.Selection) {
			src, exists := s.Attr("src")
			if exists {
				srcLower := strings.ToLower(src)
				for name, sig := range analyticsSignatures {
					if strings.Contains(srcLower, sig) {
						techStack.Analytics = appendIfNotExists(techStack.Analytics, name)
					}
				}
			}
		})
	}

	return techStack, nil
}

// appendIfNotExists 슬라이스에 중복 없이 추가
func appendIfNotExists(slice []string, item string) []string {
	for _, s := range slice {
		if s == item {
			return slice
		}
	}
	return append(slice, item)
}
