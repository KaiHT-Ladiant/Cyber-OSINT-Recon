package models

import "time"

// DomainReport Information for a single domain
type DomainReport struct {
	Domain          string              `json:"domain"`
	DomainInfo      *DomainInfo         `json:"domain_info,omitempty"`
	DNSRecords      *DNSRecords         `json:"dns_records,omitempty"`
	Subdomains      []string            `json:"subdomains,omitempty"`
	IPAddresses     []IPInfo            `json:"ip_addresses,omitempty"`
	Emails          []string            `json:"emails,omitempty"`
	TechStack       *TechStack          `json:"tech_stack,omitempty"`
	ShodanCensys    []ShodanCensysResult `json:"shodan_censys,omitempty"`
	WebArchive      []WebArchiveResult   `json:"web_archive,omitempty"`
	VirusTotal      []VirusTotalResult   `json:"virustotal,omitempty"`
}

// Report OSINT collection result report structure
type Report struct {
	Domain          string              `json:"domain"` // Primary domain (for backward compatibility)
	Domains         []DomainReport      `json:"domains,omitempty"` // All domains information
	Company         string              `json:"company,omitempty"`
	Timestamp       time.Time           `json:"timestamp"`
	DomainInfo      *DomainInfo         `json:"domain_info,omitempty"` // Primary domain info (for backward compatibility)
	DNSRecords      *DNSRecords         `json:"dns_records,omitempty"` // Primary domain DNS (for backward compatibility)
	Subdomains      []string            `json:"subdomains,omitempty"` // All subdomains from all domains
	IPAddresses     []IPInfo            `json:"ip_addresses,omitempty"` // All IPs from all domains
	Emails          []string            `json:"emails,omitempty"` // All emails from all domains
	TechStack       *TechStack          `json:"tech_stack,omitempty"` // Primary domain tech stack (for backward compatibility)
	EmailPivot      *EmailPivot         `json:"email_pivot,omitempty"`
	Usernames       *UsernameInfo       `json:"usernames,omitempty"`
	SocialMedia     *SocialMediaInfo    `json:"social_media,omitempty"`
	CompanyBackground *CompanyBackground `json:"company_background,omitempty"`
	RelatedAssets   []RelatedAsset      `json:"related_assets,omitempty"`
	CodeRepos       []CodeRepository    `json:"code_repos,omitempty"`
	Documents       []Document          `json:"documents,omitempty"`
	DataSpillage    []DataSpillage      `json:"data_spillage,omitempty"`
	SecurityThreats []SecurityThreat    `json:"security_threats,omitempty"`
	AssetInventory  *AssetInventory     `json:"asset_inventory,omitempty"`
	ShodanCensys    []ShodanCensysResult `json:"shodan_censys,omitempty"` // All Shodan/Censys results from all domains
	WebArchive      []WebArchiveResult   `json:"web_archive,omitempty"` // All web archive results from all domains
	GitHubCodeTrace []GitHubCodeTraceResult `json:"github_code_trace,omitempty"`
	EmployeeProfiles []EmployeeProfile   `json:"employee_profiles,omitempty"`
	CorporateInfo   *CorporateInfo       `json:"corporate_info,omitempty"`
	VirusTotal      []VirusTotalResult   `json:"virustotal,omitempty"` // All VirusTotal results from all domains
}

// DomainInfo Domain WHOIS information
type DomainInfo struct {
	Registrar    string    `json:"registrar,omitempty"`
	CreatedDate  time.Time `json:"created_date,omitempty"`
	UpdatedDate  time.Time `json:"updated_date,omitempty"`
	ExpiryDate   time.Time `json:"expiry_date,omitempty"`
	NameServers  []string  `json:"name_servers,omitempty"`
	Registrant   string    `json:"registrant,omitempty"`
	AdminContact string    `json:"admin_contact,omitempty"`
	TechContact  string    `json:"tech_contact,omitempty"`
}

// DNSRecords DNS records information
type DNSRecords struct {
	A     []string `json:"a,omitempty"`
	AAAA  []string `json:"aaaa,omitempty"`
	MX    []MXRecord `json:"mx,omitempty"`
	NS    []string `json:"ns,omitempty"`
	TXT   []string `json:"txt,omitempty"`
	CNAME []string `json:"cname,omitempty"`
}

// MXRecord MX 레코드 정보
type MXRecord struct {
	Host string `json:"host"`
	Pref uint16 `json:"pref"`
}

// IPInfo IP address information
type IPInfo struct {
	IP         string  `json:"ip"`
	ReverseDNS string  `json:"reverse_dns,omitempty"`
	Country    string  `json:"country,omitempty"`
	Region     string  `json:"region,omitempty"`
	City       string  `json:"city,omitempty"`
	ISP        string  `json:"isp,omitempty"`
	Org        string  `json:"org,omitempty"`
	Latitude   float64 `json:"latitude,omitempty"`
	Longitude  float64 `json:"longitude,omitempty"`
}

// TechStack Web technology stack information
type TechStack struct {
	WebServer    []string          `json:"web_server,omitempty"`
	Frameworks   []string          `json:"frameworks,omitempty"`
	CDN          []string          `json:"cdn,omitempty"`
	Analytics    []string          `json:"analytics,omitempty"`
	CMS          []string          `json:"cms,omitempty"`
	JavaScript   []string          `json:"javascript,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"`
}

// EmailPivot Email pivot information (domains/users found via email)
type EmailPivot struct {
	Email        string   `json:"email"`
	RelatedDomains []string `json:"related_domains,omitempty"`
	BreachData   []BreachInfo `json:"breach_data,omitempty"`
}

// BreachInfo Data breach information
type BreachInfo struct {
	Source       string    `json:"source"`
	Date         time.Time `json:"date,omitempty"`
	Description  string    `json:"description,omitempty"`
}

// UsernameInfo Extended username information
type UsernameInfo struct {
	Usernames    []UsernameProfile `json:"usernames,omitempty"`
}

// UsernameProfile Username profile on various platforms
type UsernameProfile struct {
	Username     string   `json:"username"`
	Platform     string   `json:"platform"`
	URL          string   `json:"url,omitempty"`
	Exists       bool     `json:"exists"`
}

// SocialMediaInfo Social media information
type SocialMediaInfo struct {
	Profiles     []SocialProfile `json:"profiles,omitempty"`
}

// SocialProfile Social media profile
type SocialProfile struct {
	Platform     string   `json:"platform"`
	Username     string   `json:"username,omitempty"`
	URL          string   `json:"url"`
	Verified     bool     `json:"verified,omitempty"`
	Followers    int      `json:"followers,omitempty"`
}

// CompanyBackground Company background information
type CompanyBackground struct {
	Description  string   `json:"description,omitempty"`
	Founded      string   `json:"founded,omitempty"`
	Industry     string   `json:"industry,omitempty"`
	Location     string   `json:"location,omitempty"`
	Employees    string   `json:"employees,omitempty"`
	Revenue      string   `json:"revenue,omitempty"`
	Website      string   `json:"website,omitempty"`
	SocialLinks  []string `json:"social_links,omitempty"`
}

// RelatedAsset Related asset information
type RelatedAsset struct {
	Type         string   `json:"type"` // domain, ip, email, etc.
	Value        string   `json:"value"`
	Relation     string   `json:"relation,omitempty"`
	Source       string   `json:"source,omitempty"`
}

// CodeRepository Code repository information
type CodeRepository struct {
	Platform     string   `json:"platform"` // github, gitlab, bitbucket, etc.
	Username     string   `json:"username,omitempty"`
	Repository   string   `json:"repository,omitempty"`
	URL          string   `json:"url"`
	Public       bool     `json:"public"`
	Description  string   `json:"description,omitempty"`
	Language     string   `json:"language,omitempty"`
}

// Document Document repository information
type Document struct {
	Platform     string   `json:"platform"` // google drive, dropbox, etc.
	Title        string   `json:"title,omitempty"`
	URL          string   `json:"url"`
	Type         string   `json:"type,omitempty"`
	Public       bool     `json:"public"`
}

// DataSpillage Data spillage information
type DataSpillage struct {
	Source       string   `json:"source"`
	Type         string   `json:"type"` // pastebin, github, s3, etc.
	URL          string   `json:"url,omitempty"`
	Description  string   `json:"description,omitempty"`
	Severity     string   `json:"severity,omitempty"`
	Date         time.Time `json:"date,omitempty"`
}

// SecurityThreat Security threat information
type SecurityThreat struct {
	Type         string   `json:"type"` // vulnerability, malware, phishing, etc.
	Title        string   `json:"title"`
	Description  string   `json:"description,omitempty"`
	Severity     string   `json:"severity,omitempty"`
	Source       string   `json:"source,omitempty"`
	URL          string   `json:"url,omitempty"`
	Date         time.Time `json:"date,omitempty"`
}

// ShodanCensysResult Shodan/Censys scan result
type ShodanCensysResult struct {
	IP              string   `json:"ip"`
	Port            int      `json:"port"`
	Service         string   `json:"service,omitempty"`
	Banner          string   `json:"banner,omitempty"`
	Version         string   `json:"version,omitempty"`
	Source          string   `json:"source"` // "shodan" or "censys"
	Hostname        string   `json:"hostname,omitempty"`
	SSLInfo         string   `json:"ssl_info,omitempty"`
	Product         string   `json:"product,omitempty"`
	OS              string   `json:"os,omitempty"`
	Vulnerabilities []string `json:"vulnerabilities,omitempty"`
	SecurityIssues  []string `json:"security_issues,omitempty"`
	IsHTTPS         bool     `json:"is_https,omitempty"`
	CertificateCN   string   `json:"certificate_cn,omitempty"`
}

// WebArchiveResult Web archive (Wayback Machine) result
type WebArchiveResult struct {
	URL         string   `json:"url"`
	Timestamp   time.Time `json:"timestamp"`
	SnapshotURL string   `json:"snapshot_url"`
	Content     string   `json:"content,omitempty"` // First few lines of content
	Type        string   `json:"type,omitempty"` // "login_page", "api_key", "email", "js_hardcoded"
}

// GitHubCodeTraceResult GitHub code trace result
type GitHubCodeTraceResult struct {
	Repository  string   `json:"repository"`
	File        string   `json:"file"`
	URL         string   `json:"url"`
	Line        int      `json:"line,omitempty"`
	Content     string   `json:"content,omitempty"`
	Type        string   `json:"type"` // "email", "api_key", "password", "secret", "old_login"
}

// EmployeeProfile Employee profile information
type EmployeeProfile struct {
	Name        string   `json:"name,omitempty"`
	Email       string   `json:"email,omitempty"`
	Username    string   `json:"username"`
	Platform    string   `json:"platform"`
	URL         string   `json:"url"`
	Verified    bool     `json:"verified,omitempty"`
	Role        string   `json:"role,omitempty"`
	Company     string   `json:"company,omitempty"`
}

// CorporateInfo Corporate information from Crunchbase/OpenCorporates
type CorporateInfo struct {
	Source          string   `json:"source"` // "crunchbase" or "opencorporates"
	Subsidiaries    []string `json:"subsidiaries,omitempty"`
	Partners        []string `json:"partners,omitempty"`
	RelatedDomains  []string `json:"related_domains,omitempty"`
	CloudAssets     []string `json:"cloud_assets,omitempty"` // AWS, Azure, GCP buckets, etc.
	FinancialInfo   string   `json:"financial_info,omitempty"`
	Employees       string   `json:"employees,omitempty"`
	Founded         string   `json:"founded,omitempty"`
}

// VirusTotalResult VirusTotal verification result
type VirusTotalResult struct {
	Resource      string   `json:"resource"` // domain, ip, url, hash
	Type          string   `json:"type"` // "domain", "ip", "url", "file"
	Positives     int      `json:"positives"` // Number of positive detections
	Total         int      `json:"total"` // Total scans
	ScanDate      time.Time `json:"scan_date,omitempty"`
	Permalink     string   `json:"permalink,omitempty"`
	Detections    []string `json:"detections,omitempty"` // Names of detecting engines
}

// AssetInventory Asset inventory information
type AssetInventory struct {
	Domains      []string `json:"domains,omitempty"`
	IPs          []string `json:"ips,omitempty"`
	Subdomains   []string `json:"subdomains,omitempty"`
	Emails       []string `json:"emails,omitempty"`
	Services     []ServiceInfo `json:"services,omitempty"`
	Assets       []AssetItem `json:"assets,omitempty"` // Detailed asset inventory with risk assessment
}

// AssetItem Detailed asset item with risk assessment
type AssetItem struct {
	Category     string `json:"category"`     // "서브도메인", "IP", "이메일", "서비스", "코드저장소", "문서", "유출정보"
	Asset        string `json:"asset"`        // e.g., "admin.domain.co.kr", "1.2.3.4"
	Details      string `json:"details"`      // e.g., "443 Apache", "NS 서버"
	EvidenceURL  string `json:"evidence_url"` // e.g., "crt.sh/12345", "Shodan/abc"
	Risk         string `json:"risk"`         // "고", "중", "저"
	Source       string `json:"source"`       // "crt.sh", "Shodan", "Censys", "DNSDumpster", etc.
	Description  string `json:"description,omitempty"`
}

// ServiceInfo Service information
type ServiceInfo struct {
	Port         int      `json:"port"`
	Protocol     string   `json:"protocol"`
	Service      string   `json:"service,omitempty"`
	Version      string   `json:"version,omitempty"`
}
