package reporter

import (
	"cyber-osint-recon/internal/models"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/xuri/excelize/v2"
)

// GenerateExcelReport generates an Excel report with multiple sheets
func GenerateExcelReport(report *models.Report, filename string) error {
	if filename == "" {
		return fmt.Errorf("Excel filename cannot be empty")
	}

	// Ensure directory exists
	dir := filepath.Dir(filename)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory for Excel file: %w", err)
		}
	}

	f := excelize.NewFile()
	defer func() {
		if err := f.Close(); err != nil {
			fmt.Printf("[WARN] Failed to close Excel file: %v\n", err)
		}
	}()

	// Create sheets first
	sheets := []struct {
		name string
		fn   func(*excelize.File, *models.Report) error
	}{
		{"요약", writeSummarySheet},
		{"자산인벤토리", writeAssetInventorySheet},
		{"서브도메인", writeSubdomainsSheet},
		{"IP주소", writeIPAddressesSheet},
		{"이메일", writeEmailsSheet},
		{"Shodan_Censys", writeShodanCensysSheet},
		{"Web_Archive", writeWebArchiveSheet},
		{"Email_Pivot", writeEmailPivotSheet},
		{"Username_Extended", writeUsernameExtendedSheet},
		{"Corporate_Info", writeCorporateInfoSheet},
		{"Leak_Search", writeLeakSearchSheet},
		{"Data_Spillage", writeDataSpillageSheet},
		{"리스크_우선순위", writeRiskPrioritySheet},
		{"모니터링", writeMonitoringSheet},
	}

	// Create first sheet and immediately delete Sheet1
	if len(sheets) > 0 {
		firstSheet := sheets[0]
		_, err := f.NewSheet(firstSheet.name)
		if err != nil {
			return fmt.Errorf("failed to create sheet %s: %w", firstSheet.name, err)
		}
		// Switch to the new sheet before deleting Sheet1
		sheetIndex, err := f.GetSheetIndex(firstSheet.name)
		if err == nil && sheetIndex >= 0 {
			f.SetActiveSheet(sheetIndex)
		}
		// Now delete Sheet1
		_ = f.DeleteSheet("Sheet1")
		// Write data to first sheet
		if err := firstSheet.fn(f, report); err != nil {
			return fmt.Errorf("failed to write sheet %s: %w", firstSheet.name, err)
		}
		// Create remaining sheets
		for i := 1; i < len(sheets); i++ {
			sheet := sheets[i]
			_, err := f.NewSheet(sheet.name)
			if err != nil {
				return fmt.Errorf("failed to create sheet %s: %w", sheet.name, err)
			}
			if err := sheet.fn(f, report); err != nil {
				return fmt.Errorf("failed to write sheet %s: %w", sheet.name, err)
			}
		}
	}

	// Set active sheet to first sheet (요약)
	sheetIndex, err := f.GetSheetIndex("요약")
	if err == nil && sheetIndex >= 0 {
		f.SetActiveSheet(sheetIndex)
	}

	// Save file
	if err := f.SaveAs(filename); err != nil {
		return fmt.Errorf("failed to save Excel file: %w", err)
	}

	return nil
}

// writeSummarySheet writes summary information
func writeSummarySheet(f *excelize.File, report *models.Report) error {
	headers := []string{"항목", "값"}
	row := 1

	// Write headers
	for col, header := range headers {
		cell, _ := excelize.CoordinatesToCellName(col+1, row)
		f.SetCellValue("요약", cell, header)
	}
	row++

	// Write data
	data := [][]interface{}{
		{"도메인", report.Domain},
		{"회사", report.Company},
		{"생성일시", report.Timestamp.Format("2006-01-02 15:04:05")},
		{"서브도메인 수", len(report.Subdomains)},
		{"IP 주소 수", len(report.IPAddresses)},
		{"이메일 수", len(report.Emails)},
		{"Shodan/Censys 결과 수", len(report.ShodanCensys)},
		{"Web Archive 결과 수", len(report.WebArchive)},
		{"유출 검색 결과 수", len(report.DataSpillage)},
	}

	for _, rowData := range data {
		for col, value := range rowData {
			cell, _ := excelize.CoordinatesToCellName(col+1, row)
			f.SetCellValue("요약", cell, value)
		}
		row++
	}

	// Style headers
	style, _ := f.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Bold: true},
		Fill:      excelize.Fill{Type: "pattern", Color: []string{"#E0E0E0"}, Pattern: 1},
		Alignment: &excelize.Alignment{Horizontal: "center"},
	})
	f.SetCellStyle("요약", "A1", "B1", style)

	return nil
}

// writeAssetInventorySheet writes detailed asset inventory with risk assessment
func writeAssetInventorySheet(f *excelize.File, report *models.Report) error {
	headers := []string{"카테고리", "자산", "세부", "증거URL", "리스크", "설명"}
	row := 1

	// Write headers
	for col, header := range headers {
		cell, _ := excelize.CoordinatesToCellName(col+1, row)
		f.SetCellValue("자산인벤토리", cell, header)
	}
	row++

	// Collect assets from various sources
	var assets []models.AssetItem

	// Subdomains
	for _, subdomain := range report.Subdomains {
		risk := "저"
		details := ""
		evidenceURL := ""
		source := "crt.sh"

		// Check if it's an admin subdomain
		if strings.Contains(strings.ToLower(subdomain), "admin") ||
			strings.Contains(strings.ToLower(subdomain), "manage") ||
			strings.Contains(strings.ToLower(subdomain), "control") {
			risk = "중"
			details = "관리자 페이지"
		}

		// Find evidence from Shodan/Censys
		for _, sc := range report.ShodanCensys {
			if sc.Hostname == subdomain || strings.Contains(sc.Hostname, subdomain) {
				evidenceURL = fmt.Sprintf("Shodan/%s", sc.IP)
				if sc.Port == 443 {
					details = fmt.Sprintf("%d %s", sc.Port, sc.Service)
				}
				if len(sc.SecurityIssues) > 0 {
					risk = "중"
				}
				break
			}
		}

		assets = append(assets, models.AssetItem{
			Category:    "서브도메인",
			Asset:       subdomain,
			Details:     details,
			EvidenceURL: evidenceURL,
			Risk:        risk,
			Source:      source,
		})
	}

	// IP Addresses
	for _, ipInfo := range report.IPAddresses {
		risk := "저"
		details := ""
		evidenceURL := ""
		source := "DNS"

		// Check Shodan/Censys for this IP
		for _, sc := range report.ShodanCensys {
			if sc.IP == ipInfo.IP {
				evidenceURL = fmt.Sprintf("Shodan/%s", sc.IP)
				details = fmt.Sprintf("%d %s", sc.Port, sc.Service)
				if len(sc.SecurityIssues) > 0 {
					risk = "중"
				}
				source = "Shodan"
				break
			}
		}

		assets = append(assets, models.AssetItem{
			Category:    "IP",
			Asset:       ipInfo.IP,
			Details:     details,
			EvidenceURL: evidenceURL,
			Risk:        risk,
			Source:      source,
		})
	}

	// Emails
	for _, email := range report.Emails {
		risk := "저"
		assets = append(assets, models.AssetItem{
			Category:    "이메일",
			Asset:       email,
			Details:     "이메일 주소",
			EvidenceURL: "",
			Risk:        risk,
			Source:      "WHOIS",
		})
	}

	// Leak Search Results
	for _, leak := range report.DataSpillage {
		risk := leak.Severity
		if risk == "high" {
			risk = "고"
		} else if risk == "medium" {
			risk = "중"
		} else {
			risk = "저"
		}
		assets = append(assets, models.AssetItem{
			Category:    "유출정보",
			Asset:       leak.URL,
			Details:     leak.Type,
			EvidenceURL: leak.URL,
			Risk:        risk,
			Source:      leak.Source,
			Description: leak.Description,
		})
	}

	// Write assets
	for _, asset := range assets {
		rowData := []interface{}{
			asset.Category,
			asset.Asset,
			asset.Details,
			asset.EvidenceURL,
			asset.Risk,
			asset.Description,
		}
		for col, value := range rowData {
			cell, _ := excelize.CoordinatesToCellName(col+1, row)
			f.SetCellValue("자산인벤토리", cell, value)
		}
		row++
	}

	// Style headers
	style, _ := f.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Bold: true},
		Fill:      excelize.Fill{Type: "pattern", Color: []string{"#E0E0E0"}, Pattern: 1},
		Alignment: &excelize.Alignment{Horizontal: "center"},
	})
	f.SetCellStyle("자산인벤토리", "A1", "F1", style)

	// Auto-fit columns
	f.SetColWidth("자산인벤토리", "A", "A", 15)
	f.SetColWidth("자산인벤토리", "B", "B", 40)
	f.SetColWidth("자산인벤토리", "C", "C", 20)
	f.SetColWidth("자산인벤토리", "D", "D", 30)
	f.SetColWidth("자산인벤토리", "E", "E", 10)
	f.SetColWidth("자산인벤토리", "F", "F", 50)

	return nil
}

// writeSubdomainsSheet writes subdomains
func writeSubdomainsSheet(f *excelize.File, report *models.Report) error {
	headers := []string{"서브도메인", "발견일시"}
	row := 1

	for col, header := range headers {
		cell, _ := excelize.CoordinatesToCellName(col+1, row)
		f.SetCellValue("서브도메인", cell, header)
	}
	row++

	for _, subdomain := range report.Subdomains {
		f.SetCellValue("서브도메인", fmt.Sprintf("A%d", row), subdomain)
		f.SetCellValue("서브도메인", fmt.Sprintf("B%d", row), report.Timestamp.Format("2006-01-02 15:04:05"))
		row++
	}

	style, _ := f.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Bold: true},
		Fill:      excelize.Fill{Type: "pattern", Color: []string{"#E0E0E0"}, Pattern: 1},
		Alignment: &excelize.Alignment{Horizontal: "center"},
	})
	f.SetCellStyle("서브도메인", "A1", "B1", style)

	return nil
}

// writeIPAddressesSheet writes IP addresses
func writeIPAddressesSheet(f *excelize.File, report *models.Report) error {
	headers := []string{"IP 주소", "Reverse DNS", "국가", "ISP"}
	row := 1

	for col, header := range headers {
		cell, _ := excelize.CoordinatesToCellName(col+1, row)
		f.SetCellValue("IP주소", cell, header)
	}
	row++

	for _, ipInfo := range report.IPAddresses {
		f.SetCellValue("IP주소", fmt.Sprintf("A%d", row), ipInfo.IP)
		f.SetCellValue("IP주소", fmt.Sprintf("B%d", row), ipInfo.ReverseDNS)
		f.SetCellValue("IP주소", fmt.Sprintf("C%d", row), ipInfo.Country)
		f.SetCellValue("IP주소", fmt.Sprintf("D%d", row), ipInfo.ISP)
		row++
	}

	style, _ := f.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Bold: true},
		Fill:      excelize.Fill{Type: "pattern", Color: []string{"#E0E0E0"}, Pattern: 1},
		Alignment: &excelize.Alignment{Horizontal: "center"},
	})
	f.SetCellStyle("IP주소", "A1", "D1", style)

	return nil
}

// writeEmailsSheet writes emails
func writeEmailsSheet(f *excelize.File, report *models.Report) error {
	headers := []string{"이메일", "발견일시"}
	row := 1

	for col, header := range headers {
		cell, _ := excelize.CoordinatesToCellName(col+1, row)
		f.SetCellValue("이메일", cell, header)
	}
	row++

	for _, email := range report.Emails {
		f.SetCellValue("이메일", fmt.Sprintf("A%d", row), email)
		f.SetCellValue("이메일", fmt.Sprintf("B%d", row), report.Timestamp.Format("2006-01-02 15:04:05"))
		row++
	}

	style, _ := f.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Bold: true},
		Fill:      excelize.Fill{Type: "pattern", Color: []string{"#E0E0E0"}, Pattern: 1},
		Alignment: &excelize.Alignment{Horizontal: "center"},
	})
	f.SetCellStyle("이메일", "A1", "B1", style)

	return nil
}

// writeShodanCensysSheet writes Shodan/Censys results
func writeShodanCensysSheet(f *excelize.File, report *models.Report) error {
	headers := []string{"IP", "포트", "서비스", "버전", "Banner", "Source", "Hostname", "리스크"}
	row := 1

	for col, header := range headers {
		cell, _ := excelize.CoordinatesToCellName(col+1, row)
		f.SetCellValue("Shodan_Censys", cell, header)
	}
	row++

	for _, sc := range report.ShodanCensys {
		risk := "저"
		if len(sc.SecurityIssues) > 0 {
			risk = "중"
		}
		f.SetCellValue("Shodan_Censys", fmt.Sprintf("A%d", row), sc.IP)
		f.SetCellValue("Shodan_Censys", fmt.Sprintf("B%d", row), sc.Port)
		f.SetCellValue("Shodan_Censys", fmt.Sprintf("C%d", row), sc.Service)
		f.SetCellValue("Shodan_Censys", fmt.Sprintf("D%d", row), sc.Version)
		f.SetCellValue("Shodan_Censys", fmt.Sprintf("E%d", row), truncateString(sc.Banner, 100))
		f.SetCellValue("Shodan_Censys", fmt.Sprintf("F%d", row), sc.Source)
		f.SetCellValue("Shodan_Censys", fmt.Sprintf("G%d", row), sc.Hostname)
		f.SetCellValue("Shodan_Censys", fmt.Sprintf("H%d", row), risk)
		row++
	}

	style, _ := f.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Bold: true},
		Fill:      excelize.Fill{Type: "pattern", Color: []string{"#E0E0E0"}, Pattern: 1},
		Alignment: &excelize.Alignment{Horizontal: "center"},
	})
	f.SetCellStyle("Shodan_Censys", "A1", "H1", style)

	return nil
}

// writeWebArchiveSheet writes web archive results
func writeWebArchiveSheet(f *excelize.File, report *models.Report) error {
	headers := []string{"URL", "타임스탬프", "타입", "Snapshot URL"}
	row := 1

	for col, header := range headers {
		cell, _ := excelize.CoordinatesToCellName(col+1, row)
		f.SetCellValue("Web_Archive", cell, header)
	}
	row++

	for _, wa := range report.WebArchive {
		f.SetCellValue("Web_Archive", fmt.Sprintf("A%d", row), wa.URL)
		f.SetCellValue("Web_Archive", fmt.Sprintf("B%d", row), wa.Timestamp.Format("2006-01-02 15:04:05"))
		f.SetCellValue("Web_Archive", fmt.Sprintf("C%d", row), wa.Type)
		f.SetCellValue("Web_Archive", fmt.Sprintf("D%d", row), wa.SnapshotURL)
		row++
	}

	style, _ := f.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Bold: true},
		Fill:      excelize.Fill{Type: "pattern", Color: []string{"#E0E0E0"}, Pattern: 1},
		Alignment: &excelize.Alignment{Horizontal: "center"},
	})
	f.SetCellStyle("Web_Archive", "A1", "D1", style)

	return nil
}

// writeEmailPivotSheet writes email pivot results
func writeEmailPivotSheet(f *excelize.File, report *models.Report) error {
	headers := []string{"도메인", "이메일 포맷", "샘플 이메일", "Holehe 결과", "유출 정보"}
	row := 1

	for col, header := range headers {
		cell, _ := excelize.CoordinatesToCellName(col+1, row)
		f.SetCellValue("Email_Pivot", cell, header)
	}
	row++

	// Write EmailPivotResults if available
	if report.EmailPivot != nil {
		emailFormat := ""
		sampleEmail := ""
		if len(report.EmailPivot.RelatedDomains) > 0 {
			domain := report.EmailPivot.RelatedDomains[0]
			f.SetCellValue("Email_Pivot", fmt.Sprintf("A%d", row), domain)
		}
		if report.EmailPivot.Email != "" {
			sampleEmail = report.EmailPivot.Email
		}
		f.SetCellValue("Email_Pivot", fmt.Sprintf("B%d", row), emailFormat)
		f.SetCellValue("Email_Pivot", fmt.Sprintf("C%d", row), sampleEmail)
		row++
	}

	style, _ := f.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Bold: true},
		Fill:      excelize.Fill{Type: "pattern", Color: []string{"#E0E0E0"}, Pattern: 1},
		Alignment: &excelize.Alignment{Horizontal: "center"},
	})
	f.SetCellStyle("Email_Pivot", "A1", "E1", style)

	return nil
}

// writeUsernameExtendedSheet writes extended username results
func writeUsernameExtendedSheet(f *excelize.File, report *models.Report) error {
	headers := []string{"Username", "Platform", "URL", "Exists"}
	row := 1

	for col, header := range headers {
		cell, _ := excelize.CoordinatesToCellName(col+1, row)
		f.SetCellValue("Username_Extended", cell, header)
	}
	row++

	if report.Usernames != nil {
		for _, username := range report.Usernames.Usernames {
			f.SetCellValue("Username_Extended", fmt.Sprintf("A%d", row), username.Username)
			f.SetCellValue("Username_Extended", fmt.Sprintf("B%d", row), username.Platform)
			f.SetCellValue("Username_Extended", fmt.Sprintf("C%d", row), username.URL)
			f.SetCellValue("Username_Extended", fmt.Sprintf("D%d", row), username.Exists)
			row++
		}
	}

	style, _ := f.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Bold: true},
		Fill:      excelize.Fill{Type: "pattern", Color: []string{"#E0E0E0"}, Pattern: 1},
		Alignment: &excelize.Alignment{Horizontal: "center"},
	})
	f.SetCellStyle("Username_Extended", "A1", "D1", style)

	return nil
}

// writeCorporateInfoSheet writes corporate information
func writeCorporateInfoSheet(f *excelize.File, report *models.Report) error {
	headers := []string{"Source", "Subsidiaries", "Partners", "Cloud Assets", "Employees", "Founded"}
	row := 1

	for col, header := range headers {
		cell, _ := excelize.CoordinatesToCellName(col+1, row)
		f.SetCellValue("Corporate_Info", cell, header)
	}
	row++

	if report.CorporateInfo != nil {
		f.SetCellValue("Corporate_Info", fmt.Sprintf("A%d", row), report.CorporateInfo.Source)
		f.SetCellValue("Corporate_Info", fmt.Sprintf("B%d", row), strings.Join(report.CorporateInfo.Subsidiaries, ", "))
		f.SetCellValue("Corporate_Info", fmt.Sprintf("C%d", row), strings.Join(report.CorporateInfo.Partners, ", "))
		f.SetCellValue("Corporate_Info", fmt.Sprintf("D%d", row), strings.Join(report.CorporateInfo.CloudAssets, ", "))
		f.SetCellValue("Corporate_Info", fmt.Sprintf("E%d", row), report.CorporateInfo.Employees)
		f.SetCellValue("Corporate_Info", fmt.Sprintf("F%d", row), report.CorporateInfo.Founded)
		row++
	}

	style, _ := f.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Bold: true},
		Fill:      excelize.Fill{Type: "pattern", Color: []string{"#E0E0E0"}, Pattern: 1},
		Alignment: &excelize.Alignment{Horizontal: "center"},
	})
	f.SetCellStyle("Corporate_Info", "A1", "F1", style)

	return nil
}

// writeLeakSearchSheet writes leak search results
func writeLeakSearchSheet(f *excelize.File, report *models.Report) error {
	headers := []string{"도메인", "Source", "Type", "URL", "Severity", "Description"}
	row := 1

	for col, header := range headers {
		cell, _ := excelize.CoordinatesToCellName(col+1, row)
		f.SetCellValue("Leak_Search", cell, header)
	}
	row++

	// Write DataSpillage results (which includes leak search results)
	for _, spill := range report.DataSpillage {
		severity := spill.Severity
		if severity == "high" {
			severity = "고"
		} else if severity == "medium" {
			severity = "중"
		} else {
			severity = "저"
		}
		f.SetCellValue("Leak_Search", fmt.Sprintf("A%d", row), report.Domain)
		f.SetCellValue("Leak_Search", fmt.Sprintf("B%d", row), spill.Source)
		f.SetCellValue("Leak_Search", fmt.Sprintf("C%d", row), spill.Type)
		f.SetCellValue("Leak_Search", fmt.Sprintf("D%d", row), spill.URL)
		f.SetCellValue("Leak_Search", fmt.Sprintf("E%d", row), severity)
		f.SetCellValue("Leak_Search", fmt.Sprintf("F%d", row), spill.Description)
		row++
	}

	style, _ := f.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Bold: true},
		Fill:      excelize.Fill{Type: "pattern", Color: []string{"#E0E0E0"}, Pattern: 1},
		Alignment: &excelize.Alignment{Horizontal: "center"},
	})
	f.SetCellStyle("Leak_Search", "A1", "F1", style)

	return nil
}

// writeDataSpillageSheet writes data spillage results
func writeDataSpillageSheet(f *excelize.File, report *models.Report) error {
	headers := []string{"Source", "Type", "URL", "Severity", "Date", "Description"}
	row := 1

	for col, header := range headers {
		cell, _ := excelize.CoordinatesToCellName(col+1, row)
		f.SetCellValue("Data_Spillage", cell, header)
	}
	row++

	for _, spill := range report.DataSpillage {
		date := ""
		if !spill.Date.IsZero() {
			date = spill.Date.Format("2006-01-02")
		}
		severity := spill.Severity
		if severity == "high" {
			severity = "고"
		} else if severity == "medium" {
			severity = "중"
		} else {
			severity = "저"
		}
		f.SetCellValue("Data_Spillage", fmt.Sprintf("A%d", row), spill.Source)
		f.SetCellValue("Data_Spillage", fmt.Sprintf("B%d", row), spill.Type)
		f.SetCellValue("Data_Spillage", fmt.Sprintf("C%d", row), spill.URL)
		f.SetCellValue("Data_Spillage", fmt.Sprintf("D%d", row), severity)
		f.SetCellValue("Data_Spillage", fmt.Sprintf("E%d", row), date)
		f.SetCellValue("Data_Spillage", fmt.Sprintf("F%d", row), spill.Description)
		row++
	}

	style, _ := f.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Bold: true},
		Fill:      excelize.Fill{Type: "pattern", Color: []string{"#E0E0E0"}, Pattern: 1},
		Alignment: &excelize.Alignment{Horizontal: "center"},
	})
	f.SetCellStyle("Data_Spillage", "A1", "F1", style)

	return nil
}

// writeRiskPrioritySheet writes risk priority assessment
func writeRiskPrioritySheet(f *excelize.File, report *models.Report) error {
	headers := []string{"우선순위", "리스크", "자산", "설명", "조치사항"}
	row := 1

	for col, header := range headers {
		cell, _ := excelize.CoordinatesToCellName(col+1, row)
		f.SetCellValue("리스크_우선순위", cell, header)
	}
	row++

	// Collect high-risk items
	var highRiskItems []models.AssetItem
	var mediumRiskItems []models.AssetItem
	var lowRiskItems []models.AssetItem

	// Categorize by risk
	for _, spill := range report.DataSpillage {
		item := models.AssetItem{
			Category:    "유출정보",
			Asset:       spill.URL,
			Details:     spill.Type,
			EvidenceURL: spill.URL,
			Description: spill.Description,
		}
		if spill.Severity == "high" {
			item.Risk = "고"
			highRiskItems = append(highRiskItems, item)
		} else if spill.Severity == "medium" {
			item.Risk = "중"
			mediumRiskItems = append(mediumRiskItems, item)
		} else {
			item.Risk = "저"
			lowRiskItems = append(lowRiskItems, item)
		}
	}

	priority := 1
	// Write high risk items
	for _, item := range highRiskItems {
		action := "즉시 조치 필요"
		f.SetCellValue("리스크_우선순위", fmt.Sprintf("A%d", row), priority)
		f.SetCellValue("리스크_우선순위", fmt.Sprintf("B%d", row), item.Risk)
		f.SetCellValue("리스크_우선순위", fmt.Sprintf("C%d", row), item.Asset)
		f.SetCellValue("리스크_우선순위", fmt.Sprintf("D%d", row), item.Description)
		f.SetCellValue("리스크_우선순위", fmt.Sprintf("E%d", row), action)
		row++
		priority++
	}

	// Write medium risk items
	for _, item := range mediumRiskItems {
		action := "조치 권장"
		f.SetCellValue("리스크_우선순위", fmt.Sprintf("A%d", row), priority)
		f.SetCellValue("리스크_우선순위", fmt.Sprintf("B%d", row), item.Risk)
		f.SetCellValue("리스크_우선순위", fmt.Sprintf("C%d", row), item.Asset)
		f.SetCellValue("리스크_우선순위", fmt.Sprintf("D%d", row), item.Description)
		f.SetCellValue("리스크_우선순위", fmt.Sprintf("E%d", row), action)
		row++
		priority++
	}

	style, _ := f.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Bold: true},
		Fill:      excelize.Fill{Type: "pattern", Color: []string{"#E0E0E0"}, Pattern: 1},
		Alignment: &excelize.Alignment{Horizontal: "center"},
	})
	f.SetCellStyle("리스크_우선순위", "A1", "E1", style)

	return nil
}

// writeMonitoringSheet writes monitoring setup information
func writeMonitoringSheet(f *excelize.File, report *models.Report) error {
	headers := []string{"자산", "카테고리", "모니터링 도구", "설정 URL", "설명"}
	row := 1

	for col, header := range headers {
		cell, _ := excelize.CoordinatesToCellName(col+1, row)
		f.SetCellValue("모니터링", cell, header)
	}
	row++

	// Add monitoring suggestions
	monitoringItems := []struct {
		asset     string
		category  string
		tool      string
		url       string
		desc      string
	}{
		{report.Domain, "도메인", "Visualping", fmt.Sprintf("https://visualping.io/?url=%s", report.Domain), "웹사이트 변화 감지"},
		{report.Domain, "도메인", "Shodan Monitor", fmt.Sprintf("https://www.shodan.io/monitor?query=hostname:%s", report.Domain), "Shodan 모니터링"},
		{report.Domain, "도메인", "Censys Monitor", fmt.Sprintf("https://search.censys.io/hosts?q=dns.names:%s", report.Domain), "Censys 모니터링"},
	}

	for _, item := range monitoringItems {
		f.SetCellValue("모니터링", fmt.Sprintf("A%d", row), item.asset)
		f.SetCellValue("모니터링", fmt.Sprintf("B%d", row), item.category)
		f.SetCellValue("모니터링", fmt.Sprintf("C%d", row), item.tool)
		f.SetCellValue("모니터링", fmt.Sprintf("D%d", row), item.url)
		f.SetCellValue("모니터링", fmt.Sprintf("E%d", row), item.desc)
		row++
	}

	style, _ := f.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Bold: true},
		Fill:      excelize.Fill{Type: "pattern", Color: []string{"#E0E0E0"}, Pattern: 1},
		Alignment: &excelize.Alignment{Horizontal: "center"},
	})
	f.SetCellStyle("모니터링", "A1", "E1", style)

	return nil
}
