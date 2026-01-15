package collector

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// LoadFindingsFromDirectory loads all findings from CSV/JSON files in Findings directory
// and returns them as structured data
func LoadFindingsFromDirectory(findingsDir string) (map[string]interface{}, error) {
	findings := make(map[string]interface{})

	if _, err := os.Stat(findingsDir); os.IsNotExist(err) {
		return findings, nil // Directory doesn't exist, return empty
	}

	files, err := os.ReadDir(findingsDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read Findings directory: %w", err)
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}

		filename := file.Name()
		fullPath := filepath.Join(findingsDir, filename)

		// Process JSON files
		if strings.HasSuffix(filename, ".json") {
			data, err := os.ReadFile(fullPath)
			if err != nil {
				fmt.Printf("[!] Failed to read %s: %v\n", filename, err)
				continue
			}

			var jsonData interface{}
			if err := json.Unmarshal(data, &jsonData); err != nil {
				fmt.Printf("[!] Failed to parse JSON %s: %v\n", filename, err)
				continue
			}

			// Store by file type
			if strings.Contains(filename, "email_pivot") {
				findings["email_pivot"] = jsonData
			} else if strings.Contains(filename, "username_extended") {
				findings["username_extended"] = jsonData
			} else if strings.Contains(filename, "corporate_info") {
				findings["corporate_info"] = jsonData
			} else if strings.Contains(filename, "leak_search") {
				findings["leak_search"] = jsonData
			}
		}

		// Process CSV files (optional - can be used for additional data)
		// CSV data is already included in JSON, so we skip it
	}

	return findings, nil
}

// CleanupFindingsDirectory deletes all files in the Findings directory
func CleanupFindingsDirectory(findingsDir string) error {
	if _, err := os.Stat(findingsDir); os.IsNotExist(err) {
		return nil // Directory doesn't exist, nothing to clean
	}

	files, err := os.ReadDir(findingsDir)
	if err != nil {
		return fmt.Errorf("failed to read Findings directory: %w", err)
	}

	deletedCount := 0
	for _, file := range files {
		if file.IsDir() {
			continue
		}

		fullPath := filepath.Join(findingsDir, file.Name())
		if err := os.Remove(fullPath); err != nil {
			fmt.Printf("[!] Failed to delete %s: %v\n", file.Name(), err)
			continue
		}
		deletedCount++
		fmt.Printf("[*] Deleted: %s\n", file.Name())
	}

	if deletedCount > 0 {
		fmt.Printf("[+] Cleaned up %d file(s) from Findings directory\n", deletedCount)
	}

	return nil
}

// ReadCSVFile reads a CSV file and returns its contents as a slice of maps
func ReadCSVFile(filepath string) ([]map[string]string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}

	if len(records) == 0 {
		return nil, nil
	}

	// First row is headers
	headers := records[0]
	results := make([]map[string]string, 0, len(records)-1)

	for i := 1; i < len(records); i++ {
		row := make(map[string]string)
		for j, header := range headers {
			if j < len(records[i]) {
				row[header] = records[i][j]
			}
		}
		results = append(results, row)
	}

	return results, nil
}
