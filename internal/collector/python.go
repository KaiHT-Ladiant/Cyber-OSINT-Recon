package collector

import (
	"cyber-osint-recon/internal/models"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

// pythonModulePath Path to Python modules directory
var pythonModulePath = "python_modules"

// runPythonScript Executes a Python script and returns JSON output
func runPythonScript(scriptName string, args ...string) ([]byte, error) {
	scriptPath := filepath.Join(pythonModulePath, scriptName)
	
	// Check if Python 3 is available
	cmd := exec.Command("python3", append([]string{scriptPath}, args...)...)
	output, err := cmd.Output()
	if err != nil {
		// Try python instead of python3
		cmd := exec.Command("python", append([]string{scriptPath}, args...)...)
		output, err = cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("failed to execute Python script %s: %w", scriptName, err)
		}
	}
	
	return output, nil
}

// CollectUsernameSherlock Uses Python Sherlock module to search for usernames
func CollectUsernameSherlock(username string) (*models.UsernameInfo, error) {
	output, err := runPythonScript("sherlock_username.py", username)
	if err != nil {
		return nil, err
	}
	
	var result struct {
		Username string `json:"username"`
		Platforms []struct {
			Platform string `json:"platform"`
			URL      string `json:"url"`
			Exists   bool   `json:"exists"`
			Verified bool   `json:"verified"`
		} `json:"platforms"`
		Error string `json:"error,omitempty"`
	}
	
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("failed to parse Python output: %w", err)
	}
	
	if result.Error != "" {
		return nil, fmt.Errorf("Python script error: %s", result.Error)
	}
	
	usernameInfo := &models.UsernameInfo{
		Usernames: make([]models.UsernameProfile, 0),
	}
	
	for _, platform := range result.Platforms {
		if platform.Exists {
			usernameInfo.Usernames = append(usernameInfo.Usernames, models.UsernameProfile{
				Username: result.Username,
				Platform: platform.Platform,
				URL:      platform.URL,
				Exists:   platform.Exists,
			})
		}
	}
	
	return usernameInfo, nil
}

// CollectEmailsTheHarvester Uses Python theHarvester module to collect emails
func CollectEmailsTheHarvester(domain, company string) ([]string, error) {
	output, err := runPythonScript("theharvester_email.py", domain, company)
	if err != nil {
		return nil, err
	}
	
	var result struct {
		Domain string `json:"domain"`
		Company string `json:"company"`
		Emails []struct {
			Email  string `json:"email"`
			Source string `json:"source"`
			Verified bool `json:"verified"`
		} `json:"emails"`
		Error string `json:"error,omitempty"`
	}
	
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("failed to parse Python output: %w", err)
	}
	
	if result.Error != "" {
		return nil, fmt.Errorf("Python script error: %s", result.Error)
	}
	
	emails := make([]string, 0)
	emailSet := make(map[string]bool)
	for _, emailData := range result.Emails {
		// Only include verified emails or emails from actual sources
		// Exclude speculative patterns: common_pattern, company_pattern
		source := emailData.Source
		if emailData.Verified || (source != "common_pattern" && source != "company_pattern") {
			email := strings.ToLower(strings.TrimSpace(emailData.Email))
			if email != "" && !emailSet[email] {
				emails = append(emails, email)
				emailSet[email] = true
			}
		}
	}

	return emails, nil
}

// CollectGitHubDorking Uses Python GitHub dorking module to find sensitive information
func CollectGitHubDorking(domain, company, githubToken string) ([]models.GitHubCodeTraceResult, error) {
	args := []string{domain, company}
	if githubToken != "" {
		args = append(args, githubToken)
	}
	
	output, err := runPythonScript("github_dorking.py", args...)
	if err != nil {
		return nil, err
	}
	
	var result struct {
		Domain   string `json:"domain"`
		Company  string `json:"company"`
		Findings []struct {
			Repository string `json:"repository"`
			File       string `json:"file"`
			URL        string `json:"url"`
			Type       string `json:"type"`
			Query      string `json:"query"`
		} `json:"findings"`
		Error string `json:"error,omitempty"`
	}
	
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("failed to parse Python output: %w", err)
	}
	
	if result.Error != "" {
		return nil, fmt.Errorf("Python script error: %s", result.Error)
	}
	
	results := make([]models.GitHubCodeTraceResult, 0)
	for _, finding := range result.Findings {
		// Determine type from query
		resultType := "code"
		if strings.Contains(strings.ToLower(finding.Query), "api_key") {
			resultType = "api_key"
		} else if strings.Contains(strings.ToLower(finding.Query), "password") {
			resultType = "password"
		} else if strings.Contains(strings.ToLower(finding.Query), "secret") {
			resultType = "secret"
		} else if strings.Contains(strings.ToLower(finding.Query), "credentials") {
			resultType = "secret"
		}
		
		results = append(results, models.GitHubCodeTraceResult{
			Repository: finding.Repository,
			File:       finding.File,
			URL:        finding.URL,
			Type:       resultType,
		})
	}
	
	return results, nil
}
