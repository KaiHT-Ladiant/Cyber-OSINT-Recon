package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Config API 키 설정 구조체
type Config struct {
	ShodanAPIKey     string `json:"shodan_api_key"`
	CensysToken      string `json:"censys_token"`
	VirusTotalAPIKey string `json:"virustotal_api_key"`
}

// LoadConfig 설정 파일 로드
// 우선순위: 현재 디렉토리 > 홈 디렉토리
func LoadConfig() (*Config, error) {
	config := &Config{}

	// 1. 현재 디렉토리의 config.json 확인
	currentDir, err := os.Getwd()
	if err == nil {
		currentConfigPath := filepath.Join(currentDir, "config.json")
		if _, err := os.Stat(currentConfigPath); err == nil {
			if data, err := os.ReadFile(currentConfigPath); err == nil {
				if err := json.Unmarshal(data, config); err == nil {
					return config, nil
				}
			}
		}
	}

	// 2. 홈 디렉토리의 .cyber-osint-recon.json 확인
	homeDir, err := os.UserHomeDir()
	if err == nil {
		homeConfigPath := filepath.Join(homeDir, ".cyber-osint-recon.json")
		if _, err := os.Stat(homeConfigPath); err == nil {
			if data, err := os.ReadFile(homeConfigPath); err == nil {
				if err := json.Unmarshal(data, config); err == nil {
					return config, nil
				}
			}
		}
	}

	// 설정 파일이 없으면 빈 Config 반환
	return config, nil
}

// SaveConfig 설정 파일 저장 (현재 디렉토리에)
func SaveConfig(config *Config, path string) error {
	if path == "" {
		// 기본값: 현재 디렉토리의 config.json
		currentDir, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("failed to get current directory: %w", err)
		}
		path = filepath.Join(currentDir, "config.json")
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// MergeConfig 명령줄 옵션과 설정 파일 병합 (명령줄 옵션이 우선)
func MergeConfig(fileConfig *Config, cmdShodan, cmdCensys, cmdVirusTotal string) (string, string, string) {
	shodan := cmdShodan
	if shodan == "" {
		shodan = fileConfig.ShodanAPIKey
	}

	censys := cmdCensys
	if censys == "" {
		censys = fileConfig.CensysToken
	}

	virustotal := cmdVirusTotal
	if virustotal == "" {
		virustotal = fileConfig.VirusTotalAPIKey
	}

	return shodan, censys, virustotal
}
