package reporter

import (
	"cyber-osint-recon/internal/models"
	"encoding/json"
	"os"
)

// GenerateJSONReport JSON 형식의 리포트 생성
func GenerateJSONReport(report *models.Report, filename string) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}

	if filename != "" {
		return os.WriteFile(filename, data, 0644)
	}

	// 파일명이 없으면 stdout에 출력
	_, err = os.Stdout.Write(data)
	return err
}
