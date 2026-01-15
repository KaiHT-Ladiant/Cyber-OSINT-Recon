package collector

import (
	"cyber-osint-recon/internal/models"
	"fmt"
	"net"
	"strings"
)

// CollectDNSRecords DNS 레코드 수집
func CollectDNSRecords(domain string) (*models.DNSRecords, error) {
	records := &models.DNSRecords{}

	// A 레코드
	if ips, err := net.LookupIP(domain); err == nil {
		for _, ip := range ips {
			if ip.To4() != nil {
				records.A = append(records.A, ip.String())
			} else {
				records.AAAA = append(records.AAAA, ip.String())
			}
		}
	}

	// MX 레코드
	if mxRecords, err := net.LookupMX(domain); err == nil {
		for _, mx := range mxRecords {
			records.MX = append(records.MX, models.MXRecord{
				Host: strings.TrimSuffix(mx.Host, "."),
				Pref: mx.Pref,
			})
		}
	}

	// NS 레코드
	if nsRecords, err := net.LookupNS(domain); err == nil {
		for _, ns := range nsRecords {
			records.NS = append(records.NS, strings.TrimSuffix(ns.Host, "."))
		}
	}

	// TXT 레코드
	if txtRecords, err := net.LookupTXT(domain); err == nil {
		records.TXT = txtRecords
	}

	// CNAME 레코드 (간접적으로 확인)
	if cname, err := net.LookupCNAME(domain); err == nil {
		if cname != domain+"." {
			records.CNAME = append(records.CNAME, strings.TrimSuffix(cname, "."))
		}
	}

	return records, nil
}

// GetIPInfo Collect IP address information
func GetIPInfo(ipStr string) (*models.IPInfo, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ipStr)
	}

	info := &models.IPInfo{
		IP: ipStr,
	}

	// Reverse DNS lookup
	if names, err := net.LookupAddr(ipStr); err == nil && len(names) > 0 {
		info.ReverseDNS = strings.TrimSuffix(names[0], ".")
		// Extract ISP information from reverse DNS if available
		if info.ReverseDNS != "" {
			parts := strings.Split(info.ReverseDNS, ".")
			if len(parts) > 0 {
				info.ISP = parts[0]
			}
		}
	}

	return info, nil
}
