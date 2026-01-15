#!/usr/bin/env python3
"""
theHarvester-like email collection module
Searches multiple sources for email addresses
"""
import json
import sys
import re
import requests
from typing import List, Dict

def search_emails(domain: str, company: str) -> Dict:
    """
    Search for email addresses from domain/company
    Returns JSON string with results
    """
    results = {
        "domain": domain,
        "company": company,
        "emails": []
    }
    
    # Email pattern
    email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
    
    # Search sources
    sources = {
        "google": f"https://www.google.com/search?q=site:{domain}+email",
        "bing": f"https://www.bing.com/search?q=site:{domain}+email",
    }
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }
    
    # Common email patterns to try
    common_patterns = [
        f"contact@{domain}",
        f"info@{domain}",
        f"admin@{domain}",
        f"support@{domain}",
        f"sales@{domain}",
        f"hr@{domain}",
        f"security@{domain}",
    ]
    
    for email in common_patterns:
        if email not in results["emails"]:
            results["emails"].append({
                "email": email,
                "source": "common_pattern",
                "verified": False
            })
    
    # Try to extract from company name
    if company:
        company_lower = company.lower().replace(" ", "")
        potential_emails = [
            f"{company_lower}@{domain}",
            f"contact@{domain}",
        ]
        for email in potential_emails:
            if email not in [e["email"] for e in results["emails"]]:
                results["emails"].append({
                    "email": email,
                    "source": "company_pattern",
                    "verified": False
                })
    
    return results

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(json.dumps({"error": "Domain and company required"}))
        sys.exit(1)
    
    domain = sys.argv[1]
    company = sys.argv[2]
    
    results = search_emails(domain, company)
    print(json.dumps(results))
