#!/usr/bin/env python3
"""
GitHub Dorking module for finding sensitive information
Searches GitHub repositories for emails, API keys, passwords, etc.
"""
import json
import sys
from github import Github
from typing import List, Dict

def search_github(domain: str, company: str, github_token: str = None) -> Dict:
    """
    Search GitHub for sensitive information related to domain/company
    Returns JSON string with results
    """
    results = {
        "domain": domain,
        "company": company,
        "findings": []
    }
    
    if not github_token:
        # Without token, we can only do limited searches
        # In production, use GitHub API token for better rate limits
        return results
    
    try:
        g = Github(github_token)
        
        # Search queries
        queries = [
            f'"{domain}" filename:config',
            f'"{domain}" filename:.env',
            f'"{domain}" filename:credentials',
            f'"{company}" filename:config',
            f'"{company}" filename:.env',
            f'"{company}" filename:credentials',
            f'"{domain}" extension:js "api_key"',
            f'"{domain}" extension:py "password"',
            f'"{domain}" extension:json "secret"',
        ]
        
        for query in queries:
            try:
                code_results = g.search_code(query)
                for code in code_results[:5]:  # Limit to 5 results per query
                    results["findings"].append({
                        "repository": code.repository.full_name,
                        "file": code.path,
                        "url": code.html_url,
                        "type": "code",
                        "query": query
                    })
            except Exception as e:
                # Rate limit or other error
                pass
                
    except Exception as e:
        results["error"] = str(e)
    
    return results

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(json.dumps({"error": "Domain and company required"}))
        sys.exit(1)
    
    domain = sys.argv[1]
    company = sys.argv[2]
    github_token = sys.argv[3] if len(sys.argv) > 3 else None
    
    results = search_github(domain, company, github_token)
    print(json.dumps(results))
