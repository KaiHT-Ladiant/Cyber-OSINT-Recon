#!/usr/bin/env python3
"""
Sherlock-like username enumeration module
Searches for usernames across multiple platforms
"""
import json
import sys
import requests
from typing import List, Dict

def search_username(username: str) -> Dict:
    """
    Search for username across multiple platforms
    Returns JSON string with results
    """
    results = {
        "username": username,
        "platforms": []
    }
    
    platforms = {
        "github": f"https://github.com/{username}",
        "twitter": f"https://twitter.com/{username}",
        "linkedin": f"https://www.linkedin.com/in/{username}",
        "instagram": f"https://www.instagram.com/{username}",
        "facebook": f"https://www.facebook.com/{username}",
        "medium": f"https://medium.com/@{username}",
        "reddit": f"https://www.reddit.com/user/{username}",
        "pinterest": f"https://www.pinterest.com/{username}",
        "tumblr": f"https://{username}.tumblr.com",
        "flickr": f"https://www.flickr.com/people/{username}",
        "vimeo": f"https://vimeo.com/{username}",
        "soundcloud": f"https://soundcloud.com/{username}",
        "spotify": f"https://open.spotify.com/user/{username}",
        "youtube": f"https://www.youtube.com/@{username}",
    }
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }
    
    for platform, url in platforms.items():
        try:
            response = requests.get(url, headers=headers, timeout=5, allow_redirects=False)
            if response.status_code == 200:
                results["platforms"].append({
                    "platform": platform,
                    "url": url,
                    "exists": True,
                    "verified": False
                })
            elif response.status_code == 301 or response.status_code == 302:
                # Redirect might indicate profile exists
                results["platforms"].append({
                    "platform": platform,
                    "url": url,
                    "exists": True,
                    "verified": False
                })
        except:
            pass
    
    return results

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Username required"}))
        sys.exit(1)
    
    username = sys.argv[1]
    results = search_username(username)
    print(json.dumps(results))
