#!/usr/bin/env python3
"""
🛡️ Enhanced Cookie Security Auditor
Detects missing Secure/HttpOnly flags, overly long expirations, and other cookie misconfigurations
"""

import requests
from urllib.parse import urlparse
import sys

DEFAULT_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
}

def normalize_url(url):
    """Ensure URL has proper scheme"""
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    return url

def audit_cookies(url):
    try:
        url = normalize_url(url)
        print(f"\n🔍 Scanning: {url}")
        
        response = requests.get(
            url, 
            headers=DEFAULT_HEADERS,
            timeout=10,
            allow_redirects=True
        )
        
        cookies = response.cookies
        if not cookies:
            print("[!] No cookies detected in response")
            return False

        print(f"\n🍪 Found {len(cookies)} cookie(s):")
        
        vulns = {
            'missing_secure': 0,
            'missing_httponly': 0,
            'long_expiry': 0
        }

        for cookie in cookies:
            print(f"\n  Cookie Name: {cookie.name}")
            print(f"  Domain: {cookie.domain or 'Not set'}")
            print(f"  Path: {cookie.path or '/'}")
            
            if not cookie.secure:
                print("  🚨 Missing Secure flag (Transmission over HTTP possible)")
                vulns['missing_secure'] += 1
            
            if not cookie.has_nonstandard_attr('HttpOnly'):
                print("  🚨 Missing HttpOnly flag (Accessible via JavaScript)")
                vulns['missing_httponly'] += 1
            
            if cookie.expires:
                days = cookie.expires / 86400  
                if days > 30:
                    print(f"  ⚠️  Long expiration: {days:.1f} days")
                    vulns['long_expiry'] += 1

        print("\n📊 Vulnerability Summary:")
        print(f"  Missing Secure: {vulns['missing_secure']}")
        print(f"  Missing HttpOnly: {vulns['missing_httponly']}")
        print(f"  Overly Long Expiration: {vulns['long_expiry']}")
        
        return True

    except requests.exceptions.SSLError:
        print("[!] SSL Certificate Verification Failed (try http://)")
    except requests.exceptions.RequestException as e:
        print(f"[!] Connection Error: {str(e)}")
    except Exception as e:
        print(f"[!] Unexpected Error: {str(e)}")
    
    return False

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = input("Enter target URL (e.g., https://anything.mw): ").strip()
    
    audit_cookies(target)