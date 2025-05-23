#!/usr/bin/env python3
"""
🛡️ Advanced Cookie Security Auditor
Detects cookie misconfigurations and web security headers with enhanced features
"""

import requests
from urllib.parse import urlparse
import sys
import argparse
import json
import os
from time import sleep
import random
from colorama import Fore, Style, init
from datetime import datetime
from typing import List, Dict, Optional, Union

# Initialize colorama for colored output
init(autoreset=True)

# Constants
DEFAULT_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
}

class AuditStats:
    """Track scanning statistics"""
    def __init__(self):
        self.total_sites = 0
        self.vulnerable_sites = 0
        self.start_time = datetime.now()
        
    def print_summary(self) -> None:
        """Print scan summary with colored output"""
        duration = datetime.now() - self.start_time
        print(f"\n{Fore.CYAN}=== Scan Summary ===")
        print(f"Sites scanned: {self.total_sites}")
        vuln_color = Fore.RED if self.vulnerable_sites else Fore.GREEN
        print(f"Vulnerable sites: {vuln_color}{self.vulnerable_sites}")
        print(f"Duration: {duration.total_seconds():.2f} seconds{Style.RESET_ALL}")

def parse_args() -> argparse.Namespace:
    """Configure command line arguments"""
    parser = argparse.ArgumentParser(
        description='Cookie Security Auditor - Detect insecure cookie configurations',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        'url', 
        nargs='?', 
        help='Target URL to scan (omit for interactive mode)'
    )
    parser.add_argument(
        '--http', 
        action='store_true', 
        help='Force HTTP protocol'
    )
    parser.add_argument(
        '--verbose', 
        '-v', 
        action='store_true', 
        help='Show detailed output'
    )
    parser.add_argument(
        '--output', 
        '-o', 
        help='Output file (JSON/CSV/TXT)'
    )
    parser.add_argument(
        '--batch', 
        '-b', 
        help='File containing list of URLs to scan'
    )
    parser.add_argument(
        '--delay', 
        type=float, 
        default=1.0, 
        help='Delay between requests (seconds)'
    )
    parser.add_argument(
        '--timeout',
        type=float,
        default=10.0,
        help='Request timeout in seconds'
    )
    return parser.parse_args()

def normalize_url(url: str, force_http: bool = False) -> str:
    """Ensure URL has proper scheme"""
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    if force_http:
        url = url.replace('https://', 'http://')
    return url.rstrip('/')

def analyze_cookie(cookie) -> Dict:
    """Perform comprehensive analysis of a single cookie"""
    analysis = {
        'name': cookie.name,
        'domain': cookie.domain or 'Not set',
        'path': cookie.path or '/',
        'secure': cookie.secure,
        'httponly': cookie.has_nonstandard_attr('HttpOnly'),
        'samesite': getattr(cookie, 'samesite', 'Not set').capitalize()
    }

    if cookie.expires:
        days = cookie.expires / 86400  # Convert seconds to days
        analysis['expiration_days'] = round(days, 1)
    
    return analysis

def check_headers(response) -> List[str]:
    """Analyze security headers for common vulnerabilities"""
    headers = response.headers
    issues = []
    
    security_headers = {
        'X-Frame-Options': 'Clickjacking protection',
        'Content-Security-Policy': 'XSS mitigation',
        'X-Content-Type-Options': 'MIME sniffing protection',
        'Strict-Transport-Security': 'HTTPS enforcement'
    }
    
    for header, description in security_headers.items():
        if header not in headers:
            issues.append(f"Missing {header}: {description}")
    
    return issues

def generate_report(results: List[Dict], format: str = 'text') -> str:
    """Generate output in multiple formats"""
    if format == 'json':
        return json.dumps(results, indent=2)
    elif format == 'csv':
        csv_lines = ['URL,Cookie Name,Domain,Path,Secure,HttpOnly,SameSite,Expiration']
        for result in results:
            for cookie in result['cookies']:
                csv_lines.append(
                    f"{result['url']},{cookie['name']},{cookie['domain']},"
                    f"{cookie['path']},{cookie['secure']},{cookie['httponly']},"
                    f"{cookie['samesite']},{cookie.get('expiration_days', 'N/A')}"
                )
        return '\n'.join(csv_lines)
    else:
        report = []
        for result in results:
            report.append(f"\n{Fore.BLUE}URL: {result['url']}")
            for cookie in result['cookies']:
                report.append(f"\n  {Fore.CYAN}Cookie: {cookie['name']}")
                report.append(f"  {'Domain:':<12} {cookie['domain']}")
                report.append(f"  {'Path:':<12} {cookie['path']}")
                report.append(f"  {'Secure:':<12} {Fore.GREEN if cookie['secure'] else Fore.RED}{cookie['secure']}")
                report.append(f"  {'HttpOnly:':<12} {Fore.GREEN if cookie['httponly'] else Fore.RED}{cookie['httponly']}")
                report.append(f"  {'SameSite:':<12} {cookie['samesite']}")
                if 'expiration_days' in cookie:
                    report.append(f"  {'Expires:':<12} {cookie['expiration_days']} days")
            
            if result['vulnerabilities']['header_issues']:
                report.append(f"\n  {Fore.MAGENTA}Header Issues:")
                for issue in result['vulnerabilities']['header_issues']:
                    report.append(f"    - {issue}")
        
        return '\n'.join(report)

def audit_cookies(url: str, stats: Optional[AuditStats] = None, args: Optional[argparse.Namespace] = None) -> Optional[Dict]:
    """Main auditing function with comprehensive checks"""
    try:
        # Configure request parameters
        force_http = args.http if args else False
        timeout = args.timeout if args else 10.0
        delay = args.delay if args else 1.0
        
        url = normalize_url(url, force_http)
        if stats:
            stats.total_sites += 1
        
        print(f"\n{Fore.BLUE}🔍 Scanning:{Style.RESET_ALL} {url}")
        
        # Random delay to avoid rate limiting
        sleep(delay * random.uniform(0.8, 1.2))
        
        # Make the request
        response = requests.get(
            url, 
            headers=DEFAULT_HEADERS,
            timeout=timeout,
            allow_redirects=True,
            verify=not force_http
        )
        
        cookies = response.cookies
        if not cookies:
            print(f"{Fore.YELLOW}[!] No cookies detected{Style.RESET_ALL}")
            return None

        print(f"\n{Fore.GREEN}🍪 Found {len(cookies)} cookie(s):{Style.RESET_ALL}")
        
        # Initialize results structure
        results = {
            'url': url,
            'cookies': [],
            'vulnerabilities': {
                'missing_secure': 0,
                'missing_httponly': 0,
                'weak_samesite': 0,
                'long_expiry': 0,
                'missing_prefix': 0,
                'header_issues': check_headers(response)
            }
        }

        # Analyze each cookie
        for cookie in cookies:
            cookie_data = analyze_cookie(cookie)
            results['cookies'].append(cookie_data)
            
            # Print cookie info
            if args and args.verbose:
                print(f"\n  {Fore.CYAN}Cookie: {cookie_data['name']}")
                print(f"  {'Domain:':<12} {cookie_data['domain']}")
                print(f"  {'Path:':<12} {cookie_data['path']}")
            
            # Check for vulnerabilities
            if not cookie_data['secure']:
                print(f"  {Fore.RED}🚨 Missing Secure flag (Transmission over HTTP possible){Style.RESET_ALL}")
                results['vulnerabilities']['missing_secure'] += 1
            
            if not cookie_data['httponly']:
                print(f"  {Fore.RED}🚨 Missing HttpOnly flag (Accessible via JavaScript){Style.RESET_ALL}")
                results['vulnerabilities']['missing_httponly'] += 1
            
            if cookie_data['samesite'].lower() not in ('strict', 'lax'):
                print(f"  {Fore.YELLOW}⚠️  Weak SameSite policy: {cookie_data['samesite']}{Style.RESET_ALL}")
                results['vulnerabilities']['weak_samesite'] += 1
            
            if 'expiration_days' in cookie_data and cookie_data['expiration_days'] > 30:
                print(f"  {Fore.YELLOW}⚠️  Long expiration: {cookie_data['expiration_days']} days{Style.RESET_ALL}")
                results['vulnerabilities']['long_expiry'] += 1
            
            if cookie_data['secure'] and not cookie_data['name'].startswith(('__Secure-', '__Host-')):
                print(f"  {Fore.YELLOW}⚠️  Secure cookie missing recommended prefix{Style.RESET_ALL}")
                results['vulnerabilities']['missing_prefix'] += 1

        # Print header issues if found
        if results['vulnerabilities']['header_issues']:
            print(f"\n{Fore.MAGENTA}🚨 Header Security Issues:{Style.RESET_ALL}")
            for issue in results['vulnerabilities']['header_issues']:
                print(f"  - {issue}")

        # Update statistics
        vuln_count = sum(
            v for k, v in results['vulnerabilities'].items() 
            if k != 'header_issues'
        )
        if vuln_count > 0 and stats:
            stats.vulnerable_sites += 1
        
        # Print summary
        print(f"\n{Fore.CYAN}📊 Vulnerability Summary:{Style.RESET_ALL}")
        for k, v in results['vulnerabilities'].items():
            if isinstance(v, int) and v > 0:
                print(f"  {k.replace('_', ' ').title()}: {Fore.RED if v else Fore.GREEN}{v}{Style.RESET_ALL}")
        
        return results

    except requests.exceptions.SSLError:
        print(f"{Fore.RED}[!] SSL Certificate Verification Failed (try --http){Style.RESET_ALL}")
    except requests.exceptions.TooManyRedirects:
        print(f"{Fore.RED}[!] Excessive redirects detected (possible redirect loop){Style.RESET_ALL}")
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[!] Connection Error: {str(e)}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Unexpected Error: {str(e)}{Style.RESET_ALL}")
    
    return None

def process_batch(file_path: str, args: argparse.Namespace) -> List[Dict]:
    """Process multiple URLs from a file"""
    stats = AuditStats()
    results = []
    
    try:
        with open(file_path) as f:
            urls = [line.strip() for line in f if line.strip()]
            
        for url in urls:
            result = audit_cookies(url, stats, args)
            if result:
                results.append(result)
    
    except FileNotFoundError:
        print(f"{Fore.RED}[!] Batch file not found: {file_path}{Style.RESET_ALL}")
    
    stats.print_summary()
    return results

def main() -> None:
    """Main execution function"""
    print("""
+-----------------------------------------------------------------------+
|__   __    _         _ _   __  __           _        _____ _     _     |
|\ \ / /__ | | ____ _(_|_) |  \/  | __ _  __| | ___  |_   _| |__ (_)___ |
| \ V / _ \| |/ / _` | | | | |\/| |/ _` |/ _` |/ _ \   | | | '_ \| / __||
|  | | (_) |   < (_| | | | | |  | | (_| | (_| |  __/   | | | | | | \__ \|
|  |_|\___/|_|\_\__,_|_|_| |_|  |_|\__,_|\__,_|\___|   |_| |_| |_|_|___/|
+-----------------------------------------------------------------------+
""")
    args = parse_args()
    all_results = []
    
    try:
        if args.batch:
            all_results = process_batch(args.batch, args)
        elif args.url:
            result = audit_cookies(args.url, None, args)
            if result:
                all_results.append(result)
        else:
            target = input(f"{Fore.BLUE}Enter target URL:{Style.RESET_ALL} ").strip()
            result = audit_cookies(target, None, args)
            if result:
                all_results.append(result)
        
        # Generate output if requested
        if args.output and all_results:
            output_format = 'json' if args.output.endswith('.json') else 'csv' if args.output.endswith('.csv') else 'text'
            report = generate_report(all_results, output_format)
            try:
                with open(args.output, 'w') as f:
                    f.write(report)
                print(f"\n{Fore.GREEN}✓ Report saved to {args.output}{Style.RESET_ALL}")
            except IOError as e:
                print(f"{Fore.RED}[!] Failed to write output: {str(e)}{Style.RESET_ALL}")
        
        # Print final results
        print(f"\n{Fore.CYAN}=== Audit Complete ===")
        if all_results:
            print(generate_report(all_results, 'text'))
        else:
            print(f"{Fore.YELLOW}No results to display.{Style.RESET_ALL}")
        print(f"======================{Style.RESET_ALL}")
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}⚠️  Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    main()
