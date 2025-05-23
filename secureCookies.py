🍪 Advanced Cookie Security Auditor

Python Version
License
Overview

The Advanced Cookie Security Auditor is a professional-grade tool designed to identify cookie misconfigurations and web security header vulnerabilities. This tool provides comprehensive scanning capabilities to help security professionals and developers ensure their web applications implement proper security controls for cookies and headers.
Key Features

    🔍 Comprehensive Cookie Analysis:

        Secure flag verification

        HttpOnly flag detection

        SameSite policy evaluation

        Domain and path scope validation

        Expiration time analysis

        Prefix requirements checking

    🛡️ Security Header Auditing:

        Content-Security-Policy presence

        X-Frame-Options validation

        Strict-Transport-Security verification

        X-Content-Type-Options checking

    📊 Professional Reporting:

        Color-coded terminal output

        JSON/CSV/TXT report generation

        Vulnerability statistics

        Scan duration tracking

    ⚙️ Flexible Operation:

        Single URL or batch scanning

        Configurable request delays

        Custom timeout settings

        HTTP/HTTPS protocol selection

Installation
Prerequisites

    Python 3.7+

    pip package manager

Setup
bash

git clone https://github.com/your-repo/cookie-security-auditor.git
cd cookie-security-auditor
pip install -r requirements.txt

Usage
Basic Scan
bash

python cookie_auditor.py https://example.com

Advanced Options
bash

python cookie_auditor.py --help

Common Commands
bash

# Scan with verbose output
python cookie_auditor.py https://example.com --verbose

# Batch scan from file
python cookie_auditor.py --batch urls.txt

# Force HTTP protocol
python cookie_auditor.py http://example.com --http

# Generate JSON report
python cookie_auditor.py https://example.com --output report.json

Output Samples
Terminal Output

Terminal Output Example
JSON Report
json

{
  "url": "https://example.com",
  "cookies": [
    {
      "name": "sessionid",
      "domain": "example.com",
      "path": "/",
      "secure": true,
      "httponly": true,
      "samesite": "Lax"
    }
  ],
  "vulnerabilities": {
    "missing_secure": 0,
    "missing_httponly": 0,
    "weak_samesite": 0,
    "long_expiry": 0,
    "missing_prefix": 0,
    "header_issues": [
      "Missing X-Frame-Options: Clickjacking protection"
    ]
  }
}

Security Checks Performed
Check	Description	Risk Level
Secure Flag	Ensures cookies are only sent over HTTPS	Critical
HttpOnly Flag	Prevents JavaScript access to cookies	High
SameSite Policy	Protects against CSRF attacks	Medium
Cookie Prefixes	Validates __Secure- and __Host- prefixes	Medium
HSTS Header	Enforces HTTPS connections	High
CSP Header	Mitigates XSS attacks	Critical
X-Frame-Options	Prevents clickjacking	High
Best Practices Detected

    ✅ Secure flag set on sensitive cookies

    ✅ HttpOnly flag preventing client-side access

    ✅ Proper SameSite policies (Strict/Lax)

    ✅ Appropriate cookie prefixes

    ✅ Security headers properly configured

    ✅ Reasonable cookie expiration times

License

This project is licensed under the MIT License - see the LICENSE file for details.
Contributing

We welcome contributions! Please see our Contribution Guidelines for details.
Support

For issues or feature requests, please open an issue.

Disclaimer: This tool is designed for authorized security testing only. Always obtain proper authorization before scanning any website. The developers are not responsible for misuse of this software.
