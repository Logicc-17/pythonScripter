# 🍪 Cookie Security Auditor

A Python script to identify insecure cookie configurations in web applications, detecting vulnerabilities that could lead to session hijacking, XSS attacks, and other security risks.

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

## Features
- Detects missing `Secure` flags (HTTP transmission risk)
- Identifies missing `HttpOnly` flags (XSS vulnerability)
- Analyzes excessive cookie expiration times
- Validates cookie scope (domain/path restrictions)
- Supports both command-line and interactive modes
- Browser-like User-Agent spoofing

## Installation
```bash
# Clone repository
git clone https://github.com/Logicc-17/pythonScripter.git
cd pythonScripter

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate    # Windows

# Install dependencies
pip install -r requirements.txt
