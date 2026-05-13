# Security Watchdog

Security Watchdog is a defensive security and integrity scanning tool designed to help developers identify potential risks inside local projects before deployment.

This tool scans projects for:

- Possible secrets and API keys
- Risky code patterns
- Dependency files
- Known vulnerabilities from a local CVE database
- Security findings and severity levels

Reports are generated in both JSON and Markdown formats for auditing and review.

---

# Features

## Current Features

- Project file scanning
- File type detection
- Secret detection
- Risky code detection
- Dependency detection
- Local CVE matching
- JSON report generation
- Markdown report generation
- Severity summaries
- Ignore system support

---

# Project Structure

```text
security-watchdog-tool/
├── watchdog.py
├── config.json
├── known_vulnerabilities.json
├── .watchdogignore
├── scanners/
├── reports/
├── tests/
└── sample_project/
