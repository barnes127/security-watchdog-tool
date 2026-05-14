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

Installation
Clone the repository:
git clone <repo-url>
cd security-watchdog-tool

No external dependencies are currently required.

Usage
Run a scan against a project folder:
python3 watchdog.py sample_project

Example Findings
[HIGH] Possible secret found
[MEDIUM] Use of eval() can be dangerous
[HIGH] requests 2.19.0 matches CVE-2018-18074

Generated Reports
Reports are automatically generated inside:
reports/

Formats:
* JSON
* Markdown