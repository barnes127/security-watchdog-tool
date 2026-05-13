import json
from pathlib import Path


def load_known_vulnerabilities(vuln_file):
    path = Path(vuln_file)

    if not path.exists():
        return []

    try:
        with open(path, "r") as file:
            return json.load(file)
    except Exception:
        return []


def parse_requirements(requirements_file):
    packages = []

    try:
        lines = requirements_file.read_text(errors="ignore").splitlines()
    except Exception:
        return packages

    for line in lines:
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        if "==" in line:
            name, version = line.split("==", 1)
            packages.append({
                "name": name.strip(),
                "version": version.strip(),
                "ecosystem": "python",
            })

    return packages


def scan_cves(project_path, vuln_file="known_vulnerabilities.json"):
    project = Path(project_path)
    vulnerabilities = load_known_vulnerabilities(vuln_file)
    findings = []

    for requirements_file in project.rglob("requirements.txt"):
        packages = parse_requirements(requirements_file)

        for package in packages:
            for vuln in vulnerabilities:
                if package["ecosystem"] != vuln["ecosystem"]:
                    continue

                if package["name"] != vuln["package"]:
                    continue

                if package["version"] in vuln["affected_versions"]:
                    findings.append({
                        "type": "known_vulnerability",
                        "severity": vuln["severity"],
                        "file": str(requirements_file),
                        "package": package["name"],
                        "version": package["version"],
                        "cve": vuln["cve"],
                        "message": vuln["message"],
                    })

    return findings
