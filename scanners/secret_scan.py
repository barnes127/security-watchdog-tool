from pathlib import Path


SECRET_PATTERNS = [
    "API_KEY",
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "PRIVATE_KEY",
]


def scan_for_secrets(project_path):
    project = Path(project_path)
    findings = []

    for file_path in project.rglob("*"):
        if not file_path.is_file():
            continue

        try:
            lines = file_path.read_text(errors="ignore").splitlines()
        except Exception:
            continue

        for line_number, line in enumerate(lines, start=1):
            for pattern in SECRET_PATTERNS:
                if pattern in line:
                    findings.append({
                        "type": "possible_secret",
                        "severity": "HIGH",
                        "file": str(file_path),
                        "line": line_number,
                        "pattern": pattern,
                        "message": f"Possible secret found: {pattern}",
                    })

    return findings
