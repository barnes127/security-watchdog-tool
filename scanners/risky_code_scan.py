from pathlib import Path


RISKY_PATTERNS = [
    ("eval(", "Use of eval() can be dangerous"),
    ("exec(", "Use of exec() can be dangerous"),
    ("os.system(", "os.system() may allow command injection"),
    ("subprocess.run(", "Check subprocess input handling"),
    ("subprocess.Popen(", "Check subprocess input handling"),
    ("child_process.exec(", "Potential command execution risk"),
    ("dangerouslySetInnerHTML", "Potential XSS risk"),
]


SUPPORTED_EXTENSIONS = [
    ".py",
    ".js",
    ".ts",
    ".tsx",
]


def scan_for_risky_code(project_path):
    project = Path(project_path)
    findings = []

    for file_path in project.rglob("*"):
        if not file_path.is_file():
            continue

        if file_path.suffix not in SUPPORTED_EXTENSIONS:
            continue

        try:
            lines = file_path.read_text(errors="ignore").splitlines()
        except Exception:
            continue

        for line_number, line in enumerate(lines, start=1):
            for pattern, message in RISKY_PATTERNS:
                if pattern in line:
                    findings.append({
                        "type": "risky_code",
                        "severity": "MEDIUM",
                        "file": str(file_path),
                        "line": line_number,
                        "pattern": pattern,
                        "message": message,
                    })

    return findings
