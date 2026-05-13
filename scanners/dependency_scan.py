from pathlib import Path


DEPENDENCY_FILES = {
    "package.json": "Node.js",
    "requirements.txt": "Python",
    "pnpm-lock.yaml": "PNPM",
    "package-lock.json": "NPM",
    "yarn.lock": "Yarn",
    "Cargo.toml": "Rust",
}


def scan_dependencies(project_path):
    project = Path(project_path)
    findings = []

    for file_path in project.rglob("*"):
        if not file_path.is_file():
            continue

        filename = file_path.name

        if filename in DEPENDENCY_FILES:
            findings.append({
                "type": "dependency_file",
                "severity": "INFO",
                "file": str(file_path),
                "ecosystem": DEPENDENCY_FILES[filename],
                "message": (
                    f"Detected {DEPENDENCY_FILES[filename]} "
                    f"dependency file"
                ),
            })

    return findings
