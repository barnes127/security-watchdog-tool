import sys
from pathlib import Path
from scanners.secret_scan import scan_for_secrets
from scanners.risky_code_scan import scan_for_risky_code
from scanners.dependency_scan import scan_dependencies
from scanners.report_writer import (
    write_json_report,
    write_markdown_report,
)
from scanners.cve_scan import scan_cves

SUPPORTED_FILES = {
    ".py": "Python",
    ".js": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "React TypeScript",
    ".json": "JSON",
    ".env": "Environment File",
    ".md": "Markdown",
}


IMPORTANT_FILENAMES = {
    "package.json": "Node Project",
    "requirements.txt": "Python Requirements",
    "pnpm-lock.yaml": "PNPM Lock File",
}

DEFAULT_IGNORES = {
    ".git",
    "node_modules",
    "venv",
    ".venv",
    "__pycache__",
    "dist",
    "build",
    "reports",
}

def load_ignores(project):
    ignore_file = project / ".watchdogignore"
    ignores = set(DEFAULT_IGNORES)

    if ignore_file.exists():
        lines = ignore_file.read_text(errors="ignore").splitlines()
        for line in lines:
            line = line.strip()
            if line and not line.startswith("#"):
                ignores.add(line)

    return ignores


def is_ignored(path, ignores):
    return any(part in ignores for part in path.parts)


def scan_project(project_path):
    project = Path(project_path)

    if not project.exists():
        print(f"Error: path does not exist: {project}")
        return

    if not project.is_dir():
        print(f"Error: path is not a folder: {project}")
        return

    ignores = load_ignores(project)

    print("Security Watchdog")
    print("-----------------")
    print(f"Scanning: {project.resolve()}\n")

    total_files = 0
    detected_files = []

    for file_path in project.rglob("*"):
        if is_ignored(file_path, ignores):
            continue 

        if file_path.is_file():
            total_files += 1

            # Check exact filenames first
            if file_path.name in IMPORTANT_FILENAMES:
                detected_files.append(
                    (file_path, IMPORTANT_FILENAMES[file_path.name])
                )

            # Check extensions
            elif file_path.suffix in SUPPORTED_FILES:
                detected_files.append(
                    (file_path, SUPPORTED_FILES[file_path.suffix])
                )

    print(f"Total files scanned: {total_files}\n")

    if detected_files:
        print("Detected files:")
        print("-----------------")

        for file_path, file_type in detected_files:
            print(f"[{file_type}] {file_path}")

    else:
        print("No supported files detected.")

    secret_findings = scan_for_secrets(project)

    if secret_findings:
        print("\nSecret Scan Findings:")
        print("---------------------")
        for finding in secret_findings:
            print(
                f"[{finding['severity']}] {finding['file']} "
                f"line {finding['line']}: {finding['message']}"
            )
    else:
        print("\nSecret Scan Findings:")
        print("---------------------")
        print("No possible secrets found.")

    risky_findings = scan_for_risky_code(project)

    if risky_findings:
        print("\nRisky Code Findings:")
        print("---------------------")

        for finding in risky_findings:
            print(
                f"[{finding['severity']}] "
                f"{finding['file']} "
                f"line {finding['line']}: "
                f"{finding['message']}"
            )
    else:
        print("\nRisky Code Findings:")
        print("---------------------")
        print("No risky code patterns found.")

    cve_findings = scan_cves(project)

    if cve_findings:
        print("\nKnown Vulnerability Findings:")
        print("---------------------")

        for finding in cve_findings:
            print(
                f"[{finding['severity']}] "
                f"{finding['package']} {finding['version']} "
                f"({finding['cve']}): "
                f"{finding['message']}"
            )
    else:
        print("\nKnown Vulnerability Findings:")
        print("---------------------")
        print("No known vulnerabilities found.")

    dependency_findings = scan_dependencies(project)

    if dependency_findings:
        print("\nDependency Findings:")
        print("---------------------")

        for finding in dependency_findings:
            print(
                f"[{finding['severity']}] "
                f"{finding['file']}: "
                f"{finding['message']}"
            )
    else:
        print("\nDependency Findings:")
        print("---------------------")
        print("No dependency files found.")

    all_findings = (
        secret_findings +
        risky_findings +
        dependency_findings +
        cve_findings
    )

    critical_count = sum(
        1 for finding in all_findings
        if finding["severity"] == "CRITICAL"
    )

    high_count = sum(
        1 for finding in all_findings
        if finding["severity"] == "HIGH"
    )

    medium_count = sum(
        1 for finding in all_findings
        if finding["severity"] == "MEDIUM"
    )

    low_count = sum(
        1 for finding in all_findings
        if finding["severity"] == "LOW"
    )

    info_count = sum(
        1 for finding in all_findings
        if finding["severity"] == "INFO"
    )

    print("\nSecurity Summary")
    print("---------------------")
    print(f"Critical: {critical_count}")
    print(f"High:     {high_count}")
    print(f"Medium:   {medium_count}")
    print(f"Low:      {low_count}")
    print(f"Info:     {info_count}")

    json_report = write_json_report(all_findings)
    markdown_report = write_markdown_report(all_findings)

    print("\nReports Generated:")
    print("---------------------")
    print(f"JSON: {json_report}")
    print(f"Markdown: {markdown_report}")

    print("\nScan complete.")


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 watchdog.py <project_path>")
        return

    project_path = sys.argv[1]
    scan_project(project_path)


if __name__ == "__main__":
    main()
