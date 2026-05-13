import json
from pathlib import Path
from datetime import datetime


def write_json_report(findings, output_dir="reports"):
    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")

    report_file = output_path / f"security-report-{timestamp}.json"

    with open(report_file, "w") as file:
        json.dump(findings, file, indent=4)

    return report_file


def write_markdown_report(findings, output_dir="reports"):
    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")

    report_file = output_path / f"security-report-{timestamp}.md"

    critical = sum(1 for f in findings if f["severity"] == "CRITICAL")
    high = sum(1 for f in findings if f["severity"] == "HIGH")
    medium = sum(1 for f in findings if f["severity"] == "MEDIUM")
    low = sum(1 for f in findings if f["severity"] == "LOW")
    info = sum(1 for f in findings if f["severity"] == "INFO")

    with open(report_file, "w") as file:
        file.write("# Security Watchdog Report\n\n")
        file.write(f"Generated: {datetime.now()}\n\n")

        file.write("## Summary\n\n")
        file.write(f"- Critical: {critical}\n")
        file.write(f"- High: {high}\n")
        file.write(f"- Medium: {medium}\n")
        file.write(f"- Low: {low}\n")
        file.write(f"- Info: {info}\n\n")

        file.write("## Findings\n\n")

        for finding in findings:
            file.write(
                f"### [{finding['severity']}] "
                f"{finding['type']}\n"
            )

            file.write(f"- File: {finding['file']}\n")

            if "line" in finding:
                file.write(f"- Line: {finding['line']}\n")

            file.write(f"- Message: {finding['message']}\n\n")

    return report_file
