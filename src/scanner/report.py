from datetime import datetime
from pathlib import Path
from typing import Optional

from .models import Finding, ScanResult, Severity


class ReportGenerator:
    def __init__(self, result: ScanResult):
        self.result = result

    def generate_markdown(self) -> str:
        sections = [
            self._header(),
            self._executive_summary(),
            self._statistics(),
            self._findings_by_severity(),
            self._findings_by_file(),
            self._tool_summary(),
            self._footer(),
        ]
        return "\n\n".join(sections)

    def _header(self) -> str:
        return f"""# Security Vulnerability Report

**Target:** `{self.result.target_path}`
**Scan Date:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
**Files Scanned:** {self.result.files_scanned}
**Scan Duration:** {self.result.scan_duration_seconds:.2f} seconds

---"""

    def _executive_summary(self) -> str:
        total = len(self.result.findings)
        if total == 0:
            return """## Executive Summary

✅ **No security vulnerabilities detected.**

The scan completed successfully and found no security issues in the analyzed codebase."""

        risk_level = self._calculate_risk_level()
        risk_emoji = {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🟡",
            "LOW": "🟢",
        }.get(risk_level, "⚪")

        return f"""## Executive Summary

{risk_emoji} **Overall Risk Level: {risk_level}**

The security scan identified **{total} potential vulnerabilities** in the codebase:

| Severity | Count |
|----------|-------|
| 🔴 Critical | {self.result.critical_count} |
| 🟠 High | {self.result.high_count} |
| 🟡 Medium | {self.result.medium_count} |
| 🟢 Low | {self.result.low_count} |
| ⚪ Info | {self.result.info_count} |

**Immediate action recommended for {self.result.critical_count + self.result.high_count} critical/high severity issues.**"""

    def _calculate_risk_level(self) -> str:
        if self.result.critical_count > 0:
            return "CRITICAL"
        if self.result.high_count > 0:
            return "HIGH"
        if self.result.medium_count > 0:
            return "MEDIUM"
        return "LOW"

    def _statistics(self) -> str:
        if not self.result.findings:
            return ""

        tools_used = set(f.tool for f in self.result.findings)
        findings_by_tool = {}
        for finding in self.result.findings:
            findings_by_tool[finding.tool] = findings_by_tool.get(finding.tool, 0) + 1

        cwe_counts: dict[str, int] = {}
        for finding in self.result.findings:
            if finding.cwe_id:
                cwe_counts[finding.cwe_id] = cwe_counts.get(finding.cwe_id, 0) + 1

        top_cwes = sorted(cwe_counts.items(), key=lambda x: x[1], reverse=True)[:5]

        stats = """## Scan Statistics

### Findings by Tool
| Tool | Findings |
|------|----------|
"""
        for tool, count in sorted(findings_by_tool.items()):
            stats += f"| {tool} | {count} |\n"

        if top_cwes:
            stats += """
### Top CWE Categories
| CWE | Count | Description |
|-----|-------|-------------|
"""
            for cwe, count in top_cwes:
                desc = self._get_cwe_description(cwe)
                stats += f"| {cwe} | {count} | {desc} |\n"

        return stats

    def _get_cwe_description(self, cwe_id: str) -> str:
        descriptions = {
            "CWE-22": "Path Traversal",
            "CWE-78": "OS Command Injection",
            "CWE-79": "Cross-site Scripting (XSS)",
            "CWE-89": "SQL Injection",
            "CWE-94": "Code Injection",
            "CWE-200": "Information Exposure",
            "CWE-259": "Hard-coded Password",
            "CWE-295": "Certificate Validation",
            "CWE-327": "Broken Cryptography",
            "CWE-330": "Weak Random",
            "CWE-377": "Insecure Temp File",
            "CWE-502": "Insecure Deserialization",
            "CWE-611": "XML External Entity (XXE)",
            "CWE-703": "Improper Error Handling",
            "CWE-732": "Incorrect Permission",
        }
        return descriptions.get(cwe_id, "Security Weakness")

    def _findings_by_severity(self) -> str:
        if not self.result.findings:
            return ""

        sections = ["## Findings by Severity"]

        severity_order = [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO,
        ]

        severity_labels = {
            Severity.CRITICAL: "🔴 Critical",
            Severity.HIGH: "🟠 High",
            Severity.MEDIUM: "🟡 Medium",
            Severity.LOW: "🟢 Low",
            Severity.INFO: "⚪ Informational",
        }

        for severity in severity_order:
            findings = [
                f for f in self.result.findings if f.severity == severity
            ]
            if not findings:
                continue

            sections.append(f"\n### {severity_labels[severity]} ({len(findings)})")

            for i, finding in enumerate(findings, 1):
                sections.append(self._format_finding(finding, i))

        return "\n".join(sections)

    def _format_finding(self, finding: Finding, index: int) -> str:
        relative_path = self._get_relative_path(finding.file_path)
        location = f"`{relative_path}`"
        if finding.line_number:
            if finding.end_line and finding.end_line != finding.line_number:
                location += f" (lines {finding.line_number}-{finding.end_line})"
            else:
                location += f" (line {finding.line_number})"

        output = f"""
#### {index}. {finding.title}

- **Location:** {location}
- **Tool:** {finding.tool}
- **Confidence:** {finding.confidence}"""

        if finding.cwe_id:
            output += f"\n- **CWE:** {finding.cwe_id}"

        if finding.owasp_category:
            output += f"\n- **OWASP:** {finding.owasp_category}"

        output += f"\n\n**Description:**\n{finding.description}"

        if finding.code_snippet:
            snippet = finding.code_snippet.strip()
            if len(snippet) > 500:
                snippet = snippet[:500] + "\n... (truncated)"
            output += f"\n\n**Vulnerable Code:**\n```\n{snippet}\n```"

        if finding.remediation:
            output += f"\n\n**Remediation:**\n{finding.remediation}"

        return output

    def _findings_by_file(self) -> str:
        if not self.result.findings:
            return ""

        files: dict[Path, list[Finding]] = {}
        for finding in self.result.findings:
            if finding.file_path not in files:
                files[finding.file_path] = []
            files[finding.file_path].append(finding)

        sections = ["## Findings by File"]

        for file_path in sorted(files.keys()):
            findings = files[file_path]
            relative_path = self._get_relative_path(file_path)

            severity_counts = []
            for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
                count = len([f for f in findings if f.severity == sev])
                if count > 0:
                    severity_counts.append(f"{count} {sev.value}")

            sections.append(f"\n### `{relative_path}` ({', '.join(severity_counts)})")

            for finding in sorted(findings, key=lambda f: f.severity, reverse=True):
                line_info = f"L{finding.line_number}" if finding.line_number else ""
                sections.append(
                    f"- [{finding.severity.value.upper()}] {finding.title} {line_info}"
                )

        return "\n".join(sections)

    def _get_relative_path(self, file_path: Path) -> str:
        try:
            return str(file_path.relative_to(self.result.target_path))
        except ValueError:
            return str(file_path)

    def _tool_summary(self) -> str:
        tools_used = set(f.tool for f in self.result.findings) if self.result.findings else set()

        all_tools = {
            "bandit": "Python security linter",
            "semgrep": "Multi-language static analysis",
            "safety": "Python dependency scanner",
            "gemini": "AI-powered code analysis",
            "gitleaks": "Secrets detection scanner",
            "trufflehog": "Git secrets scanner",
            "detect-secrets": "Secrets detection tool",
            "trivy": "Vulnerability scanner",
            "grype": "Dependency vulnerability scanner",
            "checkov": "Infrastructure as Code scanner",
            "shellcheck": "Shell script analyzer",
            "hadolint": "Dockerfile linter",
            "gosec": "Go security checker",
            "brakeman": "Rails security scanner",
            "spotbugs": "Java security scanner",
            "phpstan": "PHP static analyzer",
            "horusec": "Multi-language SAST",
        }

        rows = []
        for tool, desc in all_tools.items():
            if not tools_used or tool in tools_used:
                rows.append(f"| {tool} | {desc} |")

        if not rows:
            rows = [f"| {t} | {d} |" for t, d in list(all_tools.items())[:4]]

        return """## Tools Used

| Tool | Description |
|------|-------------|
""" + "\n".join(rows)

    def _footer(self) -> str:
        return f"""---

*Report generated by CodeScanner on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}*

**Disclaimer:** This automated scan may produce false positives or miss certain vulnerabilities.
Manual security review is recommended for critical applications."""

    def save(self, output_path: Path) -> None:
        content = self.generate_markdown()
        output_path.write_text(content, encoding="utf-8")

    def generate_json(self) -> str:
        return self.result.to_json()

    def generate_html(self) -> str:
        markdown_content = self.generate_markdown()

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Vulnerability Report</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            line-height: 1.6;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }}
        .container {{
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        h1 {{ color: #1a1a2e; border-bottom: 3px solid #e94560; padding-bottom: 10px; }}
        h2 {{ color: #16213e; margin-top: 30px; }}
        h3 {{ color: #0f3460; }}
        h4 {{ color: #533483; }}
        table {{
            border-collapse: collapse;
            width: 100%;
            margin: 15px 0;
        }}
        th, td {{
            border: 1px solid #ddd;
            padding: 12px;
            text-align: left;
        }}
        th {{ background: #16213e; color: white; }}
        tr:nth-child(even) {{ background: #f9f9f9; }}
        code {{
            background: #f4f4f4;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Consolas', 'Monaco', monospace;
        }}
        pre {{
            background: #1a1a2e;
            color: #e8e8e8;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
        }}
        pre code {{ background: none; color: inherit; }}
        .critical {{ color: #dc3545; font-weight: bold; }}
        .high {{ color: #fd7e14; font-weight: bold; }}
        .medium {{ color: #ffc107; }}
        .low {{ color: #28a745; }}
    </style>
</head>
<body>
    <div class="container">
        <pre class="markdown-content">{self._escape_html(markdown_content)}</pre>
    </div>
</body>
</html>"""
        return html

    def _escape_html(self, text: str) -> str:
        return (
            text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )
