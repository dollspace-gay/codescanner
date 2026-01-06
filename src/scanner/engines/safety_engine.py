import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional, Callable

from .base import BaseEngine
from ..models import Finding, Severity


class SafetyEngine(BaseEngine):
    name = "safety"
    description = "Python dependency vulnerability checker"

    def __init__(self, on_progress: Optional[Callable[[str], None]] = None):
        super().__init__(on_progress)
        self._executable: Optional[str] = None

    def _find_executable(self) -> Optional[str]:
        if self._executable:
            return self._executable

        exe = shutil.which("safety")
        if exe:
            self._executable = exe
            return exe

        scripts_dir = Path(sys.executable).parent / "Scripts"
        for name in ["safety.exe", "safety"]:
            candidate = scripts_dir / name
            if candidate.exists():
                self._executable = str(candidate)
                return self._executable

        return None

    def is_available(self) -> bool:
        exe = self._find_executable()
        if not exe:
            return False
        try:
            result = subprocess.run(
                [exe, "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError, OSError):
            return False

    def get_supported_extensions(self) -> set[str]:
        return {".txt", ".toml"}

    async def scan(self, target_path: Path, files: list[Path]) -> list[Finding]:
        findings: list[Finding] = []

        requirements_files = list(target_path.rglob("requirements*.txt"))
        pyproject_files = list(target_path.rglob("pyproject.toml"))

        scan_files = requirements_files + pyproject_files
        if not scan_files:
            self.log("No requirements.txt or pyproject.toml found")
            return []

        for req_file in requirements_files:
            self.log(f"Checking dependencies in {req_file.name}")
            file_findings = await self._scan_requirements(req_file)
            findings.extend(file_findings)

        return findings

    async def _scan_requirements(self, req_file: Path) -> list[Finding]:
        exe = self._find_executable()
        if not exe:
            self.log("Safety executable not found")
            return []

        try:
            result = subprocess.run(
                [
                    exe, "check",
                    "-r", str(req_file),
                    "--json",
                ],
                capture_output=True,
                text=True,
                timeout=120,
            )

            if result.stdout:
                return self._parse_results(result.stdout, req_file)
            return []

        except subprocess.TimeoutExpired:
            self.log(f"Safety check timed out for {req_file}")
            return []
        except subprocess.SubprocessError as e:
            self.log(f"Safety error: {e}")
            return []

    def _parse_results(self, output: str, req_file: Path) -> list[Finding]:
        findings: list[Finding] = []

        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            json_start = output.find("{")
            json_end = output.rfind("}") + 1
            if json_start != -1 and json_end > json_start:
                try:
                    data = json.loads(output[json_start:json_end])
                except json.JSONDecodeError:
                    self.log("Failed to parse Safety output")
                    return []
            else:
                self.log("Failed to parse Safety output")
                return []

        vulnerabilities = data.get("vulnerabilities", [])
        ignored_vulns = data.get("ignored_vulnerabilities", [])

        all_vulns = vulnerabilities + ignored_vulns

        for vuln in all_vulns:
            if isinstance(vuln, list) and len(vuln) >= 5:
                package_name = vuln[0]
                affected_versions = vuln[1]
                installed_version = vuln[2]
                description = vuln[3]
                vuln_id = vuln[4]
            elif isinstance(vuln, dict):
                package_name = vuln.get("package_name", vuln.get("name", "Unknown"))
                vuln_specs = vuln.get("vulnerable_spec", vuln.get("all_vulnerable_specs", []))
                affected_versions = ", ".join(vuln_specs) if isinstance(vuln_specs, list) else str(vuln_specs)
                installed_version = vuln.get("analyzed_version", "unpinned")
                description = vuln.get("advisory", vuln.get("description", ""))
                vuln_id = vuln.get("vulnerability_id", vuln.get("id", ""))
            else:
                continue

            if not description:
                continue

            severity = self._determine_severity(description, str(vuln_id))

            finding = Finding(
                title=f"Vulnerable dependency: {package_name}",
                description=f"{description}\n\nAffected versions: {affected_versions}\nInstalled: {installed_version}",
                severity=severity,
                file_path=req_file,
                line_number=None,
                cwe_id=self._extract_cwe(description),
                tool=self.name,
                confidence="high",
                remediation=f"Upgrade {package_name} to a patched version. Check https://pypi.org/project/{package_name}/ for the latest secure version.",
            )
            findings.append(finding)

        return findings

    def _determine_severity(self, description: str, vuln_id: str) -> Severity:
        description_lower = description.lower()

        critical_keywords = ["remote code execution", "rce", "arbitrary code", "critical"]
        high_keywords = ["sql injection", "command injection", "authentication bypass", "privilege escalation"]
        medium_keywords = ["cross-site scripting", "xss", "denial of service", "dos", "information disclosure"]

        for keyword in critical_keywords:
            if keyword in description_lower:
                return Severity.CRITICAL

        for keyword in high_keywords:
            if keyword in description_lower:
                return Severity.HIGH

        for keyword in medium_keywords:
            if keyword in description_lower:
                return Severity.MEDIUM

        return Severity.MEDIUM

    def _extract_cwe(self, description: str) -> Optional[str]:
        import re
        match = re.search(r"CWE-\d+", description, re.IGNORECASE)
        if match:
            return match.group(0).upper()
        return None
