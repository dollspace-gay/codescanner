import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional, Callable

from .base import BaseEngine
from ..models import Finding, Severity


class TrivyEngine(BaseEngine):
    name = "trivy"
    description = "Filesystem and container vulnerability scanner"

    SEVERITY_MAP = {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
        "UNKNOWN": Severity.INFO,
    }

    def __init__(self, on_progress: Optional[Callable[[str], None]] = None):
        super().__init__(on_progress)
        self._executable: Optional[str] = None

    def _find_executable(self) -> Optional[str]:
        if self._executable:
            return self._executable

        exe = shutil.which("trivy")
        if exe:
            self._executable = exe
            return exe

        scripts_dir = Path(sys.executable).parent / "Scripts"
        for name in ["trivy.exe", "trivy"]:
            candidate = scripts_dir / name
            if candidate.exists():
                self._executable = str(candidate)
                return self._executable

        common_paths = [
            Path.home() / ".local" / "bin" / "trivy",
            Path("/usr/local/bin/trivy"),
            Path("/usr/bin/trivy"),
            Path("C:/ProgramData/chocolatey/bin/trivy.exe"),
        ]
        for path in common_paths:
            if path.exists():
                self._executable = str(path)
                return self._executable

        return None

    def is_available(self) -> bool:
        exe = self._find_executable()
        if not exe:
            return False
        try:
            result = subprocess.run(
                [exe, "version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError, OSError):
            return False

    async def scan(self, target_path: Path, files: list[Path]) -> list[Finding]:
        self.log(f"Running Trivy vulnerability scan on {target_path}")

        exe = self._find_executable()
        if not exe:
            self.log("Trivy executable not found")
            return []

        try:
            result = subprocess.run(
                [
                    exe,
                    "fs",
                    "--format", "json",
                    "--scanners", "vuln,secret,misconfig",
                    "--severity", "CRITICAL,HIGH,MEDIUM,LOW",
                    str(target_path),
                ],
                capture_output=True,
                text=True,
                timeout=600,
            )

            if result.stdout:
                return self._parse_results(result.stdout, target_path)
            return []

        except subprocess.TimeoutExpired:
            self.log("Trivy scan timed out")
            return []
        except subprocess.SubprocessError as e:
            self.log(f"Trivy error: {e}")
            return []

    def _parse_results(self, output: str, target_path: Path) -> list[Finding]:
        findings: list[Finding] = []

        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            self.log("Failed to parse Trivy output")
            return []

        results = data.get("Results", [])

        for result in results:
            target = result.get("Target", "")
            result_type = result.get("Type", "")

            for vuln in result.get("Vulnerabilities", []):
                findings.append(self._parse_vulnerability(vuln, target, target_path))

            for secret in result.get("Secrets", []):
                findings.append(self._parse_secret(secret, target, target_path))

            for misconfig in result.get("Misconfigurations", []):
                findings.append(self._parse_misconfig(misconfig, target, target_path))

        self.log(f"Found {len(findings)} issues")
        return findings

    def _parse_vulnerability(
        self, vuln: dict, target: str, target_path: Path
    ) -> Finding:
        severity_str = vuln.get("Severity", "UNKNOWN")
        severity = self.SEVERITY_MAP.get(severity_str.upper(), Severity.MEDIUM)

        vuln_id = vuln.get("VulnerabilityID", "Unknown")
        pkg_name = vuln.get("PkgName", "Unknown package")
        installed_version = vuln.get("InstalledVersion", "")
        fixed_version = vuln.get("FixedVersion", "")

        title = f"{vuln_id}: {pkg_name}"
        description = vuln.get("Description", f"Vulnerability in {pkg_name}")

        if installed_version:
            description += f"\n\nInstalled: {installed_version}"
        if fixed_version:
            description += f"\nFixed in: {fixed_version}"

        refs = vuln.get("References", [])
        if refs:
            description += "\n\nReferences:\n" + "\n".join(f"- {r}" for r in refs[:3])

        cwe_ids = vuln.get("CweIDs", [])
        cwe_id = cwe_ids[0] if cwe_ids else None

        file_path = target_path / target if target else target_path

        remediation = f"Update {pkg_name} to version {fixed_version}" if fixed_version else f"Update {pkg_name} to a patched version"

        return Finding(
            title=title,
            description=description,
            severity=severity,
            file_path=file_path,
            cwe_id=cwe_id,
            tool=self.name,
            confidence="high",
            remediation=remediation,
        )

    def _parse_secret(self, secret: dict, target: str, target_path: Path) -> Finding:
        severity_str = secret.get("Severity", "HIGH")
        severity = self.SEVERITY_MAP.get(severity_str.upper(), Severity.HIGH)

        rule_id = secret.get("RuleID", "Unknown")
        category = secret.get("Category", "Secret")
        title_text = secret.get("Title", f"Secret detected: {rule_id}")

        match_text = secret.get("Match", "")

        start_line = secret.get("StartLine")
        end_line = secret.get("EndLine")

        file_path = target_path / target if target else target_path

        return Finding(
            title=f"Secret: {title_text}",
            description=f"Detected {category} secret.\n\nRule: {rule_id}",
            severity=severity,
            file_path=file_path,
            line_number=start_line,
            end_line=end_line,
            code_snippet=self._mask_secret(match_text) if match_text else None,
            cwe_id="CWE-798",
            owasp_category="A07:2021-Identification and Authentication Failures",
            tool=self.name,
            confidence="high",
            remediation="Remove the hardcoded secret and use environment variables or a secrets manager.",
        )

    def _parse_misconfig(
        self, misconfig: dict, target: str, target_path: Path
    ) -> Finding:
        severity_str = misconfig.get("Severity", "MEDIUM")
        severity = self.SEVERITY_MAP.get(severity_str.upper(), Severity.MEDIUM)

        misconfig_id = misconfig.get("ID", "Unknown")
        avd_id = misconfig.get("AVDID", "")
        title_text = misconfig.get("Title", f"Misconfiguration: {misconfig_id}")
        description = misconfig.get("Description", "")
        message = misconfig.get("Message", "")
        resolution = misconfig.get("Resolution", "")

        full_description = description
        if message:
            full_description += f"\n\n{message}"

        start_line = misconfig.get("CauseMetadata", {}).get("StartLine")
        end_line = misconfig.get("CauseMetadata", {}).get("EndLine")
        code = misconfig.get("CauseMetadata", {}).get("Code", {}).get("Lines", [])

        file_path = target_path / target if target else target_path

        return Finding(
            title=f"Misconfig: {title_text}",
            description=full_description,
            severity=severity,
            file_path=file_path,
            line_number=start_line,
            end_line=end_line,
            code_snippet="\n".join(str(line.get("Content", "")) for line in code[:5]) if code else None,
            tool=self.name,
            confidence="high",
            remediation=resolution or "Review and fix the misconfiguration according to security best practices.",
        )

    def _mask_secret(self, secret: str) -> str:
        if not secret:
            return ""
        if len(secret) <= 8:
            return "*" * len(secret)
        return secret[:4] + "*" * (len(secret) - 8) + secret[-4:]
