import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional, Callable

from .base import BaseEngine
from ..models import Finding, Severity


class CheckovEngine(BaseEngine):
    name = "checkov"
    description = "Infrastructure as Code security scanner"

    SEVERITY_MAP = {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
        "INFO": Severity.INFO,
    }

    IAC_EXTENSIONS = {
        ".tf", ".tfvars",
        ".yaml", ".yml",
        ".json",
        ".dockerfile",
        ".template",
    }

    IAC_FILENAMES = {
        "dockerfile",
        "docker-compose.yml",
        "docker-compose.yaml",
        "kubernetes.yaml",
        "kubernetes.yml",
        "serverless.yml",
        "serverless.yaml",
        "cloudformation.yaml",
        "cloudformation.yml",
        "cloudformation.json",
        "template.yaml",
        "template.yml",
        "template.json",
        "helm",
        "kustomization.yaml",
        "kustomization.yml",
    }

    def __init__(self, on_progress: Optional[Callable[[str], None]] = None):
        super().__init__(on_progress)
        self._executable: Optional[str] = None

    def _find_executable(self) -> Optional[str]:
        if self._executable:
            return self._executable

        exe = shutil.which("checkov")
        if exe:
            self._executable = exe
            return exe

        scripts_dir = Path(sys.executable).parent / "Scripts"
        for name in ["checkov.exe", "checkov"]:
            candidate = scripts_dir / name
            if candidate.exists():
                self._executable = str(candidate)
                return self._executable

        bin_dir = Path(sys.executable).parent
        for name in ["checkov.exe", "checkov"]:
            candidate = bin_dir / name
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
                timeout=30,
            )
            return result.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError, OSError):
            return False

    def _has_iac_files(self, target_path: Path, files: list[Path]) -> bool:
        for f in files:
            if f.suffix.lower() in self.IAC_EXTENSIONS:
                return True
            if f.name.lower() in self.IAC_FILENAMES:
                return True

        terraform_dir = target_path / ".terraform"
        if terraform_dir.exists():
            return True

        return False

    async def scan(self, target_path: Path, files: list[Path]) -> list[Finding]:
        if not self._has_iac_files(target_path, files):
            self.log("No Infrastructure as Code files detected, skipping Checkov")
            return []

        self.log(f"Running Checkov IaC security scan on {target_path}")

        exe = self._find_executable()
        if not exe:
            self.log("Checkov executable not found")
            return []

        try:
            result = subprocess.run(
                [
                    exe,
                    "-d", str(target_path),
                    "-o", "json",
                    "--quiet",
                    "--compact",
                ],
                capture_output=True,
                text=True,
                timeout=600,
            )

            if result.stdout:
                return self._parse_results(result.stdout, target_path)
            return []

        except subprocess.TimeoutExpired:
            self.log("Checkov scan timed out")
            return []
        except subprocess.SubprocessError as e:
            self.log(f"Checkov error: {e}")
            return []

    def _parse_results(self, output: str, target_path: Path) -> list[Finding]:
        findings: list[Finding] = []

        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            lines = output.strip().split("\n")
            for line in lines:
                try:
                    data = json.loads(line)
                    break
                except json.JSONDecodeError:
                    continue
            else:
                self.log("Failed to parse Checkov output")
                return []

        if isinstance(data, list):
            for check_result in data:
                findings.extend(self._parse_check_results(check_result, target_path))
        elif isinstance(data, dict):
            findings.extend(self._parse_check_results(data, target_path))

        self.log(f"Found {len(findings)} IaC security issues")
        return findings

    def _parse_check_results(self, data: dict, target_path: Path) -> list[Finding]:
        findings: list[Finding] = []

        failed_checks = data.get("results", {}).get("failed_checks", [])

        for check in failed_checks:
            check_id = check.get("check_id", "Unknown")
            check_name = check.get("check", check.get("name", "Unknown check"))
            check_type = check.get("check_type", "")

            severity_str = check.get("severity", "MEDIUM")
            if severity_str is None:
                severity_str = "MEDIUM"
            severity = self.SEVERITY_MAP.get(severity_str.upper(), Severity.MEDIUM)

            guideline = check.get("guideline", "")
            description = check.get("description", check_name)

            if guideline:
                description += f"\n\nGuideline: {guideline}"

            file_path_str = check.get("file_path", "")
            if file_path_str:
                if file_path_str.startswith("/"):
                    file_path_str = file_path_str[1:]
                file_path = target_path / file_path_str
            else:
                file_path = target_path

            file_line_range = check.get("file_line_range", [])
            start_line = file_line_range[0] if len(file_line_range) > 0 else None
            end_line = file_line_range[1] if len(file_line_range) > 1 else None

            resource = check.get("resource", "")
            if resource:
                description += f"\n\nResource: {resource}"

            cwe_id = None
            bc_check_id = check.get("bc_check_id", "")
            owasp = check.get("owasp", [])
            owasp_category = owasp[0] if owasp else None

            finding = Finding(
                title=f"{check_id}: {check_name}",
                description=description,
                severity=severity,
                file_path=file_path,
                line_number=start_line,
                end_line=end_line,
                cwe_id=cwe_id,
                owasp_category=owasp_category,
                tool=self.name,
                confidence="high",
                remediation=self._get_remediation(check_id, check_type),
            )
            findings.append(finding)

        return findings

    def _get_remediation(self, check_id: str, check_type: str) -> str:
        check_lower = check_id.lower()

        if "encrypt" in check_lower:
            return "Enable encryption for this resource. Use KMS keys or enable default encryption."
        elif "public" in check_lower:
            return "Restrict public access. Use private subnets or security groups to limit exposure."
        elif "logging" in check_lower:
            return "Enable logging for audit and security monitoring purposes."
        elif "iam" in check_lower:
            return "Follow least privilege principle. Restrict IAM permissions to minimum required."
        elif "secret" in check_lower or "password" in check_lower:
            return "Use secrets management (AWS Secrets Manager, Vault) instead of hardcoding secrets."
        elif "port" in check_lower:
            return "Restrict open ports. Only expose necessary ports and use security groups."
        elif "ssl" in check_lower or "tls" in check_lower or "https" in check_lower:
            return "Enable TLS/SSL. Use HTTPS and modern TLS versions (1.2+)."
        elif "backup" in check_lower:
            return "Enable backups and retention policies for data recovery."
        elif "vpc" in check_lower:
            return "Deploy resources within a VPC with proper network segmentation."
        else:
            return "Review and remediate according to infrastructure security best practices. See the check guideline for details."
