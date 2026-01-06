import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional, Callable

from .base import BaseEngine
from ..models import Finding, Severity


class TruffleHogEngine(BaseEngine):
    name = "trufflehog"
    description = "Git history secrets scanner"

    DETECTOR_SEVERITY = {
        "AWS": Severity.CRITICAL,
        "Azure": Severity.CRITICAL,
        "GCP": Severity.CRITICAL,
        "Github": Severity.CRITICAL,
        "Gitlab": Severity.CRITICAL,
        "Slack": Severity.HIGH,
        "Stripe": Severity.CRITICAL,
        "Twilio": Severity.HIGH,
        "PrivateKey": Severity.CRITICAL,
        "JWT": Severity.HIGH,
        "Generic": Severity.MEDIUM,
    }

    def __init__(self, on_progress: Optional[Callable[[str], None]] = None):
        super().__init__(on_progress)
        self._executable: Optional[str] = None

    def _find_executable(self) -> Optional[str]:
        if self._executable:
            return self._executable

        exe = shutil.which("trufflehog")
        if exe:
            self._executable = exe
            return exe

        scripts_dir = Path(sys.executable).parent / "Scripts"
        for name in ["trufflehog.exe", "trufflehog"]:
            candidate = scripts_dir / name
            if candidate.exists():
                self._executable = str(candidate)
                return self._executable

        common_paths = [
            Path.home() / ".local" / "bin" / "trufflehog",
            Path.home() / "go" / "bin" / "trufflehog",
            Path("/usr/local/bin/trufflehog"),
            Path("/usr/bin/trufflehog"),
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
                [exe, "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError, OSError):
            return False

    async def scan(self, target_path: Path, files: list[Path]) -> list[Finding]:
        self.log(f"Running TruffleHog secrets scan on {target_path}")

        exe = self._find_executable()
        if not exe:
            self.log("TruffleHog executable not found")
            return []

        git_dir = target_path / ".git"
        if git_dir.exists():
            return await self._scan_git(exe, target_path)
        else:
            return await self._scan_filesystem(exe, target_path)

    async def _scan_git(self, exe: str, target_path: Path) -> list[Finding]:
        self.log("Scanning git repository history for secrets")
        try:
            result = subprocess.run(
                [
                    exe,
                    "git",
                    f"file://{target_path}",
                    "--json",
                    "--no-update",
                ],
                capture_output=True,
                text=True,
                timeout=600,
            )

            return self._parse_results(result.stdout, target_path)

        except subprocess.TimeoutExpired:
            self.log("TruffleHog git scan timed out")
            return []
        except subprocess.SubprocessError as e:
            self.log(f"TruffleHog error: {e}")
            return []

    async def _scan_filesystem(self, exe: str, target_path: Path) -> list[Finding]:
        self.log("Scanning filesystem for secrets (no git history)")
        try:
            result = subprocess.run(
                [
                    exe,
                    "filesystem",
                    str(target_path),
                    "--json",
                    "--no-update",
                ],
                capture_output=True,
                text=True,
                timeout=300,
            )

            return self._parse_results(result.stdout, target_path)

        except subprocess.TimeoutExpired:
            self.log("TruffleHog filesystem scan timed out")
            return []
        except subprocess.SubprocessError as e:
            self.log(f"TruffleHog error: {e}")
            return []

    def _parse_results(self, output: str, target_path: Path) -> list[Finding]:
        findings: list[Finding] = []

        if not output.strip():
            return []

        for line in output.strip().split("\n"):
            if not line.strip():
                continue

            try:
                result = json.loads(line)
            except json.JSONDecodeError:
                continue

            detector_type = result.get("DetectorType", "Unknown")
            detector_name = result.get("DetectorName", detector_type)

            severity = Severity.HIGH
            for key, sev in self.DETECTOR_SEVERITY.items():
                if key.lower() in detector_name.lower() or key.lower() in detector_type.lower():
                    severity = sev
                    break

            source_metadata = result.get("SourceMetadata", {})
            data = source_metadata.get("Data", {})

            file_path_str = ""
            line_number = None

            if "Filesystem" in data:
                file_info = data["Filesystem"]
                file_path_str = file_info.get("file", "")
                line_number = file_info.get("line")
            elif "Git" in data:
                git_info = data["Git"]
                file_path_str = git_info.get("file", "")
                line_number = git_info.get("line")

            if file_path_str:
                file_path = Path(file_path_str)
                if not file_path.is_absolute():
                    file_path = target_path / file_path
            else:
                file_path = target_path

            raw_secret = result.get("Raw", "")
            masked_secret = self._mask_secret(raw_secret)

            extra_data = result.get("ExtraData", {})
            extra_info = ""
            if extra_data:
                extra_info = "\n".join(f"  {k}: {v}" for k, v in extra_data.items() if v)

            description = f"Detected {detector_name} secret"
            if extra_info:
                description += f"\n\nAdditional info:\n{extra_info}"

            verified = result.get("Verified", False)
            confidence = "high" if verified else "medium"

            finding = Finding(
                title=f"Secret Detected: {detector_name}",
                description=description,
                severity=severity,
                file_path=file_path,
                line_number=line_number,
                code_snippet=masked_secret if masked_secret else None,
                cwe_id="CWE-798",
                owasp_category="A07:2021-Identification and Authentication Failures",
                tool=self.name,
                confidence=confidence,
                remediation=self._get_remediation(detector_name),
            )
            findings.append(finding)

        self.log(f"Found {len(findings)} potential secrets")
        return findings

    def _mask_secret(self, secret: str) -> str:
        if not secret:
            return ""
        if len(secret) <= 8:
            return "*" * len(secret)
        return secret[:4] + "*" * (len(secret) - 8) + secret[-4:]

    def _get_remediation(self, detector_name: str) -> str:
        detector_lower = detector_name.lower()

        if "aws" in detector_lower:
            return "Rotate AWS credentials immediately via IAM console. Use IAM roles or environment variables instead of hardcoding."
        elif "azure" in detector_lower:
            return "Rotate Azure credentials in Azure Portal. Use Managed Identities for Azure resources."
        elif "gcp" in detector_lower or "google" in detector_lower:
            return "Rotate GCP credentials in Cloud Console. Use service accounts with minimal permissions."
        elif "github" in detector_lower:
            return "Revoke the GitHub token immediately and create a new one with minimal scopes."
        elif "gitlab" in detector_lower:
            return "Revoke the GitLab token and generate a new one with appropriate permissions."
        elif "slack" in detector_lower:
            return "Regenerate Slack tokens/webhooks from your Slack App configuration."
        elif "stripe" in detector_lower:
            return "Roll your Stripe API keys immediately from the Stripe Dashboard."
        elif "private" in detector_lower or "key" in detector_lower:
            return "Generate a new private key and revoke/replace the exposed one across all systems."
        elif "jwt" in detector_lower:
            return "Rotate the JWT signing secret and invalidate existing tokens if compromised."
        else:
            return (
                "Remove the hardcoded secret from source code and git history. "
                "Use environment variables or a secrets manager (AWS Secrets Manager, HashiCorp Vault, etc.). "
                "Rotate the credential immediately."
            )
