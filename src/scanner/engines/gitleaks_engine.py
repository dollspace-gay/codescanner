import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional, Callable

from .base import BaseEngine
from ..models import Finding, Severity


class GitleaksEngine(BaseEngine):
    name = "gitleaks"
    description = "Secrets detection scanner (API keys, passwords, tokens)"

    SEVERITY_MAP = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
    }

    RULE_SEVERITY = {
        "generic-api-key": Severity.HIGH,
        "aws-access-key-id": Severity.CRITICAL,
        "aws-secret-access-key": Severity.CRITICAL,
        "github-pat": Severity.CRITICAL,
        "github-oauth": Severity.CRITICAL,
        "github-app-token": Severity.CRITICAL,
        "github-refresh-token": Severity.CRITICAL,
        "gitlab-pat": Severity.CRITICAL,
        "gcp-api-key": Severity.CRITICAL,
        "google-api-key": Severity.CRITICAL,
        "heroku-api-key": Severity.HIGH,
        "slack-token": Severity.HIGH,
        "slack-webhook": Severity.MEDIUM,
        "stripe-api-key": Severity.CRITICAL,
        "twilio-api-key": Severity.HIGH,
        "twitter-api-key": Severity.HIGH,
        "private-key": Severity.CRITICAL,
        "jwt": Severity.HIGH,
        "password-in-url": Severity.HIGH,
        "sendgrid-api-key": Severity.HIGH,
        "mailchimp-api-key": Severity.HIGH,
        "npm-access-token": Severity.HIGH,
        "pypi-upload-token": Severity.HIGH,
        "azure-storage-key": Severity.CRITICAL,
        "firebase-url": Severity.MEDIUM,
        "facebook-token": Severity.HIGH,
        "discord-token": Severity.HIGH,
        "telegram-token": Severity.HIGH,
    }

    CWE_MAP = {
        "generic-api-key": "CWE-798",
        "aws-access-key-id": "CWE-798",
        "aws-secret-access-key": "CWE-798",
        "github-pat": "CWE-798",
        "private-key": "CWE-321",
        "password-in-url": "CWE-259",
        "jwt": "CWE-798",
    }

    def __init__(self, on_progress: Optional[Callable[[str], None]] = None):
        super().__init__(on_progress)
        self._executable: Optional[str] = None

    def _find_executable(self) -> Optional[str]:
        if self._executable:
            return self._executable

        exe = shutil.which("gitleaks")
        if exe:
            self._executable = exe
            return exe

        scripts_dir = Path(sys.executable).parent / "Scripts"
        for name in ["gitleaks.exe", "gitleaks"]:
            candidate = scripts_dir / name
            if candidate.exists():
                self._executable = str(candidate)
                return self._executable

        common_paths = [
            Path.home() / ".local" / "bin" / "gitleaks",
            Path.home() / "go" / "bin" / "gitleaks",
            Path("/usr/local/bin/gitleaks"),
            Path("/usr/bin/gitleaks"),
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
        self.log(f"Running secrets detection scan on {target_path}")

        exe = self._find_executable()
        if not exe:
            self.log("Gitleaks executable not found")
            return []

        try:
            result = subprocess.run(
                [
                    exe,
                    "detect",
                    "--source", str(target_path),
                    "--report-format", "json",
                    "--report-path", "/dev/stdout",
                    "--no-git",
                    "--exit-code", "0",
                ],
                capture_output=True,
                text=True,
                timeout=300,
            )

            if result.stdout:
                return self._parse_results(result.stdout, target_path)
            return []

        except subprocess.TimeoutExpired:
            self.log("Gitleaks scan timed out")
            return []
        except subprocess.SubprocessError as e:
            self.log(f"Gitleaks error: {e}")
            return []

    def _parse_results(self, output: str, target_path: Path) -> list[Finding]:
        findings: list[Finding] = []

        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            if not output.strip() or output.strip() == "[]":
                return []
            self.log("Failed to parse Gitleaks output")
            return []

        if not isinstance(data, list):
            return []

        for result in data:
            rule_id = result.get("RuleID", "unknown")
            severity = self.RULE_SEVERITY.get(rule_id, Severity.HIGH)

            file_path_str = result.get("File", "")
            file_path = Path(file_path_str)
            if not file_path.is_absolute():
                file_path = target_path / file_path

            secret_value = result.get("Secret", "")
            masked_secret = self._mask_secret(secret_value)

            match_text = result.get("Match", "")
            masked_match = match_text.replace(secret_value, masked_secret) if secret_value else match_text

            description = result.get("Description", f"Detected secret: {rule_id}")

            finding = Finding(
                title=f"Hardcoded Secret: {rule_id}",
                description=f"{description}\n\nMatch: {masked_match}",
                severity=severity,
                file_path=file_path,
                line_number=result.get("StartLine"),
                end_line=result.get("EndLine"),
                code_snippet=masked_match,
                cwe_id=self.CWE_MAP.get(rule_id, "CWE-798"),
                owasp_category="A07:2021-Identification and Authentication Failures",
                tool=self.name,
                confidence="high",
                remediation=self._get_remediation(rule_id),
            )
            findings.append(finding)

        self.log(f"Found {len(findings)} potential secrets")
        return findings

    def _mask_secret(self, secret: str) -> str:
        if len(secret) <= 8:
            return "*" * len(secret)
        return secret[:4] + "*" * (len(secret) - 8) + secret[-4:]

    def _get_remediation(self, rule_id: str) -> str:
        remediation_map = {
            "generic-api-key": "Remove the hardcoded API key and use environment variables or a secrets manager.",
            "aws-access-key-id": "Rotate the AWS access key immediately and use IAM roles or environment variables.",
            "aws-secret-access-key": "Rotate the AWS secret key immediately. Use IAM roles for EC2 or environment variables.",
            "github-pat": "Revoke the GitHub Personal Access Token and create a new one with minimal required scopes.",
            "github-oauth": "Revoke the GitHub OAuth token and regenerate credentials.",
            "github-app-token": "Revoke the GitHub App token and regenerate from the app settings.",
            "gitlab-pat": "Revoke the GitLab Personal Access Token and create a new one.",
            "gcp-api-key": "Restrict or delete the GCP API key and use service accounts instead.",
            "google-api-key": "Restrict or delete the Google API key and create a new one with proper restrictions.",
            "heroku-api-key": "Regenerate the Heroku API key from account settings.",
            "slack-token": "Revoke the Slack token and create a new one with minimal scopes.",
            "slack-webhook": "Regenerate the Slack webhook URL from app settings.",
            "stripe-api-key": "Roll the Stripe API key immediately and update all integrations.",
            "twilio-api-key": "Rotate the Twilio credentials from the console.",
            "private-key": "Generate a new private key and revoke/replace the exposed one.",
            "jwt": "If this is a secret key, rotate it. If it's a token, check its expiration and revoke if needed.",
            "password-in-url": "Remove password from URL and use secure authentication methods.",
            "sendgrid-api-key": "Revoke the SendGrid API key and create a new one.",
            "npm-access-token": "Revoke the npm token from your npm account settings.",
            "pypi-upload-token": "Revoke the PyPI token from your PyPI account.",
            "azure-storage-key": "Rotate the Azure storage key from the Azure portal.",
            "discord-token": "Reset the Discord bot token from the developer portal.",
            "telegram-token": "Revoke the Telegram bot token using @BotFather.",
        }
        return remediation_map.get(
            rule_id,
            "Remove the hardcoded secret from source code. Use environment variables, "
            "secrets managers (AWS Secrets Manager, HashiCorp Vault), or configuration files "
            "excluded from version control."
        )
