import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional, Callable

from .base import BaseEngine
from ..models import Finding, Severity


class SemgrepEngine(BaseEngine):
    name = "semgrep"
    description = "Multi-language static analysis with security rules"

    SEVERITY_MAP = {
        "ERROR": Severity.HIGH,
        "WARNING": Severity.MEDIUM,
        "INFO": Severity.LOW,
    }

    def __init__(self, on_progress: Optional[Callable[[str], None]] = None):
        super().__init__(on_progress)
        self._executable: Optional[str] = None

    def _find_executable(self) -> Optional[str]:
        if self._executable:
            return self._executable

        exe = shutil.which("semgrep")
        if exe:
            self._executable = exe
            return exe

        scripts_dir = Path(sys.executable).parent / "Scripts"
        for name in ["semgrep.exe", "semgrep"]:
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

    async def scan(self, target_path: Path, files: list[Path]) -> list[Finding]:
        self.log(f"Running Semgrep security scan on {target_path}")

        exe = self._find_executable()
        if not exe:
            self.log("Semgrep executable not found")
            return []

        try:
            result = subprocess.run(
                [
                    exe,
                    "scan",
                    "--config", "auto",
                    "--json",
                    "--timeout", "60",
                    "--max-target-bytes", "1000000",
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
            self.log("Semgrep scan timed out")
            return []
        except subprocess.SubprocessError as e:
            self.log(f"Semgrep error: {e}")
            return []

    def _parse_results(self, output: str, target_path: Path) -> list[Finding]:
        findings: list[Finding] = []

        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            self.log("Failed to parse Semgrep output")
            return []

        for result in data.get("results", []):
            extra = result.get("extra", {})
            severity_str = extra.get("severity", "INFO").upper()
            severity = self.SEVERITY_MAP.get(severity_str, Severity.INFO)

            metadata = extra.get("metadata", {})
            cwe_list = metadata.get("cwe", [])
            cwe_id = cwe_list[0] if cwe_list else None
            if isinstance(cwe_id, str) and "CWE-" not in cwe_id:
                cwe_id = f"CWE-{cwe_id}"

            owasp = metadata.get("owasp", [])
            owasp_category = owasp[0] if owasp else None

            file_path = Path(result.get("path", ""))
            if not file_path.is_absolute():
                file_path = target_path / file_path

            start = result.get("start", {})
            end = result.get("end", {})

            finding = Finding(
                title=result.get("check_id", "Unknown Issue"),
                description=extra.get("message", ""),
                severity=severity,
                file_path=file_path,
                line_number=start.get("line"),
                end_line=end.get("line"),
                code_snippet=extra.get("lines", ""),
                cwe_id=cwe_id,
                owasp_category=owasp_category,
                tool=self.name,
                confidence=metadata.get("confidence", "medium").lower(),
                remediation=metadata.get("fix", extra.get("fix", "")),
            )
            findings.append(finding)

        return findings
