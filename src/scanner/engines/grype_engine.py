import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional, Callable

from .base import BaseEngine
from ..models import Finding, Severity


class GrypeEngine(BaseEngine):
    name = "grype"
    description = "Dependency vulnerability scanner"

    SEVERITY_MAP = {
        "Critical": Severity.CRITICAL,
        "High": Severity.HIGH,
        "Medium": Severity.MEDIUM,
        "Low": Severity.LOW,
        "Negligible": Severity.INFO,
        "Unknown": Severity.INFO,
    }

    def __init__(self, on_progress: Optional[Callable[[str], None]] = None):
        super().__init__(on_progress)
        self._executable: Optional[str] = None

    def _find_executable(self) -> Optional[str]:
        if self._executable:
            return self._executable

        exe = shutil.which("grype")
        if exe:
            self._executable = exe
            return exe

        scripts_dir = Path(sys.executable).parent / "Scripts"
        for name in ["grype.exe", "grype"]:
            candidate = scripts_dir / name
            if candidate.exists():
                self._executable = str(candidate)
                return self._executable

        common_paths = [
            Path.home() / ".local" / "bin" / "grype",
            Path("/usr/local/bin/grype"),
            Path("/usr/bin/grype"),
            Path("C:/ProgramData/chocolatey/bin/grype.exe"),
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
        self.log(f"Running Grype dependency scan on {target_path}")

        exe = self._find_executable()
        if not exe:
            self.log("Grype executable not found")
            return []

        try:
            result = subprocess.run(
                [
                    exe,
                    f"dir:{target_path}",
                    "-o", "json",
                    "--add-cpes-if-none",
                ],
                capture_output=True,
                text=True,
                timeout=300,
            )

            if result.stdout:
                return self._parse_results(result.stdout, target_path)
            return []

        except subprocess.TimeoutExpired:
            self.log("Grype scan timed out")
            return []
        except subprocess.SubprocessError as e:
            self.log(f"Grype error: {e}")
            return []

    def _parse_results(self, output: str, target_path: Path) -> list[Finding]:
        findings: list[Finding] = []

        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            self.log("Failed to parse Grype output")
            return []

        matches = data.get("matches", [])

        for match in matches:
            vulnerability = match.get("vulnerability", {})
            artifact = match.get("artifact", {})

            vuln_id = vulnerability.get("id", "Unknown")
            severity_str = vulnerability.get("severity", "Unknown")
            severity = self.SEVERITY_MAP.get(severity_str, Severity.MEDIUM)

            pkg_name = artifact.get("name", "Unknown")
            pkg_version = artifact.get("version", "")
            pkg_type = artifact.get("type", "")

            description = vulnerability.get("description", f"Vulnerability in {pkg_name}")

            fix_versions = vulnerability.get("fix", {}).get("versions", [])
            fix_state = vulnerability.get("fix", {}).get("state", "")

            if fix_versions:
                description += f"\n\nFixed in: {', '.join(fix_versions)}"
            elif fix_state:
                description += f"\n\nFix state: {fix_state}"

            data_source = vulnerability.get("dataSource", "")
            if data_source:
                description += f"\n\nSource: {data_source}"

            related_vulns = match.get("relatedVulnerabilities", [])
            cwe_id = None
            for rv in related_vulns:
                for cwe in rv.get("cwes", []):
                    cwe_id = f"CWE-{cwe}" if isinstance(cwe, int) else cwe
                    break
                if cwe_id:
                    break

            locations = artifact.get("locations", [])
            file_path = target_path
            if locations:
                loc_path = locations[0].get("path", "")
                if loc_path:
                    file_path = target_path / loc_path

            remediation = f"Update {pkg_name} to version {fix_versions[0]}" if fix_versions else f"Update {pkg_name} to a patched version or find an alternative package"

            finding = Finding(
                title=f"{vuln_id}: {pkg_name} ({pkg_version})",
                description=description,
                severity=severity,
                file_path=file_path,
                cwe_id=cwe_id,
                tool=self.name,
                confidence="high",
                remediation=remediation,
            )
            findings.append(finding)

        self.log(f"Found {len(findings)} vulnerable dependencies")
        return findings
