import json
import shutil
import subprocess
from pathlib import Path
from typing import Optional, Callable

from .base import BaseEngine
from ..models import Finding, Severity


class HadolintEngine(BaseEngine):
    name = "hadolint"
    description = "Dockerfile linter and best practices checker"

    SEVERITY_MAP = {
        "error": Severity.HIGH,
        "warning": Severity.MEDIUM,
        "info": Severity.LOW,
        "style": Severity.INFO,
    }

    DOCKERFILE_NAMES = {
        "dockerfile",
        "dockerfile.dev",
        "dockerfile.prod",
        "dockerfile.test",
        "dockerfile.build",
    }

    CWE_MAP = {
        "DL3000": "CWE-250",  # Use absolute WORKDIR
        "DL3001": "CWE-78",   # Command injection risk
        "DL3002": "CWE-250",  # Don't run as root
        "DL3003": "CWE-426",  # Use WORKDIR instead of cd
        "DL3004": "CWE-250",  # Don't use sudo
        "DL3006": "CWE-1104", # Always tag base images
        "DL3007": "CWE-1104", # Don't use latest tag
        "DL3008": "CWE-1104", # Pin versions in apt-get
        "DL3009": "CWE-459",  # Delete apt-get lists
        "DL3013": "CWE-1104", # Pin pip versions
        "DL3015": "CWE-1104", # Avoid apt-get upgrade
        "DL3018": "CWE-1104", # Pin versions in apk add
        "DL3019": "CWE-459",  # Use --no-cache for apk
        "DL3020": "CWE-426",  # Use COPY instead of ADD
        "DL3022": "CWE-1104", # Use --no-install-recommends
        "DL3025": "CWE-78",   # Use JSON for CMD
        "DL3027": "CWE-78",   # Do not use apt
        "DL3028": "CWE-1104", # Pin gem versions
        "DL3042": "CWE-200",  # Avoid cache directory in pip
        "DL3045": "CWE-426",  # COPY --from reference
        "DL4000": "CWE-1104", # MAINTAINER is deprecated
        "DL4006": "CWE-78",   # Set SHELL for pipefail
        "SC2086": "CWE-78",   # ShellCheck - word splitting
    }

    def __init__(self, on_progress: Optional[Callable[[str], None]] = None):
        super().__init__(on_progress)
        self._executable: Optional[str] = None

    def _find_executable(self) -> Optional[str]:
        if self._executable:
            return self._executable

        exe = shutil.which("hadolint")
        if exe:
            self._executable = exe
            return exe

        common_paths = [
            "/usr/bin/hadolint",
            "/usr/local/bin/hadolint",
            "/opt/homebrew/bin/hadolint",
        ]
        for path in common_paths:
            if Path(path).exists():
                self._executable = path
                return path

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

    def _is_dockerfile(self, file_path: Path) -> bool:
        name_lower = file_path.name.lower()

        if name_lower in self.DOCKERFILE_NAMES:
            return True

        if name_lower.startswith("dockerfile"):
            return True

        if file_path.suffix.lower() == ".dockerfile":
            return True

        return False

    def _get_dockerfiles(self, target_path: Path, files: list[Path]) -> list[Path]:
        dockerfiles = [f for f in files if self._is_dockerfile(f)]

        for pattern in ["Dockerfile", "dockerfile", "*.dockerfile", "*.Dockerfile"]:
            for match in target_path.rglob(pattern):
                if match.is_file() and match not in dockerfiles:
                    dockerfiles.append(match)

        return dockerfiles

    async def scan(self, target_path: Path, files: list[Path]) -> list[Finding]:
        dockerfiles = self._get_dockerfiles(target_path, files)

        if not dockerfiles:
            self.log("No Dockerfiles detected, skipping Hadolint")
            return []

        self.log(f"Running Hadolint on {len(dockerfiles)} Dockerfiles")

        exe = self._find_executable()
        if not exe:
            self.log("Hadolint executable not found")
            return []

        all_findings: list[Finding] = []

        for dockerfile in dockerfiles:
            try:
                result = subprocess.run(
                    [exe, "--format", "json", str(dockerfile)],
                    capture_output=True,
                    text=True,
                    timeout=60,
                )

                if result.stdout:
                    findings = self._parse_results(result.stdout, dockerfile)
                    all_findings.extend(findings)

            except subprocess.TimeoutExpired:
                self.log(f"Hadolint timed out on {dockerfile.name}")
            except subprocess.SubprocessError as e:
                self.log(f"Hadolint error on {dockerfile.name}: {e}")

        self.log(f"Found {len(all_findings)} Dockerfile issues")
        return all_findings

    def _parse_results(self, output: str, dockerfile: Path) -> list[Finding]:
        findings: list[Finding] = []

        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            self.log(f"Failed to parse Hadolint JSON output for {dockerfile.name}")
            return []

        if not isinstance(data, list):
            return []

        for issue in data:
            code = issue.get("code", "")
            level = issue.get("level", "warning")
            message = issue.get("message", "Unknown issue")
            line = issue.get("line")
            column = issue.get("column")

            severity = self.SEVERITY_MAP.get(level, Severity.MEDIUM)
            cwe_id = self.CWE_MAP.get(code)

            description = message
            if column:
                description += f" (column {column})"

            finding = Finding(
                title=f"{code}: {self._get_issue_title(code)}",
                description=description,
                severity=severity,
                file_path=dockerfile,
                line_number=line,
                cwe_id=cwe_id,
                tool=self.name,
                confidence="high",
                remediation=self._get_remediation(code),
            )
            findings.append(finding)

        return findings

    def _get_issue_title(self, code: str) -> str:
        titles = {
            "DL3000": "Use absolute WORKDIR",
            "DL3001": "Invalid command",
            "DL3002": "Running as root",
            "DL3003": "Use WORKDIR instead of cd",
            "DL3004": "Do not use sudo",
            "DL3006": "Always tag base image",
            "DL3007": "Using latest tag",
            "DL3008": "Pin apt-get versions",
            "DL3009": "Delete apt-get lists",
            "DL3013": "Pin pip versions",
            "DL3015": "Avoid apt-get upgrade",
            "DL3018": "Pin apk versions",
            "DL3019": "Use apk --no-cache",
            "DL3020": "Use COPY instead of ADD",
            "DL3022": "Use --no-install-recommends",
            "DL3025": "Use JSON notation for CMD",
            "DL3027": "Do not use apt",
            "DL3028": "Pin gem versions",
            "DL3042": "Avoid pip cache",
            "DL3045": "COPY --from reference",
            "DL4000": "MAINTAINER deprecated",
            "DL4006": "Set SHELL for pipefail",
        }
        return titles.get(code, "Dockerfile issue")

    def _get_remediation(self, code: str) -> str:
        remediations = {
            "DL3000": "Use an absolute path for WORKDIR. Example: WORKDIR /app",
            "DL3001": "Review the command for syntax errors or unsupported instructions.",
            "DL3002": "Add 'USER nonroot' to run as non-root user for security.",
            "DL3003": "Replace 'RUN cd /dir && ...' with 'WORKDIR /dir' followed by 'RUN ...'",
            "DL3004": "Remove sudo. Docker runs as root by default. Use USER to switch users.",
            "DL3006": "Tag your base image with a version: FROM image:version instead of FROM image",
            "DL3007": "Avoid 'latest' tag. Pin to a specific version for reproducibility.",
            "DL3008": "Pin package versions: apt-get install package=version",
            "DL3009": "Add 'rm -rf /var/lib/apt/lists/*' after apt-get install to reduce image size.",
            "DL3013": "Pin pip packages: pip install package==version",
            "DL3015": "Remove apt-get upgrade. Use updated base images instead.",
            "DL3018": "Pin apk packages: apk add package=version",
            "DL3019": "Use 'apk add --no-cache' instead of 'apk add && rm -rf /var/cache/apk/*'",
            "DL3020": "Use COPY for local files. ADD is only for URLs or tar extraction.",
            "DL3022": "Use 'apt-get install --no-install-recommends' to reduce image size.",
            "DL3025": "Use JSON notation: CMD [\"executable\", \"param\"] instead of CMD command param",
            "DL3027": "Use apt-get instead of apt for non-interactive scripts.",
            "DL3028": "Pin gem versions: gem install package:version",
            "DL3042": "Use 'pip install --no-cache-dir' to avoid storing pip cache in image.",
            "DL3045": "Verify the --from reference in COPY exists in a previous build stage.",
            "DL4000": "Replace MAINTAINER with LABEL maintainer=\"name@example.com\"",
            "DL4006": "Add 'SHELL [\"/bin/bash\", \"-o\", \"pipefail\", \"-c\"]' before RUN with pipes.",
        }
        return remediations.get(
            code,
            "Review Hadolint documentation at https://github.com/hadolint/hadolint"
        )
