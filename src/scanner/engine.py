import asyncio
import time
from pathlib import Path
from typing import Callable, Optional

import pathspec

from .models import Finding, ScanResult
from .engines.base import BaseEngine
from .engines.bandit_engine import BanditEngine
from .engines.semgrep_engine import SemgrepEngine
from .engines.safety_engine import SafetyEngine
from .engines.gemini_engine import GeminiEngine
from .engines.gitleaks_engine import GitleaksEngine
from .engines.trufflehog_engine import TruffleHogEngine
from .engines.detect_secrets_engine import DetectSecretsEngine
from .engines.trivy_engine import TrivyEngine
from .engines.grype_engine import GrypeEngine
from .engines.checkov_engine import CheckovEngine
from .engines.shellcheck_engine import ShellCheckEngine
from .engines.hadolint_engine import HadolintEngine
from .engines.gosec_engine import GosecEngine
from .engines.brakeman_engine import BrakemanEngine
from .engines.spotbugs_engine import SpotBugsEngine
from .engines.phpstan_engine import PHPStanEngine
from .engines.horusec_engine import HorusecEngine


class Scanner:
    DEFAULT_IGNORE_PATTERNS = [
        ".git/",
        ".svn/",
        ".hg/",
        "node_modules/",
        "__pycache__/",
        "*.pyc",
        ".venv/",
        "venv/",
        ".env/",
        "env/",
        "dist/",
        "build/",
        ".idea/",
        ".vscode/",
        "*.min.js",
        "*.min.css",
        "*.map",
        "*.lock",
        "package-lock.json",
        "yarn.lock",
        "poetry.lock",
    ]

    CODE_EXTENSIONS = {
        ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb",
        ".php", ".c", ".cpp", ".h", ".hpp", ".cs", ".swift", ".kt",
        ".rs", ".scala", ".sh", ".bash", ".ps1", ".sql",
    }

    def __init__(
        self,
        on_progress: Optional[Callable[[str], None]] = None,
        gemini_api_key: Optional[str] = None,
        gemini_model: Optional[str] = None,
        enable_bandit: bool = True,
        enable_semgrep: bool = True,
        enable_safety: bool = True,
        enable_gemini: bool = True,
        enable_gitleaks: bool = True,
        enable_trufflehog: bool = True,
        enable_detect_secrets: bool = True,
        enable_trivy: bool = True,
        enable_grype: bool = True,
        enable_checkov: bool = True,
        enable_shellcheck: bool = True,
        enable_hadolint: bool = True,
        enable_gosec: bool = True,
        enable_brakeman: bool = True,
        enable_spotbugs: bool = True,
        enable_phpstan: bool = True,
        enable_horusec: bool = True,
    ):
        self.on_progress = on_progress
        self.gemini_api_key = gemini_api_key
        self.gemini_model = gemini_model
        self.enable_bandit = enable_bandit
        self.enable_semgrep = enable_semgrep
        self.enable_safety = enable_safety
        self.enable_gemini = enable_gemini
        self.enable_gitleaks = enable_gitleaks
        self.enable_trufflehog = enable_trufflehog
        self.enable_detect_secrets = enable_detect_secrets
        self.enable_trivy = enable_trivy
        self.enable_grype = enable_grype
        self.enable_checkov = enable_checkov
        self.enable_shellcheck = enable_shellcheck
        self.enable_hadolint = enable_hadolint
        self.enable_gosec = enable_gosec
        self.enable_brakeman = enable_brakeman
        self.enable_spotbugs = enable_spotbugs
        self.enable_phpstan = enable_phpstan
        self.enable_horusec = enable_horusec
        self._engines: list[BaseEngine] = []

    def log(self, message: str) -> None:
        if self.on_progress:
            self.on_progress(message)

    def _init_engines(self) -> None:
        self._engines = []

        if self.enable_bandit:
            engine = BanditEngine(on_progress=self.on_progress)
            if engine.is_available():
                self._engines.append(engine)
                self.log("Bandit engine loaded")
            else:
                self.log("Bandit not available - install with: pip install bandit")

        if self.enable_semgrep:
            engine = SemgrepEngine(on_progress=self.on_progress)
            if engine.is_available():
                self._engines.append(engine)
                self.log("Semgrep engine loaded")
            else:
                self.log("Semgrep not available - install with: pip install semgrep")

        if self.enable_safety:
            engine = SafetyEngine(on_progress=self.on_progress)
            if engine.is_available():
                self._engines.append(engine)
                self.log("Safety engine loaded")
            else:
                self.log("Safety not available - install with: pip install safety")

        if self.enable_gemini and self.gemini_api_key:
            engine = GeminiEngine(
                api_key=self.gemini_api_key,
                on_progress=self.on_progress,
                model_name=self.gemini_model,
            )
            if engine.is_available():
                self._engines.append(engine)
                self.log(f"Gemini AI engine loaded ({engine.model_name})")
            else:
                self.log("Gemini engine not available - check API key")

        if self.enable_gitleaks:
            engine = GitleaksEngine(on_progress=self.on_progress)
            if engine.is_available():
                self._engines.append(engine)
                self.log("Gitleaks engine loaded")
            else:
                self.log("Gitleaks not available - install from: https://github.com/gitleaks/gitleaks")

        if self.enable_trufflehog:
            engine = TruffleHogEngine(on_progress=self.on_progress)
            if engine.is_available():
                self._engines.append(engine)
                self.log("TruffleHog engine loaded")
            else:
                self.log("TruffleHog not available - install from: https://github.com/trufflesecurity/trufflehog")

        if self.enable_detect_secrets:
            engine = DetectSecretsEngine(on_progress=self.on_progress)
            if engine.is_available():
                self._engines.append(engine)
                self.log("detect-secrets engine loaded")
            else:
                self.log("detect-secrets not available - install with: pip install detect-secrets")

        if self.enable_trivy:
            engine = TrivyEngine(on_progress=self.on_progress)
            if engine.is_available():
                self._engines.append(engine)
                self.log("Trivy engine loaded")
            else:
                self.log("Trivy not available - install from: https://github.com/aquasecurity/trivy")

        if self.enable_grype:
            engine = GrypeEngine(on_progress=self.on_progress)
            if engine.is_available():
                self._engines.append(engine)
                self.log("Grype engine loaded")
            else:
                self.log("Grype not available - install from: https://github.com/anchore/grype")

        if self.enable_checkov:
            engine = CheckovEngine(on_progress=self.on_progress)
            if engine.is_available():
                self._engines.append(engine)
                self.log("Checkov engine loaded")
            else:
                self.log("Checkov not available - install with: pip install checkov")

        if self.enable_shellcheck:
            engine = ShellCheckEngine(on_progress=self.on_progress)
            if engine.is_available():
                self._engines.append(engine)
                self.log("ShellCheck engine loaded")
            else:
                self.log("ShellCheck not available - install from: https://github.com/koalaman/shellcheck")

        if self.enable_hadolint:
            engine = HadolintEngine(on_progress=self.on_progress)
            if engine.is_available():
                self._engines.append(engine)
                self.log("Hadolint engine loaded")
            else:
                self.log("Hadolint not available - install from: https://github.com/hadolint/hadolint")

        if self.enable_gosec:
            engine = GosecEngine(on_progress=self.on_progress)
            if engine.is_available():
                self._engines.append(engine)
                self.log("Gosec engine loaded")
            else:
                self.log("Gosec not available - install with: go install github.com/securego/gosec/v2/cmd/gosec@latest")

        if self.enable_brakeman:
            engine = BrakemanEngine(on_progress=self.on_progress)
            if engine.is_available():
                self._engines.append(engine)
                self.log("Brakeman engine loaded")
            else:
                self.log("Brakeman not available - install with: gem install brakeman")

        if self.enable_spotbugs:
            engine = SpotBugsEngine(on_progress=self.on_progress)
            if engine.is_available():
                self._engines.append(engine)
                self.log("SpotBugs engine loaded")
            else:
                self.log("SpotBugs not available - install from: https://spotbugs.github.io/")

        if self.enable_phpstan:
            engine = PHPStanEngine(on_progress=self.on_progress)
            if engine.is_available():
                self._engines.append(engine)
                self.log("PHPStan engine loaded")
            else:
                self.log("PHPStan not available - install with: composer require --dev phpstan/phpstan")

        if self.enable_horusec:
            engine = HorusecEngine(on_progress=self.on_progress)
            if engine.is_available():
                self._engines.append(engine)
                self.log("Horusec engine loaded")
            else:
                self.log("Horusec not available - install from: https://horusec.io/")

    def _load_gitignore(self, target_path: Path) -> pathspec.PathSpec:
        patterns = self.DEFAULT_IGNORE_PATTERNS.copy()
        gitignore_path = target_path / ".gitignore"

        if gitignore_path.exists():
            try:
                with open(gitignore_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            patterns.append(line)
            except (OSError, UnicodeDecodeError):
                self.log(f"Warning: Could not read {gitignore_path}")

        return pathspec.PathSpec.from_lines("gitwildmatch", patterns)

    def _discover_files(self, target_path: Path) -> list[Path]:
        self.log(f"Discovering files in {target_path}")
        ignore_spec = self._load_gitignore(target_path)
        files: list[Path] = []

        for file_path in target_path.rglob("*"):
            if not file_path.is_file():
                continue

            relative_path = file_path.relative_to(target_path)
            if ignore_spec.match_file(str(relative_path)):
                continue

            if file_path.suffix.lower() in self.CODE_EXTENSIONS:
                files.append(file_path)

        self.log(f"Found {len(files)} code files to scan")
        return files

    async def scan(self, target_path: Path) -> ScanResult:
        start_time = time.time()
        target_path = Path(target_path).resolve()

        if not target_path.exists():
            return ScanResult(
                target_path=target_path,
                errors=[f"Target path does not exist: {target_path}"],
            )

        if not target_path.is_dir():
            return ScanResult(
                target_path=target_path,
                errors=[f"Target path is not a directory: {target_path}"],
            )

        self.log(f"Starting scan of {target_path}")
        self._init_engines()

        if not self._engines:
            return ScanResult(
                target_path=target_path,
                errors=["No scanner engines available"],
            )

        files = self._discover_files(target_path)
        if not files:
            return ScanResult(
                target_path=target_path,
                files_scanned=0,
                scan_duration_seconds=time.time() - start_time,
            )

        all_findings: list[Finding] = []
        errors: list[str] = []

        tasks = [engine.scan(target_path, files) for engine in self._engines]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for engine, result in zip(self._engines, results):
            if isinstance(result, Exception):
                error_msg = f"{engine.name} error: {result}"
                self.log(error_msg)
                errors.append(error_msg)
            else:
                all_findings.extend(result)
                self.log(f"{engine.name} found {len(result)} issues")

        all_findings.sort(key=lambda f: f.severity, reverse=True)

        duration = time.time() - start_time
        self.log(f"Scan complete in {duration:.2f}s - {len(all_findings)} total findings")

        return ScanResult(
            target_path=target_path,
            findings=all_findings,
            files_scanned=len(files),
            scan_duration_seconds=duration,
            errors=errors,
        )

    def scan_sync(self, target_path: Path) -> ScanResult:
        return asyncio.run(self.scan(target_path))
