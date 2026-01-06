import json
import shutil
import subprocess
from pathlib import Path
from typing import Optional, Callable

from .base import BaseEngine
from ..models import Finding, Severity


class GosecEngine(BaseEngine):
    name = "gosec"
    description = "Go security checker"

    SEVERITY_MAP = {
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
    }

    CONFIDENCE_MAP = {
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low",
    }

    CWE_MAP = {
        "G101": "CWE-798",   # Hardcoded credentials
        "G102": "CWE-200",   # Bind to all interfaces
        "G103": "CWE-242",   # Audit use of unsafe block
        "G104": "CWE-703",   # Audit errors not checked
        "G106": "CWE-322",   # Audit use of ssh.InsecureIgnoreHostKey
        "G107": "CWE-88",    # URL provided to HTTP request as taint input
        "G108": "CWE-200",   # Profiling endpoint exposed
        "G109": "CWE-190",   # Integer overflow
        "G110": "CWE-409",   # Decompression bomb
        "G111": "CWE-22",    # Directory traversal
        "G112": "CWE-400",   # Slowloris attack
        "G113": "CWE-190",   # Integer overflow via multiplication
        "G114": "CWE-676",   # Use of net/http serve functions
        "G201": "CWE-89",    # SQL query construction using format string
        "G202": "CWE-89",    # SQL query construction using string concatenation
        "G203": "CWE-79",    # Use of unescaped data in HTML templates
        "G204": "CWE-78",    # Audit use of command execution
        "G301": "CWE-276",   # Poor file permissions used when creating a directory
        "G302": "CWE-276",   # Poor file permissions used with chmod
        "G303": "CWE-377",   # Creating tempfile using a predictable path
        "G304": "CWE-22",    # File path provided as taint input
        "G305": "CWE-22",    # File traversal when extracting zip/tar
        "G306": "CWE-276",   # Poor file permissions used when writing to a new file
        "G307": "CWE-703",   # Deferring a method which returns an error
        "G401": "CWE-326",   # Use of weak cryptographic primitive
        "G402": "CWE-295",   # TLS InsecureSkipVerify set to true
        "G403": "CWE-310",   # Use of weak RSA key
        "G404": "CWE-338",   # Use of weak random number generator
        "G501": "CWE-327",   # Import blocklist: crypto/md5
        "G502": "CWE-327",   # Import blocklist: crypto/des
        "G503": "CWE-327",   # Import blocklist: crypto/rc4
        "G504": "CWE-327",   # Import blocklist: net/http/cgi
        "G505": "CWE-327",   # Import blocklist: crypto/sha1
        "G601": "CWE-118",   # Implicit memory aliasing in for loop
        "G602": "CWE-119",   # Slice access out of bounds
    }

    def __init__(self, on_progress: Optional[Callable[[str], None]] = None):
        super().__init__(on_progress)
        self._executable: Optional[str] = None

    def _find_executable(self) -> Optional[str]:
        if self._executable:
            return self._executable

        exe = shutil.which("gosec")
        if exe:
            self._executable = exe
            return exe

        common_paths = [
            "/usr/bin/gosec",
            "/usr/local/bin/gosec",
            "/opt/homebrew/bin/gosec",
        ]
        for path in common_paths:
            if Path(path).exists():
                self._executable = path
                return path

        go_path = shutil.which("go")
        if go_path:
            go_bin = Path(go_path).parent
            gosec_path = go_bin / "gosec"
            if gosec_path.exists():
                self._executable = str(gosec_path)
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
            return result.returncode == 0 or "Version" in result.stdout or "gosec" in result.stderr.lower()
        except (subprocess.SubprocessError, FileNotFoundError, OSError):
            return False

    def _has_go_files(self, files: list[Path]) -> bool:
        return any(f.suffix.lower() == ".go" for f in files)

    def _has_go_mod(self, target_path: Path) -> bool:
        return (target_path / "go.mod").exists()

    async def scan(self, target_path: Path, files: list[Path]) -> list[Finding]:
        if not self._has_go_files(files):
            self.log("No Go files detected, skipping Gosec")
            return []

        self.log(f"Running Gosec security scan on {target_path}")

        exe = self._find_executable()
        if not exe:
            self.log("Gosec executable not found")
            return []

        try:
            result = subprocess.run(
                [
                    exe,
                    "-fmt=json",
                    "-quiet",
                    "-stdout",
                    "./...",
                ],
                capture_output=True,
                text=True,
                cwd=str(target_path),
                timeout=300,
            )

            if result.stdout:
                return self._parse_results(result.stdout, target_path)
            return []

        except subprocess.TimeoutExpired:
            self.log("Gosec scan timed out")
            return []
        except subprocess.SubprocessError as e:
            self.log(f"Gosec error: {e}")
            return []

    def _parse_results(self, output: str, target_path: Path) -> list[Finding]:
        findings: list[Finding] = []

        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            self.log("Failed to parse Gosec JSON output")
            return []

        issues = data.get("Issues", [])

        for issue in issues:
            rule_id = issue.get("rule_id", "")
            severity_str = issue.get("severity", "MEDIUM")
            confidence_str = issue.get("confidence", "MEDIUM")
            details = issue.get("details", "")
            file_path_str = issue.get("file", "")
            line = issue.get("line")
            code = issue.get("code", "")

            severity = self.SEVERITY_MAP.get(severity_str.upper(), Severity.MEDIUM)
            confidence = self.CONFIDENCE_MAP.get(confidence_str.upper(), "medium")
            cwe_id = self.CWE_MAP.get(rule_id)

            if file_path_str:
                file_path = Path(file_path_str)
                if not file_path.is_absolute():
                    file_path = target_path / file_path_str
            else:
                file_path = target_path

            try:
                line_num = int(line.split("-")[0]) if line else None
            except (ValueError, AttributeError):
                line_num = None

            description = details
            if code:
                description += f"\n\nCode:\n{code}"

            finding = Finding(
                title=f"{rule_id}: {self._get_issue_title(rule_id)}",
                description=description,
                severity=severity,
                file_path=file_path,
                line_number=line_num,
                cwe_id=cwe_id,
                tool=self.name,
                confidence=confidence,
                remediation=self._get_remediation(rule_id),
            )
            findings.append(finding)

        self.log(f"Found {len(findings)} Go security issues")
        return findings

    def _get_issue_title(self, rule_id: str) -> str:
        titles = {
            "G101": "Hardcoded credentials",
            "G102": "Bind to all interfaces",
            "G103": "Unsafe block usage",
            "G104": "Unhandled errors",
            "G106": "SSH InsecureIgnoreHostKey",
            "G107": "URL injection",
            "G108": "Profiling endpoint exposed",
            "G109": "Integer overflow",
            "G110": "Decompression bomb",
            "G111": "Directory traversal",
            "G112": "Slowloris DoS vulnerability",
            "G113": "Integer overflow multiplication",
            "G114": "Unsafe net/http serve",
            "G201": "SQL injection (format string)",
            "G202": "SQL injection (concatenation)",
            "G203": "XSS in HTML template",
            "G204": "Command execution",
            "G301": "Insecure directory permissions",
            "G302": "Insecure chmod permissions",
            "G303": "Predictable temp file path",
            "G304": "File path injection",
            "G305": "Zip/tar file traversal",
            "G306": "Insecure file permissions",
            "G307": "Deferred error not checked",
            "G401": "Weak cryptographic primitive",
            "G402": "TLS verification disabled",
            "G403": "Weak RSA key",
            "G404": "Weak random number generator",
            "G501": "Blacklisted import: MD5",
            "G502": "Blacklisted import: DES",
            "G503": "Blacklisted import: RC4",
            "G504": "Blacklisted import: CGI",
            "G505": "Blacklisted import: SHA1",
            "G601": "Memory aliasing in loop",
            "G602": "Slice bounds check",
        }
        return titles.get(rule_id, "Go security issue")

    def _get_remediation(self, rule_id: str) -> str:
        remediations = {
            "G101": "Remove hardcoded credentials. Use environment variables or a secrets manager.",
            "G102": "Bind to a specific interface instead of 0.0.0.0. Use 127.0.0.1 for local-only services.",
            "G103": "Avoid using unsafe package. If necessary, document why it's needed and review carefully.",
            "G104": "Check all returned errors. Use 'if err != nil { return err }' pattern.",
            "G106": "Implement proper host key verification instead of InsecureIgnoreHostKey.",
            "G107": "Validate and sanitize URLs before making HTTP requests.",
            "G108": "Remove pprof endpoint in production or restrict access with authentication.",
            "G109": "Check for integer overflow before operations. Use math.MaxInt checks.",
            "G110": "Limit the size of decompressed data. Use io.LimitReader.",
            "G111": "Validate file paths and use filepath.Clean. Reject paths with '..'.",
            "G112": "Set ReadTimeout and WriteTimeout on HTTP server to prevent Slowloris.",
            "G113": "Check for overflow before integer multiplication operations.",
            "G114": "Set appropriate timeouts when using http.ListenAndServe.",
            "G201": "Use parameterized queries instead of string formatting for SQL.",
            "G202": "Use parameterized queries instead of string concatenation for SQL.",
            "G203": "Use template functions to properly escape HTML content.",
            "G204": "Avoid executing user-controlled input. Validate and sanitize if necessary.",
            "G301": "Use restrictive permissions (0750 or less) when creating directories.",
            "G302": "Use restrictive permissions when using chmod (0644 for files, 0755 for executables).",
            "G303": "Use os.CreateTemp or ioutil.TempFile for secure temp file creation.",
            "G304": "Validate file paths. Use filepath.Clean and reject paths outside allowed directories.",
            "G305": "Check extracted file paths for directory traversal before extraction.",
            "G306": "Use restrictive permissions (0600 or 0644) when writing files.",
            "G307": "Handle the error returned by deferred Close() calls.",
            "G401": "Use modern cryptographic algorithms (AES-GCM, ChaCha20-Poly1305).",
            "G402": "Enable TLS certificate verification. Remove InsecureSkipVerify: true.",
            "G403": "Use RSA keys of at least 2048 bits, preferably 4096.",
            "G404": "Use crypto/rand instead of math/rand for security-sensitive operations.",
            "G501": "Replace MD5 with SHA-256 or better for hashing.",
            "G502": "Replace DES with AES for encryption.",
            "G503": "Replace RC4 with AES-GCM or ChaCha20-Poly1305.",
            "G504": "Avoid using net/http/cgi. Use modern alternatives.",
            "G505": "Replace SHA1 with SHA-256 or better for security-critical hashing.",
            "G601": "Use explicit indexing or copy the loop variable to avoid aliasing.",
            "G602": "Add bounds checking before accessing slice elements.",
        }
        return remediations.get(
            rule_id,
            "Review gosec documentation at https://github.com/securego/gosec"
        )
