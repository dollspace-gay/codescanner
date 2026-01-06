import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional, Callable

from .base import BaseEngine
from ..models import Finding, Severity


class SpotBugsEngine(BaseEngine):
    name = "spotbugs"
    description = "Java security scanner with FindSecBugs plugin"

    PRIORITY_SEVERITY = {
        1: Severity.HIGH,
        2: Severity.MEDIUM,
        3: Severity.LOW,
    }

    SECURITY_CATEGORIES = {
        "SECURITY",
        "MALICIOUS_CODE",
        "SQL_INJECTION",
        "COMMAND_INJECTION",
        "XSS",
        "PATH_TRAVERSAL",
        "WEAK_CRYPTO",
        "INSECURE_COOKIE",
    }

    CWE_MAP = {
        "SQL_INJECTION": "CWE-89",
        "SQL_INJECTION_JDBC": "CWE-89",
        "SQL_INJECTION_JPA": "CWE-89",
        "SQL_INJECTION_SPRING_JDBC": "CWE-89",
        "COMMAND_INJECTION": "CWE-78",
        "PATH_TRAVERSAL_IN": "CWE-22",
        "PATH_TRAVERSAL_OUT": "CWE-22",
        "XSS_REQUEST_WRAPPER": "CWE-79",
        "XSS_SERVLET": "CWE-79",
        "XSS_JSP_PRINT": "CWE-79",
        "WEAK_TRUST_MANAGER": "CWE-295",
        "WEAK_HOSTNAME_VERIFIER": "CWE-297",
        "WEAK_MESSAGE_DIGEST_MD5": "CWE-327",
        "WEAK_MESSAGE_DIGEST_SHA1": "CWE-327",
        "CUSTOM_MESSAGE_DIGEST": "CWE-327",
        "CIPHER_INTEGRITY": "CWE-327",
        "ECB_MODE": "CWE-327",
        "PADDING_ORACLE": "CWE-327",
        "DES_USAGE": "CWE-327",
        "RSA_NO_PADDING": "CWE-327",
        "BLOWFISH_KEY_SIZE": "CWE-326",
        "HARD_CODE_PASSWORD": "CWE-798",
        "HARD_CODE_KEY": "CWE-798",
        "PREDICTABLE_RANDOM": "CWE-330",
        "UNSAFE_HASH_EQUALS": "CWE-208",
        "XXEF": "CWE-611",
        "XXE_DOCUMENT": "CWE-611",
        "XXE_SAXPARSER": "CWE-611",
        "XXE_XMLREADER": "CWE-611",
        "XXE_XPATH": "CWE-611",
        "LDAP_INJECTION": "CWE-90",
        "XPATH_INJECTION": "CWE-643",
        "SCRIPT_ENGINE_INJECTION": "CWE-94",
        "SPEL_INJECTION": "CWE-94",
        "EL_INJECTION": "CWE-94",
        "OGNL_INJECTION": "CWE-94",
        "SEAM_LOG_INJECTION": "CWE-117",
        "HTTP_RESPONSE_SPLITTING": "CWE-113",
        "CRLF_INJECTION_LOGS": "CWE-117",
        "EXTERNAL_CONFIG_CONTROL": "CWE-15",
        "STRUTS_FILE_DISCLOSURE": "CWE-22",
        "SPRING_FILE_DISCLOSURE": "CWE-22",
        "REQUESTDISPATCHER_FILE_DISCLOSURE": "CWE-22",
        "URLCONNECTION_SSRF_FD": "CWE-918",
        "UNVALIDATED_REDIRECT": "CWE-601",
        "COOKIE_PERSISTENT": "CWE-539",
        "COOKIE_USAGE": "CWE-614",
        "INSECURE_COOKIE": "CWE-614",
        "HTTPONLY_COOKIE": "CWE-1004",
        "TRUST_BOUNDARY_VIOLATION": "CWE-501",
        "OBJECT_DESERIALIZATION": "CWE-502",
        "JACKSON_UNSAFE_DESERIALIZATION": "CWE-502",
        "SPRING_CSRF_PROTECTION_DISABLED": "CWE-352",
        "PERMISSIVE_CORS": "CWE-346",
    }

    def __init__(self, on_progress: Optional[Callable[[str], None]] = None):
        super().__init__(on_progress)
        self._executable: Optional[str] = None

    def _find_executable(self) -> Optional[str]:
        if self._executable:
            return self._executable

        exe = shutil.which("spotbugs")
        if exe:
            self._executable = exe
            return exe

        common_paths = [
            "/usr/bin/spotbugs",
            "/usr/local/bin/spotbugs",
            "/opt/spotbugs/bin/spotbugs",
            "/opt/homebrew/bin/spotbugs",
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
                [exe, "-version"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            return result.returncode == 0 or "SpotBugs" in result.stdout
        except (subprocess.SubprocessError, FileNotFoundError, OSError):
            return False

    def _has_java_files(self, files: list[Path]) -> bool:
        return any(f.suffix.lower() == ".java" for f in files)

    def _find_class_dirs(self, target_path: Path) -> list[Path]:
        class_dirs = []
        common_locations = [
            "target/classes",
            "build/classes",
            "build/classes/java/main",
            "out/production",
            "bin",
        ]

        for loc in common_locations:
            class_dir = target_path / loc
            if class_dir.exists() and class_dir.is_dir():
                class_dirs.append(class_dir)

        return class_dirs

    async def scan(self, target_path: Path, files: list[Path]) -> list[Finding]:
        if not self._has_java_files(files):
            self.log("No Java files detected, skipping SpotBugs")
            return []

        class_dirs = self._find_class_dirs(target_path)
        if not class_dirs:
            self.log("No compiled Java classes found. Build the project first (mvn compile or gradle build)")
            return []

        self.log(f"Running SpotBugs security scan on {target_path}")

        exe = self._find_executable()
        if not exe:
            self.log("SpotBugs executable not found")
            return []

        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as f:
            output_file = Path(f.name)

        try:
            cmd = [
                exe,
                "-textui",
                "-xml:withMessages",
                "-output", str(output_file),
                "-effort:max",
                "-low",
            ]

            for class_dir in class_dirs:
                cmd.append(str(class_dir))

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=str(target_path),
                timeout=600,
            )

            if output_file.exists():
                return self._parse_results(output_file, target_path)
            return []

        except subprocess.TimeoutExpired:
            self.log("SpotBugs scan timed out")
            return []
        except subprocess.SubprocessError as e:
            self.log(f"SpotBugs error: {e}")
            return []
        finally:
            if output_file.exists():
                output_file.unlink()

    def _parse_results(self, output_file: Path, target_path: Path) -> list[Finding]:
        findings: list[Finding] = []

        try:
            tree = ET.parse(output_file)
            root = tree.getroot()
        except ET.ParseError as e:
            self.log(f"Failed to parse SpotBugs XML output: {e}")
            return []

        for bug_instance in root.findall(".//BugInstance"):
            bug_type = bug_instance.get("type", "")
            category = bug_instance.get("category", "")
            priority = int(bug_instance.get("priority", "2"))

            is_security = (
                category in self.SECURITY_CATEGORIES or
                bug_type in self.CWE_MAP or
                "SECURITY" in bug_type or
                "INJECTION" in bug_type or
                "XSS" in bug_type
            )

            if not is_security:
                continue

            severity = self.PRIORITY_SEVERITY.get(priority, Severity.MEDIUM)
            cwe_id = self.CWE_MAP.get(bug_type)

            message_elem = bug_instance.find("LongMessage")
            message = message_elem.text if message_elem is not None else bug_type

            source_line = bug_instance.find("SourceLine")
            if source_line is not None:
                source_path = source_line.get("sourcepath", "")
                start_line = source_line.get("start")
                end_line = source_line.get("end")

                if source_path:
                    file_path = self._resolve_source_path(target_path, source_path)
                else:
                    file_path = target_path

                line_num = int(start_line) if start_line else None
                end_line_num = int(end_line) if end_line else None
            else:
                file_path = target_path
                line_num = None
                end_line_num = None

            finding = Finding(
                title=f"{bug_type}: {self._get_issue_title(bug_type)}",
                description=message,
                severity=severity,
                file_path=file_path,
                line_number=line_num,
                end_line=end_line_num,
                cwe_id=cwe_id,
                tool=self.name,
                confidence="high" if priority == 1 else "medium",
                remediation=self._get_remediation(bug_type),
            )
            findings.append(finding)

        self.log(f"Found {len(findings)} Java security issues")
        return findings

    def _resolve_source_path(self, target_path: Path, source_path: str) -> Path:
        common_source_dirs = ["src/main/java", "src", "java"]

        for src_dir in common_source_dirs:
            full_path = target_path / src_dir / source_path
            if full_path.exists():
                return full_path

        return target_path / source_path

    def _get_issue_title(self, bug_type: str) -> str:
        titles = {
            "SQL_INJECTION": "SQL Injection",
            "SQL_INJECTION_JDBC": "SQL Injection via JDBC",
            "SQL_INJECTION_JPA": "SQL Injection via JPA",
            "COMMAND_INJECTION": "OS Command Injection",
            "PATH_TRAVERSAL_IN": "Path Traversal (Input)",
            "PATH_TRAVERSAL_OUT": "Path Traversal (Output)",
            "XSS_REQUEST_WRAPPER": "XSS in Request Wrapper",
            "XSS_SERVLET": "XSS in Servlet",
            "XSS_JSP_PRINT": "XSS in JSP",
            "WEAK_TRUST_MANAGER": "Weak Trust Manager",
            "WEAK_HOSTNAME_VERIFIER": "Weak Hostname Verifier",
            "WEAK_MESSAGE_DIGEST_MD5": "Weak Hash (MD5)",
            "WEAK_MESSAGE_DIGEST_SHA1": "Weak Hash (SHA1)",
            "CIPHER_INTEGRITY": "Cipher without Integrity",
            "ECB_MODE": "ECB Mode Encryption",
            "DES_USAGE": "DES Encryption",
            "HARD_CODE_PASSWORD": "Hardcoded Password",
            "HARD_CODE_KEY": "Hardcoded Encryption Key",
            "PREDICTABLE_RANDOM": "Predictable Random",
            "XXE_DOCUMENT": "XXE Vulnerability",
            "LDAP_INJECTION": "LDAP Injection",
            "XPATH_INJECTION": "XPath Injection",
            "SCRIPT_ENGINE_INJECTION": "Script Injection",
            "SPEL_INJECTION": "SpEL Injection",
            "OBJECT_DESERIALIZATION": "Unsafe Deserialization",
            "UNVALIDATED_REDIRECT": "Open Redirect",
            "INSECURE_COOKIE": "Insecure Cookie",
            "PERMISSIVE_CORS": "Permissive CORS",
        }
        return titles.get(bug_type, bug_type.replace("_", " ").title())

    def _get_remediation(self, bug_type: str) -> str:
        remediations = {
            "SQL_INJECTION": "Use PreparedStatement with parameterized queries instead of string concatenation.",
            "COMMAND_INJECTION": "Avoid Runtime.exec() with user input. Use ProcessBuilder with argument list.",
            "PATH_TRAVERSAL_IN": "Validate file paths. Use canonical path and check against allowed directories.",
            "XSS_SERVLET": "Encode output using OWASP Java Encoder or framework-provided escaping.",
            "WEAK_MESSAGE_DIGEST_MD5": "Replace MD5 with SHA-256 or stronger for security-sensitive hashing.",
            "WEAK_MESSAGE_DIGEST_SHA1": "Replace SHA1 with SHA-256 or stronger for security-sensitive hashing.",
            "ECB_MODE": "Use GCM or CBC mode with random IV instead of ECB mode.",
            "DES_USAGE": "Replace DES with AES-256 for encryption.",
            "HARD_CODE_PASSWORD": "Store credentials in secure configuration or secrets manager.",
            "HARD_CODE_KEY": "Use key derivation and secure key storage instead of hardcoded keys.",
            "PREDICTABLE_RANDOM": "Use SecureRandom instead of java.util.Random for security.",
            "XXE_DOCUMENT": "Disable external entities: factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)",
            "OBJECT_DESERIALIZATION": "Implement ObjectInputFilter or use safe serialization formats like JSON.",
            "UNVALIDATED_REDIRECT": "Validate redirect URLs against whitelist of allowed destinations.",
            "INSECURE_COOKIE": "Set cookie.setSecure(true) and cookie.setHttpOnly(true).",
            "PERMISSIVE_CORS": "Restrict CORS origins to specific trusted domains.",
        }
        return remediations.get(
            bug_type,
            "Review SpotBugs/FindSecBugs documentation for remediation guidance."
        )
