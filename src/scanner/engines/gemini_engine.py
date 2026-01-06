import asyncio
import re
from pathlib import Path
from typing import Optional, Callable

from google import genai
from google.genai import types

from .base import BaseEngine
from ..models import Finding, Severity


class GeminiEngine(BaseEngine):
    name = "gemini-ai"
    description = "AI-powered code vulnerability scanner using Gemini"

    AVAILABLE_MODELS = {
        "Gemini 2.5 Pro": "gemini-2.5-pro",
        "Gemini 3 Pro": "gemini-3-pro",
    }
    DEFAULT_MODEL = "Gemini 2.5 Pro"

    MAX_FILE_SIZE = 100_000
    MAX_CONCURRENT = 5
    CHUNK_SIZE = 50_000

    SYSTEM_PROMPT = """You are a senior security engineer performing a code security audit.
Analyze the provided code for security vulnerabilities, focusing on:

1. Injection vulnerabilities (SQL, command, LDAP, XPath, etc.)
2. Authentication and authorization flaws
3. Sensitive data exposure (hardcoded secrets, PII leaks)
4. Security misconfigurations
5. Cross-site scripting (XSS) and CSRF
6. Insecure deserialization
7. Using components with known vulnerabilities
8. Insufficient logging and monitoring
9. Cryptographic failures (weak algorithms, improper key management)
10. Path traversal and file inclusion vulnerabilities

For each vulnerability found, respond in this exact format:
VULNERABILITY:
TITLE: [Short descriptive title]
SEVERITY: [CRITICAL|HIGH|MEDIUM|LOW|INFO]
LINE: [Line number or range, e.g., "42" or "42-45"]
CWE: [CWE ID if applicable, e.g., "CWE-89"]
DESCRIPTION: [Detailed explanation of the vulnerability]
REMEDIATION: [Specific steps to fix the issue]
END_VULNERABILITY

If no vulnerabilities are found, respond with: NO_VULNERABILITIES_FOUND

Be thorough but avoid false positives. Only report actual security issues, not style or performance concerns."""

    def __init__(
        self,
        api_key: str,
        on_progress: Optional[Callable[[str], None]] = None,
        model_name: Optional[str] = None,
    ):
        super().__init__(on_progress)
        self.api_key = api_key
        self._client: Optional[genai.Client] = None
        self.model_name = model_name or self.DEFAULT_MODEL
        self.model_id = self.AVAILABLE_MODELS.get(self.model_name, self.AVAILABLE_MODELS[self.DEFAULT_MODEL])

    def is_available(self) -> bool:
        if not self.api_key:
            return False
        try:
            self._client = genai.Client(api_key=self.api_key)
            return True
        except Exception:
            return False

    def _get_client(self) -> genai.Client:
        if self._client is None:
            self._client = genai.Client(api_key=self.api_key)
        return self._client

    async def scan(self, target_path: Path, files: list[Path]) -> list[Finding]:
        self.log(f"Running AI security analysis on {len(files)} files")

        scannable_files = [
            f for f in files
            if f.stat().st_size <= self.MAX_FILE_SIZE
            and f.suffix in self.get_supported_extensions()
        ]

        if not scannable_files:
            self.log("No suitable files for AI analysis")
            return []

        self.log(f"Analyzing {len(scannable_files)} files with {self.model_name}")

        semaphore = asyncio.Semaphore(self.MAX_CONCURRENT)
        all_findings: list[Finding] = []

        async def scan_with_limit(file_path: Path) -> list[Finding]:
            async with semaphore:
                return await self._scan_file(file_path)

        tasks = [scan_with_limit(f) for f in scannable_files]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for file_path, result in zip(scannable_files, results):
            if isinstance(result, Exception):
                self.log(f"Error scanning {file_path.name}: {result}")
            else:
                all_findings.extend(result)

        return all_findings

    async def _scan_file(self, file_path: Path) -> list[Finding]:
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError as e:
            self.log(f"Cannot read {file_path}: {e}")
            return []

        if not content.strip():
            return []

        if len(content) > self.CHUNK_SIZE:
            return await self._scan_large_file(file_path, content)

        return await self._analyze_code(file_path, content)

    async def _scan_large_file(
        self, file_path: Path, content: str
    ) -> list[Finding]:
        lines = content.split("\n")
        chunks: list[tuple[int, str]] = []
        current_chunk: list[str] = []
        current_size = 0
        chunk_start_line = 1

        for i, line in enumerate(lines, 1):
            line_size = len(line) + 1
            if current_size + line_size > self.CHUNK_SIZE and current_chunk:
                chunks.append((chunk_start_line, "\n".join(current_chunk)))
                current_chunk = []
                current_size = 0
                chunk_start_line = i

            current_chunk.append(line)
            current_size += line_size

        if current_chunk:
            chunks.append((chunk_start_line, "\n".join(current_chunk)))

        all_findings: list[Finding] = []
        for start_line, chunk in chunks:
            findings = await self._analyze_code(file_path, chunk, start_line)
            all_findings.extend(findings)

        return all_findings

    async def _analyze_code(
        self,
        file_path: Path,
        code: str,
        line_offset: int = 0,
    ) -> list[Finding]:
        numbered_lines = []
        for i, line in enumerate(code.split("\n"), 1):
            numbered_lines.append(f"{i + line_offset}: {line}")
        numbered_code = "\n".join(numbered_lines)

        prompt = f"""Analyze this code file for security vulnerabilities.
File: {file_path.name}
Language: {self._detect_language(file_path)}

```
{numbered_code}
```

Report any security vulnerabilities found using the specified format."""

        try:
            client = self._get_client()

            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: client.models.generate_content(
                    model=self.model_id,
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        system_instruction=self.SYSTEM_PROMPT,
                        temperature=0.1,
                        max_output_tokens=4096,
                    ),
                ),
            )

            if response.text:
                return self._parse_response(response.text, file_path, line_offset)
            return []

        except Exception as e:
            self.log(f"Gemini API error for {file_path.name}: {e}")
            return []

    def _detect_language(self, file_path: Path) -> str:
        extension_map = {
            ".py": "Python",
            ".js": "JavaScript",
            ".ts": "TypeScript",
            ".jsx": "React JSX",
            ".tsx": "React TSX",
            ".java": "Java",
            ".go": "Go",
            ".rb": "Ruby",
            ".php": "PHP",
            ".c": "C",
            ".cpp": "C++",
            ".h": "C Header",
            ".hpp": "C++ Header",
            ".cs": "C#",
            ".swift": "Swift",
            ".kt": "Kotlin",
            ".rs": "Rust",
            ".scala": "Scala",
            ".sh": "Shell",
            ".bash": "Bash",
            ".ps1": "PowerShell",
            ".sql": "SQL",
        }
        return extension_map.get(file_path.suffix.lower(), "Unknown")

    def _parse_response(
        self,
        response: str,
        file_path: Path,
        line_offset: int = 0,
    ) -> list[Finding]:
        if "NO_VULNERABILITIES_FOUND" in response:
            return []

        findings: list[Finding] = []
        vuln_pattern = re.compile(
            r"VULNERABILITY:\s*\n"
            r"TITLE:\s*(.+?)\n"
            r"SEVERITY:\s*(.+?)\n"
            r"LINE:\s*(.+?)\n"
            r"CWE:\s*(.+?)\n"
            r"DESCRIPTION:\s*(.+?)\n"
            r"REMEDIATION:\s*(.+?)\n"
            r"END_VULNERABILITY",
            re.DOTALL | re.IGNORECASE,
        )

        for match in vuln_pattern.finditer(response):
            title = match.group(1).strip()
            severity_str = match.group(2).strip().upper()
            line_str = match.group(3).strip()
            cwe = match.group(4).strip()
            description = match.group(5).strip()
            remediation = match.group(6).strip()

            severity_map = {
                "CRITICAL": Severity.CRITICAL,
                "HIGH": Severity.HIGH,
                "MEDIUM": Severity.MEDIUM,
                "LOW": Severity.LOW,
                "INFO": Severity.INFO,
            }
            severity = severity_map.get(severity_str, Severity.MEDIUM)

            line_number = None
            end_line = None
            line_match = re.match(r"(\d+)(?:\s*-\s*(\d+))?", line_str)
            if line_match:
                line_number = int(line_match.group(1))
                if line_match.group(2):
                    end_line = int(line_match.group(2))

            if cwe.upper() in ("N/A", "NONE", "-", ""):
                cwe = None
            elif cwe and not cwe.upper().startswith("CWE-"):
                cwe = f"CWE-{cwe}"

            finding = Finding(
                title=title,
                description=description,
                severity=severity,
                file_path=file_path,
                line_number=line_number,
                end_line=end_line,
                cwe_id=cwe,
                tool=self.name,
                confidence="medium",
                remediation=remediation,
            )
            findings.append(finding)

        return findings
