from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional
import json


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def weight(self) -> int:
        weights = {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1,
        }
        return weights[self]

    def __lt__(self, other: "Severity") -> bool:
        return self.weight < other.weight


@dataclass
class Finding:
    title: str
    description: str
    severity: Severity
    file_path: Path
    line_number: Optional[int] = None
    end_line: Optional[int] = None
    code_snippet: Optional[str] = None
    remediation: Optional[str] = None
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    tool: str = "unknown"
    confidence: str = "medium"

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "file_path": str(self.file_path),
            "line_number": self.line_number,
            "end_line": self.end_line,
            "code_snippet": self.code_snippet,
            "remediation": self.remediation,
            "cwe_id": self.cwe_id,
            "owasp_category": self.owasp_category,
            "tool": self.tool,
            "confidence": self.confidence,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Finding":
        data = data.copy()
        data["severity"] = Severity(data["severity"])
        data["file_path"] = Path(data["file_path"])
        return cls(**data)


@dataclass
class ScanResult:
    target_path: Path
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    scan_duration_seconds: float = 0.0
    errors: list[str] = field(default_factory=list)

    @property
    def findings_by_severity(self) -> dict[Severity, list[Finding]]:
        result: dict[Severity, list[Finding]] = {s: [] for s in Severity}
        for finding in self.findings:
            result[finding.severity].append(finding)
        return result

    @property
    def critical_count(self) -> int:
        return len([f for f in self.findings if f.severity == Severity.CRITICAL])

    @property
    def high_count(self) -> int:
        return len([f for f in self.findings if f.severity == Severity.HIGH])

    @property
    def medium_count(self) -> int:
        return len([f for f in self.findings if f.severity == Severity.MEDIUM])

    @property
    def low_count(self) -> int:
        return len([f for f in self.findings if f.severity == Severity.LOW])

    @property
    def info_count(self) -> int:
        return len([f for f in self.findings if f.severity == Severity.INFO])

    def to_json(self) -> str:
        return json.dumps(
            {
                "target_path": str(self.target_path),
                "findings": [f.to_dict() for f in self.findings],
                "files_scanned": self.files_scanned,
                "scan_duration_seconds": self.scan_duration_seconds,
                "errors": self.errors,
            },
            indent=2,
        )

    @classmethod
    def from_json(cls, json_str: str) -> "ScanResult":
        data = json.loads(json_str)
        return cls(
            target_path=Path(data["target_path"]),
            findings=[Finding.from_dict(f) for f in data["findings"]],
            files_scanned=data["files_scanned"],
            scan_duration_seconds=data["scan_duration_seconds"],
            errors=data.get("errors", []),
        )
