from abc import ABC, abstractmethod
from pathlib import Path
from typing import Callable, Optional

from ..models import Finding


class BaseEngine(ABC):
    name: str = "base"
    description: str = "Base scanner engine"

    def __init__(self, on_progress: Optional[Callable[[str], None]] = None):
        self.on_progress = on_progress

    def log(self, message: str) -> None:
        if self.on_progress:
            self.on_progress(f"[{self.name}] {message}")

    @abstractmethod
    async def scan(self, target_path: Path, files: list[Path]) -> list[Finding]:
        raise NotImplementedError("Subclasses must implement scan()")

    @abstractmethod
    def is_available(self) -> bool:
        raise NotImplementedError("Subclasses must implement is_available()")

    def get_supported_extensions(self) -> set[str]:
        return {
            ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb",
            ".php", ".c", ".cpp", ".h", ".hpp", ".cs", ".swift", ".kt",
            ".rs", ".scala", ".sh", ".bash", ".ps1", ".sql", ".yaml", ".yml",
            ".json", ".xml", ".html", ".css", ".scss", ".vue", ".svelte",
        }
