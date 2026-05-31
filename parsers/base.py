from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import ClassVar


@dataclass
class NormalizedEvent:
    timestamp: str
    source: str
    event_type: str
    severity: str
    actor: str
    action: str
    target: str
    metadata: dict = field(default_factory=dict)


class BaseParser(ABC):
    EXTENSIONS: ClassVar[list[str]] = []

    @classmethod
    @abstractmethod
    def sniff(cls, raw: bytes) -> float:
        """Return confidence 0.0–1.0 that this parser handles the given raw bytes."""

    @abstractmethod
    def parse(self, path: str) -> list[NormalizedEvent]:
        """Parse the file at path into normalized events."""
