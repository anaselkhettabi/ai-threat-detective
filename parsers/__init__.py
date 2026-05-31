from pathlib import Path
from parsers.base import BaseParser, NormalizedEvent

_REGISTRY: list[type[BaseParser]] = []


def register(cls: type[BaseParser]) -> type[BaseParser]:
    _REGISTRY.append(cls)
    return cls


# Import parsers to trigger registration — order matters for tie-breaking:
# higher-specificity parsers before the generic fallback
from parsers.cloudtrail import CloudTrailParser
from parsers.syslog import SyslogParser
from parsers.windows_event import WindowsEventParser
from parsers.cef import CEFParser
from parsers.leef import LEEFParser
from parsers.generic_json import GenericJSONParser

for _cls in [CloudTrailParser, SyslogParser, WindowsEventParser,
             CEFParser, LEEFParser, GenericJSONParser]:
    register(_cls)


def detect_parser(path: str) -> type[BaseParser]:
    """Return the best-matching parser class for a given file path."""
    ext = Path(path).suffix.lower()
    raw = Path(path).read_bytes()[:4096]

    by_extension = [cls for cls in _REGISTRY if ext in cls.EXTENSIONS]
    pool = by_extension if by_extension else _REGISTRY

    scored = [(cls, cls.sniff(raw)) for cls in pool]
    best_cls, best_score = max(scored, key=lambda x: x[1])

    if best_score < 0.3:
        raise ValueError(
            f"Cannot detect log format for '{path}' "
            f"(best match: {best_cls.__name__}, confidence: {best_score:.2f})"
        )
    return best_cls


__all__ = [
    "BaseParser",
    "NormalizedEvent",
    "detect_parser",
    "CloudTrailParser",
    "SyslogParser",
    "WindowsEventParser",
    "CEFParser",
    "LEEFParser",
    "GenericJSONParser",
]
