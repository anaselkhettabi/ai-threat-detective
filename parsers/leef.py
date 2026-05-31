import re
from dateutil import parser as dateutil_parser
from parsers.base import BaseParser, NormalizedEvent

_LEEF_HEADER = re.compile(
    r"^LEEF:(\d+\.\d+)\|([^|]*)\|([^|]*)\|([^|]*)\|(?:([^^|]*)\|)?(.*)",
    re.DOTALL,
)


def _parse_extension(ext: str, delimiter: str = "\t") -> dict:
    result = {}
    pairs = ext.split(delimiter)
    for pair in pairs:
        if "=" in pair:
            key, _, value = pair.partition("=")
            result[key.strip()] = value.strip()
    return result


def _normalize_ts(raw: str) -> str:
    if not raw:
        return ""
    try:
        return dateutil_parser.parse(raw).isoformat()
    except Exception:
        return raw


class LEEFParser(BaseParser):
    EXTENSIONS = [".leef", ".log"]

    @classmethod
    def sniff(cls, raw: bytes) -> float:
        text = raw.decode("utf-8", errors="ignore")
        for line in text.splitlines()[:10]:
            if line.startswith("LEEF:"):
                return 0.9
        return 0.0

    def parse(self, path: str) -> list[NormalizedEvent]:
        events = []
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.rstrip()
                if not line or not line.startswith("LEEF:"):
                    continue
                event = self._parse_line(line, path)
                if event:
                    events.append(event)
        return events

    def _parse_line(self, line: str, source: str) -> NormalizedEvent | None:
        m = _LEEF_HEADER.match(line)
        if not m:
            return None

        _version, vendor, product, _event_id, custom_delim, ext_str = m.groups()

        delimiter = "\t"
        if custom_delim:
            delim_match = re.search(r"x([0-9A-Fa-f]{2})", custom_delim or "")
            if delim_match:
                delimiter = chr(int(delim_match.group(1), 16))
            elif custom_delim.strip():
                delimiter = custom_delim.strip()[0]

        ext = _parse_extension(ext_str, delimiter)

        timestamp = _normalize_ts(ext.get("devTime", ext.get("startTime", "")))
        actor = ext.get("usrName", ext.get("src", "unknown"))
        target = ext.get("dst", ext.get("dstHost", ext.get("resource", "")))
        action = ext.get("cat", ext.get("action", "unknown"))

        severity_raw = ext.get("sev", "").lower()
        if severity_raw in ("critical", "10", "9"):
            severity = "Critical"
        elif severity_raw in ("high", "8", "7"):
            severity = "High"
        elif severity_raw in ("medium", "6", "5", "4"):
            severity = "Medium"
        else:
            severity = "Low"

        metadata = {"vendor": vendor, "product": product}
        metadata.update(ext)

        return NormalizedEvent(
            timestamp=timestamp,
            source=source,
            event_type=f"leef:{_event_id}",
            severity=severity,
            actor=actor,
            action=action,
            target=target,
            metadata=metadata,
        )
