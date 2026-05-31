import re
from dateutil import parser as dateutil_parser
from parsers.base import BaseParser, NormalizedEvent

_CEF_HEADER = re.compile(
    r"^CEF:(\d+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(\d+)\|(.*)",
    re.DOTALL,
)

_CEF_SEVERITY_MAP = {
    0: "Low", 1: "Low", 2: "Low", 3: "Low",
    4: "Medium", 5: "Medium", 6: "Medium",
    7: "High", 8: "High",
    9: "Critical", 10: "Critical",
}


def _parse_extension(ext: str) -> dict:
    result = {}
    # CEF extension: key=value pairs; values can be escaped \= and \\
    pattern = re.compile(r"(\w+)=((?:[^\\=\s]|\\.)*(?:\s+(?!\w+=)(?:[^\\=\s]|\\.)*)*)")
    for m in pattern.finditer(ext):
        key = m.group(1)
        value = m.group(2).strip().replace("\\=", "=").replace("\\\\", "\\")
        result[key] = value
    return result


def _normalize_ts(raw: str) -> str:
    if not raw:
        return ""
    try:
        return dateutil_parser.parse(raw).isoformat()
    except Exception:
        return raw


class CEFParser(BaseParser):
    EXTENSIONS = [".cef", ".log"]

    @classmethod
    def sniff(cls, raw: bytes) -> float:
        text = raw.decode("utf-8", errors="ignore")
        for line in text.splitlines()[:10]:
            if line.startswith("CEF:"):
                return 0.9
        return 0.0

    def parse(self, path: str) -> list[NormalizedEvent]:
        events = []
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.rstrip()
                if not line or not line.startswith("CEF:"):
                    continue
                event = self._parse_line(line, path)
                if event:
                    events.append(event)
        return events

    def _parse_line(self, line: str, source: str) -> NormalizedEvent | None:
        m = _CEF_HEADER.match(line)
        if not m:
            return None

        _version, vendor, product, dev_version, sig_id, name, severity_str, ext_str = m.groups()
        ext = _parse_extension(ext_str)

        try:
            severity = _CEF_SEVERITY_MAP.get(int(severity_str), "Low")
        except ValueError:
            severity = "Low"

        timestamp = _normalize_ts(ext.get("rt", ext.get("start", ext.get("deviceReceiptTime", ""))))
        actor = ext.get("suser", ext.get("src", ext.get("duser", "unknown")))
        target = ext.get("dst", ext.get("dhost", ext.get("destinationAddress", "")))
        action = ext.get("act", name)

        metadata = {
            "vendor": vendor,
            "product": product,
            "signatureId": sig_id,
            "name": name,
        }
        metadata.update(ext)

        return NormalizedEvent(
            timestamp=timestamp,
            source=source,
            event_type=f"cef:{sig_id}",
            severity=severity,
            actor=actor,
            action=action,
            target=target,
            metadata=metadata,
        )
