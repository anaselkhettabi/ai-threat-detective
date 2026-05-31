import json
from dateutil import parser as dateutil_parser
from parsers.base import BaseParser, NormalizedEvent

_TIMESTAMP_KEYS = ("timestamp", "time", "@timestamp", "date", "datetime", "ts", "eventTime")
_ACTOR_KEYS = ("actor", "user", "username", "src_user", "sourceUser", "account", "principal",
               "userId", "user_id", "initiator")
_ACTION_KEYS = ("action", "event", "eventName", "operation", "method", "verb", "type",
                "eventType", "activity")
_TARGET_KEYS = ("target", "resource", "destination", "dst", "object", "bucket", "host",
                "targetResource", "resourceName")
_SEVERITY_KEYS = ("severity", "level", "sev", "priority", "risk")
_EVENT_TYPE_KEYS = ("eventType", "event_type", "type", "category", "class")
_SOURCE_KEYS = ("source", "src", "origin", "logSource", "log_source")


def _first(record: dict, keys: tuple) -> str:
    for k in keys:
        v = record.get(k)
        if v and str(v).strip():
            return str(v)
    return ""


def _normalize_ts(raw: str) -> str:
    if not raw:
        return ""
    try:
        return dateutil_parser.parse(raw).isoformat()
    except Exception:
        return raw


def _normalize_severity(raw: str) -> str:
    lower = raw.lower()
    if lower in ("critical", "fatal", "emergency", "0", "1"):
        return "Critical"
    if lower in ("high", "error", "alert", "2", "3", "7", "8", "9", "10"):
        return "High"
    if lower in ("medium", "warning", "warn", "4", "5", "6"):
        return "Medium"
    return "Low"


class GenericJSONParser(BaseParser):
    EXTENSIONS = [".json", ".ndjson", ".jsonl"]

    @classmethod
    def sniff(cls, raw: bytes) -> float:
        text = raw.decode("utf-8", errors="ignore").strip()
        if not text:
            return 0.0
        # Try full JSON first
        try:
            json.loads(text)
            return 0.2
        except json.JSONDecodeError:
            pass
        # Try NDJSON (check first line only)
        try:
            first_line = text.splitlines()[0]
            json.loads(first_line)
            return 0.2
        except (json.JSONDecodeError, IndexError):
            return 0.0

    def parse(self, path: str) -> list[NormalizedEvent]:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read().strip()

        records = self._load_records(content)
        events = []
        for record in records:
            if not isinstance(record, dict):
                continue
            events.append(self._normalize(record, path))
        return events

    def _load_records(self, content: str) -> list:
        try:
            data = json.loads(content)
            return data if isinstance(data, list) else [data]
        except json.JSONDecodeError:
            pass
        # NDJSON
        records = []
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        return records

    def _normalize(self, record: dict, source: str) -> NormalizedEvent:
        known_keys = set(_TIMESTAMP_KEYS + _ACTOR_KEYS + _ACTION_KEYS +
                         _TARGET_KEYS + _SEVERITY_KEYS + _EVENT_TYPE_KEYS + _SOURCE_KEYS)

        metadata = {k: str(v) for k, v in record.items() if k not in known_keys}

        raw_severity = _first(record, _SEVERITY_KEYS)
        severity = _normalize_severity(raw_severity) if raw_severity else "Low"

        return NormalizedEvent(
            timestamp=_normalize_ts(_first(record, _TIMESTAMP_KEYS)),
            source=_first(record, _SOURCE_KEYS) or source,
            event_type=_first(record, _EVENT_TYPE_KEYS) or "generic",
            severity=severity,
            actor=_first(record, _ACTOR_KEYS) or "unknown",
            action=_first(record, _ACTION_KEYS) or "unknown",
            target=_first(record, _TARGET_KEYS) or "",
            metadata=metadata,
        )
