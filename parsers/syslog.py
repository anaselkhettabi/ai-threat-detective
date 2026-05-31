import re
from dateutil import parser as dateutil_parser
from parsers.base import BaseParser, NormalizedEvent

# RFC 3164: <PRI>MMM DD HH:MM:SS host proc[pid]: msg
_RFC3164 = re.compile(
    r"^<(\d+)>(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)"
)
# RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID MSG
_RFC5424 = re.compile(
    r"^<(\d+)>1\s+(\S+)\s+(\S+)\s+(\S+)\s+\S+\s+\S+\s*(.*)"
)

_PRIORITY_TO_SEVERITY = {
    0: "Critical", 1: "Critical",
    2: "High",
    3: "Medium", 4: "Medium",
    5: "Low", 6: "Low", 7: "Low",
}


def _priority_to_severity(priority: int) -> str:
    facility = priority >> 3
    level = priority & 0x07
    return _PRIORITY_TO_SEVERITY.get(level, "Low")


def _normalize_ts(raw: str) -> str:
    if not raw:
        return ""
    try:
        return dateutil_parser.parse(raw).isoformat()
    except Exception:
        return raw


class SyslogParser(BaseParser):
    EXTENSIONS = [".log", ".syslog"]

    @classmethod
    def sniff(cls, raw: bytes) -> float:
        text = raw.decode("utf-8", errors="ignore")
        lines = text.splitlines()[:10]
        for line in lines:
            if _RFC3164.match(line) or _RFC5424.match(line):
                return 0.9
        return 0.0

    def parse(self, path: str) -> list[NormalizedEvent]:
        events = []
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.rstrip()
                if not line:
                    continue
                event = self._parse_line(line, path)
                if event:
                    events.append(event)
        return events

    def _parse_line(self, line: str, source: str) -> NormalizedEvent | None:
        m = _RFC3164.match(line)
        if m:
            priority, timestamp, hostname, process, pid, message = m.groups()
            actor = f"{hostname}/{process}"
            if pid:
                actor += f"[{pid}]"
            return NormalizedEvent(
                timestamp=_normalize_ts(timestamp),
                source=source,
                event_type="syslog",
                severity=_priority_to_severity(int(priority)),
                actor=actor,
                action=self._extract_action(message, process),
                target=hostname,
                metadata={"host": hostname, "process": process, "pid": pid or "", "message": message},
            )

        m = _RFC5424.match(line)
        if m:
            priority, timestamp, hostname, app, message = m.groups()
            return NormalizedEvent(
                timestamp=_normalize_ts(timestamp),
                source=source,
                event_type="syslog",
                severity=_priority_to_severity(int(priority)),
                actor=f"{hostname}/{app}",
                action=self._extract_action(message, app),
                target=hostname,
                metadata={"host": hostname, "app": app, "message": message},
            )

        return None

    def _extract_action(self, message: str, process: str = "") -> str:
        lower = message.lower()
        process_lower = process.lower()
        if "failed password" in lower or "authentication failure" in lower:
            return "failed_login"
        if "accepted password" in lower or "accepted publickey" in lower:
            return "successful_login"
        if "sudo" in process_lower or "sudo" in lower:
            return "sudo_command"
        if "session opened" in lower:
            return "session_open"
        if "session closed" in lower:
            return "session_close"
        words = message.split()
        return words[0].lower() if words else "unknown"
