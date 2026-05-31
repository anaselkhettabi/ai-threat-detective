import json
from pathlib import Path
from dateutil import parser as dateutil_parser
from parsers.base import BaseParser, NormalizedEvent

_EVTX_MAGIC = b"\x45\x6c\x66\x46"

_EVENT_ID_TYPES = {
    "4625": "failed_logon",
    "4624": "successful_logon",
    "4648": "logon_explicit_creds",
    "4720": "user_account_created",
    "4732": "user_added_to_group",
    "4728": "user_added_to_group",
    "4756": "user_added_to_group",
    "4738": "user_account_changed",
    "4776": "credential_validation",
    "4768": "kerberos_ticket_request",
    "4769": "kerberos_service_ticket",
    "1102": "audit_log_cleared",
    "4698": "scheduled_task_created",
    "4702": "scheduled_task_updated",
    "4657": "registry_value_modified",
}

_EVENT_SEVERITIES = {
    "4625": "High",
    "4648": "High",
    "4720": "High",
    "4732": "High",
    "4728": "High",
    "4756": "High",
    "1102": "Critical",
    "4698": "Medium",
    "4702": "Medium",
}


def _normalize_ts(raw: str) -> str:
    if not raw:
        return ""
    try:
        return dateutil_parser.parse(raw).isoformat()
    except Exception:
        return raw


class WindowsEventParser(BaseParser):
    EXTENSIONS = [".evtx", ".xml", ".json"]

    @classmethod
    def sniff(cls, raw: bytes) -> float:
        if raw[:4] == _EVTX_MAGIC:
            return 0.95
        text = raw.decode("utf-8", errors="ignore")
        if "<Event xmlns=" in text:
            return 0.95
        try:
            data = json.loads(text)
            records = data if isinstance(data, list) else [data]
            if records and isinstance(records[0], dict) and "EventID" in records[0]:
                return 0.9
        except (json.JSONDecodeError, IndexError):
            pass
        return 0.0

    def parse(self, path: str) -> list[NormalizedEvent]:
        ext = Path(path).suffix.lower()
        if ext == ".evtx":
            return self._parse_evtx(path)
        elif ext == ".xml":
            return self._parse_xml(path)
        else:
            return self._parse_json(path)

    def _parse_evtx(self, path: str) -> list[NormalizedEvent]:
        try:
            import Evtx.Evtx as evtx
            import Evtx.Views as e_views
        except ImportError:
            raise ImportError("python-evtx is required for .evtx files: pip install python-evtx")
        events = []
        with evtx.Evtx(path) as log:
            for record in log.records():
                xml_str = record.xml()
                events.extend(self._parse_xml_string(xml_str, path))
        return events

    def _parse_xml(self, path: str) -> list[NormalizedEvent]:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        return self._parse_xml_string(content, path)

    def _parse_xml_string(self, xml_str: str, source: str) -> list[NormalizedEvent]:
        from lxml import etree
        events = []
        try:
            root = etree.fromstring(xml_str.encode("utf-8"))
            ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

            def find(xpath):
                el = root.find(xpath, ns)
                return el.text if el is not None and el.text else ""

            event_id = find(".//e:System/e:EventID")
            timestamp = find(".//e:System/e:TimeCreated").strip()
            computer = find(".//e:System/e:Computer")
            actor = self._extract_actor_xml(root, ns)
            target = self._extract_target_xml(root, ns) or computer

            events.append(NormalizedEvent(
                timestamp=_normalize_ts(timestamp),
                source=source,
                event_type=_EVENT_ID_TYPES.get(event_id, f"event_{event_id}"),
                severity=_EVENT_SEVERITIES.get(event_id, "Low"),
                actor=actor,
                action=f"EventID:{event_id}",
                target=target,
                metadata={"EventID": event_id, "Computer": computer},
            ))
        except Exception:
            pass
        return events

    def _extract_actor_xml(self, root, ns: dict) -> str:
        for field in ["SubjectUserName", "TargetUserName"]:
            el = root.find(f".//e:EventData/e:Data[@Name='{field}']", ns)
            if el is not None and el.text and el.text != "-":
                domain_el = root.find(f".//e:EventData/e:Data[@Name='{field.replace('Name','DomainName')}']", ns)
                domain = domain_el.text if domain_el is not None and domain_el.text else ""
                return f"{domain}\\{el.text}" if domain else el.text
        return "unknown"

    def _extract_target_xml(self, root, ns: dict) -> str:
        for field in ["TargetServerName", "WorkstationName", "IpAddress"]:
            el = root.find(f".//e:EventData/e:Data[@Name='{field}']", ns)
            if el is not None and el.text and el.text != "-":
                return el.text
        return ""

    def _parse_json(self, path: str) -> list[NormalizedEvent]:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        records = data if isinstance(data, list) else [data]
        events = []
        for record in records:
            event_id = str(record.get("EventID", ""))
            timestamp = record.get("TimeCreated", record.get("timestamp", ""))
            actor = self._extract_actor_json(record)
            target = record.get("WorkstationName", record.get("IpAddress", record.get("TargetServerName", "")))
            computer = record.get("Computer", record.get("MachineName", ""))
            if not target:
                target = computer

            metadata = {k: v for k, v in record.items()
                        if k not in ("EventID", "TimeCreated", "timestamp")}

            events.append(NormalizedEvent(
                timestamp=_normalize_ts(timestamp),
                source=path,
                event_type=_EVENT_ID_TYPES.get(event_id, f"event_{event_id}"),
                severity=_EVENT_SEVERITIES.get(event_id, "Low"),
                actor=actor,
                action=f"EventID:{event_id}",
                target=target or computer,
                metadata=metadata,
            ))
        return events

    def _extract_actor_json(self, record: dict) -> str:
        for name_field, domain_field in [
            ("SubjectUserName", "SubjectDomainName"),
            ("TargetUserName", "TargetDomainName"),
        ]:
            name = record.get(name_field, "")
            if name and name != "-":
                domain = record.get(domain_field, "")
                return f"{domain}\\{name}" if domain else name
        return record.get("Account", record.get("actor", "unknown"))
