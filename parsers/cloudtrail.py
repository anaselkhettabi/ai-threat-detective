import json
from dateutil import parser as dateutil_parser
from parsers.base import BaseParser, NormalizedEvent


class CloudTrailParser(BaseParser):
    EXTENSIONS = [".json"]

    @classmethod
    def sniff(cls, raw: bytes) -> float:
        text = raw.decode("utf-8", errors="ignore")
        # Avoid full JSON parse on partial bytes — use string heuristics
        if '"Records"' in text and '"eventSource"' in text:
            return 0.95
        if '"Records"' in text and ('"eventName"' in text or '"eventTime"' in text):
            return 0.5
        return 0.0

    def parse(self, path: str) -> list[NormalizedEvent]:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        events = []
        for record in data.get("Records", []):
            timestamp = self._normalize_ts(record.get("eventTime", ""))
            actor = self._extract_actor(record)
            action = record.get("eventName", "")
            target = self._extract_target(record)
            severity = self._extract_severity(record)
            event_type = record.get("eventType", record.get("eventSource", "AwsApiCall"))

            metadata = {
                "eventSource": record.get("eventSource", ""),
                "awsRegion": record.get("awsRegion", ""),
                "sourceIPAddress": record.get("sourceIPAddress", ""),
                "userAgent": record.get("userAgent", ""),
                "requestID": record.get("requestID", ""),
            }
            if record.get("errorCode"):
                metadata["errorCode"] = record["errorCode"]
                metadata["errorMessage"] = record.get("errorMessage", "")

            events.append(NormalizedEvent(
                timestamp=timestamp,
                source=path,
                event_type=event_type,
                severity=severity,
                actor=actor,
                action=action,
                target=target,
                metadata=metadata,
            ))
        return events

    def _normalize_ts(self, raw: str) -> str:
        if not raw:
            return ""
        try:
            return dateutil_parser.parse(raw).isoformat()
        except Exception:
            return raw

    def _extract_actor(self, record: dict) -> str:
        identity = record.get("userIdentity", {})
        if identity.get("arn"):
            return identity["arn"]
        if identity.get("userName"):
            return identity["userName"]
        if identity.get("type") == "Root":
            return "root"
        return identity.get("principalId", "unknown")

    def _extract_target(self, record: dict) -> str:
        params = record.get("requestParameters")
        if params:
            return str(params)[:200]
        resources = record.get("resources", [])
        if resources:
            return resources[0].get("ARN", str(resources[0]))[:200]
        return record.get("eventSource", "")

    def _extract_severity(self, record: dict) -> str:
        if record.get("errorCode"):
            return "Medium"
        action = record.get("eventName", "").lower()
        high_impact = ["deletetrail", "stoprecording", "deletebucket", "deletekey",
                       "attachrolepolicy", "createuser", "createaccesskey"]
        if any(h in action for h in high_impact):
            return "High"
        return "Low"
