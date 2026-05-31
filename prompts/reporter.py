import re
from pathlib import Path

TEMPLATE_PATH = Path(__file__).parent / "report_template.md.j2"

SECTION_MARKERS = {
    "severity":    re.compile(r"SEVERITY:\s*(Critical|High|Medium|Low)", re.IGNORECASE),
    "mitre":       re.compile(r"MITRE:\s*([T\d,\s]+)", re.IGNORECASE),
    "remediation": re.compile(r"REMEDIATION:\s*\n((?:\s*[-*]\s*.+\n?)+)", re.IGNORECASE),
}

MITRE_NAMES = {
    "T1110": "Brute Force",
    "T1078": "Valid Accounts",
    "T1021": "Remote Services",
    "T1030": "Data Transfer Size Limits",
    "T1059": "Command and Scripting Interpreter",
    "T1055": "Process Injection",
    "T1087": "Account Discovery",
    "T1098": "Account Manipulation",
    "T1136": "Create Account",
    "T1562": "Impair Defenses",
    "T1070": "Indicator Removal",
}

MITRE_BASE_URL = "https://attack.mitre.org/techniques/"


def parse_severity(text: str) -> str:
    m = SECTION_MARKERS["severity"].search(text)
    return m.group(1).capitalize() if m else "Low"


def parse_mitre(text: str) -> list[str]:
    m = SECTION_MARKERS["mitre"].search(text)
    if not m:
        return []
    raw = m.group(1)
    return [t.strip() for t in re.split(r"[,\s]+", raw) if re.match(r"T\d{4}", t.strip())]


def parse_remediation(text: str) -> list[str]:
    m = SECTION_MARKERS["remediation"].search(text)
    if not m:
        return []
    block = m.group(1)
    items = []
    for line in block.splitlines():
        line = re.sub(r"^\s*[-*]\s*", "", line).strip()
        if line:
            items.append(line)
    return items


def enrich_mitre(technique_ids: list[str]) -> list[dict]:
    result = []
    for tid in technique_ids:
        result.append({
            "id": tid,
            "name": MITRE_NAMES.get(tid, "Unknown Technique"),
            "url": f"{MITRE_BASE_URL}{tid}/",
        })
    return result
