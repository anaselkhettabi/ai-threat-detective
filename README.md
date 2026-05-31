# AI Threat Detective 🔍

An agentic AI security analyst that ingests logs from any source, correlates events across formats, and autonomously investigates suspicious patterns — producing structured incident reports.

> Most security tools detect. This one **reasons**.

---

## Features

- **Provider-agnostic LLM backend** — Groq, Gemini, Ollama, OpenAI, or Anthropic
- **Multi-format log ingestion** — auto-detects format, no config required
- **Agentic investigation loop** — AI iteratively asks follow-up questions about its own findings
- **MITRE ATT&CK mapping** — techniques identified automatically
- **Fully local option** — run with Ollama, no data leaves your machine

---

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Configure your LLM provider
cp .env.example .env
# Edit .env and add your API key

# Test the connection
python main.py test-connection

# Analyze a log file
python main.py analyze --file sample_logs/cloudtrail/sample.json
```

---

## LLM Provider Setup

Edit `.env` to choose your provider:

```env
LLM_PROVIDER=groq          # groq | gemini | ollama | openai | anthropic
LLM_API_KEY=your_key_here  # not needed for ollama
LLM_MODEL=                 # optional — overrides the default model
```

| Provider | Default Model | Notes |
|----------|--------------|-------|
| `groq` | `llama3-70b-8192` | Free tier, recommended for getting started |
| `gemini` | `gemini-1.5-flash` | Google AI Studio free tier available |
| `ollama` | `llama3` | Fully local, no API key needed |
| `openai` | `gpt-4o-mini` | OpenAI API key required |
| `anthropic` | `claude-3-haiku-20240307` | Anthropic API key required |

---

## Supported Log Formats

Auto-detected from file content — no `--format` flag needed:

| Format | Extensions |
|--------|-----------|
| AWS CloudTrail | `.json` |
| Syslog (RFC 3164 / RFC 5424) | `.log`, `.syslog` |
| Windows Event Logs (JSON/XML/EVTX) | `.json`, `.xml`, `.evtx` |
| CEF (Common Event Format) | `.cef`, `.log` |
| LEEF (Log Event Extended Format) | `.leef`, `.log` |
| Generic JSON / NDJSON | `.json`, `.ndjson`, `.jsonl` |

New formats can be added by implementing `BaseParser` in `parsers/`.

---

## CLI Usage

```bash
# Analyze a single log file
python main.py analyze --file logs/cloudtrail.json

# Correlate events across multiple log sources
python main.py analyze --file logs/cloudtrail.json --file logs/syslog.log

# Choose output format
python main.py analyze --file logs/auth.log --output json
python main.py analyze --file logs/auth.log --output markdown
python main.py analyze --file logs/auth.log --output both --out-file reports/incident

# Control investigation depth
python main.py analyze --file logs/auth.log --max-rounds 2 --top-n 3

# Watch a directory for new logs (continuous mode)
python main.py watch --dir /var/log/ --out-dir reports/

# Test LLM connectivity
python main.py test-connection
```

---

## Sample Logs

Synthetic sample logs are included for every supported format:

```
sample_logs/
├── cloudtrail/sample.json   # Brute force → privilege escalation → exfil
├── syslog/sample.log        # SSH brute force → root command execution
├── windows_event/sample.json # Failed logons → lateral movement → audit log cleared
├── cef/sample.cef           # IDS alerts: brute force + lateral movement
├── leef/sample.leef         # SIEM auth + privilege change events
└── generic_json/sample.json # Bulk data exfiltration pattern
```

---

## How It Works

1. **Ingestion** — Each log file is auto-detected and parsed into a normalized event schema (`timestamp`, `actor`, `action`, `target`, `severity`, `metadata`)
2. **Correlation** — Events are grouped by actor and time window, scored for suspiciousness, and clustered
3. **Investigation** — The LLM receives the top clusters and iteratively reasons about them, requesting additional context when needed (up to 3 rounds)
4. **Report** — A structured incident report is generated with severity rating, MITRE ATT&CK mapping, and remediation actions

---

## Output Format

Reports are generated as JSON and/or markdown:

```json
{
  "severity": "Critical",
  "clusters": [...],
  "mitre_techniques": [
    {"id": "T1110", "name": "Brute Force", "url": "..."},
    {"id": "T1078", "name": "Valid Accounts", "url": "..."}
  ],
  "remediation_actions": [
    "Block IP 203.0.113.42 at perimeter firewall",
    "Reset credentials for affected accounts"
  ]
}
```

---

## Development

```bash
# Run tests
pytest tests/

# Run a single test file
pytest tests/test_parsers.py

# Lint
flake8 . --max-line-length 100
```

### Adding a Log Parser

1. Create `parsers/your_format.py` implementing `BaseParser`
2. Register it in `parsers/__init__.py`
3. Add sample logs to `sample_logs/your_format/`
4. Add tests to `tests/test_parsers.py`

### Adding an LLM Provider

1. Add a class implementing `BaseLLMClient` in `core/llm.py`
2. Add it to `PROVIDER_DEFAULTS` in the same file
3. Add the default model to `.env.example`

---

## Project Structure

```
├── main.py              # CLI entrypoint
├── core/
│   ├── llm.py           # Provider-agnostic LLM client
│   ├── correlator.py    # Event correlation engine
│   ├── agent.py         # Agentic investigation loop
│   └── reporter.py      # Report generation
├── parsers/             # Log format parsers
├── prompts/             # LLM system prompts and templates
├── sample_logs/         # Synthetic test logs
└── tests/               # Test suite
```

---

## Requirements

- Python 3.10+
- An API key for your chosen LLM provider (or Ollama running locally)
