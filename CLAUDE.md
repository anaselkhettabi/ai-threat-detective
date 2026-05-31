# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

AI Threat Detective — a CLI tool that ingests security logs, correlates events across formats, and runs an agentic LLM investigation loop to produce structured incident reports. Python 3.10+.

## Commands

```bash
pip install -r requirements.txt

# Configure LLM provider before running
cp .env.example .env

pytest tests/                          # all tests
pytest tests/test_parsers.py           # single test file
pytest tests/test_parsers.py::test_foo # single test

flake8 . --max-line-length 100

python main.py analyze --file sample_logs/cloudtrail/sample.json
python main.py analyze --file logs/a.json --file logs/b.log  # multi-source correlation
python main.py analyze --file logs/auth.log --output json    # or markdown
python main.py watch --dir /var/log/
python main.py test-connection
```

## LLM Provider Config (`.env`)

```
LLM_PROVIDER=groq          # groq | gemini | ollama | openai | anthropic
LLM_API_KEY=your_key_here  # not needed for ollama
LLM_MODEL=                 # optional override
```

Defaults: `groq→llama3-70b-8192`, `gemini→gemini-1.5-flash`, `ollama→llama3`, `openai→gpt-4o-mini`, `anthropic→claude-3-haiku-20240307`.

## Architecture

The pipeline has four stages:

1. **Log Ingestion** — auto-detect format (extension + content sniff), parse into normalized events:
   ```python
   {"timestamp": "", "source": "", "event_type": "", "severity": "",
    "actor": "", "action": "", "target": "", "metadata": {}}
   ```
2. **Correlation** (`core/correlator.py`) — group events by time window, actor, or target; score clusters by suspiciousness; surface top N for the LLM.
3. **Agentic Loop** (`core/agent.py`) — LLM receives clusters, reasons, can request additional context from the log set, iterates max 3 rounds.
4. **Report Generation** (`core/reporter.py`) — JSON + markdown output, severity (Critical/High/Medium/Low), MITRE ATT&CK mapping, remediation actions.

All state is in-memory per session — no database.

## Extension Points

**Adding a provider:** Implement `BaseLLMClient` in `core/llm.py` and register it there. No provider names anywhere else in the codebase.

```python
class BaseLLMClient:
    def complete(self, system: str, user: str) -> str: ...
    def stream(self, system: str, user: str) -> Iterator[str]: ...
```

**Adding a parser:** Implement `BaseParser` in a new `parsers/your_format.py`, register in `parsers/__init__.py`, add sample logs to `sample_logs/your_format/`, add tests to `tests/test_parsers.py`.

## Constraints

- All LLM provider logic lives exclusively in `core/llm.py` — no provider-specific imports elsewhere.
- All prompts live in `prompts/` — never inline in logic files. Prompts must be model-agnostic and under 500 tokens.
- Sample logs must be synthetic — no real log data in the repo.
