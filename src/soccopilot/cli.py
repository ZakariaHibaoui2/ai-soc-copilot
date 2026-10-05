"""soccopilot command line."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .context import Context
from .llm import ClaudeAnalyst, OfflineAnalyst, OllamaAnalyst, assess
from .models import load_alerts
from .report import markdown
from .triage import triage


def make_analyst(name: str, model: str | None):
    if name == "claude":
        return ClaudeAnalyst(model=model or "claude-opus-5-5")
    if name == "ollama":
        return OllamaAnalyst(model=model or "qwen3:8b")
    return OfflineAnalyst()


def run(alerts_path: str, context_path: str | None, analyst) -> str:
    incidents = triage(load_alerts(alerts_path), Context.load(context_path))
    return markdown([(inc, assess(inc, analyst)) for inc in incidents])


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="soccopilot", description="AI-assisted SOC alert triage")
    ap.add_argument("alerts", help="alerts as a JSON array or JSON lines")
    ap.add_argument("--context", help="asset / identity / threat-intel context JSON")
    ap.add_argument("--provider", choices=["offline", "claude", "ollama"], default="offline")
    ap.add_argument("--model", help="model id (default: claude-opus-5-5 / qwen3:8b)")
    ap.add_argument("-o", "--output", help="write the Markdown report here (default: stdout)")
    a = ap.parse_args(argv)

    analyst = make_analyst(a.provider, a.model) if a.provider != "claude" else None
    if a.provider == "claude":
        try:
            analyst = make_analyst("claude", a.model)
        except ImportError:
            print('error: install the Claude extra:  pip install ".[claude]"', file=sys.stderr)
            return 2
    report = run(a.alerts, a.context, analyst)
    if a.output:
        Path(a.output).write_text(report, encoding="utf-8")
        print(f"report written to {a.output}")
    else:
        print(report)
    return 0


def entrypoint() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.exit(main())


if __name__ == "__main__":
    entrypoint()
