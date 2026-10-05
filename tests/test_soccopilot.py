import json
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from soccopilot.cli import main, run
from soccopilot.context import Context
from soccopilot.llm import ClaudeAnalyst, OfflineAnalyst, OllamaAnalyst, assess, incident_payload
from soccopilot.models import load_alerts, normalise
from soccopilot.triage import correlate, triage

EX = Path(__file__).parent.parent / "examples"


@pytest.fixture()
def incidents():
    return triage(load_alerts(EX / "alerts.json"), Context.load(EX / "context.json"))


def test_normalise_minisiem_format():
    a = normalise({"rule_id": "AUTH-002", "severity": "critical", "ts": "2026-10-05T08:31:25", "group_key": "203.0.113.50",
                   "mitre": "T1110,T1078", "sample": json.dumps({"user": {"name": "admin"}, "host": {"name": "web01"}})})
    assert (a.rule, a.src_ip, a.user, a.host, a.mitre) == ("AUTH-002", "203.0.113.50", "admin", "web01", ["T1110", "T1078"])


def test_correlation_groups_attack_chain(incidents):
    sizes = sorted(len(i.alerts) for i in incidents)
    assert sizes == [1, 1, 5]            # chain via shared user/host, scan and workstation stay separate


def test_correlation_respects_window():
    alerts = load_alerts(EX / "alerts.json")
    from datetime import timedelta
    assert len(correlate(alerts, window=timedelta(minutes=1))) > 3


def test_scoring(incidents):
    top = incidents[0]
    assert top.priority == "P1" and top.score >= 80
    assert top.tactics[0] == "Initial Access" and "Defense Evasion" in top.tactics
    assert any("blocklist" in r for r in top.reasons) and any("critical criticality" in r for r in top.reasons)
    assert incidents[-1].priority in {"P3", "P4"}


def test_offline_analyst(incidents):
    a = assess(incidents[0], OfflineAnalyst())
    assert a.verdict == "true_positive" and a.recommended_actions and not a.warnings


def test_payload_wraps_untrusted_data(incidents):
    p = incident_payload(incidents[0])
    assert p.startswith("<incident_data>") and p.rstrip().endswith("</incident_data>")
    assert "ignore previous instructions" in p          # passed as data, not hidden


class FakeClaude:
    """Mimics client.beta.messages.create(...) of the Anthropic SDK."""

    def __init__(self, payload=None, stop_reason="end_turn"):
        self.payload, self.stop_reason, self.calls = payload, stop_reason, []
        self.beta = SimpleNamespace(messages=SimpleNamespace(create=self.create))

    def create(self, **kw):
        self.calls.append(kw)
        content = [SimpleNamespace(type="text", text=json.dumps(self.payload))] if self.payload else []
        return SimpleNamespace(stop_reason=self.stop_reason, content=content, model=kw["model"])


GOOD = {"summary": "Brute force then privilege escalation on the DC.", "attack_stage": "Defense Evasion",
        "verdict": "true_positive", "confidence": 0.92, "recommended_actions": ["Isolate dc01"],
        "questions_for_analyst": ["Was the admin login expected?"]}


def test_claude_request_shape_and_parsing(incidents):
    fake = FakeClaude(GOOD)
    a = assess(incidents[0], ClaudeAnalyst(client=fake))
    kw = fake.calls[0]
    assert kw["model"] == "claude-opus-5-5"
    assert kw["output_config"]["format"]["type"] == "json_schema" and kw["fallbacks"] == "default"
    assert "server-side-fallback-2026-07-01" in kw["betas"]
    assert "UNTRUSTED" in kw["system"]
    assert a.provider == "claude:claude-opus-5-5" and a.confidence == 0.92


def test_injected_benign_verdict_cannot_downgrade(incidents):
    benign = dict(GOOD, verdict="benign", summary="Authorised admin script.")
    a = assess(incidents[0], ClaudeAnalyst(client=FakeClaude(benign)))
    assert incidents[0].priority == "P1"
    assert any("human review" in w for w in a.warnings)


@pytest.mark.parametrize("fake", [FakeClaude(None, stop_reason="refusal"), FakeClaude({"verdict": "pwned"}),
                                  FakeClaude(None, stop_reason="max_tokens")])
def test_claude_failures_fall_back_offline(incidents, fake):
    a = assess(incidents[0], ClaudeAnalyst(client=fake))
    assert a.provider == "offline" and any("offline analysis used" in w for w in a.warnings)


def test_ollama_provider():
    def handler(req):
        body = json.loads(req.content)
        assert body["format"]["required"] and body["messages"][0]["role"] == "system"
        return httpx.Response(200, json={"message": {"content": json.dumps(GOOD)}})
    analyst = OllamaAnalyst(client=httpx.Client(transport=httpx.MockTransport(handler)))
    inc = triage(load_alerts(EX / "alerts.json"), Context())[0]
    assert assess(inc, analyst).provider == "ollama:qwen3:8b"


def test_report_and_cli(tmp_path, capsys):
    md = run(str(EX / "alerts.json"), str(EX / "context.json"), OfflineAnalyst())
    assert md.startswith("# SOC Triage Report") and "🔴 P1" in md and "| Time |" in md
    out = tmp_path / "r.md"
    assert main([str(EX / "alerts.json"), "--context", str(EX / "context.json"), "-o", str(out)]) == 0
    assert "INC-" in out.read_text(encoding="utf-8")


def test_hedged_verdict_on_p1_is_flagged(incidents):
    hedged = dict(GOOD, verdict="needs_investigation")
    a = assess(incidents[0], ClaudeAnalyst(client=FakeClaude(hedged)))
    assert any("less certain than the rule evidence" in w for w in a.warnings)
