"""Alert model + loaders that normalise common alert formats (mini-siem, log-anomaly-detector, generic)."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

SEVERITY_WEIGHT = {"informational": 0, "low": 10, "medium": 25, "high": 40, "critical": 55}


@dataclass
class Alert:
    id: str
    timestamp: datetime
    rule: str
    severity: str
    description: str = ""
    host: str = ""
    user: str = ""
    src_ip: str = ""
    mitre: list[str] = field(default_factory=list)
    raw: dict = field(default_factory=dict)

    @property
    def entities(self) -> set[str]:
        return {f"host:{self.host}" for _ in [0] if self.host} | {f"user:{self.user}" for _ in [0] if self.user} | \
            {f"ip:{self.src_ip}" for _ in [0] if self.src_ip}


def _get(d: dict, *paths: str, default=""):
    for p in paths:
        cur = d
        for part in p.split("."):
            cur = cur.get(part) if isinstance(cur, dict) else None
        if cur not in (None, ""):
            return cur
    return default


def normalise(d: dict, i: int = 0) -> Alert:
    ts = _get(d, "timestamp", "ts", "@timestamp", "first_seen")
    sample = d.get("sample")
    if isinstance(sample, str):
        try:
            sample = json.loads(sample)
        except json.JSONDecodeError:
            sample = {}
    sample = sample or {}
    mitre = d.get("mitre") or []
    if isinstance(mitre, str):
        mitre = [m.strip() for m in mitre.split(",") if m.strip()]
    return Alert(
        id=str(_get(d, "id", "alert_id", default=f"A{i:04d}")),
        timestamp=datetime.fromisoformat(str(ts).replace("Z", "+00:00")).replace(tzinfo=None),
        rule=str(_get(d, "rule", "rule_id", "title", default="unknown")),
        severity=str(_get(d, "severity", default="medium")).lower(),
        description=str(_get(d, "description", "detail", "title", default=""))[:2000],
        host=str(_get(d, "host", "host.name", default=_get(sample, "host.name"))),
        user=str(_get(d, "user", "user.name", default=_get(sample, "user.name"))),
        src_ip=str(_get(d, "src_ip", "ip", "source.ip", "group_key", default=_get(sample, "source.ip"))),
        mitre=list(mitre),
        raw=d,
    )


def load_alerts(path: str | Path) -> list[Alert]:
    text = Path(path).read_text(encoding="utf-8").strip()
    items = json.loads(text) if text.startswith("[") else [json.loads(x) for x in text.splitlines() if x.strip()]
    return sorted((normalise(d, i) for i, d in enumerate(items)), key=lambda a: a.timestamp)
