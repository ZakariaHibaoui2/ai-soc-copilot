"""Markdown incident report."""
from __future__ import annotations

from .llm import Assessment
from .triage import Incident

BADGE = {"P1": "🔴 P1", "P2": "🟠 P2", "P3": "🟡 P3", "P4": "⚪ P4"}


def markdown(results: list[tuple[Incident, Assessment]]) -> str:
    out = ["# SOC Triage Report", "", "| Incident | Priority | Score | Alerts | Tactics | Verdict |",
           "|---|---|---|---|---|---|"]
    for inc, a in results:
        out.append(f"| [{inc.id}](#{inc.id.lower()}) | {BADGE[inc.priority]} | {inc.score} | {len(inc.alerts)} | "
                   f"{', '.join(inc.tactics) or '-'} | {a.verdict} ({a.confidence:.0%}) |")
    for inc, a in results:
        out += ["", f"## {inc.id}", "", f"**{BADGE[inc.priority]}** - score {inc.score}/100 - "
                f"{inc.start:%Y-%m-%d %H:%M} -> {inc.end:%H:%M} - analysis: `{a.provider}`", ""]
        for w in a.warnings:
            out.append(f"> ⚠️ {w}")
        out += ["", f"**Summary.** {a.summary}", "", f"**Attack stage:** {a.attack_stage}", "",
                "**Why this priority**"] + [f"- {r}" for r in inc.reasons]
        out += ["", "**Entities:** " + ", ".join(f"`{e}`" for e in inc.entities), "", "**Timeline**", "",
                "| Time | Severity | Rule | Host | User | Source | ATT&CK |", "|---|---|---|---|---|---|---|"]
        for al in inc.alerts:
            out.append(f"| {al.timestamp:%H:%M:%S} | {al.severity} | {al.rule} | {al.host or '-'} | {al.user or '-'} "
                       f"| {al.src_ip or '-'} | {', '.join(al.mitre) or '-'} |")
        out += ["", "**Recommended actions**"] + [f"{n}. {s}" for n, s in enumerate(a.recommended_actions, 1)]
        out += ["", "**Questions for the analyst**"] + [f"- {q}" for q in a.questions_for_analyst]
    return "\n".join(out) + "\n"
