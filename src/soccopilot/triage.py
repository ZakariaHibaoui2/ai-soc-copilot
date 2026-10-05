"""Correlation into incidents + deterministic priority scoring + response playbooks."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta

from .context import CRITICALITY, Context
from .models import SEVERITY_WEIGHT, Alert

TACTIC_OF = {   # technique prefix -> kill-chain tactic (ordered list below)
    "T1566": "Initial Access", "T1190": "Initial Access", "T1078": "Initial Access", "T1133": "Initial Access",
    "T1059": "Execution", "T1204": "Execution", "T1053": "Persistence", "T1547": "Persistence",
    "T1098": "Persistence", "T1543": "Persistence", "T1055": "Defense Evasion", "T1027": "Defense Evasion",
    "T1070": "Defense Evasion", "T1562": "Defense Evasion", "T1110": "Credential Access", "T1003": "Credential Access",
    "T1046": "Discovery", "T1087": "Discovery", "T1021": "Lateral Movement", "T1071": "Command and Control",
    "T1105": "Command and Control", "T1568": "Command and Control", "T1041": "Exfiltration", "T1567": "Exfiltration",
    "T1486": "Impact", "T1490": "Impact",
}
KILL_CHAIN = ["Initial Access", "Execution", "Persistence", "Defense Evasion", "Credential Access", "Discovery",
              "Lateral Movement", "Command and Control", "Exfiltration", "Impact"]
PLAYBOOK = {
    "Initial Access": "Identify the entry vector; reset affected credentials; block the source IP/sender at the perimeter.",
    "Execution": "Collect the process tree and command lines; isolate the host if malicious execution is confirmed.",
    "Persistence": "Enumerate and remove persistence (scheduled tasks, Run keys, services, new admin accounts).",
    "Defense Evasion": "Treat as hands-on-keyboard activity: preserve memory/disk evidence before remediation.",
    "Credential Access": "Assume credential theft: force password resets, revoke sessions and tokens, review MFA.",
    "Discovery": "Check for follow-on lateral movement from the same source.",
    "Lateral Movement": "Scope all hosts reached from the source; disable the compromised account network-wide.",
    "Command and Control": "Block C2 domains/IPs at DNS and proxy; hunt for the same indicators fleet-wide.",
    "Exfiltration": "Engage incident response and legal/privacy; quantify the data and destinations involved.",
    "Impact": "Activate the ransomware/IR plan: isolate affected segments and protect backups immediately.",
}


@dataclass
class Incident:
    id: str
    alerts: list[Alert]
    score: int = 0
    priority: str = "P4"
    reasons: list[str] = field(default_factory=list)
    tactics: list[str] = field(default_factory=list)
    actions: list[str] = field(default_factory=list)

    @property
    def start(self):
        return self.alerts[0].timestamp

    @property
    def end(self):
        return self.alerts[-1].timestamp

    @property
    def entities(self) -> list[str]:
        return sorted(set().union(*(a.entities for a in self.alerts)))


def correlate(alerts: list[Alert], window: timedelta = timedelta(hours=2)) -> list[Incident]:
    """Union-find: alerts sharing a host, user or source IP within the window belong to one incident."""
    parent = list(range(len(alerts)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    for i, a in enumerate(alerts):
        for j in range(i + 1, len(alerts)):
            b = alerts[j]
            if b.timestamp - a.timestamp > window:
                break
            if a.entities & b.entities:
                parent[find(j)] = find(i)
    groups: dict[int, list[Alert]] = {}
    for i, a in enumerate(alerts):
        groups.setdefault(find(i), []).append(a)
    incidents = [Incident("", sorted(g, key=lambda x: x.timestamp)) for g in groups.values()]
    incidents.sort(key=lambda inc: inc.start)
    for n, inc in enumerate(incidents, 1):
        inc.id = f"INC-{n:03d}"
    return incidents


def score(inc: Incident, ctx: Context) -> Incident:
    reasons, pts = [], 0
    top = max(inc.alerts, key=lambda a: SEVERITY_WEIGHT.get(a.severity, 25))
    pts += SEVERITY_WEIGHT.get(top.severity, 25)
    reasons.append(f"highest alert severity: {top.severity} ({top.rule})")

    tactics = sorted({TACTIC_OF[t.split(".")[0]] for a in inc.alerts for t in a.mitre if t.split(".")[0] in TACTIC_OF},
                     key=KILL_CHAIN.index)
    inc.tactics = tactics
    if len(tactics) >= 2:
        bonus = min(5 * (len(tactics) - 1), 20)
        pts += bonus
        reasons.append(f"multi-stage activity across {len(tactics)} tactics (+{bonus})")

    hosts = {a.host for a in inc.alerts if a.host}
    crit = max((CRITICALITY[ctx.host_criticality(h)] for h in hosts), default=0)
    if crit:
        pts += crit
        worst = max(hosts, key=lambda h: CRITICALITY[ctx.host_criticality(h)])
        reasons.append(f"asset {worst} is {ctx.host_criticality(worst)} criticality (+{crit})")
    priv = sorted({a.user for a in inc.alerts if a.user and ctx.is_privileged(a.user)})
    if priv:
        pts += 10
        reasons.append(f"privileged identity involved: {', '.join(priv)} (+10)")
    ips = {a.src_ip for a in inc.alerts if a.src_ip}
    bad = sorted(ips & ctx.bad_ips)
    if bad:
        pts += 15
        reasons.append(f"source on threat-intel blocklist: {', '.join(bad)} (+15)")
    elif any(ctx.is_external(ip) for ip in ips):
        pts += 5
        reasons.append("external source address (+5)")
    if len(inc.alerts) >= 5:
        pts += 5
        reasons.append(f"{len(inc.alerts)} correlated alerts (+5)")

    inc.score = min(pts, 100)
    inc.priority = "P1" if inc.score >= 80 else "P2" if inc.score >= 60 else "P3" if inc.score >= 35 else "P4"
    inc.reasons = reasons
    inc.actions = [PLAYBOOK[t] for t in tactics] or ["Review the alert details and close if expected behaviour."]
    return inc


def triage(alerts: list[Alert], ctx: Context) -> list[Incident]:
    incidents = [score(i, ctx) for i in correlate(alerts)]
    return sorted(incidents, key=lambda i: -i.score)
