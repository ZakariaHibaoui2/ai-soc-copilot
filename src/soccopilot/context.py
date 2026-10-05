"""Environment context: asset inventory, privileged identities, internal ranges, threat-intel indicators."""
from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from pathlib import Path

CRITICALITY = {"low": 0, "medium": 8, "high": 15, "critical": 22}


@dataclass
class Context:
    hosts: dict[str, dict] = field(default_factory=dict)          # name -> {criticality, role, owner}
    users: dict[str, dict] = field(default_factory=dict)          # name -> {privileged, department}
    internal_ranges: list[str] = field(default_factory=lambda: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"])
    bad_ips: set[str] = field(default_factory=set)

    @classmethod
    def load(cls, path: str | Path | None) -> Context:
        if not path:
            return cls()
        d = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(d.get("hosts", {}), d.get("users", {}), d.get("internal_ranges", cls().internal_ranges),
                   set(d.get("threat_intel", {}).get("bad_ips", [])))

    def host_criticality(self, host: str) -> str:
        return self.hosts.get(host, {}).get("criticality", "medium" if host else "low")

    def is_privileged(self, user: str) -> bool:
        u = user.lower()
        return bool(self.users.get(user, {}).get("privileged")) or u in {"root", "administrator", "admin"} or \
            u.startswith(("adm-", "svc-"))

    def is_external(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return not any(addr in ipaddress.ip_network(r) for r in self.internal_ranges) and not addr.is_loopback
