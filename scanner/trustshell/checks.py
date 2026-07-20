"""Check registry — the items marked "auto-testable" in the TrustShell Open Baseline v0.1.

Each check: id / category / title / severity / required input (target or path) / probe function.
Severity weights and the scoring model live in scoring.py.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from . import probes

CRIT, HIGH, MED = "crit", "high", "med"


@dataclass
class Check:
    id: str
    category: str
    title: str
    severity: str
    needs: str                      # "target" (network) or "path" (filesystem)
    probe: Callable[[str], probes.Result]


# order = report display order
CHECKS = [
    # A Exposure & network
    Check("A-01", "Exposure & network", "Management console binds to localhost by default", CRIT, "target", probes.a01_bind_localhost),
    Check("A-02", "Exposure & network", "No public ports open by default", CRIT, "target", probes.a02_no_public_ports),
    Check("A-03", "Exposure & network", "External interfaces enforce encryption (TLS)", HIGH, "target", probes.a03_tls),
    Check("A-04", "Exposure & network", "Debug ports disabled in production", HIGH, "target", probes.a04_no_debug),
    Check("A-05", "Exposure & network", "Resists DNS-rebinding / cross-origin", CRIT, "target", probes.a05_origin_validation),
    # B Authentication & access control
    Check("B-02", "Auth & access control", "Sensitive endpoints require authentication", CRIT, "target", probes.b02_sensitive_auth),
    # C Skills & supply chain
    Check("C-04", "Skills & supply chain", "Dependencies have integrity checks (lockfile)", MED, "path", probes.c04_lockfile),
    # E Credential management
    Check("E-01", "Credential management", "Credentials not stored in plaintext", CRIT, "path", probes.e01_plaintext_creds),
    Check("E-02", "Credential management", "Credentials not written to logs", HIGH, "path", probes.e02_creds_in_logs),
    # H Audit & forensics
    Check("H-04", "Audit & forensics", "Exportable logs exist", MED, "path", probes.h04_audit_log),
]


def checks_for(has_target: bool, has_path: bool):
    out = []
    for c in CHECKS:
        if c.needs == "target" and has_target:
            out.append(c)
        elif c.needs == "path" and has_path:
            out.append(c)
    return out
