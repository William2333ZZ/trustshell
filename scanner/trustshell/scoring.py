"""Scoring model — consistent with the TrustShell Open Baseline v0.1.

- Weights: CRIT=5, HIGH=3, MED=1
- Weighted pass rate = Σ(weight of passing items) / Σ(weight of decided items); pass/fail only (skip excluded)
- Hard veto: any critical item fails → straight D
- Bands: all criticals pass and weighted ≥90% → A; ≥75% → B; ≥60% → C; else D
"""
from __future__ import annotations

WEIGHT = {"crit": 5, "high": 3, "med": 1}


def grade(findings):
    """findings: [(Check, Result), ...] → result dict."""
    scored = [(c, r) for c, r in findings if r.status in ("pass", "fail")]
    crit_fail = [c for c, r in findings if c.severity == "crit" and r.status == "fail"]

    total_w = sum(WEIGHT[c.severity] for c, _ in scored)
    pass_w = sum(WEIGHT[c.severity] for c, r in scored if r.status == "pass")
    ratio = (pass_w / total_w) if total_w else 0.0

    if crit_fail:
        g = "D"
    elif ratio >= 0.90:
        g = "A"
    elif ratio >= 0.75:
        g = "B"
    elif ratio >= 0.60:
        g = "C"
    else:
        g = "D"

    return {
        "grade": g,
        "weighted_pass_ratio": round(ratio, 4),
        "critical_failures": [c.id for c in crit_fail],
        "counts": {
            "pass": sum(1 for _, r in findings if r.status == "pass"),
            "fail": sum(1 for _, r in findings if r.status == "fail"),
            "warn": sum(1 for _, r in findings if r.status == "warn"),
            "skip": sum(1 for _, r in findings if r.status == "skip"),
        },
        "vetoed": bool(crit_fail),
    }


GRADE_BLURB = {
    "A": "trustworthy — meets the bar for insurability / compliance",
    "B": "broadly reliable, with items to improve",
    "C": "passing, with clear gaps",
    "D": "exposed or a critical item failed — should be flagged",
}
