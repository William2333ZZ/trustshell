"""评分模型 —— 与《信壳开放基线 v0.1》一致。

- 权重:致命 CRIT=5, 高 HIGH=3, 中 MED=1
- 加权通过率 = Σ(通过项权重) / Σ(已判定项权重),仅计 pass/fail(skip 不计)
- 一票否决:任一致命项 fail → 直接 D
- 分档:致命全过且 加权≥90% → A;≥75% → B;≥60% → C;否则 D
"""
from __future__ import annotations

WEIGHT = {"crit": 5, "high": 3, "med": 1}


def grade(findings):
    """findings: [(Check, Result), ...] → dict 结果。"""
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
    "A": "可信,具备可承保/合规前提",
    "B": "基本可靠,有待改进项",
    "C": "及格线,存在明显短板",
    "D": "裸奔或有致命项未过,应上黑榜",
}
