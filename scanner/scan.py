#!/usr/bin/env python3
"""TrustShell on-device agent security scanner — command-line entry point.

Usage:
  python3 scan.py --target http://127.0.0.1:3000          # network checks
  python3 scan.py --path  /path/to/agent                  # filesystem checks
  python3 scan.py --target http://host:3000 --path ./box  # run both
  python3 scan.py --target ... --json                     # JSON output

Zero dependencies (Python stdlib only). This is the executable form of the TrustShell Open
Baseline v0.1.
"""
from __future__ import annotations

import argparse
import json
import sys

from trustshell import __baseline__, __version__, checks as C, scoring

# ANSI color (auto-off when not a TTY)
def _c(code, s, on):
    return f"\033[{code}m{s}\033[0m" if on else s

STATUS_STYLE = {
    "pass": ("32", "PASS"),
    "fail": ("31", "FAIL"),
    "warn": ("33", "WARN"),
    "skip": ("90", "SKIP"),
}
SEV_LABEL = {"crit": "crit", "high": "high", "med": "med"}
GRADE_COLOR = {"A": "32", "B": "36", "C": "33", "D": "31"}


def run(target, path):
    checks = C.checks_for(has_target=bool(target), has_path=bool(path))
    findings = []
    for chk in checks:
        arg = target if chk.needs == "target" else path
        try:
            res = chk.probe(arg)
        except Exception as e:  # noqa: BLE001
            from trustshell.probes import Result
            res = Result("skip", f"probe error: {e}")
        findings.append((chk, res))
    return findings


def to_dict(findings, summary, target, path):
    return {
        "baseline": __baseline__,
        "scanner_version": __version__,
        "target": target,
        "path": path,
        "summary": summary,
        "findings": [
            {"id": c.id, "category": c.category, "title": c.title,
             "severity": c.severity, "status": r.status, "evidence": r.evidence}
            for c, r in findings
        ],
    }


def print_report(findings, summary, target, path, color):
    print()
    print(_c("1", f"  {__baseline__} · scanner v{__version__}", color))
    if target:
        print(f"  target: {target}")
    if path:
        print(f"  path:   {path}")
    print("  " + "─" * 56)

    last_cat = None
    for c, r in findings:
        if c.category != last_cat:
            print(f"\n  [{c.category}]")
            last_cat = c.category
        code, label = STATUS_STYLE[r.status]
        tag = _c(code, f"[{label}]", color)
        sev = _c("90", f"({SEV_LABEL[c.severity]})", color)
        print(f"    {tag} {c.id} {c.title} {sev}")
        print(_c("90", f"          └ {r.evidence}", color))

    BASELINE_TOTAL = 42
    g = summary["grade"]
    evaluated = summary["counts"]["pass"] + summary["counts"]["fail"]
    partial = evaluated < BASELINE_TOTAL * 0.6   # under 60% evaluated = partial scan, no full grade

    print("\n  " + "─" * 56)
    grade_str = _c(GRADE_COLOR[g], f" {g} ", color)
    if partial:
        print(f"  partial grade (indicative only): [{grade_str}]  — based on evaluated items only")
        print(_c("33", f"  ⚠ This is NOT a full security grade: only {evaluated}/{BASELINE_TOTAL} items "
                       f"evaluated; the other {BASELINE_TOTAL - evaluated} (injection / sandbox / high-risk "
                       f"actions / supply chain / audit, etc.) were not tested.", color))
    else:
        print(f"  grade: [{grade_str}]  {scoring.GRADE_BLURB[g]}")
    print(f"  coverage: {evaluated} / {BASELINE_TOTAL} items evaluated   weighted pass rate "
          f"(evaluated only): {summary['weighted_pass_ratio']*100:.0f}%")
    print(f"  breakdown: pass {summary['counts']['pass']} / fail {summary['counts']['fail']} / "
          f"warn {summary['counts']['warn']} / skip {summary['counts']['skip']}")
    if summary["vetoed"]:
        print("  " + _c("31", f"⚠ {summary['critical_failures']} critical item(s) failed — hard veto, graded D", color))
    print()
    print(_c("90", "  Note: this automated scan only covers auto-testable network/filesystem items.", color))
    print(_c("90", "        The manual items (prompt injection, tool sandbox, high-risk action", color))
    print(_c("90", "        confirmation, channel injection, supply chain, audit) require a human", color))
    print(_c("90", "        red-team — passing every auto check != secure, it just means you didn't", color))
    print(_c("90", "        step on these few obvious traps.", color))
    print()


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="TrustShell on-device agent security scanner (executable TrustShell Open Baseline v0.1)")
    ap.add_argument("--target", help="agent management-plane address, e.g. http://127.0.0.1:3000")
    ap.add_argument("--path", help="agent install/working directory, for filesystem checks")
    ap.add_argument("--json", action="store_true", help="output JSON (for leaderboards / CI integration)")
    ap.add_argument("--no-color", action="store_true", help="disable colored output")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = ap.parse_args(argv)

    if not args.target and not args.path:
        ap.error("provide at least one of --target or --path")

    findings = run(args.target, args.path)
    summary = scoring.grade(findings)

    if args.json:
        print(json.dumps(to_dict(findings, summary, args.target, args.path),
                         ensure_ascii=False, indent=2))
    else:
        color = sys.stdout.isatty() and not args.no_color
        print_report(findings, summary, args.target, args.path, color)

    # exit code: D → 2, C/B → 1, A → 0 (for CI gating)
    return {"A": 0, "B": 1, "C": 1, "D": 2}[summary["grade"]]


if __name__ == "__main__":
    sys.exit(main())
