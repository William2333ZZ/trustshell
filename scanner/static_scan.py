#!/usr/bin/env python3
"""TrustShell static engine v0 — command-line entry point.

Usage:
  python3 static_scan.py --source /path/to/agent           # triage candidate paths
  python3 static_scan.py --source /path/to/agent --json     # JSON output

Flags CANDIDATE vulnerable paths for the dynamic red-team to confirm/refute. Candidate != vuln.
Zero dependencies (Python stdlib only).
"""
from __future__ import annotations

import argparse
import json
import sys

from trustshell import static as S


def _c(code, s, on):
    return f"\033[{code}m{s}\033[0m" if on else s


SEV_STYLE = {"crit": ("31", "CRIT"), "high": ("33", "HIGH"), "med": ("90", "MED")}


def print_report(cands, root, color):
    print()
    print(_c("1", f"  TrustShell static engine v0 · candidate-path triage", color))
    print(f"  source: {root}")
    print("  " + "─" * 58)
    if not cands:
        print("  No candidate paths found (not proof of safety — static sees only part of the")
        print("  picture; a dynamic red-team is still needed).")
        print()
        return

    last_rt = None
    for c in cands:
        if c.rt != last_rt:
            label = S.RT_LABEL.get(c.rt, c.rt)
            print(f"\n  [{c.rt}] {label}")
            last_rt = c.rt
        code, lab = SEV_STYLE.get(c.severity, ("90", c.severity))
        tag = _c(code, f"[{lab}]", color)
        print(f"    {tag} {c.file}:{c.line}")
        print(_c("90", f"          └ {c.why}", color))
        if c.snippet:
            print(_c("90", f"            {c.snippet}", color))

    print("\n  " + "─" * 58)
    n = len(cands)
    print(f"  {n} candidate path(s) — this is triage, not a verdict.")
    print(_c("36", "  Next: dynamically red-team the running agent to confirm/refute each one.", color))
    print(_c("90", "  Candidate != vulnerability; the arbiter is a real exploit, not this match.", color))
    print()


def main(argv=None):
    ap = argparse.ArgumentParser(description="TrustShell static engine v0 — candidate-path triage")
    ap.add_argument("--source", required=True, help="agent source directory")
    ap.add_argument("--json", action="store_true", help="output JSON")
    ap.add_argument("--no-color", action="store_true", help="disable color")
    args = ap.parse_args(argv)

    cands = S.analyze_source(args.source)

    if args.json:
        print(json.dumps(S.to_dict(cands, args.source), ensure_ascii=False, indent=2))
    else:
        color = sys.stdout.isatty() and not args.no_color
        print_report(cands, args.source, color)

    # exit code: candidates found → 1 (lets CI flag for manual/dynamic review), none → 0
    return 1 if cands else 0


if __name__ == "__main__":
    sys.exit(main())
