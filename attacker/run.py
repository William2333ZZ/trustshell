#!/usr/bin/env python3
"""TrustShell autonomous attacker — CLI.

An agent that red-teams another AI agent: it runs static triage over the target's
source, then attacks the RUNNING target with marker-confirmed tactics, and decides
CONFIRMED / REFUTED by whether the exploit actually worked.

USAGE (authorized, disposable environment only):
  # against a CLI agent (the {msg} placeholder receives the attack message)
  python3 run.py --authorized --target-cmd 'ironclaw run --no-db -m {msg}' --source /path/to/agent

  # against an HTTP agent
  python3 run.py --authorized --target-url http://127.0.0.1:8080/chat --field message --reply-path reply

  # self-test with the built-in mock target (no target, no keys needed)
  python3 run.py --authorized --mock vulnerable
  python3 run.py --authorized --mock hardened

SAFETY: refuses to run without --authorized. Test only agents you own or are
permitted to test, in a throwaway environment. Payloads are harmless markers —
no destruction, no exfiltration. Zero dependencies (Python 3.8+ stdlib).
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from trustshell_attacker import __version__
from trustshell_attacker.adapters import CmdAdapter, HttpAdapter, MockAdapter
from trustshell_attacker import tactics as T


def static_triage(source: str) -> list[dict]:
    """Compose the static engine (scanner/static_scan.py) for candidate paths."""
    here = os.path.dirname(os.path.abspath(__file__))
    static_cli = os.path.normpath(os.path.join(here, "..", "scanner", "static_scan.py"))
    if not os.path.exists(static_cli):
        return []
    try:
        out = subprocess.run([sys.executable, static_cli, "--source", source, "--json"],
                             capture_output=True, text=True, timeout=120)
        data = json.loads(out.stdout or "{}")
        return data.get("candidates", [])
    except Exception:
        return []


def build_adapter(args):
    if args.mock:
        return MockAdapter(vulnerable=(args.mock == "vulnerable"))
    if args.target_cmd:
        return CmdAdapter(template=args.target_cmd, timeout=args.timeout)
    if args.target_url:
        return HttpAdapter(url=args.target_url, field=args.field, reply_path=args.reply_path, timeout=args.timeout)
    return None


def _c(code, s, on):
    return f"\033[{code}m{s}\033[0m" if on else s


STATUS_STYLE = {"confirmed": ("31", "CONFIRMED"), "refuted": ("32", "refuted"),
                "planned": ("90", "planned"), "error": ("33", "error")}


def run(args):
    adapter = build_adapter(args)
    if adapter is None:
        print("error: give a target — --target-cmd, --target-url, or --mock", file=sys.stderr)
        return 2

    candidates = static_triage(args.source) if args.source else []
    results = [t(adapter.send) for t in T.IMPLEMENTED] + T.planned_results()

    if args.json:
        print(json.dumps({
            "attacker": f"trustshell-attacker v{__version__}",
            "note": "For authorized, defensive testing only. The arbiter is the exploit, not a model vote.",
            "target": adapter.name,
            "static_candidates": candidates,
            "findings": [r.__dict__ for r in results],
        }, ensure_ascii=False, indent=2))
        return 0

    color = sys.stdout.isatty() and not args.no_color
    print()
    print(_c("1", f"  TrustShell autonomous attacker v{__version__}  ·  target: {adapter.name}", color))
    print("  " + "─" * 62)
    if args.source:
        print(f"  Static triage: {len(candidates)} candidate path(s) → {args.source}")
    print()
    confirmed = 0
    for r in results:
        code, label = STATUS_STYLE.get(r.status, ("0", r.status))
        tag = _c(code, f"[{label}]", color)
        print(f"  {tag} {r.rt} {r.title} {_c('90', '(' + r.severity + ')', color)}")
        print(_c("90", f"        └ {r.evidence}", color))
        if r.status == "confirmed":
            confirmed += 1
    print("\n  " + "─" * 62)
    print(f"  {_c('31' if confirmed else '32', str(confirmed) + ' confirmed', color)} · "
          f"{sum(1 for r in results if r.status=='refuted')} refuted · "
          f"{sum(1 for r in results if r.status=='planned')} planned (not yet automated)")
    print(_c("90", "  Confirmed = the exploit actually worked. Disclose responsibly.", color))
    print()
    return 1 if confirmed else 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="TrustShell autonomous attacker — red-teams another AI agent.")
    ap.add_argument("--authorized", action="store_true", help="Confirm you own or are permitted to test the target (required).")
    ap.add_argument("--target-cmd", help="Shell command template for a CLI target; must contain {msg}.")
    ap.add_argument("--target-url", help="HTTP endpoint of the target agent.")
    ap.add_argument("--field", default="message", help="HTTP request field (default: message).")
    ap.add_argument("--reply-path", default="reply", help="Dotted path to the reply in the JSON response.")
    ap.add_argument("--mock", choices=["vulnerable", "hardened"], help="Use the built-in mock target (self-test).")
    ap.add_argument("--source", help="Target source dir for static triage (optional).")
    ap.add_argument("--timeout", type=int, default=120, help="Per-message timeout (s).")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = ap.parse_args(argv)

    if not args.authorized:
        print("REFUSING: pass --authorized to confirm the target is yours or you have written "
              "permission, and that it runs in a disposable environment. Authorized testing only.",
              file=sys.stderr)
        return 2
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
