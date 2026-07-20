# TrustShell Scanner · on-device agent security scanner

> The executable form of the TrustShell Open Baseline v0.1. Runs an automated security check on
> your self-hosted / on-device AI agent and outputs an **A/B/C/D grade**.
>
> **Zero dependencies** — Python 3.8+ only.

## What this is

An on-device agent (an AI that runs on your own machine/box, holds your account keys, and can
take real actions for you) is, if left unlocked, a "digital butler running exposed": management
plane on the public internet, poisoned skills, plaintext credentials, no trail when something
goes wrong. This tool runs the **auto-testable** items of the TrustShell Open Baseline as a single
scan and grades on the spot.

- Network checks (`--target`): does the management plane bind localhost-only, any exposed ports,
  TLS, debug endpoints, cross-origin hijack (DNS-rebinding), do sensitive endpoints require auth.
- Filesystem checks (`--path`): dependency lockfiles, plaintext credentials in config/logs,
  whether any forensic logs exist.

Scoring follows the baseline: **critical items are a hard veto** — any failed critical item grades
straight to D.

## Quickstart

```bash
# Network check (point at the agent's management-plane address)
python3 scan.py --target http://127.0.0.1:3000

# Filesystem check (point at the agent's install/working directory)
python3 scan.py --path /path/to/your-agent

# Both, for a full grade
python3 scan.py --target http://127.0.0.1:3000 --path /path/to/your-agent

# Machine-readable (CI / leaderboards)
python3 scan.py --target http://127.0.0.1:3000 --json
```

## Static engine v0

`scan.py` looks at the **running / filesystem layer**; `static_scan.py` reads the **source** —
flagging candidate vulnerable paths (untrusted content reaching a dangerous sink, signature-only
guards, missing checks), mapped to the RT-1…RT-9 attack classes.

```bash
# Read an agent's source, triage candidate paths
python3 static_scan.py --source /path/to/agent

# JSON (feed the dynamic red-team / CI)
python3 static_scan.py --source /path/to/agent --json
```

**This is triage, not a verdict.** A candidate is not a vulnerability; the arbiter of truth is
whether the dynamic red-team's exploit actually works, not this match. Static says *where to look*,
dynamic decides *what's real*. Zero dependencies, Python stdlib only.

Exit codes: `A→0`, `B/C→1`, `D→2` (for CI gating).

## Check coverage (v0.1)

| ID | Check | Severity | Type |
|---|---|---|---|
| A-01 | Management console binds localhost-only by default | crit | network |
| A-02 | No public ports open by default | crit | network |
| A-03 | External interfaces enforce TLS | high | network |
| A-04 | Debug ports disabled in production | high | network |
| A-05 | Resists DNS-rebinding / cross-origin | crit | network |
| B-02 | Sensitive endpoints require authentication | crit | network |
| C-04 | Dependencies have integrity checks (lockfile) | med | file |
| E-01 | Credentials not stored in plaintext | crit | file |
| E-02 | Credentials not written to logs | high | file |
| H-04 | Exportable logs exist | med | file |

> The full baseline has 42 items (10 categories); the rest are manual items requiring human review
> (injection robustness, sandbox isolation, out-of-band confirmation, tamper-evident audit, etc.).

## Honest limits

This is **v0.1** — checks are heuristic and may miss or over-flag; it covers the "auto-testable"
subset and **is not a substitute for a full manual security assessment**. Use it for a fast
self-check, to grade a leaderboard, or as the entry point to a deeper audit. Issues / PRs welcome
to make it sharper.

## License

- Code: MIT
- The TrustShell Open Baseline standard document: CC BY 4.0 — free to cite and build on, with
  attribution.
