<h1 align="center">TrustShell</h1>
<p align="center"><b>An open-source toolkit for AI agent security.</b><br>
Read the code, break the running agent, prove it — exploit-validated, not guessed.</p>
<p align="center">
  🔗 <a href="https://trust-shell.com">trust-shell.com</a> · ✉️ a313295747@gmail.com · Zero dependencies (Python 3.8+)
</p>

---

Every AI agent that can *act* is a new attack surface, and automated scans only catch the easy
layer. The real risk — prompt injection, memory poisoning, sandbox escape, tool/action abuse —
needs an adversary. TrustShell combines **static + dynamic** testing (like SAST + DAST for AI
agents), and **the arbiter of truth is whether the exploit actually worked, not a model vote.**

This repo is the toolkit. The write-ups, playbook, and field notes live at
[trust-shell.com](https://trust-shell.com).

## What's here

| Tool | What it does |
|---|---|
| [`attacker/`](attacker/) | **Autonomous attacker** — an agent that red-teams other agents. Static triage + marker-confirmed dynamic attacks (RT-1 injection, RT-6 memory poisoning). A finding is CONFIRMED only when the exploit's proof marker actually comes back. |
| [`scanner/`](scanner/) | **Static engine** (`static_scan.py`) — AST candidate-path analyzer over an agent's source. **Surface scanner** (`scan.py`) — network/auth + filesystem checks, the executable form of the open baseline (A–D grade). |
| [`skills/`](skills/) | **Red-team skills** — the nine attack classes (RT-1…RT-9) as portable `SKILL.md` files an AI agent can load and run against a target. Apache-2.0. |
| [`mcp/`](mcp/) | **MCP server** — expose the whole toolkit as tools any MCP agent (Claude Code, Claude Desktop, Cursor) can call: `static_scan`, `red_team`, `list_skills`. |

**Use it from your agent.** The skills load into Claude Code / agentskills.io / Hermes as
`SKILL.md` ([how](skills/#use-these-in-your-agent)); or run the [MCP server](mcp/) so any MCP
client calls the toolkit as native tools. TrustShell spreads *through* the agent ecosystem, not
just as a service you hire.

## Install as a Claude Code plugin

One command turns this repo into `/static-scan`, `/red-team`, and the `agent-red-teamer` subagent
inside Claude Code (the RT-1…RT-9 skills come with it):

```
/plugin marketplace add William2333ZZ/trustshell
/plugin install trustshell
```

Then, in a throwaway sandbox with an agent you own or are authorized to test:

```
/static-scan ./path/to/agent-source          # triage: candidate vulnerable paths
/red-team my-agent -m {msg}                   # attack the running agent; CONFIRM with a proof marker
```

or just ask: *"use the agent-red-teamer subagent to red-team my agent at ./my-agent."*
Authorized, disposable-environment testing only — the attacker refuses without `--authorized`.

## Quickstart

```bash
# Static triage: read an agent's source, flag candidate vulnerable paths (candidate ≠ vuln)
python3 scanner/static_scan.py --source /path/to/agent

# Surface scan: network/auth of a running agent + filesystem of an install dir → A/B/C/D
python3 scanner/scan.py --target http://127.0.0.1:3000 --path /path/to/agent

# Autonomous attacker (authorized, disposable env only). Self-test with the built-in mock:
python3 attacker/run.py --authorized --mock vulnerable     # → RT-1 + RT-6 CONFIRMED
python3 attacker/run.py --authorized --mock hardened       # → all refuted
# ...against a real CLI agent:
python3 attacker/run.py --authorized --target-cmd 'your-agent -m {msg}' --source /path/to/agent
```

## The loop (how the tools compose)

**Static** finds candidate paths (*where to attack*) → **dynamic** attacks the running agent to
confirm what's *actually* exploitable → a static false positive dies to a real attack, not a
vote → each confirmed break traces to the exact code path (root cause + blast radius). That
empirical arbiter is what a pure code verifier structurally can't give you.

## Safety & ethics (non-negotiable)

For **authorized, defensive security testing only.** Every tool enforces this:

1. **Authorized targets only** — an agent you own or have written permission to test.
2. **Disposable environment only** — never production, never a machine with real data.
3. **Never handle the target's real credentials** — the target's own env holds those.
4. **Harmless proof only** — a random marker; no destruction, no exfiltration, no persistence.
5. **Method, not weapons** — we publish how to test and confirm, not weaponized payloads.
6. **Responsible disclosure** — report privately with a fix; if an agent defends well, say so.

The autonomous attacker refuses to run without `--authorized`.

## Status

**v0.x — early and honest.** The static engine flags *candidates*, not verdicts. The attacker
automates RT-1 and RT-6 (validated live) and declares RT-2/3/4/5/7/8 as planned so coverage is
never overstated. Issues and PRs welcome.

## License

- Code (`scanner/`, `attacker/`): **MIT**
- Red-team skills (`skills/`): **Apache-2.0**
- The open baseline standard: **CC BY 4.0**
