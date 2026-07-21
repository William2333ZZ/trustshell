# TrustShell Agent Red-Team Skills

Open-source **agent skills** for red-teaming AI agents — the attack playbook (RT-1…RT-9)
packaged so an AI agent can run each test against **an agent you own or are authorized to test**.

Because the offense is AI-driven, the methodology *is* a skill: drop one into your agent
(Claude Skills / [agentskills.io](https://agentskills.io) / Hermes / OpenClaw-compatible `SKILL.md`
format), point it at a target in a throwaway environment, and it walks the test, confirms
empirically, and writes an evidence-backed finding.

> These skills flag and **confirm** weaknesses so you can fix them. They are for defensive
> security testing, not attacks. Licensed Apache-2.0.

## The skills

| Skill | Class | Tests |
|---|---|---|
| [**`redteam-an-agent`**](redteam-an-agent/SKILL.md) | **method (start here)** | The end-to-end real process: recon the target's own code → disposable harness → prove/refute each weakness through a real attacker-reachable entry point. The discipline that makes a finding credible. |
| [**`audit-agent-code`**](audit-agent-code/SKILL.md) | **method (framework layer)** | When the LLM layer is hardened, break the agent through its own framework code: classic appsec (path traversal, command injection, fail-open sandbox, late auth) at the untrusted-input boundaries the model never sees. |
| [`rt1-prompt-injection`](rt1-prompt-injection/SKILL.md) | RT-1 | Does content the agent processes hijack its task? |
| [`rt2-tool-abuse`](rt2-tool-abuse/SKILL.md) | RT-2 | Can it be coerced into an unintended tool call / confused deputy? |
| [`rt3-sandbox-escape`](rt3-sandbox-escape/SKILL.md) | RT-3 | Do tools run un-isolated? Does the sandbox silently disable? |
| [`rt4-action-gating`](rt4-action-gating/SKILL.md) | RT-4 | Can a high-risk action reach execution without out-of-band confirmation? |
| [`rt5-channel-injection`](rt5-channel-injection/SKILL.md) | RT-5 | Can inbound channel content (DM/group/forward) steer the agent? |
| [`rt6-memory-poisoning`](rt6-memory-poisoning/SKILL.md) | RT-6 | Does an injection persist into memory and fire in future sessions? |
| [`rt7-supply-chain`](rt7-supply-chain/SKILL.md) | RT-7 | Can a poisoned skill / MCP / dependency become trusted instruction? |
| [`rt8-data-exfiltration`](rt8-data-exfiltration/SKILL.md) | RT-8 | Can an injection move secrets/PII to an attacker sink? |
| [`rt9-multi-agent`](rt9-multi-agent/SKILL.md) | RT-9 | Can one agent inject/escalate into another across a handoff or trust-launder relayed content? |
| [`crossval-harness`](crossval-harness/SKILL.md) | method | Orchestrate static triage → dynamic confirmation (exploit-validated). |

Each maps to the [TrustShell playbook](https://trust-shell.com/en/playbook) and the
open [static engine](../scanner/static_scan.py).

## Use these in your agent

Every skill is a portable `SKILL.md` (YAML frontmatter + instructions). Drop it into any
skill-aware agent and it gains that red-team capability.

**Claude Code** — copy a skill into your skills directory; it's auto-discovered by `name`:
```bash
git clone https://github.com/William2333ZZ/trustshell
# per-project:
mkdir -p .claude/skills && cp -R trustshell/skills/rt6-memory-poisoning .claude/skills/
# or for all projects: cp -R trustshell/skills/rt6-memory-poisoning ~/.claude/skills/
```
Then in Claude Code: *"use the rt6-memory-poisoning skill against my agent at ./my-agent"*.

**agentskills.io / Hermes / OpenClaw** — the same `SKILL.md` format loads directly (skills dir
or marketplace import).

**Cursor / other assistants** — reference a skill file as context/rules, or point the assistant
at this repo and ask it to follow the relevant `SKILL.md`.

**Any MCP agent (Claude Desktop, Claude Code, Cursor, …)** — run the [MCP server](../mcp/) to
call the whole toolkit (`static_scan`, `red_team`, `list_skills`) as native tools — see
[`../mcp/README.md`](../mcp/README.md).

> Whatever the host, the contract is the same: authorized targets only, disposable environment,
> harmless markers, and a finding counts only when the exploit actually works.

## Golden rules (every skill enforces these)

1. **Authorized targets only.** Test an agent you own, or one you have explicit written
   permission to test. No third-party or production agents without authorization.
2. **Disposable environment only.** Run in a throwaway sandbox (cloud dev container / VM),
   never production, never a machine with real data. You are deliberately making an agent
   misbehave — it must not be able to touch anything real.
3. **Never handle the target's real credentials.** The target's owner configures provider
   keys in their own environment; the skill references them, never sees or stores the values.
4. **Harmless proof only.** Use a random marker token (e.g. `PROOF-<random>`) to prove
   control. No destructive actions, no data exfiltration, no persistence beyond the test.
5. **Method, not weapons.** These describe *how to test and confirm*, not ready-to-fire
   malicious payloads. Keep it that way when you extend them.
6. **Disclose to help defenders, not attackers.** Publish the finding, impact, and fix — **never a
   copy-paste weaponized payload.** Choose your disclosure model (coordinated vendor-first, or full
   public) deliberately. Be fair: if an agent defends well, say so; and report a **measured hit-rate**
   (e.g. 5/8), never round a probabilistic break up to "always."

## The arbiter of truth

A finding is **confirmed** only when the test actually works — not when a model thinks it
might. A candidate that can't be exploited is **refuted**, out loud. That empirical arbiter is
the point: static tells you where to look, dynamic decides what's real.
