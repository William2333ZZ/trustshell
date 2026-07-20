---
name: audit-agent-code
description: Security-audit an AI agent's OWN framework code for classic appsec vulnerabilities the LLM can't defend — path traversal, command injection, SSRF, fail-open security controls, missing/late auth, unsafe deserialization — especially at the untrusted-input boundaries (channels, file/media handlers, config & skill loaders) that run around and before the model. The LLM layer is often hardened; the plumbing around it usually isn't. Authorized testing of agents you own or are permitted to test.
license: Apache-2.0
tags: [ai-agent-security, appsec, code-audit, path-traversal, agent-security]
safety: authorized-targets-only
---

# Audit the agent's code · framework appsec

The companion to [`redteam-an-agent`](../redteam-an-agent/SKILL.md). That skill breaks the *running*
agent through the model. This one breaks it through **its own source code** — the classic appsec
layer the model's judgment never touches.

> Written from real engagements: two well-defended agents whose LLM refused every prompt-injection
> attempt were broken here instead — one by an unauthenticated **path traversal** in a channel's
> file handler, one by a **fail-open sandbox**. The model can't defend a code path it never sees.

## Why this layer
Flagship agents increasingly harden the **LLM layer**: they refuse injected commands, resist
memory poisoning, even decode obfuscated payloads to inspect them. Good. But the code **around** the
model — the channel that parses an inbound message, the handler that saves an attachment, the loader
that reads config/skills, the toggle that turns the sandbox on — is **ordinary software**, and it is
frequently *not* hardened. An attacker who reaches those paths bypasses the model entirely. Audit
them like you'd audit any web app.

## Authorization & safety
Follow every rule in [`../README.md`](../README.md): authorized target, disposable environment,
harmless proof, responsible disclosure. Reading source is safe; **never run untrusted target code**
on a machine you care about.

## The untrusted-input boundaries (where to look)
Trace every place external, attacker-influenced data enters, and follow it to a dangerous sink:
- **Channel / message handlers** — attachment `filename` → file write (path traversal); `sender_id`
  → path; message body → any sink. These run on *every inbound message*, often before auth.
- **File / media / download tools** — path built from untrusted input; write/read outside the
  intended dir; symlink following.
- **Config / skill / MCP / plugin loaders** — untrusted content → deserialization (`pickle`,
  `yaml.load`, `eval`), dynamic import, or a path.
- **The security controls themselves** — the sandbox toggle, the guard, the auth gate. Audit the
  control, not just the happy path.

## Sinks by language
- **Python**: `os.system`, `subprocess(..., shell=True)`, `Path(x) / untrusted`, `open(untrusted,'w')`,
  `pickle.load`, `yaml.load` (non-safe), `eval`/`exec`.
- **JS/TS**: `child_process` / `execSync`, `eval`, `new Function`, `fs.write*` with an untrusted path.
- **Rust**: `Command::new("sh").arg("-c")` with interpolated input, `fs::write`/`File::create` on a
  path joined from untrusted input without `canonicalize` + containment check.

## Four techniques that actually land
1. **Cross-component consistency diff.** When a codebase has N similar handlers (channels, parsers,
   loaders), check whether they *all* apply the same safety helper. The one that forgot is the bug.
   *(Real case: every channel ran the attachment filename through a sanitizer — except one, which
   wrote `dir / raw_filename`. That one had a path traversal.)*
2. **Auth ordering.** Find dangerous operations (file write, download, exec) that run during message
   *parsing* — before the pairing/auth gate fires. If the write happens first, it's **unauthenticated**,
   and the agent's access control (however strong) doesn't cover it.
3. **Fail-open controls.** A security control that, on a missing dependency or an error, **degrades
   to insecure and keeps running** instead of failing closed. *(Real case: a tool sandbox that
   silently disabled itself when Docker was absent and ran tools unsandboxed on the host — the
   promised isolation quietly wasn't there.)*
4. **Trust-boundary laundering.** Data that's untrusted as *content* but trusted once it's a config
   value, a stored skill, or a peer-agent message — where the same string gets more authority by
   changing container.

## Rigor — the same bar as everything we do
- **Attacker-reachability.** A sink is only a finding if *untrusted, attacker-controlled* input
  reaches it. Trace the source; if you had to set the state up yourself, it's not a vulnerability.
- **Don't overclaim "systemic."** Check each instance. *(Real case: the traversal looked like it hit
  five channels; on inspection four sanitized correctly — only one was vulnerable. Report the one.)*
- **Confirmed-in-code vs live-fired.** Say which. A traced source→sink with no sanitizer is a
  code-confirmed finding; only claim "exploited" if you actually fired it end to end.
- **Impact, concretely.** Arbitrary file write → overwrite the config to redirect the model to an
  attacker endpoint (MITM every prompt + steal the key), or plant a startup file → RCE. Spell out
  the chain; don't stop at "write primitive."

## Report
Per finding: the untrusted **source**, the **sink**, the **missing check**, whether it's
code-confirmed or live-fired, the **reachability conditions** (which channel/mode enabled), the
concrete **impact chain**, and the **fix** (the exact sanitizer/ordering/fail-closed change).
Disclose privately to the vendor before any named publication.

## Related
Behavioral / LLM-layer red-team: [`redteam-an-agent`](../redteam-an-agent/SKILL.md). Supply chain of
skills/MCP: [`rt7-supply-chain`](../rt7-supply-chain/SKILL.md).
