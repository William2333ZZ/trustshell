# Three well-defended agents. Three layers. Three ways in.

*A TrustShell red-team field report. Targets anonymized; findings responsibly disclosed to the
vendors; reproduction withheld pending fixes. Each finding is labeled with its verification status —
we don't round "read it in the code" up to "exploited it."*

---

We red-teamed three serious, security-conscious self-hosted AI agents. All three defend the layer
everyone talks about — the LLM. Two of them refused every prompt-injection variant we threw, even
decoding our obfuscated payloads to inspect them first. Impressive.

We broke all three anyway — at three **different** layers. The lesson runs through all of them: the
LLM layer is where teams invest; the code and controls **around** it are where the breaks are.

## Case A — the LLM layer · `CONFIRMED (live, 4/4)`
**Class: prompt injection → command execution + skill-scanner semantic bypass.**
Untrusted content the agent processes (a support ticket from a web form) that embeds a shell command
runs — *when the command is framed as an innocuous "repro step."* Reproduced 4/4. Frame the same
command as an obvious credential grab, or hide it in base64, and it's refused. The defense keys on how
malicious the text *looks*, not what the command *does*.
Separately, its skill scanner is signature-based: it blocks code-level exfil, but a skill carrying no
code — one that only subverts the agent in plain English — passes as `safe, allowed` (3/3 variants).
**Fix:** gate on the command's actual effect, not its phrasing; treat processed content as data, never
instruction; scan skills for semantic intent, not just signatures.

## Case B — the framework layer · `CONFIRMED (in code); not live-fired`
**Class: unauthenticated path traversal → arbitrary file write.**
This agent's LLM refused *everything* we sent it. So we audited its code. In one chat channel's
attachment handler, the inbound `fileName` (attacker-controlled) is written as `download_dir / filename`
with **no sanitization** — and the download happens during message *parsing*, **before** the agent's
sender-approval gate. An unapproved stranger sends a file named `../../../../<config path>` and the
agent writes their bytes there. It bypasses both the LLM and the auth.
The tell: **every other channel in the same codebase ran the filename through a sanitizer — exactly one
forgot.** (We checked; it was not systemic — four channels were safe, one was not. Report the one.)
**Impact:** overwrite the config → point the model at an attacker endpoint (MITM every prompt, steal the
key); or plant a startup file → RCE.
**Fix:** apply the same `safe_filename` helper the other channels already use; run auth before any
file write.

## Case C — the isolation layer · `CONFIRMED (in code); fail-open weakness`
**Class: security control fails open.**
This agent markets provable isolation and runs its tools in a Docker/process sandbox. But when Docker
is absent or not running, the sandbox **silently disables itself and keeps going** — "sandbox disabled
for this session" — and tools then execute unsandboxed on the host. Many users run without Docker. The
isolation you were promised quietly isn't there, and nothing stops you.
(Honest scope: this is a fail-*open* weakness, not a standalone exploit — it becomes RCE only chained
with a tool-invoking injection, which we did not verify against this agent's defenses.)
**Fix:** fail closed — refuse to run host-affecting tools when the sandbox can't start, or require an
explicit, loud opt-in.

## Why this is the capability
Anyone can run a prompt-injection checklist. What these three show is a red-team that **moves down the
stack when the top is hardened** — LLM behavior, then framework code, then deployment controls — and
labels each finding by how far it actually verified it. A "we couldn't break the model, so we're done"
review would have missed Cases B and C entirely.

The method is open: [`redteam-an-agent`](../skills/redteam-an-agent/SKILL.md) for the LLM layer,
[`audit-agent-code`](../skills/audit-agent-code/SKILL.md) for the framework layer. If you build or ship
an agent with real reach, we'll test it this way → [trust-shell.com](https://trust-shell.com).
