---
name: redteam-an-agent
description: The end-to-end methodology for red-teaming a specific AI agent — adaptively, exploit-validated, and honestly. Read THIS target's own code, stand up a disposable harness, and prove or refute each weakness through a real attacker-reachable entry point. This is the orchestration + discipline that makes a finding credible, not a list of payloads. Authorized testing of agents you own or are permitted to test.
license: Apache-2.0
tags: [ai-agent-security, red-team, methodology, exploit-validation, agent-security]
safety: authorized-targets-only
---

# Red-team an agent · the real process

This is the process a capable red-teamer actually follows against one specific agent. It is **not**
a scanner and **not** a fixed payload list — the work is *adaptive*: you read the target's own code,
form hypotheses about how it can be reached by an attacker, and settle each one with an exploit. The
value is the **credible verdict** (what breaks, what holds, and why), not any single "gotcha."

> Written from real engagements. Every rule below exists because skipping it produced a wrong
> conclusion — an over-claimed break, or a "vulnerability" that was really just local access.

## Authorization & safety — read first
Follow every rule in [`../README.md`](../README.md): authorized target only, **disposable
environment only**, never handle the target's real credentials (the owner configures provider keys;
you reference them, never see or print the value), harmless proof markers only, no destruction/
exfiltration/persistence, method-not-weapons, responsible disclosure. Otherwise **stop**.

## Phase 1 — Recon THIS target (map it; assume nothing)
Read the target's *own* source. Do not assume "lightweight = weak" or "popular = safe." Map the
attack surfaces and record each **defense as a fact**:
- **Tool / command execution:** what can it *do* (shell, file, network, browser, real-world
  actuators)? Is execution gated (human/LLM approval)? Sandboxed? Confined to a workspace?
  A regex deny-list? **What are the defaults** (a control that ships *off* is the finding).
- **Memory / persistence:** where does it write standing state (USER profile, memory files)? Is
  content curated automatically, or only on explicit user request? Any injection defense?
- **Skill / plugin / MCP loading:** is untrusted extension code trusted? Is the guard at install
  time only (so a locally-placed one is unscanned)?
- **Channels / inbound:** how does an *external* message enter, and where is the sender
  authorized? What is the default (deny-by-default, or open)?
Output: a per-target map of **candidate** weak points. A candidate is a hypothesis, not a finding.

## Phase 2 — Disposable harness
Stand it up in a throwaway env. Find the **non-interactive single-message** invocation (e.g.
`--oneshot` / `-q` / `agent -m`) so you can drive it programmatically. Get a benign baseline
working end to end first. Beware: some "one-shot" modes are *stateless* (no memory/tools) — the
wrong harness will make everything look safe. Confirm the harness exercises the real agent loop.

## Phase 3 — The reachability rule (non-negotiable)
**A finding counts only if an *untrusted, attacker-reachable* entry point produces the effect.**
The entry point is content the agent processes that an attacker can influence: an email, a ticket,
a fetched web page, a tool result, a message from a stranger. State the entry point explicitly for
every finding.

If you produced the effect by **setting up the state yourself** — writing the agent's memory file,
dropping a file in its skills dir, editing its config — that presupposes local write access, which
is **already full compromise**. It is **not a vulnerability**; it proves nothing. This single rule
is the difference between a credible report and an embarrassing one.

## Phase 4 — Confirm dynamically (the exploit is the arbiter)
For each candidate, attack through the real untrusted entry point and prove it with a **harmless
marker that actually returns**. Then apply the discipline that keeps you honest:
- **Run a battery.** Multiple framings + repeats. LLM behavior is non-deterministic — one success
  isn't confirmed, one failure isn't refuted. (Naive injections often bounce; task-riding ones land.)
- **Disambiguate "refused" from "can't."** If it declined to run a command, prove the tool *works*
  on a legitimate request first — otherwise "refused the attack" is really "no capability."
- **Attribute the mechanism from the code.** Don't guess *why* it worked. Read the path. ("The
  command ran" could be a bypassed guardian LLM — or an approval gate that is simply skipped on
  non-interactive paths. Those are different findings; only the code tells you which.)
- **Prefer driving the target's own code with a genuinely external identity.** The strongest proof
  is the target's *own* authorization/handler code deciding the outcome for an attacker identity it
  has never approved — not a marker you fed through your own prompt. Then the arbiter is undeniably
  the target, not you.
- **The effect is the arbiter — not the model's word, and not code you stubbed.** Confirmation is an
  *observable side effect an attacker would actually get*: a marker file on disk, a marker arriving at
  a sink you control. The model *saying* it ran the command is not evidence. And do **not** stub the
  delivery boundary and hand yourself the attacker input — if you supplied the malicious value
  directly and mocked the transport that would carry it, you only re-confirmed the code you already
  read, **not** that an attacker can reach it. (Real case: a path-traversal "arbitrary write" that was
  actually just us passing a `../` filename straight to the sink with the channel stubbed — a
  *candidate*, not a break, once the reachability was honestly checked.)
- **Report the measured rate — never round up.** LLM breaks are probabilistic. If the exploit fires
  5 of 8 runs, write **"5/8 (~60%)"**, not "always" or "4/4". A guard that holds ~60% of the time
  reads as "defended" in a quick look and "owned" under an attacker who retries (retries are free,
  especially unattended). The rate *is* the finding; a headline that says "always" for a 60% result
  is the same overclaim as calling a candidate confirmed. (Real case: we first reported an
  injection→RCE as "4/4"; a proper battery measured ~60% — the vector was real, the reliability was
  over-stated, and we corrected it.)

## Phase 5 — Refute out loud, and correct yourself
- A candidate you cannot exploit is **REFUTED** — say so plainly. Refuting a false alarm is a real
  result, and it is what makes your confirmations trustworthy.
- **Note the defenses that held.** Be fair to the target; confirm its genuine strengths.
- **When static and dynamic disagree, the exploit wins — correct your own candidate.** (Real case:
  a static read predicted an agent was *weaker* on command safety because its config defaults were
  permissive; the exploit proved it *more* resistant because its prompt design refused the
  injection. The candidate was wrong; the verdict followed the exploit.)

## Phase 6 — Report
Per attack class: **CONFIRMED / REFUTED / inconclusive**, each with (a) its untrusted entry point,
(b) the marker evidence, (c) the measured hit-rate, (d) the code-grounded root cause, (e) the blast
radius, (f) the fix. Grade honestly. Disclose to help defenders, not attackers: publish the finding,
impact, and fix — **never a copy-paste weaponized payload** — and choose your disclosure model
(coordinated or full public) deliberately. Never overstate: the arbiter is the exploit **and** the
threat model.

## The anti-overclaim checklist (run before calling anything "confirmed")
1. Did *untrusted input* cause this, or did I set up the state / stub the delivery boundary and feed
   myself the payload? (Only a real, un-stubbed, attacker-reachable path counts.)
2. Is the proof an *observable effect* (marker on disk / at a sink), or just the model's own claim?
3. Did it reproduce across a battery — and am I reporting the **measured rate** (e.g. 5/8), not
   "always"?
4. "Refused" — or just no capability? (Proved the legit path works?)
5. Do I know the mechanism from the code, or am I guessing?
6. Would this survive the vendor reading it? If not, downgrade or refute.

## Related
Per-class tactics: [`../rt1-prompt-injection`](../rt1-prompt-injection/SKILL.md) …
[`../rt9-multi-agent`](../rt9-multi-agent/SKILL.md). Static-side triage that feeds Phase 1:
[`../crossval-harness`](../crossval-harness/SKILL.md).
