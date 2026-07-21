---
name: crossval-harness
description: Orchestrate a static + dynamic, exploit-validated red-team of an AI agent — read the source to find candidate vulnerable paths, then run the dynamic skills to confirm or refute each one empirically. The arbiter of truth is whether the exploit works, not a model vote. Authorized testing of agents you own or are permitted to test.
license: Apache-2.0
tags: [ai-agent-security, red-team, methodology, cross-validation, exploit-validation]
safety: authorized-targets-only
---

# Cross-validation harness · static + dynamic

## What this is
The orchestration skill. It runs the two halves and correlates them so you get *proven*
findings and root cause — not a wall of static maybes, and not a break with no explanation.

## Authorization & safety — read first
Follow every rule in [`../README.md`](../README.md). Authorized target, disposable environment,
no real credentials, harmless markers, no destruction, responsible disclosure. Otherwise **stop**.

## Procedure
1. **Static triage — where to look.** Read the agent's source and flag candidate paths:
   untrusted content reaching a dangerous sink, a signature-only guard, a missing check, an
   un-sandboxed exec. Map each candidate to a class (RT-1…RT-9). Tooling:
   `python3 scanner/static_scan.py --source /path/to/agent`. A candidate is **not** a finding.
2. **Dynamic confirmation — what's real.** For each candidate, run the matching skill
   (`rt1-prompt-injection`, `rt6-memory-poisoning`, `rt3-sandbox-escape`, `rt4-action-gating`)
   against the running agent. A finding is **confirmed** only when the exploit actually works.
3. **Correlate.**
   - **Confirmed:** trace the working exploit back to the exact code path → root cause, blast
     radius, and where to fix.
   - **Refuted:** a static candidate the dynamic pass couldn't exploit — kill it out loud. A
     false positive dies to a real attack, not a model vote.
4. **Grade & report.** Each finding carries both the code path and a working exploit, with
   reproduction. Be fair: note the defenses that held. Disclose to help defenders — the finding and fix, not a weaponized payload.

## Why both
A pure code verifier can only guess whether a flaw is real, so it leans on model voting to
suppress false positives. A pure red-team knows something broke but not why. Cross-validation
gives you the precise, proven root cause — and an empirical arbiter a verifier can't provide.

## Output shape (suggested JSON)
```json
{
  "target": "<agent + version>",
  "environment": "disposable-sandbox",
  "confirmed": [{ "class": "RT-6", "path": "file:line", "repro": "...", "severity": "crit" }],
  "refuted":   [{ "class": "RT-3", "candidate": "file:line", "why_not": "fails closed" }],
  "defenses_that_held": ["..."],
  "disclosure": "private-to-vendor"
}
```
