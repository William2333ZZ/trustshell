---
description: Statically triage an AI agent's SOURCE for candidate vulnerable paths (RT-1..RT-9). Candidate != vuln — confirm with /red-team.
argument-hint: <path-to-agent-source>
allowed-tools: Bash(python3:*), Read, Glob, Grep
---

Run TrustShell's static engine over the target agent's source and interpret the results.

Target source directory: **$ARGUMENTS** (if empty, ask the user which agent source to scan).

Steps:
1. From the plugin root, run the static engine on the target:
   `python3 "${CLAUDE_PLUGIN_ROOT}/scanner/static_scan.py" --source "$ARGUMENTS" --json`
2. Parse the JSON. For each finding, report: the RT class (RT-1..RT-9 / RT-GUARD), the file and
   symbol, and one line on *why* it's a candidate path.
3. Be honest about what this is: **triage, not a verdict.** A flagged path is a CANDIDATE — the
   static engine says "attack here," it does NOT say "this is exploitable." Say so explicitly.
4. Recommend the highest-value candidates to confirm dynamically, and tell the user they can run
   `/red-team` to attack the running agent and prove which candidates are real.

Do not overstate. Never call a candidate a vulnerability until an exploit confirms it.
