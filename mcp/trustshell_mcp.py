#!/usr/bin/env python3
"""TrustShell MCP server — expose the toolkit as tools any MCP agent can call.

Lets Claude Code / Claude Desktop / Cursor (or any MCP client) invoke the static
engine, the autonomous attacker, and the red-team skills as native tools.

Run:  pip install mcp   &&   python3 trustshell_mcp.py     (stdio transport)
See README.md for the client config.

Safety: the attacker tool refuses unless `authorized=True` (you own or are permitted
to test the target, in a disposable environment). Method, not weapons.
"""
from __future__ import annotations

import json
import pathlib
import re
import subprocess
import sys

from mcp.server.fastmcp import FastMCP

ROOT = pathlib.Path(__file__).resolve().parent.parent   # toolkit root
SCANNER = ROOT / "scanner"
ATTACKER = ROOT / "attacker"
SKILLS = ROOT / "skills"

mcp = FastMCP("trustshell")


def _run(args: list[str], timeout: int = 300) -> str:
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return "[timed out]"
    return (p.stdout or "").strip() or (p.stderr or "").strip()


@mcp.tool()
def static_scan(source_dir: str) -> str:
    """Read an AI agent's SOURCE and flag CANDIDATE vulnerable paths (triage; candidate != vuln),
    mapped to the RT-1..RT-9 attack classes. Returns JSON. Confirm candidates dynamically with red_team."""
    return _run([sys.executable, str(SCANNER / "static_scan.py"), "--source", source_dir, "--json"])


@mcp.tool()
def red_team(target_cmd: str, authorized: bool = False, source_dir: str = "") -> str:
    """Autonomously red-team a RUNNING agent and return an exploit-validated report (JSON).

    target_cmd: a shell command template to reach the target; must contain {msg} (the attack
      message is substituted, the command's stdout is the agent's reply). e.g. 'my-agent -m {msg}'
    authorized: MUST be True — you confirm you own or have written permission to test the target,
      and it runs in a disposable environment. Refuses otherwise.
    source_dir: optional target source for static triage.

    A finding is CONFIRMED only when the exploit's proof marker actually comes back. Harmless
    markers only; no destruction. For authorized, defensive testing only."""
    if not authorized:
        return json.dumps({"refused": True, "reason":
                           "Set authorized=True only for an agent you own or are permitted to test, "
                           "running in a disposable environment. Authorized, defensive testing only."})
    args = [sys.executable, str(ATTACKER / "run.py"), "--authorized", "--target-cmd", target_cmd, "--json"]
    if source_dir:
        args += ["--source", source_dir]
    return _run(args)


@mcp.tool()
def red_team_selftest(hardened: bool = False) -> str:
    """Run the attacker against its built-in MOCK target (no real target, no keys) to see the
    exploit-validated output shape. hardened=False → RT-1+RT-6 confirmed; True → all refuted."""
    mock = "hardened" if hardened else "vulnerable"
    return _run([sys.executable, str(ATTACKER / "run.py"), "--authorized", "--mock", mock, "--json"])


@mcp.tool()
def list_skills() -> str:
    """List the available red-team skills (RT-1..RT-9 + methodology) with their descriptions."""
    out = []
    for d in sorted(SKILLS.glob("*/SKILL.md")):
        text = d.read_text(encoding="utf-8", errors="ignore")
        name = _frontmatter(text, "name") or d.parent.name
        desc = _frontmatter(text, "description") or ""
        out.append({"id": d.parent.name, "name": name, "description": desc})
    return json.dumps(out, ensure_ascii=False, indent=2)


@mcp.tool()
def read_skill(skill_id: str) -> str:
    """Return the full SKILL.md for a skill id (e.g. 'rt6-memory-poisoning'). Load it into your
    agent to run that red-team test."""
    p = SKILLS / skill_id / "SKILL.md"
    if not p.exists():
        return f"[no such skill: {skill_id}. Use list_skills first.]"
    return p.read_text(encoding="utf-8", errors="ignore")


def _frontmatter(text: str, key: str) -> str:
    m = re.search(rf"^{key}:\s*(.+)$", text, re.MULTILINE)
    return m.group(1).strip() if m else ""


if __name__ == "__main__":
    mcp.run()
