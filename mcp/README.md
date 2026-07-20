# TrustShell MCP server

Expose the TrustShell toolkit as tools **any MCP agent can call** — Claude Code, Claude Desktop,
Cursor, or anything that speaks the [Model Context Protocol](https://modelcontextprotocol.io).
Instead of copying skills around, the agent gets native tools:

| Tool | What it does |
|---|---|
| `static_scan(source_dir)` | Read an agent's source, flag candidate vulnerable paths (RT-1…RT-9). |
| `red_team(target_cmd, authorized, source_dir)` | Autonomously red-team a running agent; exploit-validated report. Refuses unless `authorized=True`. |
| `red_team_selftest(hardened)` | Run against the built-in mock target (no real target/keys) to see the output shape. |
| `list_skills()` / `read_skill(id)` | Browse and load the red-team skills. |

## Install

```bash
pip install mcp
```

## Add it to your agent

**Claude Code** (one command):
```bash
claude mcp add trustshell -- python3 /ABS/PATH/TO/trustshell/mcp/trustshell_mcp.py
```

**Claude Desktop / Cursor** — add to the MCP config (`claude_desktop_config.json`, or Cursor's
MCP settings):
```json
{
  "mcpServers": {
    "trustshell": {
      "command": "python3",
      "args": ["/ABS/PATH/TO/trustshell/mcp/trustshell_mcp.py"]
    }
  }
}
```

Then just ask: *"use trustshell to red-team my agent — target command `my-agent -m {msg}`, it's mine and running in a throwaway container"*, or *"static_scan ./my-agent and list the RT-6 candidates"*.

## Safety

For **authorized, defensive testing only.** `red_team` refuses unless you pass `authorized=True`,
confirming you own or have written permission to test the target and it runs in a disposable
environment. Harmless proof markers only — no destruction, no exfiltration. Method, not weapons.
