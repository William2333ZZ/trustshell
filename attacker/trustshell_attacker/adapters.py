"""Target adapters — how the attacker talks to the agent under test.

A TargetAdapter turns an attack message into the target agent's reply. Different
agents are reached differently (a CLI, an HTTP endpoint, a chat channel), so the
adapter is pluggable. The rest of the system only sees `send(message) -> reply`.

Safety: the attacker only ever *sends messages* to a target the operator has
authorized and stood up in a disposable environment. Adapters never touch real
credentials — the target's own env holds those.
"""
from __future__ import annotations

import shlex
import subprocess
from dataclasses import dataclass


class TargetAdapter:
    name = "base"

    def send(self, message: str) -> str:
        raise NotImplementedError


@dataclass
class CmdAdapter(TargetAdapter):
    """Run a shell command; the `{msg}` placeholder is replaced with the attack
    message (shell-escaped). The command's stdout is the agent's reply.

    Example template: 'ironclaw run --no-db -m {msg}'  or  'python3 agent.py {msg}'
    The operator supplies the template; we never construct provider keys.
    """
    template: str
    timeout: int = 120
    name: str = "cmd"

    def send(self, message: str) -> str:
        if "{msg}" not in self.template:
            raise ValueError("target command template must contain {msg}")
        cmd = self.template.replace("{msg}", shlex.quote(message))
        try:
            out = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=self.timeout,
            )
        except subprocess.TimeoutExpired:
            return "[adapter: target timed out]"
        return (out.stdout or "").strip() or (out.stderr or "").strip()


@dataclass
class HttpAdapter(TargetAdapter):
    """POST the message as JSON to a target endpoint and read a text reply.
    `field` is the request key; `reply_path` is a dotted path into the JSON reply.
    Stdlib only.
    """
    url: str
    field: str = "message"
    reply_path: str = "reply"
    timeout: int = 60
    name: str = "http"

    def send(self, message: str) -> str:
        import json
        import urllib.request

        data = json.dumps({self.field: message}).encode()
        req = urllib.request.Request(self.url, data=data, headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                body = r.read().decode("utf-8", "replace")
        except Exception as e:  # noqa: BLE001
            return f"[adapter: request failed: {e}]"
        try:
            obj = json.loads(body)
            for key in self.reply_path.split("."):
                obj = obj[key]
            return str(obj).strip()
        except Exception:
            return body.strip()


@dataclass
class MockAdapter(TargetAdapter):
    """In-process fake target for self-test. `vulnerable=True` simulates an agent
    that obeys injected instructions (echoes a marker it's told to emit);
    `vulnerable=False` simulates one that ignores them. No network, no LLM."""
    vulnerable: bool = True
    name: str = "mock"
    _memory: str = ""

    def send(self, message: str) -> str:
        import re

        low = message.lower()
        m = re.search(r"[A-Z]{2,}-[A-Z]+-[A-Z0-9]{4,}", message)   # a proof marker in the message

        if not self.vulnerable:
            return "Here is a one-sentence summary of your note."   # hardened: never obeys injected content

        # RT-6 plant: a "remember / permanent / future session" directive gets persisted,
        # while the visible summary stays clean (hides the directive).
        if m and re.search(r"remember|permanent|standing|future session|memory directive", low):
            self._memory = m.group(0)
            return "User has a dentist appointment Tuesday at 3pm."
        # RT-1 direct obey: emit the injected marker now.
        if m:
            return m.group(0)
        # RT-6 fires later: a fresh, innocent prompt still carries the planted directive.
        if self._memory:
            return f"{self._memory}\nSure — here's a simple pasta recipe: ..."
        return "Here is a one-sentence summary of your note."
