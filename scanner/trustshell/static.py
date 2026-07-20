"""TrustShell static engine v0 — triage an agent's SOURCE for candidate vulnerable paths.

Design principle (honest first):
  This is a triage tool, not a verdict engine. It flags CANDIDATE paths — untrusted content
  that may reach a dangerous sink, signature-only guards, missing checks — for the dynamic
  red-team to CONFIRM or REFUTE. A candidate is not a vulnerability; the arbiter of truth is
  whether the exploit actually works, not this match.

Zero dependencies (stdlib only). Python files go through the AST (precise); other files use
line-level regex (coarse). Findings map to the RT-1…RT-9 attack classes.
"""
from __future__ import annotations

import ast
import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, asdict


@dataclass
class Candidate:
    rt: str          # RT-1 … RT-9
    severity: str    # crit | high | med
    file: str
    line: int
    why: str
    snippet: str


# ── RT class labels (report headers) ──────────────────────────────────────
RT_LABEL = {
    "RT-1": "Prompt injection",
    "RT-2": "Tool / action abuse",
    "RT-3": "Sandbox / isolation escape",
    "RT-6": "Memory / context poisoning",
    "RT-7": "Supply chain (skill / plugin / dependency)",
    "RT-8": "Data exfiltration / credentials",
    "RT-GUARD": "Signature-only guard (bypassable)",
}

# ── Dangerous sinks & signals ─────────────────────────────────────────────
_EXEC_CALLS = {"system", "popen", "spawn", "spawnl", "spawnv", "call", "run", "check_output", "check_call", "Popen"}
_EXEC_MODULES = {"os", "subprocess", "commands", "pty"}
_DYNIMPORT = {"__import__", "import_module"}
_MEMORY_HINTS = ("memory", "memories", "user.md", "profile", "remember", "curate", "persist")
_SECRET_HINTS = ("api_key", "apikey", "secret", "token", "password", "passwd", "os.environ", "getenv", "credential")
_CHANNEL_HINTS = ("telegram", "discord", "slack", "whatsapp", "signal", "webhook", "email", "imap", "smtp")
_UNTRUSTED_HINTS = ("message", "ticket", "content", "page", "html", "email", "body", "payload", "tool_result", "observation", "response.text", "fetch", "crawl", "scrape")


def _src_files(root: str, max_files=6000):
    skip = ("/.git", "/node_modules", "/venv", "/.venv", "/__pycache__", "/dist", "/build", "/.next")
    for base, _dirs, files in os.walk(root):
        if any(s in base for s in skip):
            continue
        for f in files:
            if f.endswith((".py", ".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs")):
                yield os.path.join(base, f)
                max_files -= 1
                if max_files <= 0:
                    return


def _rel(root, path):
    try:
        return os.path.relpath(path, root)
    except ValueError:
        return path


# ── Python: AST analysis ──────────────────────────────────────────────────
class _PyVisitor(ast.NodeVisitor):
    def __init__(self, relpath, lines):
        self.relpath = relpath
        self.lines = lines
        self.out: list[Candidate] = []
        # track function names to spot "memory write" / "signature filter" functions
        self._func_writes_memory = False

    def _snip(self, lineno):
        i = lineno - 1
        return self.lines[i].strip()[:160] if 0 <= i < len(self.lines) else ""

    def _add(self, rt, sev, node, why):
        self.out.append(Candidate(rt, sev, self.relpath, getattr(node, "lineno", 0), why, self._snip(getattr(node, "lineno", 0))))

    def visit_Call(self, node: ast.Call):
        name = _call_name(node.func)
        dotted = _dotted(node.func)

        # RT-3 / RT-2: un-sandboxed execution
        if name in _EXEC_CALLS and any(m in dotted for m in _EXEC_MODULES):
            sev = "crit" if _has_kw(node, "shell", True) else "high"
            self._add("RT-3", sev, node, f"command execution {dotted}() — candidate: do tools run un-isolated? confirm the sandbox dynamically")
        if name in ("eval", "exec"):
            self._add("RT-3", "crit", node, f"{name}() dynamic execution — candidate: can the executed content be influenced by untrusted input?")

        # RT-7: dynamic import / download-and-run
        if name in _DYNIMPORT:
            self._add("RT-7", "high", node, "dynamic import — candidate: does the import name come from an external source / skill marketplace (supply chain)?")

        # RT-8: printing / logging suspected credentials
        if name in ("print", "info", "debug", "warning", "log") and _args_hint(node, _SECRET_HINTS):
            self._add("RT-8", "high", node, "suspected credential/env var written to a log/output — candidate: data exfiltration")

        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        lname = node.name.lower()
        body_src = " ".join(self.lines[node.lineno - 1: (node.end_lineno or node.lineno)]).lower()

        # RT-6: functions that write into persistent memory
        if any(h in lname for h in ("memory", "remember", "curate", "persist", "profile")) and (".write" in body_src or "write_text" in body_src or "open(" in body_src or "_write" in body_src):
            self._add("RT-6", "crit", node, f"function {node.name}() appears to write content into persistent memory — candidate: is the source trusted / provenance-checked (memory poisoning)?")

        # RT-GUARD: signature / keyword-list only filtering
        if any(h in lname for h in ("filter", "sanitiz", "scan", "guard", "block", "threat", "detect")) and any(k in body_src for k in ("re.search", "re.match", "pattern", "blocklist", "keyword", "in content", "for pat")):
            self._add("RT-GUARD", "high", node, f"function {node.name}() appears to block by signature/keyword — candidate: a semantic injection (disguised as benign content) may bypass it")

        # RT-1: external content concatenated into a prompt
        if any(h in lname for h in ("prompt", "system", "instruction")) and any(u in body_src for u in _UNTRUSTED_HINTS):
            self._add("RT-1", "high", node, f"function {node.name}() appears to concatenate external content into a prompt/instruction — candidate: prompt injection")

        self.generic_visit(node)


def _call_name(func) -> str:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def _dotted(func) -> str:
    parts = []
    cur = func
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    return ".".join(reversed(parts))


def _has_kw(node: ast.Call, key, val=True) -> bool:
    for kw in node.keywords:
        if kw.arg == key and isinstance(kw.value, ast.Constant) and kw.value.value == val:
            return True
    return False


def _args_hint(node: ast.Call, hints) -> bool:
    try:
        blob = ast.dump(node).lower()
    except Exception:
        return False
    return any(h in blob for h in hints)


def _analyze_python(path, relpath) -> list[Candidate]:
    try:
        src = open(path, "r", errors="ignore").read()
        tree = ast.parse(src)
    except (SyntaxError, OSError):
        return []
    v = _PyVisitor(relpath, src.splitlines())
    v.visit(tree)
    return v.out


# ── Non-Python: line-level regex (coarse) ─────────────────────────────────
_LINE_RULES = [
    ("RT-3", "high", re.compile(r"child_process|exec\(|execSync|spawn\("), "command execution — candidate: un-sandboxed execution"),
    ("RT-3", "crit", re.compile(r"\beval\("), "eval() — candidate: dynamic execution of untrusted content"),
    ("RT-8", "high", re.compile(r"(?i)console\.(log|info)\([^)]*(api[_-]?key|token|secret|password)"), "suspected credential written to a log — candidate: exfiltration"),
    ("RT-6", "high", re.compile(r"(?i)(USER\.md|MEMORY\.md|/memories/)"), "touches a persistent-memory file — candidate: memory poisoning"),
]


def _analyze_lines(path, relpath) -> list[Candidate]:
    out = []
    try:
        lines = open(path, "r", errors="ignore").read().splitlines()
    except OSError:
        return out
    for i, line in enumerate(lines, 1):
        for rt, sev, rx, why in _LINE_RULES:
            if rx.search(line):
                out.append(Candidate(rt, sev, relpath, i, why, line.strip()[:160]))
    return out


# ── TS/JS: real AST via the Node analyzer (falls back to regex) ────────────
_JS_EXT = (".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs")


def _analyze_js_ast(root: str) -> list[Candidate] | None:
    """Run the Node/TypeScript AST analyzer (scanner/js/analyze.mjs) over the whole tree.

    Returns a list of candidates, or None when Node or the analyzer/its `typescript` dependency
    is unavailable — so the caller can fall back to coarse line-regex and the Python core stays
    zero-dependency.
    """
    node = shutil.which("node")
    if not node:
        return None
    analyzer = os.path.join(os.path.dirname(__file__), "..", "js", "analyze.mjs")
    if not os.path.exists(analyzer):
        return None
    try:
        p = subprocess.run([node, analyzer, "--source", root, "--json"],
                           capture_output=True, text=True, timeout=120)
    except Exception:  # noqa: BLE001
        return None
    if p.returncode != 0 or not p.stdout.strip():
        return None  # e.g. `typescript` not installed → fall back to regex
    try:
        data = json.loads(p.stdout)
    except ValueError:
        return None
    return [
        Candidate(c.get("rt", ""), c.get("severity", "med"), c.get("file", ""),
                  int(c.get("line", 0)), c.get("why", ""), c.get("snippet", ""))
        for c in data.get("candidates", [])
    ]


def analyze_source(root: str) -> list[Candidate]:
    out: list[Candidate] = []
    js_files: list[str] = []
    for path in _src_files(root):
        rel = _rel(root, path)
        if path.endswith(".py"):
            out.extend(_analyze_python(path, rel))
        else:
            js_files.append(path)

    if js_files:
        js_cands = _analyze_js_ast(root)
        if js_cands is None:                       # Node/typescript unavailable → coarse fallback
            for path in js_files:
                out.extend(_analyze_lines(path, _rel(root, path)))
        else:
            out.extend(js_cands)

    # stable sort: severity → RT → file
    order = {"crit": 0, "high": 1, "med": 2}
    out.sort(key=lambda c: (order.get(c.severity, 3), c.rt, c.file, c.line))
    return out


def to_dict(cands: list[Candidate], root: str) -> dict:
    return {
        "engine": "TrustShell static v0",
        "note": "candidate paths (triage) — dynamic red-team must confirm/refute. candidate != vulnerability.",
        "source": root,
        "count": len(cands),
        "candidates": [asdict(c) for c in cands],
    }
