"""TrustShell 静态引擎 v0 —— Agent 源码"可疑路径"分级(动静互证的静态一侧).

设计原则(诚实第一):
  这不是"判决器",是"分诊器"。它标出**候选**可疑路径——不可信内容可能
  流进危险落点、只靠签名的防护、缺失的检查——交给动态红队去**证实或证伪**。
  一个候选不等于一个漏洞;真假的裁判是"真打穿",不是这里的匹配。

零依赖(仅标准库)。Python 文件走 AST(准),其它文件走行级正则(粗)。
映射到攻击手册 RT-1…RT-9。
"""
from __future__ import annotations

import ast
import json
import os
import re
from dataclasses import dataclass, asdict


@dataclass
class Candidate:
    rt: str          # RT-1 … RT-9
    severity: str    # crit | high | med
    file: str
    line: int
    why: str
    snippet: str


# ── RT 分类说明(用于报告表头)────────────────────────────────────────────
RT_LABEL = {
    "RT-1": "提示词注入 / prompt injection",
    "RT-2": "工具 / 动作滥用",
    "RT-3": "沙箱 / 隔离逃逸",
    "RT-6": "记忆 / 上下文投毒",
    "RT-7": "供应链(技能/插件/依赖)",
    "RT-8": "数据外泄 / 凭证",
    "RT-GUARD": "仅签名防护(易被绕过)",
}

# ── 危险落点(sink)与信号 ─────────────────────────────────────────────────
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
            if f.endswith((".py", ".js", ".ts", ".tsx", ".mjs")):
                yield os.path.join(base, f)
                max_files -= 1
                if max_files <= 0:
                    return


def _rel(root, path):
    try:
        return os.path.relpath(path, root)
    except ValueError:
        return path


# ── Python: AST 分析 ─────────────────────────────────────────────────────
class _PyVisitor(ast.NodeVisitor):
    def __init__(self, relpath, lines):
        self.relpath = relpath
        self.lines = lines
        self.out: list[Candidate] = []
        # 记录函数名,用于识别"记忆写入""签名过滤"这类函数
        self._func_writes_memory = False

    def _snip(self, lineno):
        i = lineno - 1
        return self.lines[i].strip()[:160] if 0 <= i < len(self.lines) else ""

    def _add(self, rt, sev, node, why):
        self.out.append(Candidate(rt, sev, self.relpath, getattr(node, "lineno", 0), why, self._snip(getattr(node, "lineno", 0))))

    def visit_Call(self, node: ast.Call):
        name = _call_name(node.func)
        dotted = _dotted(node.func)

        # RT-3 / RT-2: 未沙箱执行
        if name in _EXEC_CALLS and any(m in dotted for m in _EXEC_MODULES):
            sev = "crit" if _has_kw(node, "shell", True) else "high"
            self._add("RT-3", sev, node, f"命令执行 {dotted}() —— 候选:工具是否在无隔离环境跑?动态验证沙箱是否生效")
        if name in ("eval", "exec"):
            self._add("RT-3", "crit", node, f"{name}() 动态执行 —— 候选:被执行内容是否可被不可信输入影响?")

        # RT-7: 动态导入 / 下载执行
        if name in _DYNIMPORT:
            self._add("RT-7", "high", node, "动态导入 —— 候选:导入名是否来自外部/技能市场(供应链)?")

        # RT-8: 打印/记录疑似凭证
        if name in ("print", "info", "debug", "warning", "log") and _args_hint(node, _SECRET_HINTS):
            self._add("RT-8", "high", node, "疑似把凭证/环境变量写入日志/输出 —— 候选:数据外泄")

        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        lname = node.name.lower()
        body_src = " ".join(self.lines[node.lineno - 1: (node.end_lineno or node.lineno)]).lower()

        # RT-6: 写入持久记忆的函数
        if any(h in lname for h in ("memory", "remember", "curate", "persist", "profile")) and (".write" in body_src or "write_text" in body_src or "open(" in body_src or "_write" in body_src):
            self._add("RT-6", "crit", node, f"函数 {node.name}() 疑似把内容写入持久记忆 —— 候选:是否对来源做信任/来源校验(memory poisoning)?")

        # RT-GUARD: 仅靠签名/关键词列表的过滤
        if any(h in lname for h in ("filter", "sanitiz", "scan", "guard", "block", "threat", "detect")) and any(k in body_src for k in ("re.search", "re.match", "pattern", "blocklist", "keyword", "in content", "for pat")):
            self._add("RT-GUARD", "high", node, f"函数 {node.name}() 疑似基于签名/关键词做拦截 —— 候选:语义型注入(伪装成正常内容)可能绕过")

        # RT-1: 把外部内容拼进 prompt
        if any(h in lname for h in ("prompt", "system", "instruction")) and any(u in body_src for u in _UNTRUSTED_HINTS):
            self._add("RT-1", "high", node, f"函数 {node.name}() 疑似把外部内容拼进提示/指令 —— 候选:提示词注入")

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


# ── 非 Python:行级正则(粗)─────────────────────────────────────────────
_LINE_RULES = [
    ("RT-3", "high", re.compile(r"child_process|exec\(|execSync|spawn\("), "命令执行 —— 候选:未沙箱执行"),
    ("RT-3", "crit", re.compile(r"\beval\("), "eval() —— 候选:动态执行不可信内容"),
    ("RT-8", "high", re.compile(r"(?i)console\.(log|info)\([^)]*(api[_-]?key|token|secret|password)"), "疑似把凭证写入日志 —— 候选:外泄"),
    ("RT-6", "high", re.compile(r"(?i)(USER\.md|MEMORY\.md|/memories/)"), "触及持久记忆文件 —— 候选:memory poisoning"),
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


def analyze_source(root: str) -> list[Candidate]:
    out: list[Candidate] = []
    for path in _src_files(root):
        rel = _rel(root, path)
        if path.endswith(".py"):
            out.extend(_analyze_python(path, rel))
        else:
            out.extend(_analyze_lines(path, rel))
    # 稳定排序:严重度 → RT → 文件
    order = {"crit": 0, "high": 1, "med": 2}
    out.sort(key=lambda c: (order.get(c.severity, 3), c.rt, c.file, c.line))
    return out


def to_dict(cands: list[Candidate], root: str) -> dict:
    return {
        "engine": "TrustShell static v0",
        "note": "候选路径(triage),需动态红队证实/证伪。候选≠漏洞。",
        "source": root,
        "count": len(cands),
        "candidates": [asdict(c) for c in cands],
    }
