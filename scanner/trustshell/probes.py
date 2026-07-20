"""检测探针 —— 每个函数对应基线里一个"可自动"检查项。

约定:每个探针返回 Result(status, evidence)。
  status: "pass" | "fail" | "warn" | "skip"
  evidence: 人类可读的一句话依据

设计原则:只做只读、非破坏性的探测;拿不准就返回 skip/warn,不误判为 pass。
这是 v0.1,检查为启发式,实测后迭代。
"""
from __future__ import annotations

import os
import re
import socket
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass
class Result:
    status: str          # pass | fail | warn | skip
    evidence: str


# ---- 通用工具 ----

_LOOPBACK = {"127.0.0.1", "::1", "localhost", "0.0.0.0"}
_TIMEOUT = 4

# 各家 Agent 常见的管理/API 端口
COMMON_AGENT_PORTS = [80, 443, 3000, 3456, 5000, 7860, 8000, 8080, 8188, 8443, 11434, 18000]

# 敏感端点:这些若无需认证即可访问,视为越权可达
SENSITIVE_PATHS = [
    "/api/config", "/api/settings", "/api/skills", "/api/credentials",
    "/api/agents", "/api/execute", "/api/run", "/admin", "/api/logs",
    "/settings", "/config", "/api/v1/config", "/api/tools",
]

# 疑似调试/开发端点
DEBUG_PATHS = ["/debug", "/__debug__", "/api/debug", "/dev", "/_next/webpack-hmr", "/graphql"]

# 明文密钥的常见形态(启发式)
SECRET_PATTERNS = [
    re.compile(r"(?i)\b(api[_-]?key|secret|token|password|passwd|bearer)\b\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{12,}"),
    re.compile(r"sk-[A-Za-z0-9]{20,}"),                 # OpenAI 风格
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),          # GitHub token
    re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\."),  # JWT
]


def _host_port(target: str):
    u = urlparse(target if "://" in target else "http://" + target)
    host = u.hostname or "127.0.0.1"
    port = u.port or (443 if u.scheme == "https" else 80)
    return u.scheme, host, port


def _http(method: str, url: str, headers=None, timeout=_TIMEOUT):
    """返回 (status_code, content_type, body_snippet) 或抛异常。不跟随到危险行为,只读。"""
    req = urllib.request.Request(url, method=method, headers=headers or {})
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # 探测阶段不因证书失败中断,证书单独在 A-03 判
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            ct = r.headers.get("content-type", "")
            return r.status, ct, r.read(2048).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("content-type", "") if e.headers else "", ""
    except Exception as e:  # noqa: BLE001
        raise e


def _is_data_response(content_type: str) -> bool:
    """判断响应是否为"数据/接口"(而非 HTML 页面外壳)。
    只有返回数据(json/xml/纯文本数据)且无需认证,才算真的敏感端点暴露;
    返回 text/html 通常只是登录页/SPA 外壳,不构成未授权数据访问。"""
    ct = (content_type or "").lower()
    if "html" in ct:
        return False
    # 保守:只有明确是结构化数据(json/xml)才算数据接口暴露,尽量避免假阳性
    return ("json" in ct) or ("xml" in ct)


# ---- 网络探针(需要 --target) ----

def a01_bind_localhost(target: str) -> Result:
    """A-01 管理控制台默认只绑本机。
    若目标 host 是非环回地址且能连通,说明服务对外可达(违背默认只绑本机)。"""
    _, host, port = _host_port(target)
    if host in _LOOPBACK:
        return Result("skip", "目标即本机地址,无法判断是否对外暴露;请用局域网/公网 IP 复测")
    try:
        with socket.create_connection((host, port), timeout=_TIMEOUT):
            return Result("fail", f"服务在非本机地址 {host}:{port} 可连通,未做到默认只绑本机")
    except OSError:
        return Result("pass", f"非本机地址 {host}:{port} 不可达,符合只绑本机")


def a02_no_public_ports(target: str) -> Result:
    """A-02 无默认开放的公网端口。扫描常见 Agent 端口。"""
    _, host, _ = _host_port(target)
    open_ports = []
    for p in COMMON_AGENT_PORTS:
        try:
            with socket.create_connection((host, p), timeout=1.5):
                open_ports.append(p)
        except OSError:
            pass
    if host in _LOOPBACK:
        return Result("skip", f"本机开放端口 {open_ports or '无'};需在对外网卡复测才有意义")
    if len(open_ports) <= 1:
        return Result("pass", f"对外仅 {open_ports or '无'} 端口开放")
    return Result("fail", f"对外开放多个端口 {open_ports},攻击面偏大")


def a03_tls(target: str) -> Result:
    """A-03 对外接口强制加密。"""
    scheme, host, port = _host_port(target)
    if host in _LOOPBACK:
        return Result("skip", "本机通信可豁免 TLS;对外接口需单独核验")
    if scheme != "https":
        return Result("fail", "对外接口使用明文 HTTP,凭证与指令可被窃听")
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                ss.getpeercert()
        return Result("pass", "对外使用 HTTPS 且证书有效")
    except ssl.SSLError as e:
        return Result("fail", f"TLS 证书无效:{e}")
    except Exception as e:  # noqa: BLE001
        return Result("warn", f"TLS 检测异常:{e}")


def a04_no_debug(target: str) -> Result:
    """A-04 生产环境关闭调试端口。"""
    found = []
    for path in DEBUG_PATHS:
        try:
            code, _ct, _ = _http("GET", target.rstrip("/") + path)
            if code and code < 400:
                found.append(f"{path}({code})")
        except Exception:  # noqa: BLE001
            pass
    if found:
        return Result("fail", f"疑似暴露调试/开发端点:{', '.join(found)}")
    return Result("pass", "未发现开放的调试端点")


def a05_origin_validation(target: str) -> Result:
    """A-05 抵御 DNS-rebinding / 跨源。带伪造 Origin/Host 请求敏感端点,应被拒。"""
    evil = {"Origin": "http://evil.example", "Host": "evil.example"}
    tested = accepted = 0
    for path in SENSITIVE_PATHS[:6]:
        url = target.rstrip("/") + path
        try:
            code, ct, _ = _http("GET", url, headers=evil)
            tested += 1
            # 只有返回"数据"且接受伪造来源才算跨源数据泄露;返回 HTML 页面外壳不算
            if code and code < 400 and _is_data_response(ct):
                accepted += 1
        except Exception:  # noqa: BLE001
            pass
    if tested == 0:
        return Result("skip", "无可测的敏感端点响应")
    if accepted > 0:
        return Result("fail", f"{accepted}/{tested} 个数据端点接受了伪造 Origin/Host,存在跨源劫持风险")
    return Result("pass", "敏感端点拒绝了伪造 Origin/Host(或仅返回页面外壳)")


def b02_sensitive_auth(target: str) -> Result:
    """B-02 敏感端点需鉴权。无凭证访问敏感端点,应返回 401/403。"""
    exposed = []
    page_only = []
    probed = 0
    for path in SENSITIVE_PATHS:
        url = target.rstrip("/") + path
        try:
            code, ct, _ = _http("GET", url)
        except Exception:  # noqa: BLE001
            continue
        probed += 1
        if code and code < 400:
            if _is_data_response(ct):           # 返回数据/接口且无需认证 = 真的暴露
                exposed.append(f"{path}({code})")
            elif "html" in (ct or "").lower():  # 返回 HTML 页面外壳 = 正常(登录页/SPA),不判罚
                page_only.append(path)
    if probed == 0:
        return Result("skip", "目标未响应任何探测端点")
    if exposed:
        return Result("fail", f"以下数据端点无需认证即可访问:{', '.join(exposed[:6])}")
    note = "已探测的敏感数据端点均要求认证"
    if page_only:
        note += f"(/{', '.join(p.strip('/') for p in page_only[:3])} 等仅返回页面外壳,属正常)"
    return Result("pass", note)


# ---- 文件系统探针(需要 --path) ----

def _walk_files(root: str, exts, max_files=4000):
    for base, _dirs, files in os.walk(root):
        if any(seg in base for seg in ("/.git", "/node_modules", "/venv", "/.venv", "/__pycache__")):
            continue
        for f in files:
            if exts is None or any(f.endswith(e) for e in exts):
                yield os.path.join(base, f)
                max_files -= 1
                if max_files <= 0:
                    return


def c04_lockfile(path: str) -> Result:
    """C-04 依赖有完整性校验(锁文件)。"""
    locks = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
             "Pipfile.lock", "requirements.txt", "go.sum", "Cargo.lock"}
    found = [f for f in os.listdir(path) if f in locks] if os.path.isdir(path) else []
    if found:
        return Result("pass", f"发现依赖锁文件:{', '.join(found)}")
    return Result("warn", "未在根目录发现依赖锁文件,依赖可能未固定版本")


def _scan_secrets(files):
    hits = []
    for fp in files:
        try:
            with open(fp, "r", errors="ignore") as fh:
                text = fh.read(200_000)
        except OSError:
            continue
        for pat in SECRET_PATTERNS:
            if pat.search(text):
                hits.append(os.path.relpath(fp))
                break
    return hits


def e01_plaintext_creds(path: str) -> Result:
    """E-01 凭证加密存储(反向:配置里出现明文密钥即 fail)。"""
    cfg_exts = (".env", ".json", ".yaml", ".yml", ".ini", ".toml", ".conf", ".cfg", ".txt")
    hits = _scan_secrets(_walk_files(path, cfg_exts))
    if hits:
        return Result("fail", f"配置文件疑似含明文凭证:{', '.join(hits[:5])}")
    return Result("pass", "配置文件未发现明文凭证特征")


def e02_creds_in_logs(path: str) -> Result:
    """E-02 凭证不写入日志。"""
    log_files = set(_walk_files(path, (".log",)))
    log_files |= {f for f in _walk_files(path, None) if "/logs/" in f}
    log_files = sorted(log_files)[:400]
    hits = sorted(set(_scan_secrets(log_files)))
    if not log_files:
        return Result("skip", "未发现日志文件")
    if hits:
        return Result("fail", f"日志疑似含明文凭证:{', '.join(hits[:5])}")
    return Result("pass", "日志未发现明文凭证特征")


def h04_audit_log(path: str) -> Result:
    """H-04 日志可导出供事故调查(反向:连日志都没有则 fail)。"""
    has_log = any(True for _ in _walk_files(path, (".log",)))
    has_logdir = any(os.path.isdir(os.path.join(path, d)) for d in ("logs", "log", "audit"))
    if has_log or has_logdir:
        return Result("pass", "发现日志/审计目录")
    return Result("fail", "未发现任何日志,事故无法追溯")
