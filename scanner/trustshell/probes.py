"""Detection probes — one function per "auto-testable" baseline check.

Contract: each probe returns Result(status, evidence).
  status: "pass" | "fail" | "warn" | "skip"
  evidence: a one-line, human-readable rationale

Design principle: read-only, non-destructive probing only; when unsure, return skip/warn rather
than misreport a pass. This is v0.1 — checks are heuristic and iterate after real-world use.
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


# ---- Shared utilities ----

_LOOPBACK = {"127.0.0.1", "::1", "localhost", "0.0.0.0"}
_TIMEOUT = 4

# Management/API ports commonly used by agents
COMMON_AGENT_PORTS = [80, 443, 3000, 3456, 5000, 7860, 8000, 8080, 8188, 8443, 11434, 18000]

# Sensitive endpoints: if reachable without auth, treated as unauthorized access
SENSITIVE_PATHS = [
    "/api/config", "/api/settings", "/api/skills", "/api/credentials",
    "/api/agents", "/api/execute", "/api/run", "/admin", "/api/logs",
    "/settings", "/config", "/api/v1/config", "/api/tools",
]

# Suspected debug/dev endpoints
DEBUG_PATHS = ["/debug", "/__debug__", "/api/debug", "/dev", "/_next/webpack-hmr", "/graphql"]

# Common shapes of plaintext secrets (heuristic)
SECRET_PATTERNS = [
    re.compile(r"(?i)\b(api[_-]?key|secret|token|password|passwd|bearer)\b\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{12,}"),
    re.compile(r"sk-[A-Za-z0-9]{20,}"),                 # OpenAI-style
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),          # GitHub token
    re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\."),  # JWT
]


def _host_port(target: str):
    u = urlparse(target if "://" in target else "http://" + target)
    host = u.hostname or "127.0.0.1"
    port = u.port or (443 if u.scheme == "https" else 80)
    return u.scheme, host, port


def _http(method: str, url: str, headers=None, timeout=_TIMEOUT):
    """Return (status_code, content_type, body_snippet) or raise. Read-only; no side effects."""
    req = urllib.request.Request(url, method=method, headers=headers or {})
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # don't abort probing on cert failure; certs are judged in A-03
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            ct = r.headers.get("content-type", "")
            return r.status, ct, r.read(2048).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("content-type", "") if e.headers else "", ""
    except Exception as e:  # noqa: BLE001
        raise e


def _is_data_response(content_type: str) -> bool:
    """Is the response "data/API" (not an HTML page shell)? Only a data response (json/xml/plain
    data) served without auth counts as a real sensitive-endpoint exposure; a text/html response is
    usually just a login page / SPA shell and is not unauthorized data access."""
    ct = (content_type or "").lower()
    if "html" in ct:
        return False
    # conservative: only clearly structured data (json/xml) counts as data-API exposure, to avoid false positives
    return ("json" in ct) or ("xml" in ct)


# ---- Network probes (need --target) ----

def a01_bind_localhost(target: str) -> Result:
    """A-01 Management console binds to localhost by default.
    If the target host is non-loopback and reachable, the service is externally reachable
    (violating localhost-only binding)."""
    _, host, port = _host_port(target)
    if host in _LOOPBACK:
        return Result("skip", "target is a localhost address; can't judge external exposure — retest via a LAN/public IP")
    try:
        with socket.create_connection((host, port), timeout=_TIMEOUT):
            return Result("fail", f"service reachable at non-local address {host}:{port} — not localhost-only by default")
    except OSError:
        return Result("pass", f"non-local address {host}:{port} unreachable — consistent with localhost-only")


def a02_no_public_ports(target: str) -> Result:
    """A-02 No public ports open by default. Scans common agent ports."""
    _, host, _ = _host_port(target)
    open_ports = []
    for p in COMMON_AGENT_PORTS:
        try:
            with socket.create_connection((host, p), timeout=1.5):
                open_ports.append(p)
        except OSError:
            pass
    if host in _LOOPBACK:
        return Result("skip", f"local open ports {open_ports or 'none'}; only meaningful when retested on an external interface")
    if len(open_ports) <= 1:
        return Result("pass", f"only {open_ports or 'no'} port(s) open externally")
    return Result("fail", f"multiple ports open externally {open_ports} — large attack surface")


def a03_tls(target: str) -> Result:
    """A-03 External interfaces enforce encryption."""
    scheme, host, port = _host_port(target)
    if host in _LOOPBACK:
        return Result("skip", "localhost traffic may be exempt from TLS; verify external interfaces separately")
    if scheme != "https":
        return Result("fail", "external interface uses plaintext HTTP — credentials and commands can be eavesdropped")
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                ss.getpeercert()
        return Result("pass", "external interface uses HTTPS with a valid certificate")
    except ssl.SSLError as e:
        return Result("fail", f"invalid TLS certificate: {e}")
    except Exception as e:  # noqa: BLE001
        return Result("warn", f"TLS check error: {e}")


def a04_no_debug(target: str) -> Result:
    """A-04 Debug ports disabled in production."""
    found = []
    for path in DEBUG_PATHS:
        try:
            code, _ct, _ = _http("GET", target.rstrip("/") + path)
            if code and code < 400:
                found.append(f"{path}({code})")
        except Exception:  # noqa: BLE001
            pass
    if found:
        return Result("fail", f"suspected exposed debug/dev endpoints: {', '.join(found)}")
    return Result("pass", "no open debug endpoints found")


def a05_origin_validation(target: str) -> Result:
    """A-05 Resists DNS-rebinding / cross-origin. Requesting sensitive endpoints with a forged
    Origin/Host should be rejected."""
    evil = {"Origin": "http://evil.example", "Host": "evil.example"}
    tested = accepted = 0
    for path in SENSITIVE_PATHS[:6]:
        url = target.rstrip("/") + path
        try:
            code, ct, _ = _http("GET", url, headers=evil)
            tested += 1
            # only a data response that accepts a forged origin counts as cross-origin data leakage; an HTML shell does not
            if code and code < 400 and _is_data_response(ct):
                accepted += 1
        except Exception:  # noqa: BLE001
            pass
    if tested == 0:
        return Result("skip", "no testable sensitive-endpoint responses")
    if accepted > 0:
        return Result("fail", f"{accepted}/{tested} data endpoints accepted a forged Origin/Host — cross-origin hijack risk")
    return Result("pass", "sensitive endpoints rejected the forged Origin/Host (or returned only a page shell)")


def b02_sensitive_auth(target: str) -> Result:
    """B-02 Sensitive endpoints require authentication. Accessing them without credentials should
    return 401/403."""
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
            if _is_data_response(ct):           # data/API served without auth = real exposure
                exposed.append(f"{path}({code})")
            elif "html" in (ct or "").lower():  # HTML page shell = normal (login page / SPA), no penalty
                page_only.append(path)
    if probed == 0:
        return Result("skip", "target did not respond to any probed endpoint")
    if exposed:
        return Result("fail", f"the following data endpoints are accessible without auth: {', '.join(exposed[:6])}")
    note = "all probed sensitive data endpoints require authentication"
    if page_only:
        note += f" (/{', '.join(p.strip('/') for p in page_only[:3])} etc. return only a page shell, which is normal)"
    return Result("pass", note)


# ---- Filesystem probes (need --path) ----

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
    """C-04 Dependencies have integrity checks (lockfile)."""
    locks = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
             "Pipfile.lock", "requirements.txt", "go.sum", "Cargo.lock"}
    found = [f for f in os.listdir(path) if f in locks] if os.path.isdir(path) else []
    if found:
        return Result("pass", f"dependency lockfile(s) found: {', '.join(found)}")
    return Result("warn", "no dependency lockfile in the root — dependencies may be unpinned")


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
    """E-01 Credentials stored encrypted (inverse: plaintext secrets in config → fail)."""
    cfg_exts = (".env", ".json", ".yaml", ".yml", ".ini", ".toml", ".conf", ".cfg", ".txt")
    hits = _scan_secrets(_walk_files(path, cfg_exts))
    if hits:
        return Result("fail", f"config files appear to contain plaintext credentials: {', '.join(hits[:5])}")
    return Result("pass", "no plaintext-credential signatures found in config files")


def e02_creds_in_logs(path: str) -> Result:
    """E-02 Credentials not written to logs."""
    log_files = set(_walk_files(path, (".log",)))
    log_files |= {f for f in _walk_files(path, None) if "/logs/" in f}
    log_files = sorted(log_files)[:400]
    hits = sorted(set(_scan_secrets(log_files)))
    if not log_files:
        return Result("skip", "no log files found")
    if hits:
        return Result("fail", f"logs appear to contain plaintext credentials: {', '.join(hits[:5])}")
    return Result("pass", "no plaintext-credential signatures found in logs")


def h04_audit_log(path: str) -> Result:
    """H-04 Logs exportable for incident investigation (inverse: no logs at all → fail)."""
    has_log = any(True for _ in _walk_files(path, (".log",)))
    has_logdir = any(os.path.isdir(os.path.join(path, d)) for d in ("logs", "log", "audit"))
    if has_log or has_logdir:
        return Result("pass", "log/audit directory found")
    return Result("fail", "no logs found — incidents cannot be traced")
