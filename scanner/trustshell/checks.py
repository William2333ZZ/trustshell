"""检查项注册表 —— 对应《信壳开放基线 v0.1》里标注"可自动"的项。

每条检查:id / 分类 / 标题 / 严重度 / 需要的输入(target 或 path)/ 探针函数。
严重度权重与评分模型见 scoring.py。
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from . import probes

CRIT, HIGH, MED = "crit", "high", "med"


@dataclass
class Check:
    id: str
    category: str
    title: str
    severity: str
    needs: str                      # "target"(网络) 或 "path"(文件系统)
    probe: Callable[[str], probes.Result]


# 顺序即报告展示顺序
CHECKS = [
    # A 暴露面与网络
    Check("A-01", "暴露面与网络", "管理控制台默认只绑本机", CRIT, "target", probes.a01_bind_localhost),
    Check("A-02", "暴露面与网络", "无默认开放的公网端口", CRIT, "target", probes.a02_no_public_ports),
    Check("A-03", "暴露面与网络", "对外接口强制加密(TLS)", HIGH, "target", probes.a03_tls),
    Check("A-04", "暴露面与网络", "生产环境关闭调试端口", HIGH, "target", probes.a04_no_debug),
    Check("A-05", "暴露面与网络", "抵御 DNS-rebinding / 跨源", CRIT, "target", probes.a05_origin_validation),
    # B 认证与访问控制
    Check("B-02", "认证与访问控制", "敏感端点需鉴权", CRIT, "target", probes.b02_sensitive_auth),
    # C 技能包与供应链
    Check("C-04", "技能包与供应链", "依赖有完整性校验(锁文件)", MED, "path", probes.c04_lockfile),
    # E 凭证管理
    Check("E-01", "凭证管理", "凭证非明文存储", CRIT, "path", probes.e01_plaintext_creds),
    Check("E-02", "凭证管理", "凭证不写入日志", HIGH, "path", probes.e02_creds_in_logs),
    # H 审计与取证
    Check("H-04", "审计与取证", "存在可导出的日志", MED, "path", probes.h04_audit_log),
]


def checks_for(has_target: bool, has_path: bool):
    out = []
    for c in CHECKS:
        if c.needs == "target" and has_target:
            out.append(c)
        elif c.needs == "path" and has_path:
            out.append(c)
    return out
