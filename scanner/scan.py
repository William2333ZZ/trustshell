#!/usr/bin/env python3
"""TrustShell 端侧 Agent 安全扫描器 —— 命令行入口.

用法:
  python3 scan.py --target http://127.0.0.1:3000          # 网络检查
  python3 scan.py --path  /path/to/agent                  # 文件系统检查
  python3 scan.py --target http://host:3000 --path ./box  # 两者都跑
  python3 scan.py --target ... --json                     # 输出 JSON

零依赖(仅 Python 标准库)。这是《信壳开放基线 v0.1》的可执行版本。
"""
from __future__ import annotations

import argparse
import json
import sys

from trustshell import __baseline__, __version__, checks as C, scoring

# ANSI 颜色(非 TTY 自动关闭)
def _c(code, s, on):
    return f"\033[{code}m{s}\033[0m" if on else s

STATUS_STYLE = {
    "pass": ("32", "通过"),
    "fail": ("31", "未过"),
    "warn": ("33", "注意"),
    "skip": ("90", "跳过"),
}
SEV_LABEL = {"crit": "致命", "high": "高", "med": "中"}
GRADE_COLOR = {"A": "32", "B": "36", "C": "33", "D": "31"}


def run(target, path):
    checks = C.checks_for(has_target=bool(target), has_path=bool(path))
    findings = []
    for chk in checks:
        arg = target if chk.needs == "target" else path
        try:
            res = chk.probe(arg)
        except Exception as e:  # noqa: BLE001
            from trustshell.probes import Result
            res = Result("skip", f"探针异常:{e}")
        findings.append((chk, res))
    return findings


def to_dict(findings, summary, target, path):
    return {
        "baseline": __baseline__,
        "scanner_version": __version__,
        "target": target,
        "path": path,
        "summary": summary,
        "findings": [
            {"id": c.id, "category": c.category, "title": c.title,
             "severity": c.severity, "status": r.status, "evidence": r.evidence}
            for c, r in findings
        ],
    }


def print_report(findings, summary, target, path, color):
    print()
    print(_c("1", f"  {__baseline__} · 扫描器 v{__version__}", color))
    if target:
        print(f"  目标: {target}")
    if path:
        print(f"  目录: {path}")
    print("  " + "─" * 56)

    last_cat = None
    for c, r in findings:
        if c.category != last_cat:
            print(f"\n  【{c.category}】")
            last_cat = c.category
        code, label = STATUS_STYLE[r.status]
        tag = _c(code, f"[{label}]", color)
        sev = _c("90", f"({SEV_LABEL[c.severity]})", color)
        print(f"    {tag} {c.id} {c.title} {sev}")
        print(_c("90", f"          └ {r.evidence}", color))

    BASELINE_TOTAL = 42
    g = summary["grade"]
    evaluated = summary["counts"]["pass"] + summary["counts"]["fail"]
    partial = evaluated < BASELINE_TOTAL * 0.6   # 评估不足 60% = 部分扫描,不给完整评级

    print("\n  " + "─" * 56)
    grade_str = _c(GRADE_COLOR[g], f" {g} ", color)
    if partial:
        print(f"  部分评级(仅供参考): [{grade_str}]  —— 仅基于已评估项")
        print(_c("33", f"  ⚠ 这不是完整安全评级:只评估了 {evaluated}/{BASELINE_TOTAL} 项,"
                       f"其余 {BASELINE_TOTAL - evaluated} 项(注入/沙箱/高危动作/供应链/审计等)未测。", color))
    else:
        print(f"  评级: [{grade_str}]  {scoring.GRADE_BLURB[g]}")
    print(f"  覆盖: 已评估 {evaluated} / {BASELINE_TOTAL} 项   加权通过率(仅已评估项): "
          f"{summary['weighted_pass_ratio']*100:.0f}%")
    print(f"  明细: 通过 {summary['counts']['pass']} / 未过 {summary['counts']['fail']} / "
          f"注意 {summary['counts']['warn']} / 跳过 {summary['counts']['skip']}")
    if summary["vetoed"]:
        print("  " + _c("31", f"⚠ 致命项未过 {summary['critical_failures']} — 一票否决,直接判 D", color))
    print()
    print(_c("90", "  提示: 自动扫描只覆盖网络/文件类可自动项。手动项(提示词注入、", color))
    print(_c("90", "        工具沙箱、高危动作确认、通道注入、供应链、审计)必须人工红队评估——", color))
    print(_c("90", "        自动全过 ≠ 安全,只代表没踩到这几脚明坑。", color))
    print()


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="TrustShell 端侧 Agent 安全扫描器(《信壳开放基线 v0.1》可执行版)")
    ap.add_argument("--target", help="Agent 管理面地址,如 http://127.0.0.1:3000")
    ap.add_argument("--path", help="Agent 安装/工作目录,用于文件系统检查")
    ap.add_argument("--json", action="store_true", help="以 JSON 输出(便于红黑榜/CI 集成)")
    ap.add_argument("--no-color", action="store_true", help="关闭彩色输出")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = ap.parse_args(argv)

    if not args.target and not args.path:
        ap.error("至少提供 --target 或 --path 之一")

    findings = run(args.target, args.path)
    summary = scoring.grade(findings)

    if args.json:
        print(json.dumps(to_dict(findings, summary, args.target, args.path),
                         ensure_ascii=False, indent=2))
    else:
        color = sys.stdout.isatty() and not args.no_color
        print_report(findings, summary, args.target, args.path, color)

    # 退出码:D → 2,C/B → 1,A → 0(便于 CI 卡门)
    return {"A": 0, "B": 1, "C": 1, "D": 2}[summary["grade"]]


if __name__ == "__main__":
    sys.exit(main())
