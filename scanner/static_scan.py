#!/usr/bin/env python3
"""TrustShell 静态引擎 v0 —— 命令行入口(动静互证的静态一侧).

用法:
  python3 static_scan.py --source /path/to/agent           # 分诊候选路径
  python3 static_scan.py --source /path/to/agent --json     # JSON 输出

它标出**候选**可疑路径,交给动态红队证实/证伪。候选 ≠ 漏洞。
零依赖(仅 Python 标准库)。
"""
from __future__ import annotations

import argparse
import json
import sys

from trustshell import static as S


def _c(code, s, on):
    return f"\033[{code}m{s}\033[0m" if on else s


SEV_STYLE = {"crit": ("31", "致命"), "high": ("33", "高"), "med": ("90", "中")}


def print_report(cands, root, color):
    print()
    print(_c("1", f"  TrustShell 静态引擎 v0 · 动静互证(静态侧)", color))
    print(f"  源码: {root}")
    print("  " + "─" * 58)
    if not cands:
        print("  未发现候选可疑路径(不代表安全 —— 静态只看得到一部分,仍需动态红队)。")
        print()
        return

    last_rt = None
    for c in cands:
        if c.rt != last_rt:
            label = S.RT_LABEL.get(c.rt, c.rt)
            print(f"\n  【{c.rt}】{label}")
            last_rt = c.rt
        code, lab = SEV_STYLE.get(c.severity, ("90", c.severity))
        tag = _c(code, f"[{lab}]", color)
        print(f"    {tag} {c.file}:{c.line}")
        print(_c("90", f"          └ {c.why}", color))
        if c.snippet:
            print(_c("90", f"            {c.snippet}", color))

    print("\n  " + "─" * 58)
    n = len(cands)
    print(f"  候选路径: {n} 处 —— 这是分诊,不是判决。")
    print(_c("36", "  下一步:动态红队对运行中的 Agent 逐条证实/证伪(动静互证)。", color))
    print(_c("90", "  候选 ≠ 漏洞;真假的裁判是‘真打穿’,不是这里的匹配。", color))
    print()


def main(argv=None):
    ap = argparse.ArgumentParser(description="TrustShell 静态引擎 v0(动静互证静态侧)")
    ap.add_argument("--source", required=True, help="Agent 源码目录")
    ap.add_argument("--json", action="store_true", help="以 JSON 输出")
    ap.add_argument("--no-color", action="store_true", help="关闭彩色")
    args = ap.parse_args(argv)

    cands = S.analyze_source(args.source)

    if args.json:
        print(json.dumps(S.to_dict(cands, args.source), ensure_ascii=False, indent=2))
    else:
        color = sys.stdout.isatty() and not args.no_color
        print_report(cands, args.source, color)

    # 退出码:有候选 → 1(便于 CI 提示人工/动态复核),无候选 → 0
    return 1 if cands else 0


if __name__ == "__main__":
    sys.exit(main())
