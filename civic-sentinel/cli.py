from __future__ import annotations

import argparse
import json
from pathlib import Path

from .report import build_html_report
from .scanner import scan_target


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="civic-sentinel",
        description="Defensive early-warning scanner for authorized web assets.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Scan an authorized website.")
    scan.add_argument("target", help="Domain or URL to assess, for example https://example.go.id")
    scan.add_argument(
        "--i-am-authorized",
        action="store_true",
        help="Required confirmation that you are authorized to assess this asset.",
    )
    scan.add_argument("--timeout", type=float, default=8.0, help="Network timeout in seconds.")
    scan.add_argument("--json", type=Path, help="Write JSON report to this path.")
    scan.add_argument("--html", type=Path, help="Write HTML report to this path.")
    scan.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color in terminal output.",
    )
    return parser


def _color(text: str, code: str, enabled: bool) -> str:
    if not enabled:
        return text
    return f"\033[{code}m{text}\033[0m"


def print_summary(result: dict, color: bool = True) -> None:
    risk = result["risk"]
    score = risk["score"]
    level = risk["level"]
    code = "32" if score < 25 else "33" if score < 50 else "31"
    print(_color(f"Civic Sentinel risk: {score}/100 ({level})", code, color))
    print(f"Target: {result['target']['normalized_url']}")
    print(f"Completed checks: {len(result['findings'])} findings")

    for finding in result["findings"]:
        severity = finding["severity"].upper()
        sev_code = {"critical": "31", "high": "31", "medium": "33", "low": "36", "info": "37"}.get(
            finding["severity"],
            "37",
        )
        print()
        print(_color(f"[{severity}] {finding['title']}", sev_code, color))
        print(f"Evidence: {finding['evidence']}")
        print(f"Recommendation: {finding['recommendation']}")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        if not args.i_am_authorized:
            parser.error("--i-am-authorized is required. Only scan assets you are permitted to assess.")

        try:
            result = scan_target(args.target, timeout=args.timeout)
        except ValueError as exc:
            parser.error(str(exc))

        if args.json:
            args.json.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
        if args.html:
            args.html.write_text(build_html_report(result), encoding="utf-8")

        print_summary(result, color=not args.no_color)
        if args.json:
            print(f"\nJSON report: {args.json}")
        if args.html:
            print(f"HTML report: {args.html}")
        return 0

    parser.error("Unknown command.")
    return 2
