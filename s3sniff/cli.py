"""Command-line interface for S3SNIFF.

Usage:
    python -m s3sniff scan INPUT.json [--format table|json]
    python -m s3sniff --version

INPUT.json may be a single triage document or a list of them. Each document
may carry 'bucket', 'acl', 'policy', and/or 'listing' keys.

Exit codes:
    0  no findings
    1  usage / IO / parse error
    2  findings present (severity-gated)
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from . import TOOL_NAME, TOOL_VERSION
from .core import (
    Finding,
    Severity,
    SEVERITY_ORDER,
    analyze_document,
    summarize,
)

_EXIT_OK = 0
_EXIT_ERROR = 1
_EXIT_FINDINGS = 2


def _load_documents(path: str) -> list[dict[str, Any]]:
    if path == "-":
        raw = sys.stdin.read()
    else:
        with open(path, "r", encoding="utf-8") as fh:
            raw = fh.read()
    data = json.loads(raw)
    if isinstance(data, list):
        docs = data
    else:
        docs = [data]
    out: list[dict[str, Any]] = []
    for d in docs:
        if not isinstance(d, dict):
            raise ValueError("each triage document must be a JSON object")
        out.append(d)
    return out


def _render_table(findings: list[Finding], summary: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append(f"{TOOL_NAME} {TOOL_VERSION} — cloud bucket triage")
    lines.append("=" * 60)
    if not findings:
        lines.append("No risky ACLs or policy statements detected.")
        return "\n".join(lines)

    ordered = sorted(
        findings,
        key=lambda f: SEVERITY_ORDER.get(f.severity, -1),
        reverse=True,
    )
    for f in ordered:
        lines.append(f"[{f.severity:<8}] {f.bucket}  {f.rule_id}")
        lines.append(f"           {f.title}")
        lines.append(f"           {f.detail}")
        if f.recommendation:
            lines.append(f"           -> {f.recommendation}")
        lines.append("")
    bys = summary["by_severity"]
    breakdown = "  ".join(
        f"{s}={bys.get(s, 0)}"
        for s in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                  Severity.LOW, Severity.INFO)
    )
    lines.append("-" * 60)
    lines.append(f"Total findings: {summary['total']}   {breakdown}")
    lines.append(f"Highest severity: {summary['highest_severity']}")
    return "\n".join(lines)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=(
            "Defensive triage of cloud-bucket ACLs/policies/listings. "
            "Detection only; performs no network access or mutation."
        ),
    )
    parser.add_argument(
        "--version", action="version",
        version=f"{TOOL_NAME} {TOOL_VERSION}",
    )
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser(
        "scan",
        help="Scan a triage JSON document (or list) for risky configs.",
    )
    scan.add_argument(
        "input",
        help="Path to triage JSON, or '-' to read from stdin.",
    )
    scan.add_argument(
        "--format", choices=("table", "json"), default="table",
        help="Output format (default: table).",
    )
    scan.add_argument(
        "--fail-on",
        choices=("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"),
        default="LOW",
        help=(
            "Minimum severity that triggers a non-zero (findings) exit "
            "code (default: LOW)."
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command != "scan":
        parser.print_help(sys.stderr)
        return _EXIT_ERROR

    try:
        docs = _load_documents(args.input)
    except FileNotFoundError:
        print(f"{TOOL_NAME}: input not found: {args.input}", file=sys.stderr)
        return _EXIT_ERROR
    except (json.JSONDecodeError, ValueError) as exc:
        print(f"{TOOL_NAME}: invalid input: {exc}", file=sys.stderr)
        return _EXIT_ERROR
    except OSError as exc:
        print(f"{TOOL_NAME}: cannot read input: {exc}", file=sys.stderr)
        return _EXIT_ERROR

    findings: list[Finding] = []
    for doc in docs:
        findings.extend(analyze_document(doc))
    summary = summarize(findings)

    if args.format == "json":
        payload = {
            "tool": TOOL_NAME,
            "version": TOOL_VERSION,
            "summary": summary,
            "findings": [f.to_dict() for f in findings],
        }
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(_render_table(findings, summary))

    threshold = SEVERITY_ORDER[args.fail_on]
    triggered = any(
        SEVERITY_ORDER.get(f.severity, -1) >= threshold for f in findings
    )
    return _EXIT_FINDINGS if triggered else _EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
