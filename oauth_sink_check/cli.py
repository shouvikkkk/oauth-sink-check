"""Command-line interface for oauth-sink-check.

Usage:
    oauth-sink-check scan <path> [--format text|json] [--strict]

Exit codes (exact, documented scheme):
    0 -- clean, or LOW findings only
    1 -- at least one MEDIUM finding, none higher
         (with --strict, LOW findings also exit 1)
    2 -- at least one CRITICAL or HIGH finding
    3 -- usage error (missing path, unreadable path, bad arguments)
"""

import argparse
import os
import sys

from . import lockfiles, mcpconfig
from .report import Finding, exit_code_for, render_json, render_text
from .taint import find_chains

CODE_EXTENSIONS = {
    ".js": "js", ".mjs": "js", ".cjs": "js",
    ".ts": "js", ".tsx": "js", ".jsx": "js",
    ".py": "python",
}
SKIP_DIRS = {"node_modules", ".git", "__pycache__", ".venv", "venv"}


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        print("%s: error: %s" % (self.prog, message), file=sys.stderr)
        raise SystemExit(3)


def _lockfile_findings_to_findings(raw, root):
    out = []
    for item in raw:
        status = item["status"]
        if status in ("vulnerable", "affected"):
            severity = "HIGH"
        elif status == "legacy_unknown":
            severity = "LOW"
        else:  # unpinned
            severity = "LOW"
        out.append(Finding(
            severity=severity, kind="vulnerable-dependency",
            file=os.path.relpath(item["file"], root)
            if os.path.isabs(item["file"]) else item["file"],
            line=0, message=item["message"],
            evidence="declared=%s resolved=%s source=%s"
                     % (item["declared"], item["resolved"],
                        item["source"])))
    return out


def _mcp_findings_to_findings(raw):
    return [Finding(severity=item["severity"], kind=item["kind"],
                    file=item["file"], line=item["line"],
                    message=item["message"],
                    evidence=item.get("evidence", ""))
            for item in raw]


def scan_path(target):
    """Scan a file or directory; returns a list of ``Finding``."""
    findings = []
    if os.path.isfile(target):
        files = [target]
        root = os.path.dirname(os.path.abspath(target))
    else:
        root = os.path.abspath(target)
        files = []
        for dirpath, dirnames, filenames in os.walk(target):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for name in filenames:
                files.append(os.path.join(dirpath, name))
    for path in files:
        _, ext = os.path.splitext(path)
        if ext in CODE_EXTENSIONS:
            try:
                with open(path, "r", encoding="utf-8",
                          errors="replace") as handle:
                    text = handle.read()
            except OSError:
                continue
            findings.extend(find_chains(
                text, CODE_EXTENSIONS[ext],
                filename=os.path.relpath(path, root)))
        elif mcpconfig.is_config_file(path):
            findings.extend(_mcp_findings_to_findings(
                mcpconfig.scan_config_file(path)))
    if os.path.isdir(target):
        findings.extend(_lockfile_findings_to_findings(
            lockfiles.scan_project(target), root))
    elif os.path.basename(target) in ("package.json", "package-lock.json",
                                     "yarn.lock", "pnpm-lock.yaml"):
        findings.extend(_lockfile_findings_to_findings(
            lockfiles.scan_project(target), root))
    return findings


def build_parser():
    parser = _Parser(prog="oauth-sink-check",
                     description="Scan code, lockfiles and MCP configs "
                                 "for the OAuth URL -> shell sink attack "
                                 "class (CVE-2026-119025 / open < 11).")
    sub = parser.add_subparsers(dest="command")
    scan = sub.add_parser("scan", help="scan a file or directory")
    scan.add_argument("path", help="file or directory to scan")
    scan.add_argument("--format", choices=("text", "json"),
                      default="text", help="report format")
    scan.add_argument("--strict", action="store_true",
                      help="LOW findings also cause a non-zero exit")
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command != "scan":
        parser.print_help(sys.stderr)
        return 3
    if not os.path.exists(args.path):
        print("oauth-sink-check: error: no such path: %s" % args.path,
              file=sys.stderr)
        return 3
    findings = scan_path(args.path)
    if args.format == "json":
        print(render_json(findings, args.path), end="")
    else:
        print(render_text(findings, args.path), end="")
    return exit_code_for(findings, strict=args.strict)


if __name__ == "__main__":
    raise SystemExit(main())
