"""Findings, text/JSON reports, and severity-gated exit codes."""

import json
from dataclasses import dataclass, field

SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

# Exit-code scheme (documented in README.md, kept exact):
#   0 -- clean, or LOW findings only
#   1 -- at least one MEDIUM finding, none higher
#   2 -- at least one CRITICAL or HIGH finding
#   3 -- usage error (bad path, bad arguments)
# With --strict, LOW findings also exit 1.


@dataclass
class Finding:
    severity: str
    kind: str
    file: str
    line: int
    message: str
    evidence: str = ""
    chain: str = ""

    def to_dict(self):
        return {
            "severity": self.severity,
            "kind": self.kind,
            "file": self.file,
            "line": self.line,
            "message": self.message,
            "evidence": self.evidence,
            "chain": self.chain,
        }


def exit_code_for(findings, strict=False):
    """Map a finding list to the documented exit code."""
    if not findings:
        return 0
    worst = min(SEVERITY_RANK[f.severity] for f in findings)
    if worst <= 1:
        return 2
    if worst == 2:
        return 1
    # LOW only.
    return 1 if strict else 0


def render_text(findings, target):
    """Human-readable report."""
    lines = ["oauth-sink-check: %s" % target, ""]
    if not findings:
        lines.append("No findings. Clean.")
        return "\n".join(lines) + "\n"
    counts = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    summary = ", ".join(
        "%s %s" % (counts[s], s)
        for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        if counts.get(s)
    )
    lines.append("Findings: %s" % summary)
    lines.append("")
    ordered = sorted(
        findings,
        key=lambda f: (SEVERITY_RANK[f.severity], f.file, f.line),
    )
    for finding in ordered:
        lines.append("[%s] %s:%s %s" % (
            finding.severity, finding.file, finding.line, finding.kind))
        lines.append("  %s" % finding.message)
        if finding.chain:
            lines.append("  chain: %s" % finding.chain)
        if finding.evidence:
            lines.append("  evidence: %s" % finding.evidence)
    return "\n".join(lines) + "\n"


def render_json(findings, target):
    """Machine-readable report."""
    ordered = sorted(
        findings,
        key=lambda f: (SEVERITY_RANK[f.severity], f.file, f.line),
    )
    payload = {
        "target": target,
        "finding_count": len(findings),
        "counts": {
            severity: sum(1 for f in findings if f.severity == severity)
            for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        },
        "findings": [f.to_dict() for f in ordered],
    }
    return json.dumps(payload, indent=2) + "\n"
