"""Lockfile and manifest version checks.

CVE-2026-119025 (published 29 Oct 2026): the ``open`` npm package
7.2.0 before 11.0.0 allows OS command injection via crafted URLs on
Windows/WSL (CWE-78, CVSS 7.5).  Versions below 7.2.0 are treated as
unknown/legacy, NOT vulnerable -- the CVE range starts at 7.2.0.

Affected consumers flagged here:

* ``opencode`` < 1.18.33 (OpenCode before 1.18.33);
* ``@modelcontextprotocol/inspector`` < 2.12.0 (MCP Inspector).

``package.json`` + ``package-lock.json`` are parsed accurately (JSON).
``yarn.lock`` and ``pnpm-lock.yaml`` are best-effort regex parses and
are labelled as such in findings.  A missing lockfile is handled, not
an error: the declared range in ``package.json`` is assessed instead.

Range resolver: covers the common cases -- exact versions, ``^``,
``~``, ``>=`` / ``>`` / ``<=`` / ``<`` / ``=``, comma/space-separated
AND combinations, and ``||`` OR branches.  Hyphen ranges and dist-tags
(``latest``) are unknown, not guessed.
"""

import json
import os
import re

VULN_OPEN_LOW = (7, 2, 0)
VULN_OPEN_HIGH = (11, 0, 0)  # exclusive
OPENCODE_FIXED = (1, 18, 33)
INSPECTOR_FIXED = (2, 12, 0)

# package -> (threshold, label) for "affected consumer" checks where
# anything below the threshold is affected.
AFFECTED_CONSUMERS = {
    "opencode": (OPENCODE_FIXED, "OpenCode before 1.18.33"),
    "@modelcontextprotocol/inspector": (
        INSPECTOR_FIXED, "MCP Inspector before 2.12.0"),
}

_VERSION_RE = re.compile(r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?")


def parse_version(text):
    """Parse ``1.2.3`` (or ``v1.2``, ``1``) to a 3-tuple, else None."""
    if not text:
        return None
    match = _VERSION_RE.match(str(text).strip())
    if not match:
        return None
    parts = [int(p) if p is not None else 0 for p in match.groups()]
    return tuple(parts)


def _cmp(a, b):
    return (a > b) - (a < b)


def _caret_upper(version):
    major, minor, patch = version
    if major > 0:
        return (major + 1, 0, 0)
    if minor > 0:
        return (0, minor + 1, 0)
    return (0, 0, patch + 1)


def _tilde_upper(version):
    major, minor, patch = version
    return (major, minor + 1, 0)


def _branch_satisfies(version, branch):
    """Check AND-combined constraints in one ``||`` branch."""
    tokens = [t for t in re.split(r"[\s,]+", branch.strip()) if t]
    for token in tokens:
        if token in ("*", "x", "X", ""):
            continue
        if token.startswith("^"):
            base = parse_version(token[1:])
            if base is None:
                return False
            if _cmp(version, base) < 0 or _cmp(version, _caret_upper(base)) >= 0:
                return False
        elif token.startswith("~"):
            base = parse_version(token[1:])
            if base is None:
                return False
            if _cmp(version, base) < 0 or _cmp(version, _tilde_upper(base)) >= 0:
                return False
        elif token.startswith(">="):
            base = parse_version(token[2:])
            if base is None or _cmp(version, base) < 0:
                return False
        elif token.startswith("<="):
            base = parse_version(token[2:])
            if base is None or _cmp(version, base) > 0:
                return False
        elif token.startswith(">"):
            base = parse_version(token[1:])
            if base is None or _cmp(version, base) <= 0:
                return False
        elif token.startswith("<"):
            base = parse_version(token[1:])
            if base is None or _cmp(version, base) >= 0:
                return False
        elif token.startswith("="):
            base = parse_version(token[1:])
            if base is None or _cmp(version, base) != 0:
                return False
        else:
            base = parse_version(token)
            if base is None or _cmp(version, base) != 0:
                return False
    return True


def satisfies_range(version_text, range_text):
    """True when ``version_text`` satisfies ``range_text`` (common cases)."""
    version = parse_version(version_text)
    if version is None or not range_text:
        return False
    return any(_branch_satisfies(version, branch)
               for branch in str(range_text).split("||"))


def _branch_lower_bound(branch):
    """Best-effort lower bound of one range branch, else None."""
    tokens = [t for t in re.split(r"[\s,]+", branch.strip()) if t]
    lower = None
    for token in tokens:
        base = None
        if token.startswith(("^", "~", ">=", ">", "=")):
            base = parse_version(token.lstrip("^~>= "))
        elif not token.startswith("<"):
            base = parse_version(token)
        if base is not None and (lower is None or _cmp(base, lower) > 0):
            lower = base
    return lower


def range_allows_vulnerable_open(range_text):
    """True when ``range_text`` can resolve into [7.2.0, 11.0.0)."""
    if not range_text:
        return False
    for branch in str(range_text).split("||"):
        candidates = [VULN_OPEN_LOW, (10, 0, 0), (10, 99, 99)]
        lower = _branch_lower_bound(branch)
        if lower is not None:
            candidates.append(lower)
        if any(_cmp(c, VULN_OPEN_LOW) >= 0
               and _cmp(c, VULN_OPEN_HIGH) < 0
               and _branch_satisfies(c, branch) for c in candidates):
            return True
    return False


def range_allows_below(range_text, threshold):
    """True when ``range_text`` can resolve below ``threshold``."""
    if not range_text:
        return False
    for branch in str(range_text).split("||"):
        lower = _branch_lower_bound(branch)
        candidates = [c for c in (lower, (0, 0, 0)) if c is not None]
        if any(_cmp(c, threshold) < 0 and _branch_satisfies(c, branch)
               for c in candidates):
            return True
    return False


def classify_open(version_text):
    """Classify a resolved ``open`` version.

    Returns ``vulnerable``, ``clean`` or ``legacy_unknown`` (< 7.2.0).
    """
    version = parse_version(version_text)
    if version is None:
        return "unknown"
    if _cmp(version, VULN_OPEN_LOW) < 0:
        return "legacy_unknown"
    if _cmp(version, VULN_OPEN_HIGH) < 0:
        return "vulnerable"
    return "clean"


def _package_lock_versions(path):
    """Accurate package-lock parse: name -> resolved version."""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return {}
    found = {}
    packages = data.get("packages", {})
    for key, entry in packages.items():
        if not isinstance(entry, dict):
            continue
        name = key.replace("node_modules/", "", 1) if key else ""
        if name and entry.get("version"):
            found[name] = entry["version"]
    for name, entry in (data.get("dependencies") or {}).items():
        if isinstance(entry, dict) and entry.get("version"):
            found.setdefault(name, entry["version"])
    return found


def _yarn_lock_versions(path):
    """Best-effort yarn.lock parse: name -> version."""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            text = handle.read()
    except OSError:
        return {}
    found = {}
    for match in re.finditer(
            r'"?([^"\s@][^"@\n]*?)@[^:\n]*:\s*\n\s+version\s+"([^"]+)"',
            text):
        found[match.group(1)] = match.group(2)
    return found


def _pnpm_lock_versions(path):
    """Best-effort pnpm-lock.yaml parse: name -> version."""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            text = handle.read()
    except OSError:
        return {}
    found = {}
    for match in re.finditer(r"/?(@?[\w.-]+(?:/[\w.-]+)?)/(\d+\.\d+\.\d+)",
                             text):
        found.setdefault(match.group(1), match.group(2))
    for match in re.finditer(r"^\s+([\w@./-]+)@(\d+\.\d+\.\d+):",
                             text, re.MULTILINE):
        found.setdefault(match.group(1), match.group(2))
    return found


def _manifest_deps(path):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return {}
    deps = {}
    for section in ("dependencies", "devDependencies"):
        for name, spec in (data.get(section) or {}).items():
            deps.setdefault(name, spec)
    return deps


def _assess(package, declared, resolved, lock_source):
    """One finding dict (or None when clean) for a watched package."""
    if package == "open":
        if resolved is not None:
            status = classify_open(resolved)
            if status == "vulnerable":
                return {
                    "package": package, "declared": declared,
                    "resolved": resolved, "status": "vulnerable",
                    "source": lock_source,
                    "message": "open %s is in the CVE-2026-119025 "
                               "vulnerable range 7.2.0-<11.0.0"
                               % resolved,
                }
            if status == "legacy_unknown":
                return {
                    "package": package, "declared": declared,
                    "resolved": resolved, "status": "legacy_unknown",
                    "source": lock_source,
                    "message": "open %s predates the CVE-2026-119025 "
                               "range (7.2.0+); treat as unknown/legacy, "
                               "not confirmed vulnerable" % resolved,
                }
            return None
        if declared in (None, "", "*", "latest"):
            return {
                "package": package, "declared": declared,
                "resolved": None, "status": "unpinned",
                "source": "package.json",
                "message": "open is declared without a pinned version "
                           "and no lockfile resolves it",
            }
        if range_allows_vulnerable_open(declared):
            return {
                "package": package, "declared": declared,
                "resolved": None, "status": "vulnerable",
                "source": "package.json",
                "message": "open range %s can resolve into the "
                           "CVE-2026-119025 vulnerable range "
                           "7.2.0-<11.0.0" % declared,
            }
        return None
    threshold, label = AFFECTED_CONSUMERS[package]
    if resolved is not None:
        version = parse_version(resolved)
        if version is not None and _cmp(version, threshold) < 0:
            return {
                "package": package, "declared": declared,
                "resolved": resolved, "status": "affected",
                "source": lock_source,
                "message": "%s %s is an affected consumer (%s)"
                           % (package, resolved, label),
            }
        return None
    if declared not in (None, "", "*", "latest") \
            and range_allows_below(declared, threshold):
        return {
            "package": package, "declared": declared,
            "resolved": None, "status": "affected",
            "source": "package.json",
            "message": "%s range %s can resolve into an affected "
                       "version (%s)" % (package, declared, label),
        }
    return None


def scan_project(root):
    """Scan one project directory (or a single manifest file).

    Returns a list of finding dicts for watched packages.  Lockfile
    resolutions take precedence over manifest ranges; a missing
    lockfile falls back to the declared range.
    """
    if os.path.isfile(root):
        root = os.path.dirname(os.path.abspath(root))
    watched = {"open"} | set(AFFECTED_CONSUMERS)
    results = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if d not in ("node_modules", ".git", "__pycache__")]
        declared = {}
        resolved = {}
        lock_source = None
        if "package.json" in filenames:
            declared = _manifest_deps(os.path.join(dirpath, "package.json"))
        if "package-lock.json" in filenames:
            resolved = _package_lock_versions(
                os.path.join(dirpath, "package-lock.json"))
            lock_source = "package-lock.json"
        elif "yarn.lock" in filenames:
            resolved = _yarn_lock_versions(
                os.path.join(dirpath, "yarn.lock"))
            lock_source = "yarn.lock (best-effort)"
        elif "pnpm-lock.yaml" in filenames:
            resolved = _pnpm_lock_versions(
                os.path.join(dirpath, "pnpm-lock.yaml"))
            lock_source = "pnpm-lock.yaml (best-effort)"
        for package in sorted(watched):
            if package not in declared and package not in resolved:
                continue
            finding = _assess(package, declared.get(package),
                              resolved.get(package), lock_source)
            if finding is not None:
                finding["file"] = os.path.join(dirpath, "package.json") \
                    if package in declared else os.path.join(
                        dirpath, lock_source.split(" ")[0])
                results.append(finding)
    return results
