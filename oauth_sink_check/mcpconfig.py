"""MCP server config scanning.

Scans ``.mcp.json`` / ``mcp.json`` / ``opencode.json`` /
``.cursor/mcp.json``-style files and flags:

* remote MCP servers (a ``url`` entry, or an http/sse transport);
* any ``authorization_endpoint`` / ``issuer`` value that literally
  contains a ``$(...)`` subexpression or a backtick payload -- the
  shape of the Pillar attack payload, sitting in config;
* remote servers with auth configured but no pinned client version
  info available in the config (there is nowhere in these files to pin
  the client, so the finding is a prompt to check the lockfile, which
  the lockfile scan does separately).
"""

import json
import os
import re

CONFIG_NAMES = {".mcp.json", "mcp.json", "opencode.json"}

AUTH_KEYS = {"auth", "oauth", "headers", "authorization"}
PAYLOAD_FIELDS = ("authorization_endpoint", "issuer")
_PAYLOAD_RE = re.compile(r"\$\(|`")


def _line_of(text, needle):
    for lineno, line in enumerate(text.splitlines(), start=1):
        if needle and needle in line:
            return lineno
    return 0


def _is_remote(entry):
    if not isinstance(entry, dict):
        return False
    if "url" in entry:
        return True
    if entry.get("transport") in ("http", "sse", "streamable-http"):
        return True
    if entry.get("type") in ("http", "sse", "streamable-http"):
        return True
    return False


def _has_auth(entry):
    if not isinstance(entry, dict):
        return False
    if AUTH_KEYS & set(entry):
        return True
    return any(isinstance(v, dict) and (AUTH_KEYS & set(v))
               for v in entry.values())


def _payload_strings(entry):
    """Yield (field, value) pairs carrying a payload in this entry."""
    found = []

    def walk(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if key in PAYLOAD_FIELDS and isinstance(value, str) \
                        and _PAYLOAD_RE.search(value):
                    found.append((key, value))
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(entry)
    return found


def _server_entries(data):
    """Yield (server_name, entry_dict) for server entries in ``data``."""
    if not isinstance(data, dict):
        return
    for container in ("mcpServers", "servers", "mcp"):
        mapping = data.get(container)
        if isinstance(mapping, dict):
            for name, entry in mapping.items():
                if isinstance(entry, dict):
                    yield name, entry
    if _is_remote(data) or _has_auth(data):
        yield data.get("name", "server"), data


def scan_config_file(path):
    """Scan one MCP config file; returns a list of finding dicts."""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            text = handle.read()
    except OSError:
        return []
    try:
        data = json.loads(text)
    except ValueError:
        # Best-effort fallback for trailing-comma / commented JSON.
        findings = []
        for field in PAYLOAD_FIELDS:
            for match in re.finditer(
                    r'"' + field + r'"\s*:\s*"([^"]*)"', text):
                if _PAYLOAD_RE.search(match.group(1)):
                    findings.append({
                        "severity": "HIGH", "kind": "mcp-config-payload",
                        "file": path,
                        "line": _line_of(text, match.group(1)),
                        "message": "MCP config %s value literally "
                                   "contains a $(...) / backtick payload"
                                   % field,
                        "evidence": match.group(1),
                    })
        return findings
    findings = []
    for name, entry in _server_entries(data):
        for field_name, value in _payload_strings(entry):
            findings.append({
                "severity": "HIGH", "kind": "mcp-config-payload",
                "file": path, "line": _line_of(text, value),
                "message": "MCP server %r has a %s value literally "
                           "containing a $(...) / backtick payload -- "
                           "treat this server config as malicious"
                           % (name, field_name),
                "evidence": value,
            })
        if not _is_remote(entry):
            continue
        if _has_auth(entry):
            findings.append({
                "severity": "MEDIUM", "kind": "mcp-remote-auth-unpinned",
                "file": path, "line": _line_of(text, name),
                "message": "Remote MCP server %r has auth configured "
                           "but no pinned client version info is "
                           "available in this config; verify the client "
                           "against the lockfile scan" % name,
                "evidence": "",
            })
        else:
            findings.append({
                "severity": "LOW", "kind": "mcp-remote-server",
                "file": path, "line": _line_of(text, name),
                "message": "Remote MCP server %r configured" % name,
                "evidence": "",
            })
    return findings


def is_config_file(path):
    """True for the MCP config filenames this scanner covers."""
    base = os.path.basename(path)
    if base in CONFIG_NAMES:
        return True
    return base == "mcp.json" and ".cursor" in path.replace(os.sep, "/")
