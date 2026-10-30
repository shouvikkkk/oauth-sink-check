"""Detection of untrusted URL sources.

A "source" is any expression whose value can be supplied by a remote
party: an OAuth / OIDC metadata field, an MCP discovery field, or a
value read out of a server-supplied config object.  If such a value
flows into a shell or browser-open sink without validation, the
OpenCode / ``open`` OAuth attack class (see README.md) becomes possible.

Supported languages: JavaScript / TypeScript and Python.  Detection is
syntactic (field-name based) and therefore heuristic by design.
"""

import re

# OAuth / OIDC metadata fields whose values come from a remote server.
SOURCE_FIELDS = (
    "authorization_endpoint",
    "token_endpoint",
    "issuer",
    "redirect_uri",
    "authorization_server",
    "registration_endpoint",
    "jwks_uri",
    "userinfo_endpoint",
    "end_session_endpoint",
)

# Extra fields that appear in MCP discovery documents and server configs.
MCP_FIELDS = (
    "authorization_endpoint",
    "issuer",
    "server_url",
    "mcp_url",
)


def _field_patterns(field):
    """Regexes matching the ways ``field`` is read in JS/TS and Python."""
    return (
        re.compile(r"\.\s*" + re.escape(field) + r"\b"),
        re.compile(r"\[\s*['\"]" + re.escape(field) + r"['\"]\s*\]"),
        re.compile(r"\.\s*get\s*\(\s*['\"]" + re.escape(field) + r"['\"]"),
    )


def extract_source_field(expr):
    """Return the source field name read by ``expr``, or ``None``.

    Matches ``obj.authorization_endpoint``, ``obj["token_endpoint"]``,
    ``obj.get("issuer")`` and the equivalent Python forms.
    """
    if not expr:
        return None
    for field in SOURCE_FIELDS:
        for pattern in _field_patterns(field):
            if pattern.search(expr):
                return field
    return None


def is_source_expression(expr):
    """True when ``expr`` reads a value from an untrusted URL source."""
    return extract_source_field(expr) is not None
