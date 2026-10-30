"""PowerShell quoting simulator.

Models whether a URL payload survives the quoting style it is embedded
in, for the vulnerable ``open`` < 11 behaviour on Windows/WSL: the URL
was placed *unescaped* inside a double-quoted PowerShell string, so a
``$(...)`` subexpression inside an otherwise valid ``https`` URL was
expanded and executed by PowerShell.

This module NEVER executes anything.  It only inspects strings.  The
Pillar payload below is test data, never run.

Quoting styles modelled:

* ``double``   -- ``" <url> "`` : ``$(...)`` expands, backtick escapes
  and an unescaped ``"`` breaking out of the string both survive.
* ``single``   -- ``' <url> '`` : ``$(...)`` is literal and does NOT
  survive; only a literal ``'`` breaking out of the string survives.
* ``encoded``  -- ``-EncodedCommand <base64>`` : the base64 blob is
  decoded (UTF-16LE first, then UTF-8) and the decoded text is
  re-checked as script: a ``$(...)`` inside it survives.
* ``unquoted`` -- a bare argument: ``$(...)`` still expands.
"""

import base64
import binascii
import re

# Payload shape published by Pillar Security (19 Oct 2026).  Kept here
# purely as a representative attacker-controlled value for simulation
# and as a test fixture.  It is never executed by this tool.
PILLAR_PAYLOAD = (
    "https://evil.test/$([IO.File]::WriteAllText("
    "'C:\\Users\\Public\\pwned.txt','RCE'))"
)

_SUBEXPRESSION_RE = re.compile(r"\$\(")
_BACKTICK_ESCAPE_RE = re.compile(r"`[$`\"'\\]")


def contains_subexpression(url):
    """True when ``url`` carries a PowerShell ``$(...)`` subexpression."""
    return bool(_SUBEXPRESSION_RE.search(url or ""))


def contains_backtick_escape(url):
    """True when ``url`` carries a PowerShell backtick escape sequence."""
    return bool(_BACKTICK_ESCAPE_RE.search(url or ""))


def decode_encoded_command(blob):
    """Base64-decode a ``-EncodedCommand`` blob, or return ``None``.

    PowerShell's ``-EncodedCommand`` expects UTF-16LE; fall back to
    UTF-8 for blobs that decode as printable text that way.
    """
    if not blob:
        return None
    compact = re.sub(r"\s+", "", blob)
    try:
        raw = base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError):
        return None
    for encoding in ("utf-16-le", "utf-8"):
        try:
            text = raw.decode(encoding)
        except UnicodeDecodeError:
            continue
        if text and all(c.isprintable() or c in "\r\n\t" for c in text):
            return text
    return None


def simulate(url, quoting):
    """Decide whether a payload in ``url`` survives ``quoting``.

    Returns a dict with ``survives`` (bool), ``reasons`` (list of
    human-readable strings) and, for ``encoded`` input, ``decoded``.
    """
    url = url or ""
    reasons = []
    decoded = None

    if quoting == "encoded":
        decoded = decode_encoded_command(url)
        if decoded is None:
            return {
                "survives": False,
                "reasons": ["-EncodedCommand blob is not valid base64"],
                "decoded": None,
            }
        inner = simulate(decoded, "double")
        if inner["survives"]:
            reasons.append(
                "decoded -EncodedCommand text contains a surviving payload"
            )
            reasons.extend(inner["reasons"])
        return {"survives": inner["survives"], "reasons": reasons,
                "decoded": decoded}

    survives = False
    if quoting == "single":
        # Inside single quotes everything is literal -- except that a
        # literal single quote ends the string and breaks out of it.
        if "'" in url:
            survives = True
            reasons.append("single-quote breakout: ' inside a "
                           "single-quoted string")
    elif quoting in ("double", "unquoted"):
        if contains_subexpression(url):
            survives = True
            reasons.append("$(...) subexpression expands inside a "
                           "double-quoted / unquoted PowerShell string")
        if quoting == "double" and '"' in url:
            survives = True
            reasons.append('double-quote breakout: " inside a '
                           "double-quoted string")
        if contains_backtick_escape(url):
            survives = True
            reasons.append("backtick escape sequence can neutralise "
                           "quoting or escape a delimiter")
    else:
        raise ValueError("unknown quoting style: %r" % (quoting,))

    return {"survives": survives, "reasons": reasons, "decoded": decoded}


def simulate_tainted_sink(quoting):
    """Simulate the representative attacker payload at a sink.

    A tainted variable's runtime value is unknown, so for a tainted
    URL reaching a shell sink we ask: *if* the attacker supplied the
    Pillar payload shape, would it survive this sink's quoting?  That
    is the conservative, documented assumption behind CRITICAL vs
    MEDIUM for shell sinks.
    """
    return simulate(PILLAR_PAYLOAD, quoting)
