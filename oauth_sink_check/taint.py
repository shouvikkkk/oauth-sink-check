"""Lightweight INTRA-FILE taint tracking.

Scope, stated honestly: this tracks taint within a single file only.
There is no cross-file or full interprocedural analysis in v1.  What
it does track, within one file:

* variables assigned from an untrusted URL source (see sources.py);
* propagation through template literals, f-strings, ``+``
  concatenation, ``.format()`` and ``%`` formatting (all of these are
  just "the right-hand side mentions a tainted variable", so they fall
  out of identifier tracking);
* simple same-file function arguments/returns: if a function returns
  one of its parameters, a call passing a tainted argument taints the
  result.

A sanitiser breaks taint: assigning ``encodeURIComponent(x)``,
``encodeURI(x)``, ``urllib.parse.quote(x)`` or ``shlex.quote(x)`` to a
variable leaves that variable untainted, and passing a sanitised value
to a sink is not a finding.  This is the mechanism the clean example
relies on, alongside its ``https`` allowlist check.
"""

import re
from dataclasses import dataclass, field

from .powershell import simulate, simulate_tainted_sink
from .report import Finding
from .sinks import find_sinks
from .sources import extract_source_field

SANITIZERS = (
    "encodeURIComponent",
    "encodeURI",
    "shlex.quote",
    "urllib.parse.quote",
    "quote",
    "sanitize",
)

_DECL_RE = re.compile(
    r"^\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=(?!=)")
_PLAIN_RE = re.compile(r"^\s*([A-Za-z_][\w]*)\s*=(?!=)")
_AUG_RE = re.compile(r"^\s*([A-Za-z_][\w]*)\s*\+=(?!=)")
_DEF_RE = re.compile(r"^\s*def\s+([A-Za-z_]\w*)\s*\(([^)]*)\)")
_FUNC_RE = re.compile(
    r"(?:function\s+([A-Za-z_$][\w$]*)|"
    r"const\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\("
    r"\s*([^)]*)\)")
_RETURN_RE = re.compile(r"^\s*return\s+(.+)$")
_CALL_RE = re.compile(r"([A-Za-z_$][\w$]*)\s*\(([^()]*)\)")


@dataclass
class SourceInfo:
    field: str
    line: int


@dataclass
class TaintResult:
    tainted: dict = field(default_factory=dict)  # var -> SourceInfo
    passthrough_functions: dict = field(default_factory=dict)
    # func name -> set of parameter indexes it returns verbatim


def _identifiers(expr):
    return set(re.findall(r"[A-Za-z_$][\w$]*", expr or ""))


def _strip_sanitizer_calls(expr):
    """Remove ``sanitizer(...)`` calls (single-level parens) from expr."""
    result = expr or ""
    for name in SANITIZERS:
        result = re.sub(
            re.escape(name) + r"\s*\([^()]*\)", "", result)
    return result


def _references_tainted(expr, tainted):
    return bool(_identifiers(expr) & set(tainted))


def _call_passes_taint(expr, tainted, passthrough):
    """True when a call in ``expr`` forwards a tainted argument."""
    for match in _CALL_RE.finditer(expr or ""):
        name, args = match.group(1), match.group(2)
        indexes = passthrough.get(name)
        if not indexes:
            continue
        arg_list = [a.strip() for a in args.split(",")] if args.strip() \
            else []
        for index in indexes:
            if index < len(arg_list) and _identifiers(arg_list[index]) \
                    & set(tainted):
                return True
    return False


def _find_passthrough_functions(lines):
    """Map function names to the parameter indexes they return."""
    functions = {}  # name -> [param names]
    for line in lines:
        match = _DEF_RE.search(line)
        if match:
            params = [p.strip().split("=")[0].strip()
                      for p in match.group(2).split(",") if p.strip()]
            functions[match.group(1)] = params
            continue
        match = _FUNC_RE.search(line)
        if match:
            name = match.group(1) or match.group(2)
            params = [p.strip().split("=")[0].strip()
                      for p in match.group(3).split(",") if p.strip()]
            if name:
                functions[name] = params
    passthrough = {}
    for line in lines:
        match = _RETURN_RE.search(line)
        if not match:
            continue
        returned = match.group(1)
        for name, params in functions.items():
            for index, param in enumerate(params):
                if param and param in _identifiers(returned):
                    passthrough.setdefault(name, set()).add(index)
    return passthrough


def _assignment(line):
    """Return ``(variable, rhs)`` for an assignment line, else None."""
    stripped = line.strip()
    if (stripped.startswith(("if ", "while ", "for ", "return ",
                             "import ", "from ", "elif ", "else",
                             "export ", "class "))):
        return None
    match = _DECL_RE.match(line) or _PLAIN_RE.match(line)
    if match:
        rhs = line.split("=", 1)[1]
        return match.group(1), rhs
    match = _AUG_RE.match(line)
    if match:
        rhs = line.split("+=", 1)[1]
        return match.group(1), rhs
    return None


def analyse_file(text):
    """Run intra-file taint analysis; returns a ``TaintResult``."""
    lines = text.splitlines()
    passthrough = _find_passthrough_functions(lines)
    tainted = {}
    # Fixpoint iteration: later lines can feed earlier ones through
    # same-file helpers, and reassignment can sanitise a variable.
    for _ in range(20):
        changed = False
        for lineno, line in enumerate(lines, start=1):
            assigned = _assignment(line)
            if not assigned:
                continue
            var, rhs = assigned
            stripped = _strip_sanitizer_calls(rhs)
            if extract_source_field(stripped):
                # A source read outside a sanitiser call.
                pass
            field = extract_source_field(rhs)
            sanitised_only = (
                not _references_tainted(stripped, tainted)
                and extract_source_field(stripped) is None)
            if field is None and not _references_tainted(rhs, tainted) \
                    and not _call_passes_taint(rhs, tainted, passthrough):
                # Not tainted by this line.  A sanitiser-only
                # reassignment actively clears prior taint.
                if sanitised_only and var in tainted:
                    del tainted[var]
                    changed = True
                continue
            if sanitised_only:
                if var in tainted:
                    del tainted[var]
                    changed = True
                continue
            if field is not None:
                info = SourceInfo(field=field, line=lineno)
            elif var in tainted:
                info = tainted[var]
            else:
                # Tainted via another variable: keep the earliest source.
                refs = _identifiers(rhs) & set(tainted)
                info = tainted[sorted(refs)[0]] if refs else \
                    SourceInfo(field="tainted-argument", line=lineno)
            if tainted.get(var) != info:
                tainted[var] = info
                changed = True
        if not changed:
            break
    return TaintResult(tainted=tainted, passthrough_functions=passthrough)


def _arg_is_sanitised(arg, tainted_vars):
    """True when every tainted reference in ``arg`` sits in a sanitiser."""
    stripped = _strip_sanitizer_calls(arg)
    if _identifiers(stripped) & set(tainted_vars):
        return False
    if extract_source_field(stripped):
        return False
    return True


def _quoting_for_sink(arg, tainted_vars):
    """Guess the PowerShell quoting wrapping a tainted value in ``arg``.

    What matters is the quoting *in the resulting command string*,
    not the host language's quotes: ``'${x}'`` (JS) and ``'{x}'``
    (Python f-string) wrap the value in single quotes and neutralise
    ``$(...)`` expansion, while ``"{x}"`` inside an f-string wraps it
    in double quotes and does not.  Anything else defaults to the
    vulnerable double-quoted model, the conservative documented choice.
    Note ``'`` + x concatenation does NOT count: the quote ends before
    the value, so the value itself is unquoted.
    """
    for var in tainted_vars:
        if re.search(r"'\s*(?:\$\{|\{)\s*" + re.escape(var) +
                     r"\s*\}\s*'", arg):
            return "single"
    return "double"


def find_chains(text, language, filename="<input>"):
    """Find source -> sink chains in one file; returns ``Finding`` list."""
    result = analyse_file(text)
    findings = []
    for sink in find_sinks(text, language):
        tainted_vars = [v for v in result.tainted
                        if re.search(r"\b" + re.escape(v) + r"\b",
                                     sink.arg)]
        direct_field = extract_source_field(sink.arg)
        if not tainted_vars and not direct_field:
            continue
        if tainted_vars and _arg_is_sanitised(sink.arg, tainted_vars):
            continue
        if direct_field:
            chain = "%s (line %d) -> %s sink (line %d)" % (
                direct_field, sink.line, sink.kind, sink.line)
            source_desc = direct_field
        else:
            info = result.tainted[tainted_vars[0]]
            chain = "%s (line %d) -> %s -> %s sink (line %d)" % (
                info.field, info.line, tainted_vars[0],
                sink.kind, sink.line)
            source_desc = info.field
        if sink.severity_class == "browser":
            findings.append(Finding(
                severity="MEDIUM", kind="tainted-browser-open",
                file=filename, line=sink.line,
                message="Unvalidated %s URL reaches webbrowser.open; "
                        "browser-open only, not a shell sink." % source_desc,
                evidence=sink.raw, chain=chain))
            continue
        quoting = _quoting_for_sink(sink.arg, tainted_vars)
        if quoting == "single":
            # Single quotes neutralise $(...) expansion, but NOT a
            # literal quote inside the value (which would break out).
            # So a single-quoted sink is MEDIUM -- flagged for review,
            # never clean -- simulated here with a quote-free
            # subexpression payload to test the expansion mechanism.
            sim = simulate("https://evil.test/$(whoami)", "single")
        else:
            sim = simulate_tainted_sink(quoting)
        if sim["survives"]:
            findings.append(Finding(
                severity="CRITICAL", kind="tainted-shell-sink",
                file=filename, line=sink.line,
                message="Tainted %s URL reaches shell sink %s and a "
                        "$(...) payload survives its %s-quoted "
                        "PowerShell embedding (%s)."
                        % (source_desc, sink.kind, quoting,
                           "; ".join(sim["reasons"])),
                evidence=sink.raw, chain=chain))
        else:
            findings.append(Finding(
                severity="MEDIUM", kind="tainted-sink-neutralised",
                file=filename, line=sink.line,
                message="Tainted %s URL reaches %s sink, but the "
                        "single-quoted embedding neutralises $(...) "
                        "expansion. A literal quote in the value could "
                        "still break out, so review this -- it is not "
                        "clean." % (source_desc, sink.kind),
                evidence=sink.raw, chain=chain))
    return findings
