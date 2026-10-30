"""Sink detection: calls that hand a string to a shell or a browser.

Sink classes:

* ``shell``   -- the value can become executed code on Windows/WSL
  (npm ``open``, ``child_process.exec``, ``powershell.exe``,
  ``os.system``, ``subprocess`` with ``shell=True``, ``os.popen``).
* ``browser`` -- the value only opens a browser (Python
  ``webbrowser.open``).  Deliberately NOT conflated with shell sinks:
  a browser-open sink is MEDIUM at worst, never CRITICAL.

``window.open`` / ``self.open`` are excluded: they are browser APIs,
not the npm ``open`` package, and flagging them would drown the signal.
"""

import re
from dataclasses import dataclass


@dataclass
class Sink:
    line: int
    kind: str
    arg: str
    severity_class: str  # "shell" or "browser"
    raw: str


def _balanced_arg(text, open_paren_index):
    """Extract the argument text starting at ``open_paren_index``.

    Returns the text inside the outermost parens, or the rest of the
    line when the parens do not balance on this line (multi-line calls
    are a documented limitation).
    """
    depth = 0
    for i in range(open_paren_index, len(text)):
        char = text[i]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return text[open_paren_index + 1:i]
    return text[open_paren_index + 1:]


def _arg_after(text, match):
    paren = text.find("(", match.end() - 1)
    if paren == -1:
        paren = text.find("(", match.start())
    if paren == -1:
        return ""
    return _balanced_arg(text, paren)


def find_sinks(text, language):
    """Return all sink occurrences in ``text`` for ``language``.

    ``language`` is ``"js"`` (JavaScript/TypeScript) or ``"python"``.
    """
    sinks = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        line_start = len(sinks)
        if language == "js":
            # npm open(): `open(...)` but not `window.open(...)`.
            match = re.search(r"(?<![\w.])open\s*\(", line)
            if match:
                sinks.append(Sink(lineno, "open", _arg_after(line, match),
                                  "shell", line.strip()))
            if re.search(r"\bexecSync\s*\(", line):
                match = re.search(r"\bexecSync\s*\(", line)
                sinks.append(Sink(lineno, "execSync",
                                  _arg_after(line, match), "shell",
                                  line.strip()))
            elif re.search(r"\bexec\s*\(", line):
                match = re.search(r"\bexec\s*\(", line)
                sinks.append(Sink(lineno, "exec", _arg_after(line, match),
                                  "shell", line.strip()))
            if (re.search(r"\bspawn\s*\(", line)
                    and re.search(r"shell\s*:\s*true", line)):
                match = re.search(r"\bspawn\s*\(", line)
                sinks.append(Sink(lineno, "spawn_shell",
                                  _arg_after(line, match), "shell",
                                  line.strip()))
            # A bare `powershell` mention is a sink only when this line
            # is not already covered by another sink (e.g. exec(...))
            # and is not merely constructing a command string in an
            # assignment -- otherwise one sink would be counted twice.
            if (re.search(r"powershell", line, re.IGNORECASE)
                    and len(sinks) == line_start
                    and not re.match(
                        r"^\s*(?:(?:const|let|var)\s+)?"
                        r"[A-Za-z_$][\w$]*\s*=(?!=)", line)):
                sinks.append(Sink(lineno, "powershell", line.strip(),
                                  "shell", line.strip()))
        elif language == "python":
            if re.search(r"\bos\.system\s*\(", line):
                match = re.search(r"\bos\.system\s*\(", line)
                sinks.append(Sink(lineno, "os_system",
                                  _arg_after(line, match), "shell",
                                  line.strip()))
            if re.search(r"\bos\.popen\s*\(", line):
                match = re.search(r"\bos\.popen\s*\(", line)
                sinks.append(Sink(lineno, "os_popen",
                                  _arg_after(line, match), "shell",
                                  line.strip()))
            if (re.search(r"\bsubprocess\.\w+\s*\(", line)
                    and re.search(r"shell\s*=\s*True", line)):
                match = re.search(r"\bsubprocess\.\w+\s*\(", line)
                sinks.append(Sink(lineno, "subprocess_shell",
                                  _arg_after(line, match), "shell",
                                  line.strip()))
            if re.search(r"\bPopen\s*\(", line) and re.search(
                    r"shell\s*=\s*True", line):
                match = re.search(r"\bPopen\s*\(", line)
                sinks.append(Sink(lineno, "Popen_shell",
                                  _arg_after(line, match), "shell",
                                  line.strip()))
            if re.search(r"\bwebbrowser\.open\s*\(", line):
                match = re.search(r"\bwebbrowser\.open\s*\(", line)
                sinks.append(Sink(lineno, "webbrowser_open",
                                  _arg_after(line, match), "browser",
                                  line.strip()))
            # Same bare-powershell rule as for JS: only when no other
            # sink fired on this line and the line is not merely
            # building a command string in an assignment.
            if (re.search(r"powershell", line, re.IGNORECASE)
                    and len(sinks) == line_start
                    and not re.match(
                        r"^\s*[A-Za-z_][\w]*\s*=(?!=)", line)):
                sinks.append(Sink(lineno, "powershell", line.strip(),
                                  "shell", line.strip()))
    return sinks
