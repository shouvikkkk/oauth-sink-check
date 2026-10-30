# oauth-sink-check

Trace **your** code from an untrusted OAuth/endpoint URL source to a
shell or browser-open sink, simulate whether a PowerShell payload
survives the quoting used, and check **your** lockfile and MCP configs
— for the attack class behind CVE-2026-119025.

Stdlib only. No dependencies. This tool **never executes payloads**;
it only inspects strings.

## The problem

On 19 October 2026, Pillar Security disclosed that OpenCode
1.0.137–1.18.32 on Windows/WSL let an attacker-controlled remote MCP
server execute arbitrary code during MCP OAuth sign-in. The chain:

> server's discovery document → MCP SDK → `oauth-provider.ts` →
> `mcp/index.ts` → `browser.ts` → `open()` → PowerShell.

The server-supplied `authorization_endpoint` URL went unescaped into
PowerShell. PowerShell expands `$(…)` inside double-quoted strings,
so a well-formed `https` URL carrying a subexpression ran as code.
Pillar's example payload:

```
https://evil.test/$([IO.File]::WriteAllText('C:\Users\Public\pwned.txt','RCE'))
```

The fix landed in OpenCode 1.18.33 (the `open` package's 11.0.4 plus
http/https scheme checks); the vendor said malicious MCP servers were
"outside their threat model". Pillar proposed CVSS 9.8.

On 29 October 2026, CVE-2026-119025 was published: the `open` npm
package 7.2.0 before 11.0.0 allows OS command injection via crafted
URLs on Windows/WSL (CWE-78, CVSS 7.5). Affected consumers include MCP
Inspector before 2.12.0 (GHSA-q978-78c7-phqw) and OpenCode before
1.18.33. `open` 11.0.0 fixed the escaping (2025-11-15) with no
security wording, so `^10` pins kept the vulnerable version for most
of a year; `mcp-remote` 0.15.2 still declares `^10.1.0`.

## The gap this fills

* `npm audit` / CVE feeds flag **vulnerable versions only** — they
  say nothing about whether your code actually passes an untrusted URL
  to a sink.
* Generic SAST misses **PowerShell quoting semantics**: the payload
  is not a weird string, it is a valid `https` URL.
* **Scheme allowlists (https-only) do NOT stop it** — the payload
  rides inside a valid `https` URL. An https check is necessary but
  not sufficient; the URL must also be encoded/escaped before it
  reaches a shell.

No dedicated tool traced *your* code from untrusted OAuth/endpoint URL
source → string interpolation → shell/browser-open sink, simulated
whether the payload survives the quoting used, and checked *your*
lockfile and MCP configs. This is that tool.

## Setup

Requires Python 3.9+. No third-party dependencies — there is no
`requirements.txt` because there is nothing to install.

```bash
git clone https://github.com/shouvikkkk/oauth-sink-check.git
cd oauth-sink-check
python -m oauth_sink_check scan ./your-project
# or, after pip install . :
oauth-sink-check scan ./your-project
```

## Usage

```
oauth-sink-check scan <path> [--format text|json] [--strict]
```

* `scan` accepts a file or a directory (directories are walked
  recursively, skipping `node_modules`, `.git`, `__pycache__`).
* `--format json` emits a machine-readable report.
* `--strict` makes LOW findings exit 1 as well.

### Exit codes (exact scheme)

| Code | Meaning |
| ---- | ------- |
| 0 | Clean, or LOW findings only |
| 1 | At least one MEDIUM finding, none higher (with `--strict`, LOW also exits 1) |
| 2 | At least one CRITICAL or HIGH finding |
| 3 | Usage error (missing/unreadable path, bad arguments) |

### Severities

| Severity | Meaning |
| -------- | ------- |
| CRITICAL | Tainted URL reaches a **shell** sink and a `$(…)` payload survives its quoting simulation |
| HIGH | Vulnerable `open` pin (CVE-2026-119025 range 7.2.0–<11.0.0), affected consumer version (opencode < 1.18.33, inspector < 2.12.0), or a literal `$(…)`/backtick payload in an MCP config |
| MEDIUM | Unvalidated URL reaches a browser-open sink; tainted URL reaches a sink whose quoting neutralises the payload; remote MCP server with auth but no pinned client version info |
| LOW | Informational — e.g. unpinned lockfile entry, `open` version predating the CVE range (unknown/legacy, not confirmed vulnerable), remote MCP server without auth |

### Example output

Scanning `examples/vulnerable` (exit code 2):

```
oauth-sink-check: examples/vulnerable

Findings: 1 CRITICAL, 1 HIGH

[CRITICAL] client.js:13 tainted-shell-sink
  Tainted authorization_endpoint URL reaches shell sink open and a
  $(...) payload survives its double-quoted PowerShell embedding
  ($(...) subexpression expands inside a double-quoted / unquoted
  PowerShell string).
  chain: authorization_endpoint (line 9) -> authUrl -> open sink (line 13)
  evidence: await open(authUrl);
[HIGH] package.json:0 vulnerable-dependency
  open 10.1.2 is in the CVE-2026-119025 vulnerable range 7.2.0-<11.0.0
  evidence: declared=^10.1.0 resolved=10.1.2 source=package-lock.json
```

Scanning `examples/clean` exits **0**: it pins `open` 11.0.4 and
allowlists `https` plus `encodeURIComponent` before `open()`.

## What it checks

| Module | What it does |
| ------ | ------------ |
| `sources.py` | Untrusted URL sources: OAuth fields (`authorization_endpoint`, `token_endpoint`, `issuer`, `redirect_uri`, `authorization_server`, `registration_endpoint`, …), MCP discovery fields, config values. JS/TS + Python. |
| `taint.py` | Intra-file taint: sources → variables → template literals, f-strings, `+` concatenation, `.format()`, `%` formatting, simple same-file function args/returns. Reports source→sink chains with `file:line`. |
| `sinks.py` | JS/TS: `open()`, `exec`/`execSync`, `spawn` with `shell:true`, PowerShell invocations. Python: `os.system`, `subprocess` with `shell=True`, `os.popen`. `webbrowser.open` is a **lower-severity** browser sink, never conflated with shell sinks. |
| `powershell.py` | Quoting simulator: double-quoted, single-quoted, `-EncodedCommand` (base64-decoded, then re-checked), unquoted. Models the vulnerable `open` < 11 behaviour: URL unescaped inside a double-quoted PowerShell string → `$(…)` executes. |
| `lockfiles.py` | `package.json` + `package-lock.json` (accurate), `yarn.lock` and `pnpm-lock.yaml` (best-effort regex). `open` < 11.0.0 flagged vulnerable only inside 7.2.0–<11.0.0; below 7.2.0 is unknown/legacy, not vulnerable. Small semver range resolver for `^`, `~`, `>=`, `<`, `||` and friends. |
| `mcpconfig.py` | `.mcp.json` / `mcp.json` / `opencode.json` / `.cursor/mcp.json`: remote servers, literal `$(…)`/backtick payloads in `authorization_endpoint`/`issuer`, auth-without-pinned-client-version. |
| `report.py` | Text + JSON reports, severity-gated exit codes. |

## Differentiation

| Tool | What it misses that this catches |
| ---- | ------------------------------- |
| `npm audit` / CVE feeds | Whether your code actually routes an untrusted URL into a sink; your MCP configs |
| Generic SAST | PowerShell quoting semantics — `$(…)` inside a valid `https` URL |
| Scheme allowlists | The payload *is* a valid `https` URL; https-only does not stop it |

## Honest limitations

* **Heuristic, intra-file taint only.** No cross-file or full
  interprocedural tracking in v1; a chain split across files or
  through a framework's indirection will be missed. Taint is also
  over-approximate in places (e.g. a boolean derived from a tainted
  URL is tracked as tainted until a sanitiser clears it).
* **PowerShell model covers the `open` < 11 double-quoted-string
  case.** Other shells and exotic quoting constructions are not
  modelled.
* **Windows/WSL-specific.** The underlying vulnerability only
  executes on Windows/WSL PowerShell paths.
* **yarn/pnpm lock parsing is best-effort regex**, not a full parser.
* **Multi-line calls** are analysed per line; a sink split across
  lines may be missed.
* **This tool never executes payloads.** Findings are simulations
  and heuristics, not proof of exploitability — verify before acting.
* A tainted value reaching a shell sink is reported CRITICAL on the
  conservative assumption that the attacker controls the value (the
  Pillar payload shape is used as the representative value). A
  single-quoted embedding drops the finding to MEDIUM, because it
  neutralises `$(…)` expansion — but that is a review flag, not a
  clean bill: a literal quote inside the value could still break out
  of single quotes, so MEDIUM findings need a human look.

## License

MIT — Copyright (c) 2026 Shouvik Maji. See `LICENSE`.
