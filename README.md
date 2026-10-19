<h1 align="center">pi-ghidra</h1>

<p align="center">
  <strong>Autonomous, headless Ghidra 12 for Pi, omp, and any MCP client.</strong><br>
  Decompile, trace xrefs, map call graphs, search bytes, and patch a program database
  without opening the GUI, running a bridge server, or preparing a project by hand.
</p>

<p align="center">
  <a href="https://github.com/immutex/pi-ghidra/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/immutex/pi-ghidra/actions/workflows/ci.yml/badge.svg"></a>
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square"></a>
  <img alt="Node.js 22.19+" src="https://img.shields.io/badge/node-%E2%89%A522.19-339933.svg?style=flat-square&logo=node.js&logoColor=white">
  <img alt="Ghidra 12" src="https://img.shields.io/badge/Ghidra-12.x-orange.svg?style=flat-square">
  <img alt="Platforms" src="https://img.shields.io/badge/platforms-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey.svg?style=flat-square">
  <img alt="MCP" src="https://img.shields.io/badge/MCP-stdio-6f42c1.svg?style=flat-square">
  <img alt="Agents: Pi and omp" src="https://img.shields.io/badge/agents-Pi%20%7C%20omp-success.svg?style=flat-square">
</p>

## What pi-ghidra is

`pi-ghidra` gives a coding agent a real reverse-engineering loop. The agent calls one
`ghidra` tool; the tool invokes Ghidra's official `analyzeHeadless` launcher, imports
the binary on first use, analyzes it, and answers from a cached project on later calls.
Related questions run in a single JVM through `batch`.

Nothing else is required: no PyGhidra daemon, no Ghidra plugin, no open project, no
bridge port. The package is a thin TypeScript scheduler around one Java `GhidraScript`
that is the entire Ghidra API adapter.

|  | pi-ghidra | GUI automation | Long-lived bridge |
|---|---|---|---|
| Setup | Install package; Ghidra auto-detected | Launch and drive a GUI | Run and supervise a server |
| Isolation | One disposable JVM per call | Shared GUI state | Shared JVM and project state |
| Cancellation | Process-tree kill | Fragile UI abort | RPC-level only |
| Failure scope | One call | Whole session | Whole daemon |
| Cache | SHA-256 content-addressed projects | Manual | Custom |
| Hosts | Pi, omp, MCP clients | Usually one | Usually one |

The design trades warm-call latency for crash isolation and predictable cancellation.
Batch related operations when latency matters.

> [!NOTE]
> Edits (`rename`, `comment`, `patch`) persist in the cached Ghidra project only.
> The source binary is copied into the cache and never modified.


## Example session

```text
❯ find the config parser, decompile it, and show what calls it

✓ ghidra  batch  4.2s
  functions  query="config"        → 6 matches
  decompile  address=140012a40     → C output + signature
  call_graph address=140012a40     → 2 callers, 5 callees

❯ what does the caller at 140010f20 pass in?

✓ ghidra  decompile  1.1s
  ...
```

The first call imports and analyzes the binary, so it takes as long as a normal
headless Ghidra analysis. Later calls reuse the cached project.

## Quick start

### Pi

```bash
pi install npm:pi-ghidra
```

From Git, or from a checkout:

```bash
pi install git:github.com/immutex/pi-ghidra
pi install ./pi-ghidra
```

### omp

```bash
omp plugin install pi-ghidra
```

Requires pi-ghidra 0.3.0 or newer on npm; that release adds the `omp.extensions`
manifest. From a checkout:

```bash
omp plugin link .
```

The package declares both `pi.extensions` and `omp.extensions`, so the same
`extensions/index.ts` loads under either harness. Skills ship in `skills/` and are
discovered by both.

### MCP (any client)

The `mcp/server.ts` entry point is a zero-dependency stdio MCP server over the same
runtime. Run it with Node 22.19+ (native TypeScript stripping):

```bash
node /path/to/pi-ghidra/mcp/server.ts
```

Register it with an MCP client, for example omp's `.mcp.json`:

```json
{
  "mcpServers": {
    "pi-ghidra": {
      "command": "node",
      "args": ["C:/path/to/pi-ghidra/mcp/server.ts"]
    }
  }
}
```

Command Code:

```bash
cmd mcp add-json pi-ghidra '{"command":"node","args":["C:/path/to/pi-ghidra/mcp/server.ts"]}' -s user
```

The server exposes one `ghidra` tool with the same schema as the extension, plus an
optional `cwd` argument for relative binary paths. It implements `initialize`,
`tools/list`, `tools/call`, `ping`, and `notifications/cancelled`.

### Requirements

| Component | Version |
|---|---|
| Ghidra | 12.x |
| JDK | 21 or newer |
| Node.js | 22.19+ (MCP server only; Pi and omp bundle their runtime) |
| Pi | 1.x, or omp 18.x, or any MCP client |

## Setup

No environment variables or config file are normally needed. On first use,
`pi-ghidra` searches common install locations on Windows, macOS, and Linux, including
package-manager roots and user folders.

If Ghidra is not found:

```text
/ghidra-setup
```

Select a detected installation, enter a directory, or pass one directly:

```text
/ghidra-setup C:\ghidra_12.1.2
```

You can also tell the agent: "My Ghidra is at `C:\ghidra_12.1.2`." It validates the
path with `action: "setup"` and persists it. In print, JSON, or MCP mode, call the
`setup` action directly instead of using the interactive command.

Settings live in the active harness agent directory:

| Harness | Default path |
|---|---|
| Pi | `~/.pi/agent/pi-ghidra.json` |
| omp | `~/.omp/agent/pi-ghidra.json` |
| Either | `PI_CODING_AGENT_DIR/pi-ghidra.json` |
| Override | `PI_GHIDRA_CONFIG` (full file path) |

Ghidra resolution order:

1. Per-call `ghidraHome`
2. `PI_GHIDRA_HOME`
3. `GHIDRA_HOME`
4. Saved setup
5. Automatic discovery

`JAVA_HOME` wins when it is JDK 21+; otherwise the saved `javaHome`, then common
JDK locations on Windows, macOS, and Linux. If none is selected, Ghidra uses the
Java on `PATH`.

Use `discover` to list candidates and `health` to report the active Ghidra, JDK,
cache, config path, and detected homes. `health` returns `error` and a `null`
`ghidraHome` when Ghidra is missing instead of failing, which makes it a safe first
diagnostic.

## Usage

Ask the agent to analyze a binary. The package exposes one `ghidra` tool and a skill
that teaches the efficient workflow.

Inventory in one JVM:

```json
{
  "action": "batch",
  "binary": "./sample.exe",
  "operations": [
    { "action": "info" },
    { "action": "functions", "query": "main", "limit": 20 },
    { "action": "strings", "query": "password", "limit": 50 },
    { "action": "imports", "limit": 100 }
  ]
}
```

Decompile an exact function:

```json
{
  "action": "decompile",
  "binary": "./sample.exe",
  "address": "140001000"
}
```

Trace what reaches a function, then inspect its callees:

```json
{
  "action": "batch",
  "binary": "./sample.exe",
  "operations": [
    { "action": "references", "address": "140001000", "direction": "to", "limit": 50 },
    { "action": "call_graph", "address": "140001000", "limit": 50 }
  ]
}
```

## Actions

| Action | Purpose |
|---|---|
| `discover` | Find installed Ghidra 12 locations |
| `setup` | Validate and persist Ghidra, JDK, and cache locations |
| `health` | Report Ghidra, Java, cache, config, and detected homes |
| `analyze`, `info` | Import/analyze as needed and return program metadata |
| `rebuild` | Delete the cached project and analyze from a clean import |
| `functions`, `function` | List or inspect functions, parameters, locals, and signatures |
| `decompile` | Produce Ghidra decompiler C output |
| `disassemble`, `data` | Read instructions and defined data |
| `strings`, `symbols` | Search analyzer-defined strings and symbols |
| `imports`, `exports`, `entry_points` | Inspect linkage and entry points |
| `references`, `call_graph` | Inspect xrefs, callers, and callees |
| `memory_blocks`, `memory` | Inspect memory layout and read bytes |
| `search_bytes`, `search_text` | Search wildcard byte patterns or raw UTF-8 text |
| `analysis_options`, `set_analysis_options`, `reanalyze` | Inspect/configure analyzers and run fresh analysis passes |
| `rename`, `comment`, `patch` | Persist edits in the cached Ghidra project |
| `batch` | Run up to 50 operations in one Ghidra process |

Rules enforced before a JVM starts:

- `binary` is required for every operation action, `batch`, and `rebuild`.
- `decompile`, `function`, `call_graph`, `memory`, `references`, `comment`, `rename`,
  and `patch` need an `address` or `name`.
- `search_bytes` needs `pattern`; `search_text` needs `query`.
- `patch` needs `bytes`; `rename` needs `value`; `set_analysis_options` needs `options`.
- Unknown fields are rejected so typos fail loudly instead of being ignored.

List results accept `offset` and `limit`; the maximum page is 2,000 items. Memory reads
and patches are capped at 1 MiB. Byte and text searches scan at most 64 MiB and return
`{ matches, scannedBytes, truncated }`. Tool output is capped at 50 KB; the extension
writes the full JSON to a temporary file when truncated, and MCP clients get a
truncation notice.

## Cache

Projects are content-addressed by the input binary's SHA-256 and serialized per
artifact with a lock file, so concurrent calls cannot corrupt a project.

| Platform | Default cache |
|---|---|
| Windows | `%LOCALAPPDATA%\pi-ghidra` |
| macOS | `~/Library/Caches/pi-ghidra` |
| Linux | `~/pi-ghidra-cache` |

Override per call with `cacheDir`, persist one through `setup`, or set
`PI_GHIDRA_CACHE`. Ghidra rejects project paths containing dot-prefixed directory
components, so avoid paths such as `~/.cache/pi-ghidra`. On Windows, paths containing
`&`, `%`, `!`, `^`, `|`, `<`, `>`, `"`, `?`, or `*` are also rejected.

Analysis imports are staged in `project.next` and renamed into place only after a
successful run, so a crash cannot leave a half-written cache. `PI_GHIDRA_CPUS`
controls `-max-cpu` (default 2, capped at 4).

## Architecture

```text
extensions/index.ts   Pi/omp tool + /ghidra-setup command
mcp/server.ts         stdio JSON-RPC 2.0 wrapper (no dependencies)
src/runtime.ts        validation, discovery, cache, locks, process control
src/schema.ts         one JSON Schema shared by every host
src/metadata.ts       tool descriptions shared by every host
src/text.ts           UTF-8-safe output truncation
ghidra_scripts/
  PiGhidra.java       the only Ghidra-side adapter
skills/ghidra/
  SKILL.md            workflow guidance for the agent
```

One call follows a fixed path:

```text
tool call
  -> validate request
  -> resolve Ghidra 12 + JDK
  -> hash binary, acquire per-artifact lock
  -> import + analyze (staged) or reuse cached project
  -> analyzeHeadless -process -postScript PiGhidra.java request.json response.json
  -> validate response JSON
  -> release lock, return result
```

Ghidra's stdout is treated as diagnostics, never as protocol. Requests and responses
are files, so quoting and log noise cannot corrupt a result.

## Development

```bash
npm install
npm run check          # tsc --noEmit
npm test               # unit + MCP protocol tests
npm run pack:check     # inspect the published file set
```

Run the real-Ghidra suite:

```bash
GHIDRA_HOME=/path/to/ghidra \
GHIDRA_TEST_BINARY=/path/to/test-binary \
npm run test:integration
```

PowerShell:

```powershell
$env:GHIDRA_HOME = "C:\ghidra_12.1.2"
$env:GHIDRA_TEST_BINARY = "C:\Windows\System32\where.exe"
npm run test:integration
```

The integration suite imports a real binary, batches inventory and decompilation,
applies a rename/comment/patch, verifies the edit, and restores the original state.

Load the extension under either harness without installing it:

```bash
pi -e ./pi-ghidra
omp --no-extensions -e ./extensions/index.ts
```

## Security

Ghidra parses untrusted binaries with native components. This package provides
process isolation, bounded output, and a path allowlist for its own artifacts; it is
not an OS sandbox. Analyze hostile files in a disposable VM or container.

The tool deliberately does not expose arbitrary Java/Python execution, arbitrary
project paths, or a network transport. Patch and rename operations affect only the
cached project. Report vulnerabilities privately through
[GitHub Security Advisories](https://github.com/immutex/pi-ghidra/security/advisories/new);
see [SECURITY.md](SECURITY.md).


## FAQ

**Does it modify the binary?**
No. The binary is copied into the cache and hashed. `rename`, `comment`, and `patch`
change only the cached Ghidra project.

**Can I use it without Pi?**
Yes. omp loads the same extension, and `mcp/server.ts` exposes the same tool to any
MCP client.

**Does it support Ghidra 11?**
No. The adapter uses Ghidra 12 APIs and validates `application.version` against `12.`.

**Why is the first call slow?**
It starts a JVM, imports the binary, and runs the analyzers. Use `batch` to amortize
the JVM start, and reuse the SHA-256 cache for later calls.

**Can two analyses run at once?**
Different binaries run in parallel. Calls for the same binary are serialized by a lock
so the project cannot be corrupted.

**Is there a JavaScript API?**
`src/runtime.ts` exports `runGhidra`, `discoverGhidraHomes`, `resolveGhidraHome`,
`validateGhidraRequest`, and the action constants. The Pi/omp extension and MCP server
are thin adapters over it.

**Where do I report a security issue?**
Through [GitHub Security Advisories](https://github.com/immutex/pi-ghidra/security/advisories/new),
never in a public issue.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) for setup, the code layout, and the checks CI
runs. Every trap that costs real time should end up as a test or a documented
constraint.

- [Changelog](CHANGELOG.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Security policy](SECURITY.md)

## License

MIT. Ghidra is a separate Apache-2.0 project and is not bundled.

**Topics:** `ghidra` · `reverse-engineering` · `binary-analysis` · `decompiler` ·
`disassembler` · `headless` · `mcp` · `mcp-server` · `pi-package` · `pi` · `omp` ·
`oh-my-pi` · `ai-agent` · `malware-analysis` · `firmware`
