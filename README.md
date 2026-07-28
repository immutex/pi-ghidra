# pi-ghidra

Autonomous, native Ghidra tools for [Pi](https://pi.dev). No GUI, bridge server, open Ghidra window, or manual project setup is required.

`pi-ghidra` invokes Ghidra's official `analyzeHeadless` launcher, imports and analyzes a binary on first use, and reuses a SHA-256-keyed project on later calls. Related operations can be batched into one JVM invocation.

## Requirements

- Pi
- Ghidra 12.x
- JDK 21 or newer
- Node.js 20+

## Install

```bash
pi install npm:pi-ghidra
```

From Git:

```bash
pi install git:github.com/immutex/pi-ghidra
```

Try a local checkout:

```bash
pi -e ./pi-ghidra
```

## Setup

No environment variables or manual config file are normally needed. On first use, `pi-ghidra` searches common Windows, macOS, and Linux install locations.

If Ghidra is not found, run:

```text
/ghidra-setup
```

Select a detected installation, enter a directory, or pass it directly:

```text
/ghidra-setup C:\ghidra_12.1.2
```

You can also tell Pi: “My Ghidra is at `C:\ghidra_12.1.2`.” Pi will validate and save it. In print or JSON mode, provide the path through the `setup` tool action instead of using the interactive command.

Saved settings live in `~/.pi/agent/pi-ghidra.json`, or `PI_CODING_AGENT_DIR/pi-ghidra.json` when that variable is set. The `setup` action can also persist optional `javaHome` and `cacheDir` values.

Ghidra location precedence is:

1. Per-call `ghidraHome`
2. `PI_GHIDRA_HOME`
3. `GHIDRA_HOME`
4. Saved setup
5. Automatic discovery

A working `JAVA_HOME` takes precedence over a saved JDK. On Windows, common Eclipse Adoptium and Oracle JDK locations are also detected. If no JDK home is selected, Ghidra can use Java from `PATH`.

Use `discover` to list detected installations and `health` to show the active Ghidra, JDK, cache, and saved settings.

## Usage

Ask Pi to analyze a binary normally. The package exposes one `ghidra` tool and a skill that teaches Pi the efficient workflow.

Example tool input:

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

Then decompile an exact function:

```json
{
  "action": "decompile",
  "binary": "./sample.exe",
  "address": "140001000"
}
```

## Actions

| Action | Purpose |
| --- | --- |
| `discover` | Find installed Ghidra 12 locations |
| `setup` | Validate and persist Ghidra, JDK, and cache locations |
| `health` | Show detected Ghidra, Java, cache, and capabilities |
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

List results accept `offset` and `limit`; the maximum page is 2,000 items. Memory reads and patches are capped at 1 MiB. Tool output is capped at 50 KB and the full JSON is saved to a temporary file when truncated.

## Cache

Projects are content-addressed by the input binary's SHA-256 and serialized per artifact. Defaults:

- Windows: `%LOCALAPPDATA%\pi-ghidra`
- macOS: `~/Library/Caches/pi-ghidra`
- Linux: `~/pi-ghidra-cache`

Override per call with `cacheDir`, persist a cache directory through the `setup` action, or set `PI_GHIDRA_CACHE`. Ghidra rejects project paths containing dot-prefixed directory components, so avoid paths such as `~/.cache/pi-ghidra`.

Edits affect only the cached Ghidra project. The source binary is copied and never modified.

## Development

```bash
npm install
npm run check
npm test
npm run pack:check
```

Run the real-Ghidra integration suite:

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

## Security

Ghidra parses untrusted binaries with native components. This package provides process isolation and bounded output, not an OS sandbox. Analyze hostile files in a disposable VM or container. The package deliberately does not expose arbitrary Java/Python execution or network transport.

## License

MIT. Ghidra is a separate Apache-2.0-licensed project and is not bundled.
