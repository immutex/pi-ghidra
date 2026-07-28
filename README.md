# pi-ghidra

Autonomous, native Ghidra tools for [Pi](https://pi.dev). No GUI, bridge server, open Ghidra window, or manual project setup is required.

`pi-ghidra` invokes Ghidra's official `analyzeHeadless` launcher, imports and analyzes a binary on first use, and reuses a SHA-256-keyed project on later calls. Related operations can be batched into one JVM invocation.

## Requirements

- Pi
- Ghidra 12.x
- The JDK required by your Ghidra release
- Node.js 20+

Ghidra is resolved in this order:

1. `ghidraHome` on a tool call
2. `PI_GHIDRA_HOME`
3. `GHIDRA_HOME`
4. Common install locations, including `C:\ghidra_12.1.2`

On Windows, `JAVA_HOME` is used when set. Otherwise common Eclipse Adoptium and Oracle JDK locations are checked automatically.

## Install

```bash
pi install npm:pi-ghidra
```

From Git:

```bash
pi install git:github.com/OWNER/pi-ghidra
```

Try a local checkout:

```bash
pi -e ./pi-ghidra
```

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

Override with `PI_GHIDRA_CACHE`, `cacheDir`, or both. Ghidra rejects project paths containing dot-prefixed directory components, so avoid paths such as `~/.cache/pi-ghidra`.

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
