# Contributing

Thanks for helping improve pi-ghidra. This guide covers setup, the parts of the code
that matter in review, and the checks CI runs.

## Setup

Requirements:

- Node.js 20+ (22.18+ to run the MCP server directly)
- JDK 21+
- Ghidra 12.x

```bash
npm install
npm run check
npm test
```

For end-to-end coverage, point the integration suite at a real installation:

```bash
GHIDRA_HOME=/path/to/ghidra GHIDRA_TEST_BINARY=/path/to/test-binary npm run test:integration
```

The binary is imported and analyzed in a temporary cache, then removed. Prefer a
small executable such as `where.exe` on Windows or `/bin/true` on Linux; the suite
takes a couple of minutes because it starts a real JVM.

## Layout

| Path | Responsibility |
|---|---|
| `extensions/index.ts` | Pi/omp tool registration and `/ghidra-setup` |
| `mcp/server.ts` | stdio JSON-RPC wrapper, no dependencies |
| `src/runtime.ts` | validation, discovery, cache, locks, process control |
| `src/schema.ts` | the single tool input schema |
| `src/metadata.ts` | tool and field descriptions |
| `src/text.ts` | UTF-8-safe truncation |
| `ghidra_scripts/PiGhidra.java` | the only Ghidra API adapter |
| `skills/ghidra/SKILL.md` | agent workflow guidance |

Rules that keep the design small:

- Keep one Ghidra-side adapter. Do not add a Java script per action.
- Keep the MCP server dependency-free.
- Add a new action in four places: `ACTIONS` and validation in `src/runtime.ts`, the
  schema in `src/schema.ts`, the dispatch and implementation in `PiGhidra.java`, and
  the README/skill tables.
- Share descriptions instead of copying them between hosts.

## Style

- TypeScript: tabs, double quotes, strict types. No `any` in new code.
- Java: four spaces, no wildcard imports, `Locale.ROOT` for case folding.
- Fail closed: reject unknown fields and invalid ranges before spawning a JVM.
- Never parse Ghidra stdout as protocol; use the request/response files.
- Keep user-facing errors actionable: name the field, the valid range, or the path.

Comments should explain a non-obvious constraint, not restate the next line.

## Tests

`npm test` covers request validation, configuration resolution, truncation, the
extension command, and the MCP protocol. Add a unit test when behavior is observable
without Ghidra. Add the integration suite when the change depends on the Ghidra API.

Before opening a pull request:

```bash
npm run check
npm test
npm run pack:check
```

If you touched `PiGhidra.java`, run the integration suite as well. A Java compile
error only appears when Ghidra loads the script, so the unit tests cannot catch it.

## Commits and pull requests

- One logical change per pull request.
- Describe the failure mode being fixed, not only the new code.
- Include the commands you ran and their result.
- Update `CHANGELOG.md` for user-visible changes.
- Update the README and skill when the action surface changes.

## Reporting bugs

Open an issue with:

- OS, Node version, Ghidra version, and JDK version
- The action and a redacted request body
- The error message and, when available, the tail of the Ghidra log

Never attach proprietary binaries. Reproduce with a public sample or describe the
binary format and the failing action.
