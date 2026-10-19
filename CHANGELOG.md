# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-10-19

### Added

- omp support: `omp.extensions` manifest, omp agent-directory config resolution,
  and install instructions for `omp plugin install` / `omp plugin link`.
- Shared JSON Schema (`src/schema.ts`) and metadata (`src/metadata.ts`) so the Pi
  extension and MCP server cannot drift.
- Request validation for every entry point: unknown fields, action requirements,
  ranges, batch size, and per-action target rules fail before a JVM starts.
- `PI_GHIDRA_CONFIG` to relocate the settings file.
- MCP protocol tests and validation/truncation unit tests.
- Community files: contributing guide, security policy, code of conduct, changelog,
  issue templates, pull request template, and Dependabot.

### Changed

- MCP server negotiates the client protocol version, advertises server instructions,
  reports its version from `package.json`, and exits only after in-flight calls settle.
- Search actions return `{ matches, scannedBytes, truncated }` instead of a bare array,
  so a truncated scan is visible.
- `exports` now includes the primary symbol type/source and every symbol at the address.
- `health` returns `ghidraHome: null` plus an `error` when Ghidra is missing.
- TypeScript target raised to ES2024 with `noUncheckedIndexedAccess`.
- README rewritten with host-specific quick starts, architecture, and SEO metadata.

### Fixed

- Cache imports are staged in `project.next` and renamed after success; a crash can no
  longer leave a half-written project.
- Manifests are validated before use and written atomically.
- Config saves merge only defined fields instead of writing `undefined` keys.
- A stale reaper directory no longer blocks artifact locks forever.
- Lock and queue waits honor cancellation.
- Cancelling a queued call releases the queue slot.
- `rebuild` and `batch` now require a binary.
- Windows cache-path validation no longer rejects valid POSIX paths.
- Ghidra script failures surface the script's structured error instead of `exit 1`.
- Java: locale-independent case folding, two-digit hex validation, address parsing
  without unchecked exceptions, partial memory reads across holes, deterministic call
  graph ordering, pagination for references and call graphs, bounded batch size, and
  safer numeric parsing.
- UTF-8 truncation no longer splits a multi-byte character.
- Extension no longer imports host-only helpers, so the same module loads under omp.

### Removed

- Unused `StringEnum`, `formatSize`, and host `truncateHead` imports.
- `NPM_PUBLISH_STEPS.tmp.md` (publishing steps moved to the README/CONTRIBUTING flow).

## [0.2.0] - 2026-07-28

### Added

- Guided setup, automatic Ghidra discovery, `/ghidra-setup`, and persistent settings.
- MCP stdio server exposing the same tool as the extension.
- Health, discover, and setup actions.
- Real-Ghidra integration suite.

## [0.1.0] - 2026-07-27

### Added

- Initial release: headless import/analysis, decompilation, listing queries, xrefs,
  call graphs, memory, searches, reanalysis, and cached project edits.
