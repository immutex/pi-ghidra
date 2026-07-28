---
name: ghidra
summary: Autonomously reverse engineer binaries with Ghidra headless tools.
description: Use when analyzing executables, firmware, libraries, object files, malware, or unknown binaries with Ghidra. Covers automatic import/analysis, decompilation, symbols, strings, xrefs, call graphs, memory, searches, reanalysis, and safe program-database edits without opening the Ghidra GUI.
---

# Ghidra

Use the `ghidra` tool directly. Never ask the user to open Ghidra.

1. Start with `action: "info"` and the binary path. Import and analysis happen automatically.
2. If Ghidra is not found, use `action: "discover"`. If the user provides or chooses a location, use `action: "setup"` with `ghidraHome`; it persists globally.
3. Use `action: "batch"` for related inventory calls: `functions`, `strings`, `imports`, `exports`, `memory_blocks`, and `entry_points`.
4. Resolve exact function entry addresses before `decompile`, `disassemble`, `references`, `call_graph`, `rename`, or `comment`.
5. Prefer addresses over names after discovery because names can collide or change.
6. Paginate broad output with `offset` and `limit`.
7. Use `reanalyze` after changing analysis options. Use `rebuild` only when a clean import is required.
8. Treat `rename`, `comment`, and `patch` as persistent edits to the cached Ghidra project. `patch` changes the project database, never the source binary.
9. Report decompiler warnings and analyzer uncertainty instead of presenting inferred types or indirect calls as facts.

`search_text` searches raw UTF-8 bytes. Use `strings` with `query` for analyzer-defined strings and other encodings.
