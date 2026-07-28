import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { runGhidra } from "../src/runtime.ts";

const ghidraHome = process.env.GHIDRA_HOME;
const binary = process.env.GHIDRA_TEST_BINARY;

test("real Ghidra headless analysis", { skip: !ghidraHome || !binary, timeout: 20 * 60_000 }, async () => {
  const cacheDir = await mkdtemp(join(tmpdir(), "pi-ghidra-integration-"));
  const base = { binary, ghidraHome, cacheDir };
  try {
    const imported = await runGhidra({ ...base, action: "info" });
    const info = imported.result as { functionCount: number; format: string };
    assert.ok(info.functionCount > 0);
    assert.ok(info.format);

    const inventory = await runGhidra({
      ...base,
      action: "batch",
      operations: [
        { action: "functions", limit: 5 },
        { action: "strings", limit: 5 },
        { action: "imports", limit: 5 },
        { action: "memory_blocks" },
        { action: "entry_points" },
        { action: "analysis_options" },
      ],
    });
    const results = inventory.result as Array<{ action: string; result: unknown }>;
    const functions = results[0].result as Array<{ entry: string; name: string }>;
    assert.ok(functions.length > 0);
    assert.ok((results[3].result as unknown[]).length > 0);

    const entry = functions[0].entry;
    const name = functions[0].name;
    const inspected = await runGhidra({
      ...base,
      action: "batch",
      operations: [
        { action: "decompile", address: entry },
        { action: "disassemble", address: entry, limit: 5 },
        { action: "references", address: entry, limit: 5 },
        { action: "call_graph", address: entry, limit: 5 },
        { action: "memory", address: entry, length: 8 },
        { action: "search_bytes", pattern: "??", limit: 1 },
      ],
    });
    const inspectedResults = inspected.result as Array<{ action: string; result: unknown }>;
    assert.match((inspectedResults[0].result as { code: string }).code, /\S/);
    assert.equal((inspectedResults[1].result as unknown[]).length, 5);
    const bytes = (inspectedResults[4].result as { hex: string }).hex;

    await runGhidra({
      ...base,
      action: "batch",
      operations: [
        { action: "rename", address: entry, value: "pi_ghidra_integration_test" },
        { action: "comment", address: entry, value: "pi-ghidra integration test" },
        { action: "patch", address: entry, bytes },
      ],
    });
    const changed = await runGhidra({ ...base, action: "function", address: entry });
    assert.equal((changed.result as { name: string }).name, "pi_ghidra_integration_test");
    await runGhidra({
      ...base,
      action: "batch",
      operations: [
        { action: "rename", address: entry, value: name },
        { action: "comment", address: entry },
      ],
    });
  } finally { await rm(cacheDir, { recursive: true, force: true }); }
});
