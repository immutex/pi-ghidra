import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
	ACTIONS,
	hashFile,
	resolveGhidraHome,
	runGhidra,
} from "../src/runtime.ts";

test("hashFile returns SHA-256", async () => {
	const root = await mkdtemp(join(tmpdir(), "pi-ghidra-test-"));
	try {
		const file = join(root, "sample.bin");
		await writeFile(file, "abc");
		assert.equal(
			await hashFile(file),
			"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
		);
	} finally {
		await rm(root, { recursive: true, force: true });
	}
});

test("explicit Ghidra home and health require no GUI", async () => {
	const root = await mkdtemp(join(tmpdir(), "pi-ghidra-test-"));
	try {
		await mkdir(join(root, "Ghidra"), { recursive: true });
		await mkdir(join(root, "support"), { recursive: true });
		await writeFile(
			join(root, "Ghidra", "application.properties"),
			"application.version=12.1.2\n",
		);
		await writeFile(
			join(
				root,
				"support",
				process.platform === "win32"
					? "analyzeHeadless.bat"
					: "analyzeHeadless",
			),
			"",
		);
		assert.equal(resolveGhidraHome(root), root);
		const result = await runGhidra({
			action: "health",
			ghidraHome: root,
			cacheDir: join(root, "cache"),
		});
		assert.equal((result.result as { version: string }).version, "12.1.2");
		assert.deepEqual((result.result as { actions: string[] }).actions, ACTIONS);
		await writeFile(
			join(root, "Ghidra", "application.properties"),
			"application.version=11.4\n",
		);
		assert.throws(() => resolveGhidraHome(root), /Ghidra 12 is required/);
	} finally {
		await rm(root, { recursive: true, force: true });
	}
});

test("missing binaries fail before Ghidra starts", async () => {
	const root = await mkdtemp(join(tmpdir(), "pi-ghidra-test-"));
	try {
		await mkdir(join(root, "Ghidra"), { recursive: true });
		await mkdir(join(root, "support"), { recursive: true });
		await writeFile(
			join(root, "Ghidra", "application.properties"),
			"application.version=12.1.2\n",
		);
		await writeFile(
			join(
				root,
				"support",
				process.platform === "win32"
					? "analyzeHeadless.bat"
					: "analyzeHeadless",
			),
			"",
		);
		await assert.rejects(
			runGhidra({ action: "info", binary: "missing.bin", ghidraHome: root }),
			/Binary not found/,
		);
		const binary = join(root, "sample.bin");
		await writeFile(binary, "abc");
		await assert.rejects(
			runGhidra({
				action: "info",
				binary,
				ghidraHome: root,
				cacheDir: join(root, ".hidden"),
			}),
			/dot-prefixed/,
		);
		const controller = new AbortController();
		controller.abort();
		await assert.rejects(
			runGhidra(
				{
					action: "info",
					binary,
					ghidraHome: root,
					cacheDir: join(root, "cache"),
				},
				process.cwd(),
				controller.signal,
			),
			/cancelled/,
		);
	} finally {
		await rm(root, { recursive: true, force: true });
	}
});
