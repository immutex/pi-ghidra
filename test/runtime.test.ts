import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
	ACTIONS,
	discoverGhidraHomes,
	ghidraConfigPath,
	hashFile,
	parseJavaMajor,
	readGhidraConfig,
	resolveGhidraHome,
	runGhidra,
	validateGhidraRequest,
} from "../src/runtime.ts";
import { truncateHead, truncateUtf8 } from "../src/text.ts";
import { TOOL_INPUT_SCHEMA } from "../src/schema.ts";

test("Java version parsing enforces the Ghidra 12 baseline", () => {
	assert.equal(parseJavaMajor('openjdk version "17.0.12"'), 17);
	assert.equal(parseJavaMajor('openjdk version "21.0.8"'), 21);
	assert.equal(parseJavaMajor('java version "1.8.0_401"'), 8);
	assert.equal(parseJavaMajor("not java output"), undefined);
});

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

test("setup persists and reuses a discovered Ghidra home", async () => {
	const root = await mkdtemp(join(tmpdir(), "pi-ghidra-setup-test-"));
	const configDir = join(root, "pi-config");
	const oldConfigDir = process.env.PI_CODING_AGENT_DIR;
	const oldPiHome = process.env.PI_GHIDRA_HOME;
	const oldHome = process.env.GHIDRA_HOME;
	try {
		process.env.PI_CODING_AGENT_DIR = configDir;
		delete process.env.PI_GHIDRA_HOME;
		delete process.env.GHIDRA_HOME;
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
		const result = await runGhidra({
			action: "setup",
			ghidraHome: root,
			cacheDir: join(root, "cache"),
		});
		assert.equal(result.ghidraHome, root);
		assert.equal(ghidraConfigPath(), join(configDir, "pi-ghidra.json"));
		assert.equal(readGhidraConfig().ghidraHome, root);
		assert.equal(resolveGhidraHome(), root);
		assert.ok(discoverGhidraHomes().includes(root));
		const discovered = await runGhidra({ action: "discover" });
		assert.equal(discovered.ghidraHome, root);
		const secondCache = join(root, "cache-2");
		await runGhidra({
			action: "setup",
			ghidraHome: root,
			cacheDir: secondCache,
		});
		assert.equal(readGhidraConfig().cacheDir, secondCache);
		await writeFile(ghidraConfigPath(), "{broken json");
		await runGhidra({ action: "setup", ghidraHome: root });
		assert.equal(readGhidraConfig().ghidraHome, root);
		await assert.rejects(
			runGhidra({
				action: "setup",
				ghidraHome: root,
				cacheDir: join(root, ".hidden"),
			}),
			/dot-prefixed/,
		);
		await assert.rejects(
			runGhidra({
				action: "setup",
				ghidraHome: root,
				javaHome: join(root, "missing-java"),
			}),
			/working Java installation/,
		);
	} finally {
		if (oldConfigDir === undefined) delete process.env.PI_CODING_AGENT_DIR;
		else process.env.PI_CODING_AGENT_DIR = oldConfigDir;
		if (oldPiHome === undefined) delete process.env.PI_GHIDRA_HOME;
		else process.env.PI_GHIDRA_HOME = oldPiHome;
		if (oldHome === undefined) delete process.env.GHIDRA_HOME;
		else process.env.GHIDRA_HOME = oldHome;
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

test("requests are validated before any Ghidra process starts", () => {
	assert.throws(
		() => validateGhidraRequest({ action: "info" }),
		/binary is required/,
	);
	assert.throws(
		() =>
			validateGhidraRequest({
				action: "info",
				binary: "sample.exe",
				nope: true,
			}),
		/unknown field "nope"/,
	);
	assert.throws(
		() => validateGhidraRequest({ action: "batch", operations: [] }),
		/binary is required for batch/,
	);
	assert.throws(
		() =>
			validateGhidraRequest({
				action: "batch",
				binary: "sample.exe",
				operations: [{ action: "decompile" }],
			}),
		/address or name is required/,
	);
	assert.throws(
		() =>
			validateGhidraRequest({
				action: "batch",
				binary: "sample.exe",
				operations: [{ action: "batch", operations: [] }],
			}),
		/unknown field "operations"/,
	);
	assert.throws(
		() => validateGhidraRequest({ action: "rebuild" }),
		/binary is required for rebuild/,
	);
	assert.throws(
		() => validateGhidraRequest({ action: "health", binary: "x" }),
		/binary is not valid for health/,
	);
	assert.throws(
		() =>
			validateGhidraRequest({
				action: "info",
				binary: "sample.exe",
				limit: 5000,
			}),
		/limit must be between/,
	);
	const batch = validateGhidraRequest({
		action: "batch",
		binary: "sample.exe",
		operations: [
			{ action: "functions", query: "main" },
			{ action: "decompile", address: "140001000" },
		],
	});
	assert.equal(batch.operations?.length, 2);
});

test("output truncation never splits a UTF-8 character", () => {
	const text = "aaaa\n" + "é".repeat(40);
	const cut = truncateUtf8(text, 10);
	assert.equal(cut.truncated, true);
	assert.ok(!cut.text.includes("\uFFFD"));
	assert.ok(Buffer.byteLength(cut.text, "utf8") <= 10);
	const head = truncateHead(text, 64, 100);
	assert.equal(head.truncated, true);
	assert.equal(head.totalLines, 2);
	assert.equal(head.outputLines, 1);
	assert.equal(head.content, "aaaa");
	const whole = truncateHead("short", 64, 10);
	assert.equal(whole.truncated, false);
	assert.equal(whole.content, "short");
});

test("the shared schema matches the runtime action surface", () => {
	const action = TOOL_INPUT_SCHEMA.properties.action;
	assert.deepEqual([...action.enum], [...ACTIONS]);
	const operationAction = TOOL_INPUT_SCHEMA.properties.operations.items.properties.action;
	assert.ok(operationAction.enum.every((value) => ACTIONS.includes(value)));
	assert.equal(
		operationAction.enum.length,
		ACTIONS.length - 5,
		"batch, discover, health, rebuild, and setup are not operation actions",
	);
	assert.equal(TOOL_INPUT_SCHEMA.properties.limit.maximum, 2000);
	assert.equal(TOOL_INPUT_SCHEMA.properties.length.maximum, 1048576);
	assert.equal(TOOL_INPUT_SCHEMA.properties.operations.maxItems, 50);
});
