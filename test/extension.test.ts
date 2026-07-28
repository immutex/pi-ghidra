import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import ghidraExtension from "../extensions/index.ts";
import { readGhidraConfig } from "../src/runtime.ts";

test("/ghidra-setup persists a direct path without interactive UI", async () => {
	const root = await mkdtemp(join(tmpdir(), "pi-ghidra-command-test-"));
	const oldConfigDir = process.env.PI_CODING_AGENT_DIR;
	const commands = new Map<string, { handler: (args: string, ctx: any) => Promise<void> }>();
	const notifications: string[] = [];
	try {
		process.env.PI_CODING_AGENT_DIR = join(root, "pi-config");
		await mkdir(join(root, "Ghidra"), { recursive: true });
		await mkdir(join(root, "support"), { recursive: true });
		await writeFile(join(root, "Ghidra", "application.properties"), "application.version=12.1.2\n");
		await writeFile(
			join(root, "support", process.platform === "win32" ? "analyzeHeadless.bat" : "analyzeHeadless"),
			"",
		);
		ghidraExtension({
			registerCommand(name: string, command: any) {
				commands.set(name, command);
			},
			registerTool() {},
		} as unknown as ExtensionAPI);
		const command = commands.get("ghidra-setup");
		assert.ok(command);
		await command.handler(root, {
			cwd: process.cwd(),
			hasUI: false,
			signal: undefined,
			ui: { notify(message: string) { notifications.push(message); } },
		});
		assert.equal(readGhidraConfig().ghidraHome, root);
		assert.match(notifications[0], /configured/);
	} finally {
		if (oldConfigDir === undefined) delete process.env.PI_CODING_AGENT_DIR;
		else process.env.PI_CODING_AGENT_DIR = oldConfigDir;
		await rm(root, { recursive: true, force: true });
	}
});
