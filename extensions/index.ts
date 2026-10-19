import { randomUUID } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Type, type Static, type TSchema } from "typebox";
import {
	discoverGhidraHomes,
	runGhidra,
	type GhidraRequest,
} from "../src/runtime.ts";
import { TOOL_DESCRIPTION, TOOL_NAME } from "../src/metadata.ts";
import { TOOL_INPUT_SCHEMA } from "../src/schema.ts";
import { truncateHead } from "../src/text.ts";

// `TOOL_INPUT_SCHEMA` is plain JSON Schema so the MCP server can share it
// without a runtime dependency. The host needs a TypeBox schema, and the
// generated JSON is identical.
const paramsSchema = Type.Unsafe<GhidraRequest>(
	TOOL_INPUT_SCHEMA as unknown as TSchema,
);
type Params = Static<typeof paramsSchema>;

function formatBytes(bytes: number): string {
	if (bytes < 1024) return `${bytes} B`;
	if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
	return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function unquote(value: string): string {
	const trimmed = value.trim();
	return trimmed.replace(/^"(.*)"$/s, "$1");
}

export default function ghidraExtension(pi: ExtensionAPI) {
	pi.registerCommand("ghidra-setup", {
		description: "Find or configure the local Ghidra 12 installation",
		handler: async (args, ctx) => {
			let home = unquote(args);
			if (!home) {
				const candidates = discoverGhidraHomes(true);
				if (candidates.length === 1) home = candidates[0] ?? "";
				else if (ctx.hasUI) {
					const manual = "Enter another location...";
					const selected = candidates.length
						? await ctx.ui.select("Select Ghidra 12", [...candidates, manual])
						: manual;
					if (selected === manual)
						home = (await ctx.ui.input("Ghidra 12 installation directory"))?.trim() ?? "";
					else home = selected ?? "";
				} else {
					ctx.ui.notify("Usage: /ghidra-setup /path/to/ghidra", "warning");
					return;
				}
			}
			if (!home) return;
			try {
				const result = await runGhidra(
					{ action: "setup", ghidraHome: home },
					ctx.cwd,
					ctx.signal,
				);
				const details = result.result as {
					configPath: string;
					version: string;
				};
				ctx.ui.notify(
					`Ghidra ${details.version} configured in ${details.configPath}`,
					"info",
				);
			} catch (error) {
				ctx.ui.notify(
					error instanceof Error ? error.message : String(error),
					"error",
				);
			}
		},
	});

	pi.registerTool({
		name: TOOL_NAME,
		label: "Ghidra",
		description: TOOL_DESCRIPTION,
		promptSnippet: "Analyze binaries autonomously with headless Ghidra",
		promptGuidelines: [
			"Use ghidra directly for binary analysis; do not ask the user to open Ghidra.",
			"If Ghidra is not found, use ghidra action=discover, then action=setup with the chosen ghidraHome; setup persists it globally.",
			"When the user states their Ghidra location, use ghidra action=setup to save it instead of requiring an environment variable.",
			"Use ghidra with action=batch for related queries to avoid repeated JVM startup.",
			"Use ghidra action=functions or symbols to discover canonical addresses before decompiling or mutating.",
		],
		parameters: paramsSchema,
		async execute(_toolCallId, params: Params, signal, onUpdate, ctx) {
			onUpdate?.({
				content: [
					{ type: "text", text: `Running Ghidra: ${params.action}...` },
				],
				details: { action: params.action },
			});
			const result = await runGhidra(params, ctx.cwd, signal);
			const output = JSON.stringify(result, null, 2);
			const truncated = truncateHead(output, 50_000, 1500);
			let text = truncated.content;
			if (truncated.truncated) {
				const fullPath = join(tmpdir(), `pi-ghidra-${randomUUID()}.json`);
				await writeFile(fullPath, output);
				text += `\n\n[Output truncated: ${truncated.outputLines}/${truncated.totalLines} lines, ${formatBytes(truncated.outputBytes)}/${formatBytes(truncated.totalBytes)}. Full output: ${fullPath}]`;
			}
			return { content: [{ type: "text", text }], details: result };
		},
	});
}
