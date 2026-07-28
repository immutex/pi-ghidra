import { randomUUID } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { formatSize, truncateHead } from "@earendil-works/pi-coding-agent";
import { StringEnum } from "@earendil-works/pi-ai";
import { Type, type Static } from "typebox";
import {
	ACTIONS,
	discoverGhidraHomes,
	runGhidra,
	type GhidraRequest,
} from "../src/runtime.ts";

const OPERATION_ACTIONS = ACTIONS.filter(
	(action) => !["discover", "setup", "health", "batch", "rebuild"].includes(action),
);

const operationSchema = Type.Object({
	action: StringEnum(OPERATION_ACTIONS),
	address: Type.Optional(
		Type.String({
			description:
				"Address such as 00401000, ram:00401000, or function address",
		}),
	),
	name: Type.Optional(Type.String({ description: "Function or symbol name" })),
	query: Type.Optional(
		Type.String({ description: "Text/name filter or UTF-8 text to search" }),
	),
	pattern: Type.Optional(
		Type.String({
			description: "Hex byte pattern with ?? wildcards, such as '48 8b ?? 89'",
		}),
	),
	value: Type.Optional(
		Type.String({ description: "New name or comment text" }),
	),
	bytes: Type.Optional(Type.String({ description: "Hex bytes for patch" })),
	commentType: Type.Optional(
		StringEnum(["EOL", "PRE", "POST", "PLATE", "REPEATABLE"] as const),
	),
	direction: Type.Optional(StringEnum(["to", "from", "both"] as const)),
	offset: Type.Optional(Type.Integer({ minimum: 0 })),
	limit: Type.Optional(Type.Integer({ minimum: 1, maximum: 2000 })),
	length: Type.Optional(Type.Integer({ minimum: 1, maximum: 1048576 })),
	timeoutSeconds: Type.Optional(Type.Integer({ minimum: 1, maximum: 900 })),
	options: Type.Optional(Type.Record(Type.String(), Type.String())),
});

const paramsSchema = Type.Object({
	action: StringEnum(ACTIONS),
	binary: Type.Optional(
		Type.String({
			description:
				"Binary path, absolute or relative to Pi's current directory. Required except for discover, setup, and health.",
		}),
	),
	address: Type.Optional(
		Type.String({
			description:
				"Address such as 00401000, ram:00401000, or function address",
		}),
	),
	name: Type.Optional(Type.String({ description: "Function or symbol name" })),
	query: Type.Optional(
		Type.String({ description: "Text/name filter or UTF-8 text to search" }),
	),
	pattern: Type.Optional(
		Type.String({ description: "Hex byte pattern with ?? wildcards" }),
	),
	value: Type.Optional(
		Type.String({
			description: "New name or comment text; omit to remove a comment",
		}),
	),
	bytes: Type.Optional(Type.String({ description: "Hex bytes for patch" })),
	commentType: Type.Optional(
		StringEnum(["EOL", "PRE", "POST", "PLATE", "REPEATABLE"] as const),
	),
	direction: Type.Optional(StringEnum(["to", "from", "both"] as const)),
	offset: Type.Optional(Type.Integer({ minimum: 0 })),
	limit: Type.Optional(Type.Integer({ minimum: 1, maximum: 2000 })),
	length: Type.Optional(Type.Integer({ minimum: 1, maximum: 1048576 })),
	timeoutSeconds: Type.Optional(Type.Integer({ minimum: 1, maximum: 900 })),
	options: Type.Optional(Type.Record(Type.String(), Type.String())),
	operations: Type.Optional(
		Type.Array(operationSchema, { minItems: 1, maxItems: 50 }),
	),
	ghidraHome: Type.Optional(
		Type.String({
			description:
				"Ghidra install root. Auto-detected when omitted; action=setup saves it for future sessions.",
		}),
	),
	javaHome: Type.Optional(
		Type.String({
			description: "Optional JDK root to persist with action=setup.",
		}),
	),
	cacheDir: Type.Optional(
		Type.String({ description: "Persistent analysis cache directory" }),
	),
	force: Type.Optional(
		Type.Boolean({
			description: "Discard cached project and import/analyze again",
		}),
	),
});

type Params = Static<typeof paramsSchema>;

export default function ghidraExtension(pi: ExtensionAPI) {
	pi.registerCommand("ghidra-setup", {
		description: "Find or configure the local Ghidra 12 installation",
		handler: async (args, ctx) => {
			let home = args.trim().replace(/^"(.*)"$/, "$1");
			if (!home) {
				const candidates = discoverGhidraHomes(true);
				if (candidates.length === 1) home = candidates[0];
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
				const result = await runGhidra({ action: "setup", ghidraHome: home }, ctx.cwd, ctx.signal);
				const details = result.result as { configPath: string; version: string };
				ctx.ui.notify(`Ghidra ${details.version} configured in ${details.configPath}`, "info");
			} catch (error) {
				ctx.ui.notify(error instanceof Error ? error.message : String(error), "error");
			}
		},
	});

	pi.registerTool({
		name: "ghidra",
		label: "Ghidra",
		description:
			"Run autonomous Ghidra 12 headless reverse engineering. Automatically discovers common installations; discover lists candidates and setup persists a chosen path. Imports and analyzes binaries automatically, caches projects by SHA-256, decompiles functions, queries listings/symbols/xrefs/call graphs/memory, reruns analyzers, and applies renames/comments/patches. Use batch to run up to 50 operations in one JVM. Results are capped at 50KB; use offset/limit for pagination.",
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
			const result = await runGhidra(params as GhidraRequest, ctx.cwd, signal);
			const output = JSON.stringify(result, null, 2);
			const truncated = truncateHead(output, {
				maxBytes: 50_000,
				maxLines: 1500,
			});
			let text = truncated.content;
			if (truncated.truncated) {
				const fullPath = join(tmpdir(), `pi-ghidra-${randomUUID()}.json`);
				await writeFile(fullPath, output);
				text += `\n\n[Output truncated: ${truncated.outputLines}/${truncated.totalLines} lines, ${formatSize(truncated.outputBytes)}/${formatSize(truncated.totalBytes)}. Full output: ${fullPath}]`;
			}
			return { content: [{ type: "text", text }], details: result };
		},
	});
}
