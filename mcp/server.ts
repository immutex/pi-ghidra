// MCP stdio wrapper around pi-ghidra's runtime, so any MCP client (Command
// Code, Claude Desktop, omp, ...) gets the same `ghidra` tool the Pi extension
// exposes. Zero dependencies: newline-delimited JSON-RPC 2.0 over stdio.
// Run with `node mcp/server.ts` on Node >= 22.18 (native type stripping).
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
	MAX_OUTPUT_BYTES,
	runGhidra,
	type GhidraRequest,
	type RunResult,
} from "../src/runtime.ts";
import { TOOL_DESCRIPTION, TOOL_NAME } from "../src/metadata.ts";
import { TOOL_INPUT_SCHEMA } from "../src/schema.ts";
import { truncateUtf8 } from "../src/text.ts";

const SERVER_NAME = "pi-ghidra";
const SUPPORTED_PROTOCOL_VERSIONS = [
	"2025-06-18",
	"2025-03-26",
	"2024-11-05",
] as const;
const FALLBACK_PROTOCOL_VERSION = "2024-11-05";
const TOOL_NOT_FOUND = -32602;

const PACKAGE_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const SERVER_VERSION = readPackageVersion();

interface JsonRpcMessage {
	jsonrpc: string;
	id?: number | string | null;
	method?: string;
	params?: unknown;
	result?: unknown;
	error?: { code: number; message: string; data?: unknown };
}

interface JsonRpcResponse {
	jsonrpc: "2.0";
	id: number | string | null;
	result?: unknown;
	error?: { code: number; message: string };
}

function readPackageVersion(): string {
	try {
		const manifest = JSON.parse(
			readFileSync(join(PACKAGE_ROOT, "package.json"), "utf8"),
		) as { version?: unknown };
		return typeof manifest.version === "string" ? manifest.version : "0.0.0";
	} catch {
		return "0.0.0";
	}
}

function truncateOutput(text: string): string {
	const result = truncateUtf8(text, MAX_OUTPUT_BYTES);
	if (!result.truncated) return text;
	return `${result.text}\n\n[Output truncated: ${Buffer.byteLength(text, "utf8")} bytes. Use offset/limit parameters to paginate.]`;
}

export function formatResult(result: RunResult): string {
	return truncateOutput(JSON.stringify(result, null, 2));
}

function response(
	id: number | string | null,
	result: unknown,
): JsonRpcResponse {
	return { jsonrpc: "2.0", id, result };
}

function errorResponse(
	id: number | string | null,
	code: number,
	message: string,
): JsonRpcResponse {
	return { jsonrpc: "2.0", id, error: { code, message } };
}

const toolDefinition = {
	name: TOOL_NAME,
	description: TOOL_DESCRIPTION,
	inputSchema: TOOL_INPUT_SCHEMA,
	annotations: {
		title: "Ghidra",
		readOnlyHint: false,
		openWorldHint: false,
	},
};

interface ToolCallParams {
	name?: unknown;
	arguments?: unknown;
}

const inflight = new Map<string, AbortController>();

async function callTool(
	id: number | string | null,
	params: ToolCallParams,
): Promise<JsonRpcResponse> {
	if (params.name !== TOOL_NAME)
		return errorResponse(id, TOOL_NOT_FOUND, `Unknown tool: ${String(params.name)}`);
	const args = params.arguments ?? {};
	const requestId = String(id ?? "notification");
	const controller = new AbortController();
	inflight.set(requestId, controller);
	try {
		if (typeof args !== "object" || args === null || Array.isArray(args))
			throw new Error("Tool arguments must be an object");
		const { cwd, ...request } = args as Record<string, unknown>;
		if (cwd !== undefined && typeof cwd !== "string")
			throw new Error("cwd must be a string");
		const result = await runGhidra(
			request as unknown as GhidraRequest,
			cwd || process.cwd(),
			controller.signal,
		);
		return response(id, {
			content: [{ type: "text", text: formatResult(result) }],
		});
	} catch (error) {
		return response(id, {
			content: [
				{
					type: "text",
					text: error instanceof Error ? error.message : String(error),
				},
			],
			isError: true,
		});
	} finally {
		inflight.delete(requestId);
	}
}

/**
 * Handle one decoded JSON-RPC message. Returns null for notifications and for
 * client responses, which never receive a reply.
 */
export async function handleMessage(
	message: JsonRpcMessage,
): Promise<JsonRpcResponse | null> {
	const method = message.method;
	if (!method) return null;
	if (method === "notifications/cancelled") {
		const params = message.params as { requestId?: unknown } | undefined;
		const cancelled = params?.requestId;
		if (cancelled !== undefined) inflight.get(String(cancelled))?.abort();
		return null;
	}
	if (method.startsWith("notifications/")) return null;
	// A request without an id is a notification: never reply.
	if (message.id === undefined) return null;
	const id = message.id;
	if (method === "initialize") {
		const params = message.params as
			| { protocolVersion?: unknown }
			| undefined;
		const requested = params?.protocolVersion;
		const negotiated =
			typeof requested === "string" &&
			SUPPORTED_PROTOCOL_VERSIONS.some((value) => value === requested)
				? requested
				: FALLBACK_PROTOCOL_VERSION;
		return response(id, {
			protocolVersion: negotiated,
			capabilities: { tools: { listChanged: false } },
			serverInfo: { name: SERVER_NAME, version: SERVER_VERSION },
			instructions:
				"Use the ghidra tool for headless binary analysis. Call action=health first when Ghidra may not be installed.",
		});
	}
	if (method === "ping") return response(id, {});
	if (method === "tools/list")
		return response(id, { tools: [toolDefinition] });
	if (method === "tools/call")
		return callTool(id, (message.params ?? {}) as ToolCallParams);
	return errorResponse(id, -32601, `Method not found: ${method}`);
}

function writeMessage(message: JsonRpcResponse): void {
	process.stdout.write(`${JSON.stringify(message)}\n`);
}

export function startServer(): void {
	const reader = createInterface({ input: process.stdin, crlfDelay: Infinity });
	let pending = 0;
	let closing = false;
	const finish = () => {
		if (closing && pending === 0) process.exit(0);
	};
	reader.on("line", (line) => {
		const trimmed = line.trim();
		if (!trimmed) return;
		let message: JsonRpcMessage;
		try {
			message = JSON.parse(trimmed) as JsonRpcMessage;
		} catch {
			writeMessage(errorResponse(null, -32700, "Parse error"));
			return;
		}
		pending += 1;
		void handleMessage(message)
			.then((reply) => {
				if (reply) writeMessage(reply);
			})
			.catch((error: unknown) => {
				const id = message.id ?? null;
				writeMessage(
					errorResponse(
						id,
						-32603,
						error instanceof Error ? error.message : String(error),
					),
				);
			})
			.finally(() => {
				pending -= 1;
				finish();
			});
	});
	reader.on("close", () => {
		// Drain accepted calls instead of aborting them: a client that sends a
		// request and closes stdin still gets the reply, and every call is
		// bounded by its own Ghidra timeout.
		closing = true;
		finish();
	});
}

const entry = process.argv[1];
if (entry && import.meta.url === pathToFileURL(entry).href) startServer();
