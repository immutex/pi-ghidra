import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { join } from "node:path";

const SERVER = join(process.cwd(), "mcp", "server.ts");

interface JsonRpcReply {
	jsonrpc: string;
	id: number | string | null;
	result?: Record<string, unknown>;
	error?: { code: number; message: string };
}

function session(
	lines: string[],
	timeoutMs = 20_000,
): Promise<{ replies: JsonRpcReply[]; code: number | null }> {
	return new Promise((resolvePromise, reject) => {
		const child = spawn(process.execPath, [SERVER], {
			cwd: process.cwd(),
			stdio: ["pipe", "pipe", "pipe"],
		});
		let stdout = "";
		let stderr = "";
		const timer = setTimeout(() => {
			child.kill();
			reject(new Error(`MCP server timed out\n${stderr}`));
		}, timeoutMs);
		child.stdout.setEncoding("utf8");
		child.stderr.setEncoding("utf8");
		child.stdout.on("data", (chunk: string) => {
			stdout += chunk;
		});
		child.stderr.on("data", (chunk: string) => {
			stderr += chunk;
		});
		child.once("error", reject);
		child.once("close", (code) => {
			clearTimeout(timer);
			const replies = stdout
				.split("\n")
				.filter(Boolean)
				.map((line) => JSON.parse(line) as JsonRpcReply);
			resolvePromise({ replies, code });
		});
		child.stdin.end(`${lines.join("\n")}\n`);
	});
}

test("MCP server negotiates, lists tools, and rejects bad input", async () => {
	const { replies, code } = await session([
		JSON.stringify({
			jsonrpc: "2.0",
			id: 1,
			method: "initialize",
			params: {
				protocolVersion: "2025-03-26",
				capabilities: {},
				clientInfo: { name: "test", version: "0" },
			},
		}),
		JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }),
		JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" }),
		JSON.stringify({
			jsonrpc: "2.0",
			id: 3,
			method: "tools/call",
			params: { name: "ghidra", arguments: { action: "not_an_action" } },
		}),
		JSON.stringify({
			jsonrpc: "2.0",
			id: 4,
			method: "tools/call",
			params: { name: "missing", arguments: {} },
		}),
		"{not json",
	]);
	assert.equal(code, 0);
	assert.equal(replies.length, 5, JSON.stringify(replies));
	const byId = new Map(replies.map((reply) => [String(reply.id), reply]));
	const initialized = byId.get("1");
	assert.equal(initialized?.result?.protocolVersion, "2025-03-26");
	const tools = byId.get("2")?.result?.tools as Array<{
		name: string;
		inputSchema: { properties: Record<string, unknown> };
	}>;
	assert.equal(tools.length, 1);
	assert.equal(tools[0]?.name, "ghidra");
	assert.ok(tools[0] && "binary" in tools[0].inputSchema.properties);
	const rejected = byId.get("3")?.result as {
		isError?: boolean;
		content: Array<{ text: string }>;
	};
	assert.equal(rejected.isError, true);
	assert.match(rejected.content[0]?.text ?? "", /action must be one of/);
	assert.equal(byId.get("4")?.error?.code, -32602);
	const parseError = replies.find((reply) => reply.error?.code === -32700);
	assert.equal(parseError?.id, null);
});
