// Shared presentation metadata for every entry point (Pi, omp, MCP).
// Keeping descriptions here prevents the extension and the MCP server from
// drifting apart as actions are added.

export const TOOL_NAME = "ghidra";

export const TOOL_DESCRIPTION =
	"Run autonomous Ghidra 12 headless reverse engineering. Automatically discovers common installations; discover lists candidates and setup persists a chosen path. Imports and analyzes binaries automatically, caches projects by SHA-256, decompiles functions, queries listings/symbols/xrefs/call graphs/memory, reruns analyzers, and applies renames/comments/patches. Use batch to run up to 50 operations in one JVM. Results are capped at 50KB; use offset/limit for pagination.";

export const FIELD_DESCRIPTIONS = {
	binary:
		"Binary path, absolute or relative to the working directory. Required except for discover, setup, and health.",
	address: "Address such as 00401000, ram:00401000, or a function address",
	name: "Function or symbol name",
	query: "Text/name filter or UTF-8 text to search",
	pattern: "Hex byte pattern with ?? wildcards, such as '48 8b ?? 89'",
	value: "New name or comment text; omit to remove a comment",
	bytes: "Hex bytes for patch",
	commentType: "Comment kind: EOL, PRE, POST, PLATE, or REPEATABLE",
	direction: "Reference direction: to, from, or both",
	offset: "Zero-based result offset for pagination",
	limit: "Maximum results to return (1-2000)",
	length: "Bytes to read or patch (1-1048576)",
	timeoutSeconds: "Operation timeout in seconds (1-900)",
	options: "Analysis option overrides as string key/value pairs",
	operations: "Only for action=batch: up to 50 operations in one JVM.",
	ghidraHome:
		"Ghidra install root. Auto-detected when omitted; action=setup saves it for future sessions.",
	javaHome: "Optional JDK root to persist with action=setup.",
	cacheDir: "Persistent analysis cache directory",
	force: "Discard cached project and import/analyze again",
} as const;
