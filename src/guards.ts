// Canonical object guard for this package. Runtime input arrives from MCP
// clients and direct callers, so every boundary uses this single definition.

export function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}
