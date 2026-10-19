// Single source of truth for the `ghidra` tool input schema.
//
// Plain JSON Schema keeps the MCP server dependency-free, while the Pi/omp
// extension wraps this object with `Type.Unsafe` so the host still receives a
// TypeBox-compatible schema. Field descriptions live in metadata.ts.
import {
	ACTIONS,
	COMMENT_TYPES,
	MAX_BATCH_OPERATIONS,
	MAX_LIMIT,
	MAX_MEMORY_BYTES,
	MAX_OFFSET,
	MAX_TIMEOUT_SECONDS,
	OPERATION_ACTIONS,
	REFERENCE_DIRECTIONS,
} from "./runtime.ts";
import { FIELD_DESCRIPTIONS } from "./metadata.ts";

const stringField = (description: string) => ({
	type: "string",
	description,
});

const operationProperties = {
	action: {
		type: "string",
		enum: OPERATION_ACTIONS,
		description: "Operation to run against the analyzed program.",
	},
	address: stringField(FIELD_DESCRIPTIONS.address),
	name: stringField(FIELD_DESCRIPTIONS.name),
	query: stringField(FIELD_DESCRIPTIONS.query),
	pattern: stringField(FIELD_DESCRIPTIONS.pattern),
	value: stringField(FIELD_DESCRIPTIONS.value),
	bytes: stringField(FIELD_DESCRIPTIONS.bytes),
	commentType: {
		type: "string",
		enum: COMMENT_TYPES,
		description: FIELD_DESCRIPTIONS.commentType,
	},
	direction: {
		type: "string",
		enum: REFERENCE_DIRECTIONS,
		description: FIELD_DESCRIPTIONS.direction,
	},
	offset: {
		type: "integer",
		minimum: 0,
		maximum: MAX_OFFSET,
		description: FIELD_DESCRIPTIONS.offset,
	},
	limit: {
		type: "integer",
		minimum: 1,
		maximum: MAX_LIMIT,
		description: FIELD_DESCRIPTIONS.limit,
	},
	length: {
		type: "integer",
		minimum: 1,
		maximum: MAX_MEMORY_BYTES,
		description: FIELD_DESCRIPTIONS.length,
	},
	timeoutSeconds: {
		type: "integer",
		minimum: 1,
		maximum: MAX_TIMEOUT_SECONDS,
		description: FIELD_DESCRIPTIONS.timeoutSeconds,
	},
	options: {
		type: "object",
		additionalProperties: { type: "string" },
		description: FIELD_DESCRIPTIONS.options,
	},
} as const;

export const OPERATION_SCHEMA = {
	type: "object",
	properties: operationProperties,
	required: ["action"],
	additionalProperties: false,
} as const;

export const TOOL_INPUT_SCHEMA = {
	type: "object",
	properties: {
		...operationProperties,
		action: {
			type: "string",
			enum: ACTIONS,
			description:
				"Operation to run. discover/setup/health/batch/rebuild do not require a binary; all others do.",
		},
		binary: stringField(FIELD_DESCRIPTIONS.binary),
		operations: {
			type: "array",
			items: OPERATION_SCHEMA,
			minItems: 1,
			maxItems: MAX_BATCH_OPERATIONS,
			description: FIELD_DESCRIPTIONS.operations,
		},
		ghidraHome: stringField(FIELD_DESCRIPTIONS.ghidraHome),
		javaHome: stringField(FIELD_DESCRIPTIONS.javaHome),
		cacheDir: stringField(FIELD_DESCRIPTIONS.cacheDir),
		force: { type: "boolean", description: FIELD_DESCRIPTIONS.force },
	},
	required: ["action"],
	additionalProperties: false,
} as const;

export type ToolInputSchema = typeof TOOL_INPUT_SCHEMA;
