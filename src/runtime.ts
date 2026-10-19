import { createHash, randomUUID } from "node:crypto";
import {
	closeSync,
	createReadStream,
	existsSync,
	openSync,
	readFileSync,
	readdirSync,
	statSync,
} from "node:fs";
import {
	copyFile,
	mkdir,
	open,
	readFile,
	rename as renameFile,
	rm,
	stat,
	utimes,
	writeFile,
} from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import {
	dirname,
	extname,
	isAbsolute,
	join,
	resolve,
} from "node:path";
import { fileURLToPath } from "node:url";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { isRecord } from "./guards.ts";

export const ACTIONS = [
	"discover",
	"setup",
	"health",
	"analyze",
	"rebuild",
	"info",
	"memory_blocks",
	"entry_points",
	"functions",
	"function",
	"decompile",
	"disassemble",
	"data",
	"strings",
	"symbols",
	"imports",
	"exports",
	"references",
	"call_graph",
	"memory",
	"search_bytes",
	"search_text",
	"analysis_options",
	"set_analysis_options",
	"reanalyze",
	"rename",
	"comment",
	"patch",
	"batch",
] as const;

export type Action = (typeof ACTIONS)[number];

export const NON_OPERATION_ACTIONS = [
	"discover",
	"setup",
	"health",
	"batch",
	"rebuild",
] as const;

export type OperationAction = Exclude<
	Action,
	(typeof NON_OPERATION_ACTIONS)[number]
>;

export const OPERATION_ACTIONS = ACTIONS.filter(
	(action): action is OperationAction =>
		!NON_OPERATION_ACTIONS.some((value) => value === action),
);

export const COMMENT_TYPES = [
	"EOL",
	"PRE",
	"POST",
	"PLATE",
	"REPEATABLE",
] as const;

export const REFERENCE_DIRECTIONS = ["to", "from", "both"] as const;

export const MAX_LIMIT = 2000;
export const MAX_MEMORY_BYTES = 1024 * 1024;
export const MAX_BATCH_OPERATIONS = 50;
export const MAX_TIMEOUT_SECONDS = 900;
export const MAX_OFFSET = 2_147_483_647;
export const MAX_OUTPUT_BYTES = 50_000;

const MAX_RESPONSE_BYTES = 64 * 1024 * 1024;
const LOCK_STALE_MS = 30 * 60_000;
const LOCK_WAIT_MS = 60_000;
const REAP_STALE_MS = 60_000;
const DEFAULT_IMPORT_TIMEOUT_MS = 15 * 60_000;

export interface Operation {
	action: OperationAction;
	address?: string;
	name?: string;
	query?: string;
	pattern?: string;
	value?: string;
	bytes?: string;
	commentType?: (typeof COMMENT_TYPES)[number];
	direction?: (typeof REFERENCE_DIRECTIONS)[number];
	offset?: number;
	limit?: number;
	length?: number;
	timeoutSeconds?: number;
	options?: Record<string, string>;
}

export interface GhidraRequest extends Omit<Operation, "action"> {
	action: Action;
	binary?: string;
	operations?: Operation[];
	ghidraHome?: string;
	javaHome?: string;
	cacheDir?: string;
	force?: boolean;
}

export interface RunResult {
	action: Action;
	artifact?: string;
	cached?: boolean;
	ghidraHome: string | null;
	project?: string;
	program?: string;
	result: unknown;
}

interface Manifest {
	schema: 1;
	hash: string;
	source: string;
	program: string;
	ghidraVersion: string;
	createdAt: string;
}

export interface GhidraConfig {
	ghidraHome?: string;
	javaHome?: string;
	cacheDir?: string;
}

const PACKAGE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SCRIPT_DIR = join(PACKAGE_ROOT, "ghidra_scripts");
const PROJECT_NAME = "pi-ghidra";
const queues = new Map<string, Promise<void>>();
let automaticHomesCache: string[] | undefined;
const READ_ACTIONS: Record<string, true> = {
	info: true,
	memory_blocks: true,
	entry_points: true,
	functions: true,
	function: true,
	decompile: true,
	disassemble: true,
	data: true,
	strings: true,
	symbols: true,
	imports: true,
	exports: true,
	references: true,
	call_graph: true,
	memory: true,
	search_bytes: true,
	search_text: true,
	analysis_options: true,
};

const REQUEST_KEYS: Record<string, true> = {
	action: true,
	binary: true,
	address: true,
	name: true,
	query: true,
	pattern: true,
	value: true,
	bytes: true,
	commentType: true,
	direction: true,
	offset: true,
	limit: true,
	length: true,
	timeoutSeconds: true,
	options: true,
	operations: true,
	ghidraHome: true,
	javaHome: true,
	cacheDir: true,
	force: true,
};

const OPERATION_KEYS: Record<string, true> = {
	action: true,
	address: true,
	name: true,
	query: true,
	pattern: true,
	value: true,
	bytes: true,
	commentType: true,
	direction: true,
	offset: true,
	limit: true,
	length: true,
	timeoutSeconds: true,
	options: true,
};

const STRING_KEYS = [
	"address",
	"name",
	"query",
	"pattern",
	"value",
	"bytes",
] as const;

function fail(message: string): never {
	throw new Error(message);
}

function checkString(
	record: Record<string, unknown>,
	key: string,
	label: string,
): void {
	const value = record[key];
	if (value !== undefined && typeof value !== "string")
		fail(`${label}${key} must be a string`);
}

function checkInteger(
	record: Record<string, unknown>,
	key: string,
	label: string,
	minimum: number,
	maximum: number,
): void {
	const value = record[key];
	if (value === undefined) return;
	if (typeof value !== "number" || !Number.isInteger(value))
		fail(`${label}${key} must be an integer`);
	if (value < minimum || value > maximum)
		fail(`${label}${key} must be between ${minimum} and ${maximum}`);
}

function checkOptions(
	record: Record<string, unknown>,
	label: string,
): void {
	const value = record.options;
	if (value === undefined) return;
	if (!isRecord(value))
		fail(`${label}options must be an object of string values`);
	for (const [key, option] of Object.entries(value)) {
		if (typeof option !== "string")
			fail(`${label}options.${key} must be a string`);
	}
}

const ACTION_LOOKUP: Record<string, Action> = Object.fromEntries(
	ACTIONS.map((action) => [action, action]),
);

const OPERATION_ACTION_LOOKUP: Record<string, OperationAction> =
	Object.fromEntries(OPERATION_ACTIONS.map((action) => [action, action]));

function parseOperationFields(
	value: Record<string, unknown>,
	label: string,
): Operation {
	for (const key of STRING_KEYS) checkString(value, key, label);
	checkInteger(value, "offset", label, 0, MAX_OFFSET);
	checkInteger(value, "limit", label, 1, MAX_LIMIT);
	checkInteger(value, "length", label, 1, MAX_MEMORY_BYTES);
	checkInteger(value, "timeoutSeconds", label, 1, MAX_TIMEOUT_SECONDS);
	checkOptions(value, label);
	if (
		value.commentType !== undefined &&
		!COMMENT_TYPES.includes(
			value.commentType as (typeof COMMENT_TYPES)[number],
		)
	)
		fail(`${label}commentType must be one of: ${COMMENT_TYPES.join(", ")}`);
	if (
		value.direction !== undefined &&
		!REFERENCE_DIRECTIONS.includes(
			value.direction as (typeof REFERENCE_DIRECTIONS)[number],
		)
	)
		fail(
			`${label}direction must be one of: ${REFERENCE_DIRECTIONS.join(", ")}`,
		);
	const operation = value as unknown as Operation;
	const hasTarget = Boolean(operation.address || operation.name);
	switch (operation.action) {
		case "search_bytes":
			if (!operation.pattern)
				fail(`${label}pattern is required for search_bytes`);
			break;
		case "search_text":
			if (!operation.query)
				fail(`${label}query is required for search_text`);
			break;
		case "rename":
			if (!operation.value?.trim())
				fail(`${label}value is required for rename`);
			if (!hasTarget)
				fail(`${label}address or name is required for rename`);
			break;
		case "patch":
			if (!operation.bytes) fail(`${label}bytes is required for patch`);
			if (!hasTarget)
				fail(`${label}address or name is required for patch`);
			break;
		case "comment":
			if (!hasTarget)
				fail(`${label}address or name is required for comment`);
			break;
		case "memory":
		case "decompile":
		case "function":
		case "call_graph":
		case "references":
			if (!hasTarget)
				fail(
					`${label}address or name is required for ${operation.action}`,
				);
			break;
		case "set_analysis_options":
			if (!operation.options || Object.keys(operation.options).length === 0)
				fail(`${label}options is required for set_analysis_options`);
			break;
		default:
			break;
	}
	return operation;
}

function validateOperation(value: unknown, label: string): Operation {
	if (!isRecord(value)) fail(`${label} must be an object`);
	for (const key of Object.keys(value)) {
		if (OPERATION_KEYS[key] !== true)
			fail(`${label}has unknown field "${key}"`);
	}
	if (
		typeof value.action !== "string" ||
		OPERATION_ACTION_LOOKUP[value.action] === undefined
	)
		fail(`${label}action must be one of: ${OPERATION_ACTIONS.join(", ")}`);
	return parseOperationFields(value, label);
}

/**
 * Validate and normalize an untrusted request. The Pi extension validates with
 * its JSON schema, but MCP clients and direct runtime callers do not, so every
 * entry point funnels through here.
 */
export function validateGhidraRequest(value: unknown): GhidraRequest {
	if (!isRecord(value)) fail("Ghidra request must be an object");
	for (const key of Object.keys(value)) {
		if (REQUEST_KEYS[key] !== true)
			fail(`Ghidra request has unknown field "${key}"`);
	}
	if (
		typeof value.action !== "string" ||
		ACTION_LOOKUP[value.action] === undefined
	)
		fail(`action must be one of: ${ACTIONS.join(", ")}`);
	const action = ACTION_LOOKUP[value.action] ?? fail("unknown action");
	for (const key of ["binary", "ghidraHome", "javaHome", "cacheDir"] as const)
		checkString(value, key, "");
	if (value.force !== undefined && typeof value.force !== "boolean")
		fail("force must be a boolean");
	const request = value as unknown as GhidraRequest;
	if (action === "batch") {
		if (!request.binary) fail("binary is required for batch");
		if (!Array.isArray(request.operations) || request.operations.length === 0)
			fail("operations is required for batch");
		if (request.operations.length > MAX_BATCH_OPERATIONS)
			fail(`batch accepts at most ${MAX_BATCH_OPERATIONS} operations`);
		const operations = request.operations.map((operation, index) =>
			validateOperation(operation, `operations[${index}].`),
		);
		return { ...request, action, operations };
	}
	if (request.operations !== undefined)
		fail("operations is only valid for action=batch");
	const operation = parseOperationFields(value, "");
	if (NON_OPERATION_ACTIONS.some((value) => value === action)) {
		if (action === "rebuild" && !request.binary)
			fail("binary is required for rebuild");
		if (action !== "rebuild" && request.binary)
			fail(`binary is not valid for ${action}`);
		return { ...operation, ...request, action };
	}
	if (!request.binary) fail(`binary is required for ${action}`);
	return { ...operation, ...request, action };
}

export function ghidraConfigPath(): string {
	const explicit = process.env.PI_GHIDRA_CONFIG;
	if (explicit) return resolve(explicit);
	return join(agentDirectory(), "pi-ghidra.json");
}

function isOmpRuntime(): boolean {
	return typeof (globalThis as { Bun?: unknown }).Bun !== "undefined";
}

/**
 * Resolve the agent directory the same way the running harness does. Explicit
 * `PI_CODING_AGENT_DIR` wins; otherwise an existing `.omp`/`.pi` profile root
 * decides, so a config saved by Pi stays visible under omp and vice versa.
 */
function agentDirectory(): string {
	const explicit = process.env.PI_CODING_AGENT_DIR;
	if (explicit) return resolve(explicit);
	const profile = process.env.OMP_PROFILE?.trim();
	const withProfile = (root: string) =>
		profile && profile !== "default"
			? join(root, "profiles", profile, "agent")
			: join(root, "agent");
	if (process.env.PI_CONFIG_DIR) {
		const configured = process.env.PI_CONFIG_DIR;
		const root = isAbsolute(configured)
			? configured
			: join(homedir(), configured);
		return withProfile(root);
	}
	const roots = isOmpRuntime() ? [".omp", ".pi"] : [".pi", ".omp"];
	for (const name of roots) {
		const root = join(homedir(), name);
		if (existsSync(join(root, "agent"))) return withProfile(root);
	}
	return withProfile(join(homedir(), isOmpRuntime() ? ".omp" : ".pi"));
}

export function readGhidraConfig(): GhidraConfig {
	const path = ghidraConfigPath();
	if (!existsSync(path)) return {};
	try {
		const value = JSON.parse(readFileSync(path, "utf8")) as unknown;
		if (!isRecord(value)) throw new Error("Expected a JSON object");
		for (const key of ["ghidraHome", "javaHome", "cacheDir"] as const) {
			if (key in value && typeof value[key] !== "string")
				throw new Error(`${key} must be a string`);
		}
		return value as GhidraConfig;
	} catch (error) {
		throw new Error(`Invalid pi-ghidra configuration: ${path}`, {
			cause: error,
		});
	}
}

function readableGhidraConfig(): GhidraConfig {
	try {
		return readGhidraConfig();
	} catch (error) {
		if (
			error instanceof Error &&
			error.message.startsWith("Invalid pi-ghidra configuration:")
		)
			return {};
		throw error;
	}
}

export function validateCacheDir(path: string): string {
	const resolved = resolve(path);
	if (dirname(resolved) === resolved)
		fail(`Cache directory cannot be a filesystem root: ${resolved}`);
	const parts = resolved.split(/[\\/]+/).filter(Boolean);
	if (parts.some((part) => part.startsWith(".")))
		fail(
			`Ghidra project paths cannot contain dot-prefixed directories: ${resolved}`,
		);
	if (parts.some((part) => /[\u0000-\u001f]/.test(part)))
		fail(`Ghidra project paths cannot contain control characters: ${resolved}`);
	if (
		process.platform === "win32" &&
		parts.some((part) => /[&%!^|<>"?*]/.test(part))
	)
		fail(
			`Ghidra project paths cannot contain &, %, !, ^, |, <, >, ", ?, or * on Windows: ${resolved}`,
		);
	return resolved;
}

function defaultCacheDir(): string {
	if (process.env.PI_GHIDRA_CACHE)
		return validateCacheDir(process.env.PI_GHIDRA_CACHE);
	const configured = readableGhidraConfig().cacheDir;
	if (configured) return validateCacheDir(configured);
	if (process.platform === "win32")
		return join(
			process.env.LOCALAPPDATA || join(homedir(), "AppData", "Local"),
			"pi-ghidra",
		);
	if (process.platform === "darwin")
		return join(homedir(), "Library", "Caches", "pi-ghidra");
	return join(homedir(), "pi-ghidra-cache");
}

function applicationVersion(home: string): string | undefined {
	const file = join(home, "Ghidra", "application.properties");
	try {
		if (!existsSync(file)) return undefined;
		return readFileSync(file, "utf8")
			.match(/^application\.version=(.+)$/m)?.[1]
			?.trim();
	} catch {
		return undefined;
	}
}

function launcherPath(home: string): string {
	return join(
		home,
		"support",
		process.platform === "win32" ? "analyzeHeadless.bat" : "analyzeHeadless",
	);
}

function usableGhidraHome(
	home: string,
): { path: string; version: string } | undefined {
	const resolved = resolve(home);
	if (!existsSync(launcherPath(resolved))) return undefined;
	const version = applicationVersion(resolved);
	if (!version?.startsWith("12.")) return undefined;
	return { path: resolved, version };
}

function validateGhidraHome(home: string): string {
	const resolved = resolve(home);
	if (!existsSync(launcherPath(resolved)))
		fail(`Ghidra analyzeHeadless not found under ${resolved}`);
	const version = applicationVersion(resolved);
	if (!version?.startsWith("12."))
		fail(
			`Ghidra 12 is required; found ${version ?? "an unreadable version"} under ${resolved}`,
		);
	return resolved;
}

const SKIP_DIRECTORIES = new Set([
	"node_modules",
	"$Recycle.Bin",
	"System Volume Information",
	"Windows",
	"AppData",
	"Library",
]);

function scanGhidraRoot(
	root: string,
	depth: number,
	insideMatch = false,
): string[] {
	if (depth < 0 || !existsSync(root)) return [];
	try {
		const result: string[] = [];
		const entries = readdirSync(root, { withFileTypes: true }).sort((a, b) =>
			b.name.localeCompare(a.name, undefined, { numeric: true }),
		);
		for (const entry of entries) {
			if (!entry.isDirectory() && !entry.isSymbolicLink()) continue;
			if (!insideMatch && SKIP_DIRECTORIES.has(entry.name)) continue;
			const matched = insideMatch || /ghidra/i.test(entry.name);
			if (!matched) continue;
			const path = join(root, entry.name);
			result.push(path);
			if (
				existsSync(launcherPath(path)) &&
				applicationVersion(path)?.startsWith("12.")
			)
				continue;
			result.push(...scanGhidraRoot(path, depth - 1, true));
		}
		return result;
	} catch (error) {
		if (
			["EACCES", "ENOENT", "EPERM"].includes(
				(error as NodeJS.ErrnoException).code ?? "",
			)
		)
			return [];
		throw error;
	}
}

function discoveryRoots(): string[] {
	if (process.platform === "win32") {
		const user = process.env.USERPROFILE || homedir();
		const local = process.env.LOCALAPPDATA;
		const programData = process.env.ProgramData;
		return [
			"C:\\",
			user,
			join(user, "Desktop"),
			join(user, "Downloads"),
			join(user, "Documents"),
			join(user, "tools"),
			join(user, "Applications"),
			process.env.ProgramFiles,
			process.env["ProgramFiles(x86)"],
			process.env.ProgramW6432,
			programData && join(programData, "chocolatey", "lib"),
			local && join(local, "Programs"),
			local && join(local, "Microsoft", "WinGet", "Packages"),
			join(user, "scoop", "apps"),
		].filter((value): value is string => Boolean(value));
	}
	if (process.platform === "darwin") {
		return [
			"/Applications",
			join(homedir(), "Applications"),
			join(homedir(), "Downloads"),
			join(homedir(), "Desktop"),
			join(homedir(), "tools"),
			"/opt/homebrew/Cellar",
			"/opt/homebrew/Caskroom",
			"/opt/homebrew/opt",
			"/usr/local/Cellar",
			"/usr/local/opt",
			"/usr/share",
		];
	}
	return [
		"/opt",
		"/usr/local",
		"/usr/share",
		"/snap",
		join(homedir(), "Downloads"),
		join(homedir(), "Desktop"),
		join(homedir(), "tools"),
		join(homedir(), ".local", "share"),
		join(homedir(), ".linuxbrew", "Cellar"),
		join(homedir(), ".linuxbrew", "opt"),
		join(homedir(), "snap"),
	];
}

function automaticGhidraHomes(refresh: boolean): string[] {
	if (!refresh && automaticHomesCache) return automaticHomesCache;
	const direct =
		process.platform === "win32"
			? [
					"C:\\ghidra",
					join(process.env.ProgramFiles || "C:\\Program Files", "ghidra"),
					join(
						process.env.LOCALAPPDATA || join(homedir(), "AppData", "Local"),
						"ghidra",
					),
				]
			: [
					"/opt/ghidra",
					"/usr/local/ghidra",
					"/usr/share/ghidra",
					"/snap/ghidra/current",
					join(homedir(), "ghidra"),
					join(homedir(), "tools", "ghidra"),
				];
	const values = [
		...direct,
		...discoveryRoots().flatMap((root) => [root, ...scanGhidraRoot(root, 3)]),
	];
	const seen = new Set<string>();
	automaticHomesCache = values
		.map((value) => resolve(value))
		.filter((value) => {
			const key = process.platform === "win32" ? value.toLowerCase() : value;
			if (seen.has(key)) return false;
			seen.add(key);
			return Boolean(usableGhidraHome(value));
		});
	return automaticHomesCache;
}

export function discoverGhidraHomes(refresh = false): string[] {
	const configured = readableGhidraConfig().ghidraHome;
	const preferred = [
		process.env.PI_GHIDRA_HOME,
		process.env.GHIDRA_HOME,
		configured,
	].flatMap((value) => (value ? [resolve(value)] : []));
	const seen = new Set<string>();
	return [...preferred, ...automaticGhidraHomes(refresh)].filter((value) => {
		const key = process.platform === "win32" ? value.toLowerCase() : value;
		if (seen.has(key)) return false;
		seen.add(key);
		return Boolean(usableGhidraHome(value));
	});
}

export function resolveGhidraHome(explicit?: string): string {
	if (explicit) return validateGhidraHome(explicit);
	for (const name of ["PI_GHIDRA_HOME", "GHIDRA_HOME"] as const) {
		const value = process.env[name];
		if (!value) continue;
		const usable = usableGhidraHome(value);
		if (usable) return usable.path;
		fail(`${name} does not point to a Ghidra 12 installation: ${resolve(value)}`);
	}
	const configured = readableGhidraConfig().ghidraHome;
	if (configured) {
		const usable = usableGhidraHome(configured);
		if (usable) return usable.path;
	}
	const [home] = discoverGhidraHomes();
	if (!home)
		fail(
			"Ghidra 12 was not found. Run /ghidra-setup, call ghidra with action=setup, or set PI_GHIDRA_HOME.",
		);
	return home;
}

export function parseJavaMajor(output: string): number | undefined {
	const match = output.match(/version "(?:1\.)?(\d+)/i);
	const digits = match?.[1];
	if (!digits) return undefined;
	const major = Number.parseInt(digits, 10);
	return Number.isFinite(major) ? major : undefined;
}

function usableJavaHome(
	home: string,
): { home: string; major: number } | undefined {
	const resolved = resolve(home);
	const executable = join(
		resolved,
		"bin",
		process.platform === "win32" ? "java.exe" : "java",
	);
	if (!existsSync(executable)) return undefined;
	const result = spawnSync(executable, ["-version"], {
		encoding: "utf8",
		timeout: 5000,
		windowsHide: true,
	});
	if (result.error || result.status !== 0) return undefined;
	const major = parseJavaMajor(
		`${result.stderr ?? ""}\n${result.stdout ?? ""}`,
	);
	return major === undefined ? undefined : { home: resolved, major };
}

function validateJavaHome(home: string): string {
	const java = usableJavaHome(home);
	if (!java)
		fail(`A working Java installation was not found under ${resolve(home)}`);
	if (java.major < 21)
		fail(
			`Ghidra 12 requires JDK 21 or newer; found Java ${java.major} under ${java.home}`,
		);
	return java.home;
}

function javaCandidates(): string[] {
	if (process.platform === "win32") {
		const programFiles = process.env.ProgramFiles || "C:\\Program Files";
		const programFilesX86 =
			process.env["ProgramFiles(x86)"] || "C:\\Program Files (x86)";
		const roots = [
			join(programFiles, "Eclipse Adoptium"),
			join(programFiles, "Java"),
			join(programFiles, "Microsoft"),
			join(programFiles, "Zulu"),
			join(programFiles, "BellSoft", "LibericaJDK"),
			join(programFiles, "Amazon Corretto"),
			join(programFiles, "IBM", "Semeru"),
			join(programFilesX86, "Eclipse Adoptium"),
			join(programFilesX86, "Java"),
		];
		const result: string[] = [];
		for (const root of roots) {
			if (!existsSync(root)) continue;
			let names: string[];
			try {
				names = readdirSync(root);
			} catch {
				continue;
			}
			for (const name of names.sort((a, b) =>
				b.localeCompare(a, undefined, { numeric: true }),
			))
				result.push(join(root, name));
		}
		return result;
	}
	if (process.platform === "darwin") {
		const root = "/Library/Java/JavaVirtualMachines";
		if (!existsSync(root)) return [];
		try {
			return readdirSync(root)
				.sort((a, b) => b.localeCompare(a, undefined, { numeric: true }))
				.map((entry) => join(root, entry, "Contents", "Home"));
		} catch {
			return [];
		}
	}
	const root = "/usr/lib/jvm";
	if (!existsSync(root)) return [];
	try {
		return readdirSync(root)
			.sort((a, b) => b.localeCompare(a, undefined, { numeric: true }))
			.map((entry) => join(root, entry));
	} catch {
		return [];
	}
}

function javaHome(): string | undefined {
	for (const candidate of [process.env.JAVA_HOME, readableGhidraConfig().javaHome]) {
		if (!candidate) continue;
		const java = usableJavaHome(candidate);
		if (java && java.major >= 21) return java.home;
	}
	for (const candidate of javaCandidates()) {
		const java = usableJavaHome(candidate);
		if (java && java.major >= 21) return java.home;
	}
	return undefined;
}

export async function saveGhidraConfig(
	update: GhidraConfig,
): Promise<GhidraConfig> {
	let current: GhidraConfig = {};
	try {
		current = readGhidraConfig();
	} catch (error) {
		if (!update.ghidraHome) throw error;
	}
	const next: GhidraConfig = { ...current };
	if (update.ghidraHome !== undefined)
		next.ghidraHome = validateGhidraHome(update.ghidraHome);
	if (update.javaHome !== undefined)
		next.javaHome = validateJavaHome(update.javaHome);
	if (update.cacheDir !== undefined)
		next.cacheDir = validateCacheDir(update.cacheDir);
	const path = ghidraConfigPath();
	const temporary = `${path}.${randomUUID()}.tmp`;
	await mkdir(dirname(path), { recursive: true });
	try {
		await writeFile(temporary, `${JSON.stringify(next, null, 2)}\n`, {
			mode: 0o600,
		});
		await renameFile(temporary, path);
	} finally {
		await rm(temporary, { force: true });
	}
	return next;
}

export async function hashFile(path: string): Promise<string> {
	const hash = createHash("sha256");
	const stream = createReadStream(path);
	const finished = new Promise<void>((resolvePromise, reject) => {
		stream.on("data", (chunk) => hash.update(chunk));
		stream.on("end", resolvePromise);
		stream.on("error", reject);
	});
	await finished;
	return hash.digest("hex");
}

function cancellationError(): Error {
	return new Error("Ghidra operation cancelled");
}

async function delay(ms: number, signal?: AbortSignal): Promise<void> {
	if (signal?.aborted) throw cancellationError();
	const { promise, resolve, reject } = Promise.withResolvers<void>();
	const timer = setTimeout(() => {
		cleanup();
		resolve();
	}, ms);
	const onAbort = () => {
		cleanup();
		reject(cancellationError());
	};
	const cleanup = () => {
		clearTimeout(timer);
		signal?.removeEventListener("abort", onAbort);
	};
	signal?.addEventListener("abort", onAbort, { once: true });
	await promise;
}

async function waitFor<T>(
	promise: Promise<T>,
	signal?: AbortSignal,
): Promise<T> {
	if (!signal) return promise;
	if (signal.aborted) throw cancellationError();
	const { promise: guarded, resolve, reject } = Promise.withResolvers<T>();
	const onAbort = () => {
		cleanup();
		reject(cancellationError());
	};
	const cleanup = () => signal.removeEventListener("abort", onAbort);
	signal.addEventListener("abort", onAbort, { once: true });
	promise.then(
		(value) => {
			cleanup();
			resolve(value);
		},
		(error) => {
			cleanup();
			reject(error);
		},
	);
	return guarded;
}

async function serialized<T>(
	key: string,
	run: () => Promise<T>,
	signal?: AbortSignal,
): Promise<T> {
	const previous = queues.get(key) ?? Promise.resolve();
	const { promise: current, resolve: release } = Promise.withResolvers<void>();
	const tail = previous.then(() => current);
	queues.set(key, tail);
	try {
		await waitFor(previous, signal);
		return await run();
	} finally {
		release();
		if (queues.get(key) === tail) queues.delete(key);
	}
}

async function lockAge(path: string): Promise<{ mtimeMs: number }> {
	try {
		return await stat(join(path, "owner.json"));
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
		return stat(path);
	}
}

async function acquireLock(
	path: string,
	signal?: AbortSignal,
): Promise<() => Promise<void>> {
	const started = Date.now();
	const token = randomUUID();
	const reapPath = `${path}.reap`;
	while (true) {
		if (signal?.aborted) throw cancellationError();
		let reapAge: number | undefined;
		try {
			reapAge = Date.now() - (await stat(reapPath)).mtimeMs;
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
		}
		if (reapAge !== undefined) {
			if (reapAge > REAP_STALE_MS)
				await rm(reapPath, { recursive: true, force: true });
			else await delay(200, signal);
			continue;
		}
		try {
			await mkdir(path);
			await writeFile(
				join(path, "owner.json"),
				JSON.stringify({
					pid: process.pid,
					token,
					at: new Date().toISOString(),
				}),
			);
			const ownerPath = join(path, "owner.json");
			const heartbeat = setInterval(() => {
				const now = new Date();
				void utimes(ownerPath, now, now).catch(() => undefined);
			}, 5000);
			heartbeat.unref();
			let released = false;
			return async () => {
				if (released) return;
				released = true;
				clearInterval(heartbeat);
				try {
					const owner = JSON.parse(
						await readFile(join(path, "owner.json"), "utf8"),
					) as { token?: string };
					if (owner.token === token)
						await rm(path, { recursive: true, force: true });
				} catch (error) {
					const code = (error as NodeJS.ErrnoException).code;
					if (code === "ENOENT") return;
					if (error instanceof SyntaxError) {
						await rm(path, { recursive: true, force: true });
						return;
					}
					throw error;
				}
			};
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
			let age: number;
			try {
				age = Date.now() - (await lockAge(path)).mtimeMs;
			} catch (statError) {
				if ((statError as NodeJS.ErrnoException).code === "ENOENT") continue;
				throw statError;
			}
			if (age > LOCK_STALE_MS) {
				try {
					await mkdir(reapPath);
					try {
						const currentAge = Date.now() - (await lockAge(path)).mtimeMs;
						if (currentAge > LOCK_STALE_MS)
							await rm(path, { recursive: true, force: true });
					} catch (reapError) {
						if ((reapError as NodeJS.ErrnoException).code !== "ENOENT")
							throw reapError;
					} finally {
						await rm(reapPath, { recursive: true, force: true });
					}
				} catch (reaperError) {
					if ((reaperError as NodeJS.ErrnoException).code !== "EEXIST")
						throw reaperError;
				}
				continue;
			}
			if (Date.now() - started > LOCK_WAIT_MS)
				fail(`Ghidra artifact is busy: ${dirname(path)}`);
			await delay(200, signal);
		}
	}
}

function killTree(child: ChildProcess): void {
	if (!child.pid) return;
	if (process.platform === "win32")
		spawnSync("taskkill", ["/pid", String(child.pid), "/t", "/f"], {
			stdio: "ignore",
			windowsHide: true,
		});
	else {
		try {
			process.kill(-child.pid, "SIGKILL");
		} catch {
			child.kill("SIGKILL");
		}
	}
}

async function tail(path: string, bytes = 12_000): Promise<string> {
	let handle;
	try {
		handle = await open(path, "r");
		const info = await handle.stat();
		const start = Math.max(0, info.size - bytes);
		const buffer = Buffer.alloc(info.size - start);
		await handle.read(buffer, 0, buffer.length, start);
		return buffer.toString("utf8");
	} catch {
		return "";
	} finally {
		await handle?.close().catch(() => undefined);
	}
}

async function launch(
	home: string,
	args: string[],
	cwd: string,
	signal: AbortSignal | undefined,
	timeoutMs: number,
	responseFile?: string,
): Promise<void> {
	if (signal?.aborted) throw cancellationError();
	const launcher = launcherPath(home);
	const log = join(cwd, `ghidra-${randomUUID()}.log`);
	const wrapper =
		process.platform === "win32"
			? join(tmpdir(), `pi-ghidra-${randomUUID()}.cmd`)
			: undefined;
	let fd: number | undefined;
	let child: ChildProcess | undefined;
	let timedOut = false;
	try {
		if (wrapper) {
			const quote = (value: string) => {
				if (/["\r\n%!^&|<>]/.test(value))
					fail(
						`Unsupported character in Windows Ghidra path or argument: ${value}`,
					);
				return `"${value}"`;
			};
			await writeFile(
				wrapper,
				`@echo off\r\ncall ${[launcher, ...args].map(quote).join(" ")}\r\nexit /b %errorlevel%\r\n`,
			);
		}
		fd = openSync(log, "w");
		const env = Object.fromEntries(
			Object.entries(process.env).filter(([key]) => key !== "JAVA_HOME"),
		);
		const resolvedJavaHome = javaHome();
		if (resolvedJavaHome) env.JAVA_HOME = resolvedJavaHome;
		try {
			child = wrapper
				? spawn(
						process.env.ComSpec || "cmd.exe",
						["/d", "/s", "/v:off", "/c", `call "${wrapper}"`],
						{
							cwd,
							env,
							stdio: ["ignore", fd, fd],
							windowsHide: true,
							windowsVerbatimArguments: true,
						},
					)
				: spawn(launcher, args, {
						cwd,
						env,
						stdio: ["ignore", fd, fd],
						detached: true,
					});
		} catch (error) {
			fail(
				`Could not start Ghidra: ${error instanceof Error ? error.message : String(error)}`,
			);
		}
		const timer = setTimeout(() => {
			timedOut = true;
			if (child) killTree(child);
		}, timeoutMs);
		const abort = () => {
			if (child) killTree(child);
		};
		signal?.addEventListener("abort", abort, { once: true });
		if (signal?.aborted) abort();
		const exited = Promise.withResolvers<{
			code: number | null;
			error?: Error;
		}>();
		let settled = false;
		const finish = (value: { code: number | null; error?: Error }) => {
			if (settled) return;
			settled = true;
			exited.resolve(value);
		};
		child?.once("error", (error) => finish({ code: null, error }));
		child?.once("close", (code) => finish({ code }));
		const result = await exited.promise;
		clearTimeout(timer);
		signal?.removeEventListener("abort", abort);
		const failed =
			Boolean(result.error) ||
			result.code !== 0 ||
			timedOut ||
			signal?.aborted ||
			Boolean(responseFile && !existsSync(responseFile));
		const diagnostic = failed ? await tail(log) : "";
		if (failed) {
			if (signal?.aborted) throw cancellationError();
			if (timedOut) fail(`Ghidra timed out after ${timeoutMs}ms`);
			const reason =
				result.error?.message ??
				(result.code !== 0
					? `exit ${result.code}`
					: "script produced no response");
			fail(`Ghidra failed (${reason})\n${diagnostic}`);
		}
	} finally {
		if (fd !== undefined) {
			try {
				closeSync(fd);
			} catch {
				// The descriptor is already closed by the child exit path.
			}
		}
		await rm(log, { force: true });
		if (wrapper) await rm(wrapper, { force: true });
	}
}

function opFromRequest(request: GhidraRequest): Record<string, unknown> {
	const {
		binary: _binary,
		ghidraHome: _home,
		javaHome: _java,
		cacheDir: _cache,
		force: _force,
		operations,
		...operation
	} = request;
	return request.action === "batch"
		? { action: "batch", operations }
		: operation;
}

function isReadRequest(request: GhidraRequest): boolean {
	if (request.action === "batch")
		return Boolean(
			request.operations?.every((op) => READ_ACTIONS[op.action] === true),
		);
	return READ_ACTIONS[request.action] === true;
}

function assertBinary(request: GhidraRequest, cwd: string): string {
	if (!request.binary) fail(`binary is required for ${request.action}`);
	// Pi and omp file mentions arrive as "@path"; accept both spellings.
	const value = request.binary.startsWith("@")
		? request.binary.slice(1)
		: request.binary;
	const path = resolve(cwd, value);
	let isFile = false;
	try {
		isFile = statSync(path).isFile();
	} catch {
		fail(`Binary not found: ${path}`);
	}
	if (!isFile) fail(`Not a file: ${path}`);
	return path;
}

async function prepareArtifact(
	binary: string,
	cacheRoot: string,
): Promise<{ artifact: string; hash: string }> {
	const hash = await hashFile(binary);
	const artifact = join(cacheRoot, "artifacts", hash);
	await mkdir(join(artifact, "input"), { recursive: true });
	return { artifact, hash };
}

function isManifest(value: unknown, hash: string): value is Manifest {
	if (!isRecord(value)) return false;
	return (
		value.schema === 1 &&
		value.hash === hash &&
		typeof value.source === "string" &&
		typeof value.program === "string" &&
		value.program.length > 0 &&
		typeof value.ghidraVersion === "string" &&
		typeof value.createdAt === "string"
	);
}

async function readManifest(
	artifact: string,
	hash: string,
	home: string,
): Promise<Manifest | undefined> {
	const manifestPath = join(artifact, "manifest.json");
	if (!existsSync(join(artifact, "project"))) return undefined;
	let value: unknown;
	try {
		value = JSON.parse(await readFile(manifestPath, "utf8"));
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
		throw new Error(`Invalid Ghidra manifest: ${manifestPath}`, {
			cause: error,
		});
	}
	if (!isManifest(value, hash))
		throw new Error(`Invalid Ghidra manifest: ${manifestPath}`);
	if (value.ghidraVersion !== (applicationVersion(home) ?? "unknown"))
		return undefined;
	return value;
}

async function writeManifest(
	artifact: string,
	manifest: Manifest,
): Promise<void> {
	const path = join(artifact, "manifest.json");
	const temporary = `${path}.${randomUUID()}.tmp`;
	await writeFile(temporary, `${JSON.stringify(manifest, null, 2)}\n`);
	try {
		await renameFile(temporary, path);
	} finally {
		await rm(temporary, { force: true });
	}
}

async function importArtifact(
	binary: string,
	artifact: string,
	hash: string,
	home: string,
	requestFile: string,
	responseFile: string,
	signal?: AbortSignal,
): Promise<Manifest> {
	const suffix = extname(binary)
		.replace(/[^.a-zA-Z0-9]/g, "")
		.slice(0, 12);
	const program = `${hash.slice(0, 16)}${suffix || ".bin"}`;
	const input = join(artifact, "input", program);
	if (!existsSync(input)) await copyFile(binary, input);
	const staging = join(artifact, "project.next");
	await rm(staging, { recursive: true, force: true });
	await mkdir(staging, { recursive: true });
	try {
		await runScript(
			home,
			[
				staging,
				PROJECT_NAME,
				"-import",
				input,
				"-scriptPath",
				SCRIPT_DIR,
				"-postScript",
				"PiGhidra.java",
				requestFile,
				responseFile,
				"-analysisTimeoutPerFile",
				"600",
				"-max-cpu",
				String(
					Math.max(1, Math.min(4, Number(process.env.PI_GHIDRA_CPUS) || 2)),
				),
			],
			artifact,
			signal,
			DEFAULT_IMPORT_TIMEOUT_MS,
			responseFile,
		);
		const manifest: Manifest = {
			schema: 1,
			hash,
			source: binary,
			program,
			ghidraVersion: applicationVersion(home) || "unknown",
			createdAt: new Date().toISOString(),
		};
		const project = join(artifact, "project");
		await rm(project, { recursive: true, force: true });
		await renameFile(staging, project);
		await writeManifest(artifact, manifest);
		return manifest;
	} catch (error) {
		await rm(staging, { recursive: true, force: true });
		throw error;
	}
}

async function readResponse(path: string): Promise<unknown> {
	let info;
	try {
		info = await stat(path);
	} catch (error) {
		throw new Error(`Ghidra did not produce a response: ${path}`, {
			cause: error,
		});
	}
	if (info.size > MAX_RESPONSE_BYTES)
		throw new Error(
			`Ghidra response exceeds ${MAX_RESPONSE_BYTES} bytes: ${path}`,
		);
	try {
		return JSON.parse(await readFile(path, "utf8"));
	} catch (error) {
		throw new Error(`Ghidra did not produce a valid response: ${path}`, {
			cause: error,
		});
	}
}

async function runScript(
	home: string,
	args: string[],
	cwd: string,
	signal: AbortSignal | undefined,
	timeoutMs: number,
	responseFile: string,
): Promise<void> {
	try {
		await launch(home, args, cwd, signal, timeoutMs, responseFile);
	} catch (error) {
		// The script writes a structured error before exiting non-zero; prefer
		// that message over "exit 1" plus a truncated launcher log.
		let scriptError: string | undefined;
		if (
			!(error instanceof Error) ||
			!error.message.startsWith("Ghidra failed (exit")
		)
			throw error;
		try {
			const payload = await readResponse(responseFile);
			if (
				isRecord(payload) &&
				payload.ok === false &&
				typeof payload.error === "string"
			)
				scriptError = payload.error;
		} catch {
			// No usable response; keep the launcher diagnostic.
		}
		if (scriptError) throw new Error(scriptError, { cause: error });
		throw error;
	}
}

export async function runGhidra(
	input: GhidraRequest,
	cwd = process.cwd(),
	signal?: AbortSignal,
): Promise<RunResult> {
	const request = validateGhidraRequest(input);
	if (request.action === "discover") {
		const homes = discoverGhidraHomes(true);
		return {
			action: "discover",
			ghidraHome: homes[0] ?? null,
			result: {
				configPath: ghidraConfigPath(),
				config: readableGhidraConfig(),
				ghidraHomes: homes.map((home) => ({
					path: home,
					version: applicationVersion(home),
				})),
			},
		};
	}
	if (request.action === "setup") {
		const home = resolveGhidraHome(
			request.ghidraHome ? resolve(cwd, request.ghidraHome) : undefined,
		);
		const update: GhidraConfig = { ghidraHome: home };
		if (request.javaHome) update.javaHome = resolve(cwd, request.javaHome);
		if (request.cacheDir) update.cacheDir = resolve(cwd, request.cacheDir);
		const config = await saveGhidraConfig(update);
		return {
			action: "setup",
			ghidraHome: home,
			result: {
				configured: true,
				configPath: ghidraConfigPath(),
				config,
				version: applicationVersion(home),
			},
		};
	}
	if (request.action === "health") {
		let home: string | null = null;
		let error: string | undefined;
		try {
			home = resolveGhidraHome(
				request.ghidraHome ? resolve(cwd, request.ghidraHome) : undefined,
			);
		} catch (cause) {
			error = cause instanceof Error ? cause.message : String(cause);
		}
		let cacheDir: string | null = null;
		let cacheError: string | undefined;
		try {
			cacheDir = validateCacheDir(
				request.cacheDir ? resolve(cwd, request.cacheDir) : defaultCacheDir(),
			);
		} catch (cause) {
			cacheError = cause instanceof Error ? cause.message : String(cause);
		}
		return {
			action: "health",
			ghidraHome: home,
			result: {
				version: home ? applicationVersion(home) : null,
				javaHome: javaHome() ?? null,
				cacheDir,
				cacheError,
				error,
				configPath: ghidraConfigPath(),
				config: readableGhidraConfig(),
				detectedHomes: discoverGhidraHomes(),
				actions: ACTIONS,
			},
		};
	}
	const home = resolveGhidraHome(
		request.ghidraHome ? resolve(cwd, request.ghidraHome) : undefined,
	);
	const binary = assertBinary(request, cwd);
	const cacheRoot = validateCacheDir(
		request.cacheDir ? resolve(cwd, request.cacheDir) : defaultCacheDir(),
	);
	await mkdir(cacheRoot, { recursive: true });
	const prepared = await prepareArtifact(binary, cacheRoot);
	return serialized(
		prepared.artifact,
		async () => {
			const release = await acquireLock(
				join(prepared.artifact, ".lock"),
				signal,
			);
			let runDir: string | undefined;
			try {
				const rebuild = request.action === "rebuild" || request.force;
				let manifest = rebuild
					? undefined
					: await readManifest(prepared.artifact, prepared.hash, home);
				const cached = Boolean(manifest);
				runDir = join(prepared.artifact, "runs", randomUUID());
				await mkdir(runDir, { recursive: true });
				const requestFile = join(runDir, "request.json");
				const responseFile = join(runDir, "response.json");
				const effective =
					request.action === "rebuild"
						? { action: "info" }
						: opFromRequest(request);
				await writeFile(requestFile, JSON.stringify(effective));
				if (!manifest)
					manifest = await importArtifact(
						binary,
						prepared.artifact,
						prepared.hash,
						home,
						requestFile,
						responseFile,
						signal,
					);
				else {
					const args = [
						join(prepared.artifact, "project"),
						PROJECT_NAME,
						"-process",
						manifest.program,
						"-noanalysis",
						"-scriptPath",
						SCRIPT_DIR,
						"-postScript",
						"PiGhidra.java",
						requestFile,
						responseFile,
					];
					if (isReadRequest(request)) args.push("-readOnly");
					await runScript(
						home,
						args,
						prepared.artifact,
						signal,
						Math.max(
							30_000,
							Math.min(
								15 * 60_000,
								(request.timeoutSeconds ?? 120) * 1000,
							),
						),
						responseFile,
					);
				}
				const payload = await readResponse(responseFile);
				if (!isRecord(payload) || payload.ok !== true) {
					const message =
						isRecord(payload) && typeof payload.error === "string"
							? payload.error
							: "Ghidra operation failed";
					throw new Error(message);
				}
				return {
					action: request.action,
					artifact: prepared.hash,
					cached,
					ghidraHome: home,
					project: join(
						prepared.artifact,
						"project",
						`${PROJECT_NAME}.gpr`,
					),
					program: manifest.program,
					result: payload.result,
				};
			} finally {
				try {
					if (runDir) await rm(runDir, { recursive: true, force: true });
				} finally {
					await release();
				}
			}
		},
		signal,
	);
}
