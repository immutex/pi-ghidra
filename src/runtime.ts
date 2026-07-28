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
	readFile,
	rm,
	stat,
	utimes,
	writeFile,
} from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { dirname, extname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";

export const ACTIONS = [
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

export interface Operation {
	action: Exclude<Action, "health" | "batch" | "rebuild">;
	address?: string;
	name?: string;
	query?: string;
	pattern?: string;
	value?: string;
	bytes?: string;
	commentType?: "EOL" | "PRE" | "POST" | "PLATE" | "REPEATABLE";
	direction?: "to" | "from" | "both";
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
	cacheDir?: string;
	force?: boolean;
}

export interface RunResult {
	action: Action;
	artifact?: string;
	cached?: boolean;
	ghidraHome: string;
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

const PACKAGE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SCRIPT_DIR = join(PACKAGE_ROOT, "ghidra_scripts");
const PROJECT_NAME = "pi-ghidra";
const queues = new Map<string, Promise<void>>();
const READ_ACTIONS = new Set<Action>([
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
]);

function defaultCacheDir(): string {
	if (process.env.PI_GHIDRA_CACHE) return resolve(process.env.PI_GHIDRA_CACHE);
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
	if (!existsSync(file)) return undefined;
	return readFileSync(file, "utf8")
		.match(/^application\.version=(.+)$/m)?.[1]
		?.trim();
}

function candidateHomes(): string[] {
	const values = [process.env.PI_GHIDRA_HOME, process.env.GHIDRA_HOME];
	if (process.platform === "win32") {
		values.push("C:\\ghidra_12.1.2");
		for (const root of ["C:\\", process.env.USERPROFILE]) {
			if (!root || !existsSync(root)) continue;
			try {
				values.push(
					...readdirSync(root)
						.filter((name) => /^ghidra_/i.test(name))
						.sort((a, b) => b.localeCompare(a, undefined, { numeric: true }))
						.map((name) => join(root, name)),
				);
			} catch (error) {
				if ((error as NodeJS.ErrnoException).code !== "EACCES") throw error;
			}
		}
	} else {
		values.push("/opt/ghidra", "/usr/local/ghidra", join(homedir(), "ghidra"));
	}
	return values.filter((value): value is string => Boolean(value));
}

export function resolveGhidraHome(explicit?: string): string {
	const home = candidateHomes()
		.map((candidate) => resolve(candidate))
		.find((candidate) => {
			const launcher = join(
				candidate,
				"support",
				process.platform === "win32"
					? "analyzeHeadless.bat"
					: "analyzeHeadless",
			);
			return (
				existsSync(launcher) && applicationVersion(candidate)?.startsWith("12.")
			);
		});
	if (explicit) {
		const resolved = resolve(explicit);
		const launcher = join(
			resolved,
			"support",
			process.platform === "win32" ? "analyzeHeadless.bat" : "analyzeHeadless",
		);
		if (!existsSync(launcher))
			throw new Error(`Ghidra analyzeHeadless not found under ${resolved}`);
		const version = applicationVersion(resolved);
		if (!version?.startsWith("12."))
			throw new Error(
				`Ghidra 12 is required; found ${version ?? "an unreadable version"} under ${resolved}`,
			);
		return resolved;
	}
	if (!home)
		throw new Error(
			"Ghidra 12 was not found. Set PI_GHIDRA_HOME or GHIDRA_HOME.",
		);
	return home;
}

function javaHome(): string | undefined {
	if (
		process.env.JAVA_HOME &&
		existsSync(
			join(
				process.env.JAVA_HOME,
				"bin",
				process.platform === "win32" ? "java.exe" : "java",
			),
		)
	)
		return process.env.JAVA_HOME;
	if (process.platform !== "win32") return undefined;
	const roots = [
		join(process.env.ProgramFiles || "C:\\Program Files", "Eclipse Adoptium"),
		join(process.env.ProgramFiles || "C:\\Program Files", "Java"),
	];
	for (const root of roots) {
		if (!existsSync(root)) continue;
		const found = readdirSync(root)
			.filter((name) => /^jdk/i.test(name))
			.sort((a, b) => b.localeCompare(a, undefined, { numeric: true }))
			.find((name) => existsSync(join(root, name, "bin", "java.exe")));
		if (found) return join(root, found);
	}
	return undefined;
}

export async function hashFile(path: string): Promise<string> {
	const hash = createHash("sha256");
	await new Promise<void>((resolvePromise, reject) => {
		const stream = createReadStream(path);
		stream.on("data", (chunk) => hash.update(chunk));
		stream.on("end", resolvePromise);
		stream.on("error", reject);
	});
	return hash.digest("hex");
}

async function serialized<T>(key: string, run: () => Promise<T>): Promise<T> {
	const previous = queues.get(key) ?? Promise.resolve();
	let release!: () => void;
	const current = new Promise<void>((resolvePromise) => {
		release = resolvePromise;
	});
	const tail = previous.then(() => current);
	queues.set(key, tail);
	await previous;
	try {
		return await run();
	} finally {
		release();
		if (queues.get(key) === tail) queues.delete(key);
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
		if (signal?.aborted) throw new Error("Ghidra operation cancelled");
		try {
			await stat(reapPath);
			await new Promise((resolvePromise) => setTimeout(resolvePromise, 200));
			continue;
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
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
			const heartbeat = setInterval(() => {
				const now = new Date();
				void utimes(path, now, now).catch(() => undefined);
			}, 5000);
			heartbeat.unref();
			return async () => {
				clearInterval(heartbeat);
				try {
					const owner = JSON.parse(
						await readFile(join(path, "owner.json"), "utf8"),
					) as { token?: string };
					if (owner.token === token)
						await rm(path, { recursive: true, force: true });
				} catch (error) {
					if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
				}
			};
		} catch (error) {
			const code = (error as NodeJS.ErrnoException).code;
			if (code !== "EEXIST") throw error;
			let age: number;
			try {
				age = Date.now() - (await stat(path)).mtimeMs;
			} catch (statError) {
				if ((statError as NodeJS.ErrnoException).code === "ENOENT") continue;
				throw statError;
			}
			if (age > 30 * 60_000) {
				try {
					await mkdir(reapPath);
					try {
						const currentAge = Date.now() - (await stat(path)).mtimeMs;
						if (currentAge > 30 * 60_000)
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
			if (Date.now() - started > 30_000)
				throw new Error(`Ghidra artifact is busy: ${dirname(path)}`);
			await new Promise((resolvePromise) => setTimeout(resolvePromise, 200));
		}
	}
}

function killTree(child: ChildProcess): void {
	if (!child.pid) return;
	if (process.platform === "win32")
		spawnSync("taskkill", ["/pid", String(child.pid), "/t", "/f"], {
			stdio: "ignore",
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
	try {
		const value = await readFile(path);
		return value.subarray(Math.max(0, value.length - bytes)).toString("utf8");
	} catch {
		return "";
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
	if (signal?.aborted) throw new Error("Ghidra operation cancelled");
	const launcher = join(
		home,
		"support",
		process.platform === "win32" ? "analyzeHeadless.bat" : "analyzeHeadless",
	);
	const log = join(cwd, `ghidra-${randomUUID()}.log`);
	const wrapper =
		process.platform === "win32"
			? join(tmpdir(), `pi-ghidra-${randomUUID()}.cmd`)
			: undefined;
	if (wrapper) {
		const quote = (value: string) => {
			if (/["\r\n%!^]/.test(value))
				throw new Error(
					`Unsupported character in Windows Ghidra path or argument: ${value}`,
				);
			return `"${value}"`;
		};
		await writeFile(
			wrapper,
			`@echo off\r\ncall ${[launcher, ...args].map(quote).join(" ")}\r\nexit /b %errorlevel%\r\n`,
		);
	}
	const fd = openSync(log, "w");
	const env = {
		...process.env,
		JAVA_HOME: javaHome() || process.env.JAVA_HOME,
	};
	const child = wrapper
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
	let timedOut = false;
	const timer = setTimeout(() => {
		timedOut = true;
		killTree(child);
	}, timeoutMs);
	const abort = () => killTree(child);
	signal?.addEventListener("abort", abort, { once: true });
	if (signal?.aborted) abort();
	const result = await new Promise<{ code: number | null; error?: Error }>(
		(resolvePromise) => {
			child.once("error", (error) => resolvePromise({ code: null, error }));
			child.once("close", (code) => resolvePromise({ code }));
		},
	);
	clearTimeout(timer);
	signal?.removeEventListener("abort", abort);
	closeSync(fd);
	const failed =
		result.error ||
		result.code !== 0 ||
		timedOut ||
		signal?.aborted ||
		(responseFile && !existsSync(responseFile));
	const diagnostic = failed ? await tail(log) : "";
	await rm(log, { force: true });
	if (wrapper) await rm(wrapper, { force: true });
	if (failed) {
		if (signal?.aborted) throw new Error("Ghidra operation cancelled");
		if (timedOut) throw new Error(`Ghidra timed out after ${timeoutMs}ms`);
		const reason =
			result.error?.message ??
			(result.code !== 0
				? `exit ${result.code}`
				: "script produced no response");
		throw new Error(`Ghidra failed (${reason})\n${diagnostic}`);
	}
}

function opFromRequest(request: GhidraRequest): Record<string, unknown> {
	const {
		binary: _binary,
		ghidraHome: _home,
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
			request.operations?.every((op) => READ_ACTIONS.has(op.action)),
		);
	return READ_ACTIONS.has(request.action);
}

function assertBinary(request: GhidraRequest, cwd: string): string {
	if (!request.binary)
		throw new Error(`binary is required for ${request.action}`);
	const value = request.binary.startsWith("@")
		? request.binary.slice(1)
		: request.binary;
	const path = resolve(cwd, value);
	if (!existsSync(path) || !statSync(path).isFile())
		throw new Error(`Binary not found: ${path}`);
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

async function readManifest(
	artifact: string,
	home: string,
): Promise<Manifest | undefined> {
	const manifestPath = join(artifact, "manifest.json");
	let manifest: Manifest | undefined;
	try {
		manifest = JSON.parse(await readFile(manifestPath, "utf8")) as Manifest;
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code !== "ENOENT")
			throw new Error(`Invalid Ghidra manifest: ${manifestPath}`, {
				cause: error,
			});
	}
	if (manifest && manifest.ghidraVersion !== applicationVersion(home)) {
		await rm(join(artifact, "project"), { recursive: true, force: true });
		await rm(manifestPath, { force: true });
		return undefined;
	}
	return manifest;
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
	const project = join(artifact, "project");
	await rm(project, { recursive: true, force: true });
	await mkdir(project, { recursive: true });
	await launch(
		home,
		[
			project,
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
			String(Math.max(1, Math.min(4, Number(process.env.PI_GHIDRA_CPUS) || 2))),
		],
		artifact,
		signal,
		15 * 60_000,
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
	await writeFile(
		join(artifact, "manifest.json"),
		JSON.stringify(manifest, null, 2),
	);
	return manifest;
}

export async function runGhidra(
	request: GhidraRequest,
	cwd = process.cwd(),
	signal?: AbortSignal,
): Promise<RunResult> {
	const home = resolveGhidraHome(request.ghidraHome);
	if (request.action === "health") {
		return {
			action: "health",
			ghidraHome: home,
			result: {
				version: applicationVersion(home),
				javaHome: javaHome() ?? process.env.JAVA_HOME ?? null,
				cacheDir: resolve(request.cacheDir || defaultCacheDir()),
				actions: ACTIONS,
			},
		};
	}
	const binary = assertBinary(request, cwd);
	const cacheRoot = resolve(request.cacheDir || defaultCacheDir());
	const cacheParts = cacheRoot.split(/[\\/]+/);
	if (cacheParts.some((part) => part.startsWith("."))) {
		throw new Error(
			`Ghidra project paths cannot contain dot-prefixed directories: ${cacheRoot}`,
		);
	}
	if (cacheParts.some((part) => /[&%!^]/.test(part))) {
		throw new Error(
			`Ghidra project paths cannot contain &, %, !, or ^: ${cacheRoot}`,
		);
	}
	await mkdir(cacheRoot, { recursive: true });
	const prepared = await prepareArtifact(binary, cacheRoot);
	return serialized(prepared.hash, async () => {
		const release = await acquireLock(join(prepared.artifact, ".lock"), signal);
		let runDir: string | undefined;
		try {
			let manifest = await readManifest(prepared.artifact, home);
			const rebuild = request.action === "rebuild" || request.force;
			if (rebuild) {
				await rm(join(prepared.artifact, "project"), {
					recursive: true,
					force: true,
				});
				await rm(join(prepared.artifact, "manifest.json"), { force: true });
				manifest = undefined;
			}
			const activeRunDir = await mkdir(join(prepared.artifact, "runs"), {
				recursive: true,
			}).then(() => join(prepared.artifact, "runs", randomUUID()));
			runDir = activeRunDir;
			await mkdir(activeRunDir);
			const requestFile = join(activeRunDir, "request.json");
			const responseFile = join(activeRunDir, "response.json");
			const effective =
				request.action === "rebuild"
					? { action: "info" }
					: opFromRequest(request);
			await writeFile(requestFile, JSON.stringify(effective));
			const cached = Boolean(manifest);
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
				await launch(
					home,
					args,
					prepared.artifact,
					signal,
					Math.max(
						30_000,
						Math.min(15 * 60_000, (request.timeoutSeconds ?? 120) * 1000),
					),
					responseFile,
				);
			}
			let payload: unknown;
			try {
				payload = JSON.parse(await readFile(responseFile, "utf8"));
			} catch (error) {
				throw new Error(
					`Ghidra did not produce a valid response: ${responseFile}`,
					{ cause: error },
				);
			}
			if (!(payload as { ok?: boolean }).ok)
				throw new Error(
					(payload as { error?: string }).error || "Ghidra operation failed",
				);
			return {
				action: request.action,
				artifact: prepared.hash,
				cached,
				ghidraHome: home,
				project: join(prepared.artifact, "project", `${PROJECT_NAME}.gpr`),
				program: manifest.program,
				result: (payload as { result: unknown }).result,
			};
		} finally {
			try {
				if (runDir) await rm(runDir, { recursive: true, force: true });
			} finally {
				await release();
			}
		}
	});
}
