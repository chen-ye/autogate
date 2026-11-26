import crypto from "node:crypto";
import { spawn, type ChildProcess } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Database } from "bun:sqlite";
import {
  isClassifierVerdict,
  isRecord,
  type ClassifierResult,
  type GateAction,
  type GateEvaluator,
} from "../../packages/core/src/index.js";
import { DEDICATED_AUTO_GATE_DIR } from "../../packages/opencode/src/evaluator.js";

const BENCH_TMP_BASE = "/tmp/opencode";
const DEFAULT_STARTUP_TIMEOUT_MS = 30000;
const SQL_IDENT_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;

const INHERITED_ENV_STRIP_KEYS = [
  "OPENCODE_CONFIG",
  "OPENCODE_CONFIG_CONTENT",
  "OPENCODE_CONFIG_DIR",
  "OPENCODE_DB",
  "OPENCODE_PASSWORD",
  "OPENCODE_SERVER_PASSWORD",
  "OPENCODE_SERVER_URL",
  "OPENCODE_PORT",
  "AUTOGATE_CONFIG",
  "AUTOGATE_AUTO_MODE",
  "OPENCODE_AUTO_MODE",
  "AUTOGATE_FALLBACK",
  "AUTOGATE_NTFY_TOPIC",
  "NTFY_TOPIC",
  "OPENCODE_NTFY_TOPIC",
  "NTFY_SERVER",
  "NTFY_TOKEN",
  "AUTOGATE_NTFY_TOKEN",
  "AUTOGATE_EVAL_LOG",
  "AUTOGATE_EVAL_DB",
  "AUTOGATE_EVAL_SESSION_CLEANUP",
  "CLASSIFIER_MODEL",
  "CLASSIFIER_TIMEOUT",
  "AUTOGATE_SYSTEM_ONE_ENABLED",
  "AUTOGATE_SYSTEM_ONE_MODE",
  "AUTOGATE_SYSTEM_ONE_ENDPOINT",
  "AUTOGATE_SYSTEM_ONE_MODEL",
  "AUTOGATE_SYSTEM_ONE_API_KEY",
  "AUTOGATE_SYSTEM_ONE_TIMEOUT_MS",
  "AUTOGATE_BENCH_ROOT",
  "AUTOGATE_BENCH_READY_FILE",
  "AUTOGATE_BENCH_TOKEN",
  "AUTOGATE_BENCH_EVAL_LOG",
  "AUTOGATE_BENCH_EVAL_DB",
] as const;

export interface OpenCodeS2RunnerOptions {
  readonly classifierModel?: string;
  readonly classifierTimeoutMs?: number;
  readonly mockProvider?: {
    readonly baseUrl: string;
    readonly modelId?: string;
    readonly apiKey?: string;
  };
  readonly sourceConfigDir?: string;
  readonly sourceDataDir?: string;
  readonly startupTimeoutMs?: number;
}

export function stripJsonCommentsAndTrailingCommas(raw: string): string {
  let withoutComments = "";
  let inString = false;
  let escaped = false;

  for (let i = 0; i < raw.length; i++) {
    const ch = raw[i];
    if (inString) {
      withoutComments += ch;
      if (escaped) {
        escaped = false;
      } else if (ch === "\\") {
        escaped = true;
      } else if (ch === '"') {
        inString = false;
      }
      continue;
    }

    if (ch === '"') {
      inString = true;
      withoutComments += ch;
      continue;
    }

    if (ch === "/" && raw[i + 1] === "/") {
      i += 2;
      while (i < raw.length && raw[i] !== "\n" && raw[i] !== "\r") {
        i++;
      }
      if (i < raw.length) {
        withoutComments += raw[i];
      }
      continue;
    }

    if (ch === "/" && raw[i + 1] === "*") {
      i += 2;
      while (i < raw.length && !(raw[i] === "*" && raw[i + 1] === "/")) {
        i++;
      }
      i += 1;
      continue;
    }

    withoutComments += ch;
  }

  let result = "";
  inString = false;
  escaped = false;

  for (let i = 0; i < withoutComments.length; i++) {
    const ch = withoutComments[i];
    if (inString) {
      result += ch;
      if (escaped) {
        escaped = false;
      } else if (ch === "\\") {
        escaped = true;
      } else if (ch === '"') {
        inString = false;
      }
      continue;
    }

    if (ch === '"') {
      inString = true;
      result += ch;
      continue;
    }

    if (ch === ",") {
      let j = i + 1;
      while (j < withoutComments.length && /\s/.test(withoutComments[j])) {
        j++;
      }
      const nextNonWs = withoutComments[j];
      if (nextNonWs === "}" || nextNonWs === "]") {
        continue;
      }
    }

    result += ch;
  }

  return result;
}

function readSourceProviderSettings(sourceConfigDir: string): {
  provider?: Record<string, unknown>;
  providers?: Record<string, unknown>;
} {
  const mergedProvider: Record<string, unknown> = {};
  const mergedProviders: Record<string, unknown> = {};
  let foundProvider = false;
  let foundProviders = false;

  for (const filename of ["opencode.json", "opencode.jsonc"]) {
    const filePath = path.join(sourceConfigDir, filename);
    if (!fs.existsSync(filePath)) {
      continue;
    }
    try {
      const raw = fs.readFileSync(filePath, "utf8");
      const stripped = stripJsonCommentsAndTrailingCommas(raw);
      const parsed: unknown = JSON.parse(stripped);
      if (!isRecord(parsed)) {
        continue;
      }
      if (isRecord(parsed.provider)) {
        Object.assign(mergedProvider, parsed.provider);
        foundProvider = true;
      }
      if (isRecord(parsed.providers)) {
        Object.assign(mergedProviders, parsed.providers);
        foundProviders = true;
      }
    } catch (err) {
      console.warn(
        `[OpenCodeS2Runner] Failed to parse source config at ${filePath}:`,
        err instanceof Error ? err.message : String(err),
      );
    }
  }

  return {
    ...(foundProvider ? { provider: mergedProvider } : {}),
    ...(foundProviders ? { providers: mergedProviders } : {}),
  };
}

export function seedCredentialsFromSourceDb(srcDbPath: string, dstDbPath: string): void {
  if (!fs.existsSync(srcDbPath) || !fs.existsSync(dstDbPath)) {
    return;
  }

  let srcDb: Database | undefined;
  let dstDb: Database | undefined;
  try {
    srcDb = new Database(srcDbPath, { readonly: true });
    srcDb.exec("PRAGMA busy_timeout = 5000;");
    dstDb = new Database(dstDbPath);
    dstDb.exec("PRAGMA busy_timeout = 5000;");

    const srcTable = srcDb
      .query("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'credential'")
      .get();
    const dstTable = dstDb
      .query("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'credential'")
      .get();
    if (!srcTable || !dstTable) {
      return;
    }

    const srcColsRaw = srcDb.query("PRAGMA table_info(credential)").all() as Array<{
      name?: unknown;
    }>;
    const dstColsRaw = dstDb.query("PRAGMA table_info(credential)").all() as Array<{
      name?: unknown;
    }>;

    const srcCols = new Set(
      srcColsRaw
        .map((c) => c.name)
        .filter((name): name is string => typeof name === "string" && SQL_IDENT_RE.test(name)),
    );
    const commonCols = dstColsRaw
      .map((c) => c.name)
      .filter(
        (name): name is string =>
          typeof name === "string" && SQL_IDENT_RE.test(name) && srcCols.has(name),
      );

    if (commonCols.length === 0) {
      return;
    }

    const colList = commonCols.map((c) => `"${c}"`).join(", ");
    const placeholders = commonCols.map(() => "?").join(", ");
    const rows = srcDb.query(`SELECT ${colList} FROM credential`).values() as unknown[][];
    if (rows.length === 0) {
      return;
    }

    const integrationColIdx = commonCols.indexOf("integration_id");
    const integrationIds =
      integrationColIdx >= 0
        ? Array.from(
            new Set(
              rows
                .map((row) => row[integrationColIdx])
                .filter((val): val is string => typeof val === "string" && val.trim().length > 0),
            ),
          )
        : [];

    const deleteIntegrationStmt =
      integrationIds.length > 0
        ? dstDb.prepare("DELETE FROM credential WHERE integration_id = ?")
        : undefined;
    const insertStmt = dstDb.prepare(
      `INSERT OR REPLACE INTO credential (${colList}) VALUES (${placeholders})`,
    );
    const tx = dstDb.transaction((items: unknown[][]) => {
      if (deleteIntegrationStmt) {
        for (const integrationId of integrationIds) {
          deleteIntegrationStmt.run(integrationId);
        }
      }
      for (const row of items) {
        insertStmt.run(...(row as Parameters<typeof insertStmt.run>));
      }
    });
    tx(rows);
  } catch (err) {
    console.warn(
      "[OpenCodeS2Runner] Failed to seed credentials from source opencode.db:",
      err instanceof Error ? err.message : String(err),
    );
  } finally {
    try {
      srcDb?.close();
    } catch {}
    try {
      dstDb?.close();
    } catch {}
  }
}

async function allocateEphemeralPort(): Promise<number> {
  const dummy = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch: () => new Response(""),
  });
  const port = dummy.port;
  await dummy.stop(true);
  if (!port || port <= 0) {
    throw new Error("Failed to allocate ephemeral port for opencode serve");
  }
  return port;
}

function resolveRepoRoot(): string {
  const currentFile = fileURLToPath(import.meta.url);
  return path.resolve(path.dirname(currentFile), "../..");
}

function appendTail(current: string, chunk: string, maxLen = 8192): string {
  const combined = current + chunk;
  return combined.length > maxLen ? combined.slice(combined.length - maxLen) : combined;
}

export class OpenCodeS2Runner implements GateEvaluator {
  public static readonly activeRunners: Set<OpenCodeS2Runner> = new Set();
  private static exitListener?: () => void;
  private static signalListeners: Array<{ sig: NodeJS.Signals; fn: () => void }> = [];

  public static disposeAllSync(): void {
    for (const runner of Array.from(this.activeRunners)) {
      try {
        runner.disposeSync();
      } catch {
        // Best-effort cleanup during exit/signal teardown
      }
    }
    this.detachExitHooksIfEmpty();
  }

  private static attachExitHooks(): void {
    if (this.exitListener || this.signalListeners.length > 0) {
      return;
    }

    const exitFn = () => {
      this.disposeAllSync();
    };
    this.exitListener = exitFn;
    process.on("exit", exitFn);

    for (const sig of ["SIGINT", "SIGTERM", "SIGHUP"] as const) {
      const fn = () => {
        this.disposeAllSync();
        if (process.listenerCount(sig) === 0) {
          process.kill(process.pid, sig);
        }
      };
      this.signalListeners.push({ sig, fn });
      process.on(sig, fn);
    }
  }

  private static detachExitHooksIfEmpty(): void {
    if (this.activeRunners.size > 0) {
      return;
    }
    if (this.exitListener) {
      process.off("exit", this.exitListener);
      this.exitListener = undefined;
    }
    for (const { sig, fn } of this.signalListeners) {
      process.off(sig, fn);
    }
    this.signalListeners = [];
  }

  readonly name = "opencode-v2-s2-runner";

  private readonly options: OpenCodeS2RunnerOptions;
  private readonly repoRoot: string;
  private readonly rootDir: string;
  private readonly isolatedHome: string;
  private readonly isolatedConfig: string;
  private readonly isolatedData: string;
  private readonly isolatedState: string;
  private readonly isolatedCache: string;
  private readonly isolatedDb: string;
  private readonly isolatedEvalDb: string;
  private readonly isolatedWorkspace: string;
  private readonly readyFile: string;
  private readonly sandboxDir: string;
  private readonly sourceConfigDir: string;
  private readonly sourceDataDir: string;
  private readonly benchToken: string;
  private readonly serverPassword: string;
  private readonly effectiveClassifierModel?: string;

  private serverProc?: ChildProcess;
  private serverPid?: number;
  private serverExited = false;
  private baseUrl?: string;
  private pluginPort?: number;
  private startPromise?: Promise<void>;
  private disposePromise?: Promise<void>;
  private disposed = false;

  constructor(options: OpenCodeS2RunnerOptions = {}) {
    this.options = options;
    this.repoRoot = resolveRepoRoot();
    this.rootDir = path.join(BENCH_TMP_BASE, `autogate-bench-${crypto.randomUUID()}`);
    this.isolatedHome = path.join(this.rootDir, "home");
    this.isolatedConfig = path.join(this.isolatedHome, ".config", "opencode");
    this.isolatedData = path.join(this.isolatedHome, ".local", "share", "opencode");
    this.isolatedState = path.join(this.isolatedHome, ".local", "state", "opencode");
    this.isolatedCache = path.join(this.isolatedHome, ".cache");
    this.isolatedDb = path.join(this.isolatedData, "opencode.db");
    this.isolatedEvalDb = path.join(this.isolatedHome, "evals.db");
    this.isolatedWorkspace = path.join(this.rootDir, "workspace");
    this.readyFile = path.join(this.rootDir, "plugin-ready.json");
    this.sandboxDir = DEDICATED_AUTO_GATE_DIR;

    const realHome = os.homedir();
    this.sourceConfigDir = options.sourceConfigDir ?? path.join(realHome, ".config", "opencode");
    this.sourceDataDir =
      options.sourceDataDir ?? path.join(realHome, ".local", "share", "opencode");

    this.benchToken = crypto.randomUUID();
    this.serverPassword = crypto.randomUUID();
    this.effectiveClassifierModel =
      options.classifierModel?.trim() ||
      (options.mockProvider
        ? `mock-provider/${options.mockProvider.modelId ?? "mock-model"}`
        : undefined);
  }

  public static async create(options: OpenCodeS2RunnerOptions = {}): Promise<OpenCodeS2Runner> {
    const runner = new OpenCodeS2Runner(options);
    await runner.start();
    return runner;
  }

  public getBaseUrl(): string {
    if (!this.baseUrl) {
      throw new Error("OpenCodeS2Runner has not been started yet");
    }
    return this.baseUrl;
  }

  public getIsolatedHome(): string {
    return this.isolatedHome;
  }

  public getEvalDbFile(): string {
    return this.isolatedEvalDb;
  }

  public getPluginBaseUrl(): string {
    if (!this.pluginPort) {
      throw new Error("OpenCodeS2Runner companion eval plugin is not ready yet");
    }
    return `http://127.0.0.1:${this.pluginPort}`;
  }

  public async start(): Promise<void> {
    if (this.disposed) {
      throw new Error("OpenCodeS2Runner has already been disposed");
    }
    if (this.startPromise) {
      return this.startPromise;
    }

    this.startPromise = this.doStart().catch(async (err) => {
      await this.dispose();
      throw err;
    });

    return this.startPromise;
  }

  private async doStart(): Promise<void> {
    OpenCodeS2Runner.activeRunners.add(this);
    OpenCodeS2Runner.attachExitHooks();

    fs.mkdirSync(this.rootDir, { recursive: true, mode: 0o700 });
    fs.chmodSync(this.rootDir, 0o700);
    for (const dir of [
      this.isolatedHome,
      this.isolatedConfig,
      this.isolatedData,
      this.isolatedState,
      this.isolatedCache,
      this.isolatedWorkspace,
    ]) {
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
      fs.chmodSync(dir, 0o700);
    }

    // Pre-create empty isolatedDb with 0o600 so SQLite Unix VFS inherits 0o600 onto -wal/-shm
    fs.writeFileSync(this.isolatedDb, "", { mode: 0o600, flag: "a" });
    fs.chmodSync(this.isolatedDb, 0o600);

    this.ensureAndWarnSandboxDir();

    const opencodeBinary = path.resolve(this.repoRoot, "node_modules/.bin/opencode");
    if (!fs.existsSync(opencodeBinary)) {
      throw new Error(`OpenCode CLI binary not found at ${opencodeBinary}`);
    }

    const serverPort = await allocateEphemeralPort();
    const serverUrl = `http://127.0.0.1:${serverPort}`;

    const opencodeConfig = this.buildOpenCodeConfig(serverUrl);
    const opencodeJsonPath = path.join(this.isolatedConfig, "opencode.json");
    fs.writeFileSync(opencodeJsonPath, JSON.stringify(opencodeConfig, null, 2) + "\n", {
      encoding: "utf8",
      mode: 0o600,
    });
    fs.chmodSync(opencodeJsonPath, 0o600);

    if (!this.options.mockProvider) {
      const srcAuthJson = path.join(this.sourceDataDir, "auth.json");
      if (fs.existsSync(srcAuthJson)) {
        const dstAuthJson = path.join(this.isolatedData, "auth.json");
        fs.copyFileSync(srcAuthJson, dstAuthJson);
        try {
          fs.chmodSync(dstAuthJson, 0o600);
        } catch {}
      }
    }

    const childEnv = this.buildChildEnv(opencodeConfig);
    const proc = spawn(opencodeBinary, ["serve", "--hostname=127.0.0.1", `--port=${serverPort}`], {
      cwd: this.isolatedWorkspace,
      env: childEnv,
      stdio: ["ignore", "pipe", "pipe"],
      detached: true,
    });
    this.serverProc = proc;
    this.serverPid = proc.pid;
    this.serverExited = false;

    let outputTail = "";
    let resolvedServerUrl: string | undefined;
    const startupTimeoutMs = this.options.startupTimeoutMs ?? DEFAULT_STARTUP_TIMEOUT_MS;
    const deadlineMs = Date.now() + startupTimeoutMs;

    let earlyExitErr: Error | undefined;
    const onProcExit = (code: number | null, signal: NodeJS.Signals | null) => {
      this.serverExited = true;
      earlyExitErr = new Error(
        `opencode serve exited prematurely (code=${code}, signal=${signal}). Output:\n${outputTail}`,
      );
    };
    const onProcError = (err: Error) => {
      this.serverExited = true;
      earlyExitErr = new Error(`Failed to spawn opencode serve: ${err.message}`);
    };
    const onProcData = (chunk: Buffer) => {
      const text = chunk.toString("utf8");
      outputTail = appendTail(outputTail, text);
      if (!resolvedServerUrl) {
        const match = outputTail.match(/listening on\s+(https?:\/\/[^\s]+)/);
        if (match) {
          resolvedServerUrl = match[1];
        }
      }
    };

    proc.stdout?.on("data", onProcData);
    proc.stderr?.on("data", onProcData);
    proc.on("exit", onProcExit);
    proc.on("error", onProcError);

    try {
      // 1. Wait for opencode serve HTTP listener + Drizzle schema migrations
      while (!resolvedServerUrl) {
        if (earlyExitErr) throw earlyExitErr;
        if (this.disposed) throw new Error("OpenCodeS2Runner disposed during startup");
        if (Date.now() >= deadlineMs) {
          throw new Error(
            `Timed out after ${startupTimeoutMs}ms waiting for opencode serve to listen. Output:\n${outputTail}`,
          );
        }
        await Bun.sleep(20);
      }

      this.baseUrl = resolvedServerUrl;

      // 2. Seed credentials after migrations have run but before booting Location services
      if (!this.options.mockProvider) {
        const srcDbPath = path.join(this.sourceDataDir, "opencode.db");
        seedCredentialsFromSourceDb(srcDbPath, this.isolatedDb);
      }
      for (const dbFile of [this.isolatedDb, `${this.isolatedDb}-wal`, `${this.isolatedDb}-shm`]) {
        if (fs.existsSync(dbFile)) {
          fs.chmodSync(dbFile, 0o600);
        }
      }

      // 3. OpenCode 2.0.21 boots Location plugins lazily on first request for a directory.
      // Wake the isolated bench Location so @autogate/opencode and opencode-eval-plugin run setup(ctx).
      const authHeader =
        "Basic " + Buffer.from(`opencode:${this.serverPassword}`).toString("base64");
      const wakeUrl = `${resolvedServerUrl}/api/agent?directory=${encodeURIComponent(this.isolatedWorkspace)}`;
      const wakeRes = await fetch(wakeUrl, {
        headers: {
          Authorization: authHeader,
          "x-opencode-directory": this.isolatedWorkspace,
        },
        signal: AbortSignal.timeout(Math.max(1000, deadlineMs - Date.now())),
      });
      if (!wakeRes.ok) {
        const bodyText = await wakeRes.text().catch(() => "");
        throw new Error(`Failed to wake OpenCode bench Location (${wakeRes.status}): ${bodyText}`);
      }

      // 4. Wait for the companion eval plugin ready file
      let resolvedPluginPort: number | undefined;
      while (!resolvedPluginPort) {
        if (earlyExitErr) throw earlyExitErr;
        if (this.disposed) throw new Error("OpenCodeS2Runner disposed during startup");
        if (fs.existsSync(this.readyFile)) {
          try {
            const raw = fs.readFileSync(this.readyFile, "utf8");
            const parsed: unknown = JSON.parse(raw);
            if (
              isRecord(parsed) &&
              typeof parsed.port === "number" &&
              Number.isFinite(parsed.port) &&
              parsed.port > 0
            ) {
              resolvedPluginPort = parsed.port;
              break;
            }
          } catch {
            // Ready file might still be appearing; retry on next tick
          }
        }
        if (Date.now() >= deadlineMs) {
          throw new Error(
            `Timed out after ${startupTimeoutMs}ms waiting for eval plugin ready file (${this.readyFile}). Output:\n${outputTail}`,
          );
        }
        await Bun.sleep(25);
      }

      this.pluginPort = resolvedPluginPort;

      // 5. Confirm @autogate/opencode finished registering auto-gate-eval on BOTH the bench Location
      // and DEDICATED_AUTO_GATE_DIR (where classifyRequest opens evaluation sessions) before
      // accepting evaluate() calls (prevents resolveEvaluationAgent() caching "build" or concurrent
      // cold Location races under --concurrency > 1).
      const locationsToConfirm = Array.from(new Set([this.isolatedWorkspace, this.sandboxDir]));
      for (const dir of locationsToConfirm) {
        const agentUrl = `${resolvedServerUrl}/api/agent?directory=${encodeURIComponent(dir)}`;
        let evalAgentReady = false;
        while (!evalAgentReady) {
          if (earlyExitErr) throw earlyExitErr;
          if (this.disposed) throw new Error("OpenCodeS2Runner disposed during startup");
          try {
            const agentRes = await fetch(agentUrl, {
              headers: {
                Authorization: authHeader,
                "x-opencode-directory": dir,
              },
              signal: AbortSignal.timeout(Math.max(1000, deadlineMs - Date.now())),
            });
            if (agentRes.ok) {
              const payload = (await agentRes.json()) as {
                data?: Array<{ id?: unknown; name?: unknown }>;
              };
              const agents = Array.isArray(payload?.data) ? payload.data : [];
              if (agents.some((a) => a?.id === "auto-gate-eval" || a?.name === "auto-gate-eval")) {
                evalAgentReady = true;
                break;
              }
            }
          } catch {
            // Retry until deadline
          }
          if (Date.now() >= deadlineMs) {
            throw new Error(
              `Timed out after ${startupTimeoutMs}ms waiting for auto-gate-eval agent registration in ${dir}. Output:\n${outputTail}`,
            );
          }
          await Bun.sleep(25);
        }
      }
    } finally {
      proc.removeListener("exit", onProcExit);
      proc.removeListener("error", onProcError);
    }

    // Keep tracking unexpected exit and draining stdout/stderr via onProcData so pipes never backpressure.
    proc.on("exit", () => {
      this.serverExited = true;
    });
    proc.unref();
    try {
      (proc.stdout as unknown as { unref?: () => void } | null)?.unref?.();
      (proc.stderr as unknown as { unref?: () => void } | null)?.unref?.();
    } catch {}
  }

  private ensureAndWarnSandboxDir(): void {
    fs.mkdirSync(this.sandboxDir, { recursive: true });
    for (const entry of ["AGENTS.md", ".opencode"]) {
      const candidate = path.join(this.sandboxDir, entry);
      if (fs.existsSync(candidate)) {
        console.warn(
          `[OpenCodeS2Runner] Warning: found stray ${entry} inside ${this.sandboxDir}; this may alter auto-gate-eval instructions.`,
        );
      }
    }
  }

  private buildOpenCodeConfig(serverUrl: string): Record<string, unknown> {
    const autoGatePluginPath = path.resolve(this.repoRoot, "packages/opencode");
    const evalPluginPath = path.resolve(this.repoRoot, "scripts/bench/opencode-eval-plugin");

    const autoGatePluginOptions: Record<string, unknown> = {
      ...(this.effectiveClassifierModel ? { classifierModel: this.effectiveClassifierModel } : {}),
      ...(this.options.classifierTimeoutMs !== undefined
        ? { classifierTimeout: this.options.classifierTimeoutMs }
        : {}),
      evalDbFile: this.isolatedEvalDb,
      autoMode: true,
      notifyOnVerdict: false,
      reviewFallbackMode: "native",
      serverUrl,
    };

    const evalPluginOptions: Record<string, unknown> = {
      benchRoot: this.isolatedWorkspace,
      readyFile: this.readyFile,
      token: this.benchToken,
      evalDbFile: this.isolatedEvalDb,
      serverUrl,
      ...(this.effectiveClassifierModel ? { classifierModel: this.effectiveClassifierModel } : {}),
      ...(this.options.classifierTimeoutMs !== undefined
        ? { classifierTimeout: this.options.classifierTimeoutMs }
        : {}),
    };

    const config: Record<string, unknown> = {
      plugins: [
        { package: autoGatePluginPath, options: autoGatePluginOptions },
        { package: evalPluginPath, options: evalPluginOptions },
      ],
    };

    if (this.options.mockProvider) {
      const rawBase = this.options.mockProvider.baseUrl.replace(/\/+$/, "");
      const baseURL = rawBase.endsWith("/v1") ? rawBase : `${rawBase}/v1`;
      const modelId = this.options.mockProvider.modelId ?? "mock-model";
      const apiKey = this.options.mockProvider.apiKey ?? "mock-api-key";

      config.model = `mock-provider/${modelId}`;
      config.provider = {
        "mock-provider": {
          npm: "@ai-sdk/openai-compatible",
          name: "Mock Provider",
          options: {
            baseURL,
            apiKey,
          },
          models: {
            [modelId]: {
              name: "Mock Model",
            },
          },
        },
      };
      config.providers = {
        "mock-provider": {
          name: "Mock Provider",
          package: "aisdk:@ai-sdk/openai-compatible",
          settings: {
            baseURL,
            apiKey,
          },
          models: {
            [modelId]: {
              name: "Mock Model",
            },
          },
        },
      };
    } else {
      const inherited = readSourceProviderSettings(this.sourceConfigDir);
      if (inherited.provider) {
        config.provider = inherited.provider;
      }
      if (inherited.providers) {
        config.providers = inherited.providers;
      }
    }

    return config;
  }

  private buildChildEnv(opencodeConfig: Record<string, unknown>): NodeJS.ProcessEnv {
    const childEnv: NodeJS.ProcessEnv = { ...process.env };
    for (const key of INHERITED_ENV_STRIP_KEYS) {
      delete childEnv[key];
    }

    const localBinDir = path.resolve(this.repoRoot, "node_modules/.bin");
    const localNodeModules = path.resolve(this.repoRoot, "node_modules");

    childEnv.PATH = childEnv.PATH ? `${localBinDir}:${childEnv.PATH}` : localBinDir;
    childEnv.NODE_PATH = localNodeModules;
    childEnv.HOME = this.isolatedHome;
    childEnv.XDG_CONFIG_HOME = path.join(this.isolatedHome, ".config");
    childEnv.XDG_DATA_HOME = path.join(this.isolatedHome, ".local", "share");
    childEnv.XDG_STATE_HOME = path.join(this.isolatedHome, ".local", "state");
    childEnv.XDG_CACHE_HOME = this.isolatedCache;
    childEnv.OPENCODE_DB = this.isolatedDb;
    childEnv.OPENCODE_CONFIG_DIR = this.isolatedConfig;
    childEnv.OPENCODE_CONFIG_CONTENT = JSON.stringify(opencodeConfig);
    childEnv.OPENCODE_SERVER_PASSWORD = this.serverPassword;
    childEnv.AUTOGATE_BENCH_ROOT = this.isolatedWorkspace;
    childEnv.AUTOGATE_BENCH_READY_FILE = this.readyFile;
    childEnv.AUTOGATE_BENCH_TOKEN = this.benchToken;
    childEnv.AUTOGATE_BENCH_EVAL_DB = this.isolatedEvalDb;
    childEnv.AUTOGATE_EVAL_DB = this.isolatedEvalDb;

    return childEnv;
  }

  async evaluate(
    action: GateAction,
    runtimeOptions?: Record<string, unknown>,
  ): Promise<ClassifierResult> {
    if (this.disposed) {
      throw new Error("OpenCodeS2Runner has been disposed");
    }
    if (action.signal?.aborted) {
      return {
        verdict: "UNSURE",
        reason: "Classifier evaluation aborted by signal",
      };
    }

    await this.start();

    if (this.disposed) {
      throw new Error("OpenCodeS2Runner has been disposed");
    }
    if (action.signal?.aborted) {
      return {
        verdict: "UNSURE",
        reason: "Classifier evaluation aborted by signal",
      };
    }

    if (!this.pluginPort) {
      throw new Error("OpenCodeS2Runner companion eval plugin port is unavailable");
    }

    const { signal, ...serializableAction } = action;
    const classifierModel =
      typeof runtimeOptions?.classifierModel === "string" &&
      runtimeOptions.classifierModel.trim().length > 0
        ? runtimeOptions.classifierModel.trim()
        : this.effectiveClassifierModel;
    const classifierTimeout =
      typeof runtimeOptions?.classifierTimeout === "number" &&
      Number.isFinite(runtimeOptions.classifierTimeout) &&
      runtimeOptions.classifierTimeout > 0
        ? runtimeOptions.classifierTimeout
        : this.options.classifierTimeoutMs;

    let res: Response;
    try {
      res = await fetch(`http://127.0.0.1:${this.pluginPort}/bench/evaluate`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${this.benchToken}`,
        },
        body: JSON.stringify({
          action: serializableAction,
          ...(classifierModel ? { classifierModel } : {}),
          ...(classifierTimeout !== undefined ? { classifierTimeout } : {}),
        }),
        ...(signal ? { signal } : {}),
      });
    } catch (err) {
      if (signal?.aborted) {
        return {
          verdict: "UNSURE",
          reason: "Classifier evaluation aborted by signal",
        };
      }
      throw err;
    }

    if (!res.ok) {
      const errText = await res.text().catch(() => "");
      throw new Error(`OpenCodeS2Runner evaluate failed (${res.status}): ${errText}`);
    }

    const payload: unknown = await res.json();
    if (
      !isRecord(payload) ||
      !isRecord(payload.result) ||
      typeof payload.result.verdict !== "string" ||
      !isClassifierVerdict(payload.result.verdict)
    ) {
      throw new Error(
        `OpenCodeS2Runner received malformed response from eval plugin: ${JSON.stringify(payload)}`,
      );
    }

    return payload.result as unknown as ClassifierResult;
  }

  private signalServer(sig: NodeJS.Signals): void {
    const pid = this.serverPid;
    if (!pid || pid <= 1 || this.serverExited) {
      return;
    }
    try {
      process.kill(-pid, sig);
    } catch {}
    try {
      this.serverProc?.kill(sig);
    } catch {}
  }

  private isServerAlive(): boolean {
    const pid = this.serverPid;
    if (!pid || pid <= 1 || this.serverExited) {
      return false;
    }
    try {
      process.kill(pid, 0);
      return true;
    } catch {
      this.serverExited = true;
      return false;
    }
  }

  public disposeSync(): void {
    if (this.disposed) {
      return;
    }
    this.disposed = true;
    OpenCodeS2Runner.activeRunners.delete(this);
    OpenCodeS2Runner.detachExitHooksIfEmpty();

    if (this.isServerAlive()) {
      this.signalServer("SIGTERM");
      if (this.isServerAlive()) {
        this.signalServer("SIGKILL");
      }
    }

    try {
      if (fs.existsSync(this.rootDir)) {
        fs.rmSync(this.rootDir, { recursive: true, force: true });
      }
    } catch {}
  }

  public async dispose(): Promise<void> {
    if (this.disposePromise) {
      return this.disposePromise;
    }

    this.disposePromise = (async () => {
      this.disposed = true;
      OpenCodeS2Runner.activeRunners.delete(this);
      OpenCodeS2Runner.detachExitHooksIfEmpty();

      if (this.isServerAlive()) {
        this.signalServer("SIGTERM");
        for (let i = 0; i < 20; i++) {
          if (!this.isServerAlive()) {
            break;
          }
          await Bun.sleep(25);
        }
        if (this.isServerAlive()) {
          this.signalServer("SIGKILL");
        }
      }

      try {
        if (fs.existsSync(this.rootDir)) {
          fs.rmSync(this.rootDir, { recursive: true, force: true });
        }
      } catch {}
    })();

    return this.disposePromise;
  }
}
