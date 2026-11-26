import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import {
  AutoGateEvalStore,
  isRecord,
  loadConfig,
  type ClassifierResult,
  type GateAction,
  type ResolvedAutoGateConfig,
} from "../../../packages/core/src/index.js";
import {
  definePlugin,
  OpenCodeSessionEvaluator,
  resolveWorkspaceDirectory,
  type OpenCodePluginInput,
  type OpenCodeSessionClient,
} from "../../../packages/opencode/src/index.js";

interface BenchEvalServerState {
  server: ReturnType<typeof Bun.serve>;
  port: number;
  refcount: number;
  client: OpenCodeSessionClient;
  benchRoot?: string;
  readyFile?: string;
  token: string;
  evalDbFile?: string;
  evalStore?: AutoGateEvalStore;
  baseConfig?: ResolvedAutoGateConfig;
  classifierModel?: string;
  classifierTimeout?: number;
  serverUrl?: string;
}

const g = globalThis as unknown as {
  __autogate_bench_eval_server__?: BenchEvalServerState;
};

function readNonEmptyString(val: unknown): string | undefined {
  return typeof val === "string" && val.trim().length > 0 ? val.trim() : undefined;
}

function readPositiveNumber(val: unknown): number | undefined {
  if (typeof val === "number" && Number.isFinite(val) && val > 0) {
    return val;
  }
  if (typeof val === "string" && val.trim().length > 0) {
    const parsed = Number(val);
    if (Number.isFinite(parsed) && parsed > 0) {
      return parsed;
    }
  }
  return undefined;
}

function timingSafeEqualString(a: string, b: string): boolean {
  const bufA = Buffer.from(a, "utf8");
  const bufB = Buffer.from(b, "utf8");
  if (bufA.length !== bufB.length) {
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

function writeJsonAtomic(filePath: string, payload: unknown): void {
  const dir = path.dirname(filePath);
  fs.mkdirSync(dir, { recursive: true });
  const tmpPath = `${filePath}.tmp.${process.pid}.${Math.random().toString(36).slice(2)}`;
  try {
    fs.writeFileSync(tmpPath, JSON.stringify(payload) + "\n", "utf8");
    fs.renameSync(tmpPath, filePath);
  } catch (err) {
    try {
      if (fs.existsSync(tmpPath)) {
        fs.rmSync(tmpPath, { force: true });
      }
    } catch {}
    throw err;
  }
}

export default definePlugin({
  id: "autogate-bench-eval",
  setup: async (ctx: OpenCodePluginInput) => {
    const opts = isRecord(ctx.options) ? ctx.options : undefined;
    const client = (ctx.client ?? ctx) as unknown as OpenCodeSessionClient;

    const locationDir =
      resolveWorkspaceDirectory(ctx.directory) ??
      resolveWorkspaceDirectory(ctx.worktree) ??
      resolveWorkspaceDirectory(ctx.location);
    const normalizedLocation = locationDir ? path.resolve(locationDir) : undefined;

    const configuredBenchRoot =
      readNonEmptyString(opts?.benchRoot) ?? readNonEmptyString(process.env.AUTOGATE_BENCH_ROOT);
    const normalizedBenchRoot = configuredBenchRoot ? path.resolve(configuredBenchRoot) : undefined;

    const readyFile =
      readNonEmptyString(opts?.readyFile) ??
      readNonEmptyString(process.env.AUTOGATE_BENCH_READY_FILE);
    const token =
      readNonEmptyString(opts?.token) ?? readNonEmptyString(process.env.AUTOGATE_BENCH_TOKEN) ?? "";
    const evalDbFile =
      readNonEmptyString(opts?.evalDbFile) ??
      readNonEmptyString(process.env.AUTOGATE_BENCH_EVAL_DB) ??
      readNonEmptyString(process.env.AUTOGATE_EVAL_DB);
    const classifierModel = readNonEmptyString(opts?.classifierModel);
    const classifierTimeout = readPositiveNumber(opts?.classifierTimeout);
    const serverUrl =
      readNonEmptyString(opts?.serverUrl) ??
      readNonEmptyString(ctx.serverUrl) ??
      readNonEmptyString(process.env.OPENCODE_SERVER_URL);

    const existing = g.__autogate_bench_eval_server__;
    if (existing) {
      existing.refcount += 1;
      if (normalizedBenchRoot && normalizedLocation && normalizedLocation === normalizedBenchRoot) {
        existing.benchRoot = normalizedBenchRoot;
        existing.client = client;
      } else if (
        existing.benchRoot &&
        normalizedLocation &&
        normalizedLocation === existing.benchRoot
      ) {
        existing.client = client;
      } else if (!existing.client) {
        existing.client = client;
      }
      if (!existing.token && token) {
        existing.token = token;
      }
      if (!existing.evalDbFile && evalDbFile) {
        existing.evalDbFile = evalDbFile;
      }
      if (!existing.classifierModel && classifierModel) {
        existing.classifierModel = classifierModel;
      }
      if (existing.classifierTimeout === undefined && classifierTimeout !== undefined) {
        existing.classifierTimeout = classifierTimeout;
      }
      if (!existing.serverUrl && serverUrl) {
        existing.serverUrl = serverUrl;
      }

      let cleaned = false;
      return async () => {
        if (cleaned) return;
        cleaned = true;
        existing.refcount = Math.max(0, existing.refcount - 1);
        if (existing.refcount === 0) {
          try {
            existing.evalStore?.close();
          } catch {
            // Ignore cleanup errors on close
          }
          existing.evalStore = undefined;
          try {
            existing.server.stop(true);
          } catch {
            // Ignore stop errors
          }
          if (g.__autogate_bench_eval_server__ === existing) {
            delete g.__autogate_bench_eval_server__;
          }
        }
      };
    }

    const baseConfig = loadConfig(
      {
        evalDbFile: evalDbFile ?? ":memory:",
        ...(serverUrl ? { serverUrl } : {}),
        systemOne: { enabled: false },
      },
      "opencode",
    );
    const evalStore = new AutoGateEvalStore(evalDbFile ?? ":memory:");

    const state: BenchEvalServerState = {
      server: null as unknown as ReturnType<typeof Bun.serve>,
      port: 0,
      refcount: 1,
      client,
      benchRoot: normalizedBenchRoot ?? normalizedLocation,
      readyFile,
      token,
      evalDbFile,
      evalStore,
      baseConfig,
      classifierModel,
      classifierTimeout,
      serverUrl,
    };

    const server = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      idleTimeout: 255,
      fetch: async (req) => {
        const url = new URL(req.url);
        if (url.pathname !== "/bench/evaluate") {
          return Response.json({ error: "Not found" }, { status: 404 });
        }
        if (req.method !== "POST") {
          return Response.json({ error: "Method not allowed" }, { status: 405 });
        }

        const authHeader = req.headers.get("authorization") ?? "";
        if (!state.token || !timingSafeEqualString(authHeader, `Bearer ${state.token}`)) {
          return Response.json({ error: "Unauthorized" }, { status: 401 });
        }

        let body: unknown;
        try {
          body = await req.json();
        } catch {
          return Response.json({ error: "Invalid JSON body" }, { status: 400 });
        }

        if (!isRecord(body) || !isRecord(body.action) || typeof body.action.toolName !== "string") {
          return Response.json(
            { error: "Request body must include a valid GateAction under `action`" },
            { status: 400 },
          );
        }

        const evalAbortController = new AbortController();
        const onReqAbort = () => {
          if (!evalAbortController.signal.aborted) {
            evalAbortController.abort(req.signal.reason ?? "bench-request-aborted");
          }
        };
        if (req.signal.aborted) {
          onReqAbort();
        } else {
          req.signal.addEventListener("abort", onReqAbort, { once: true });
        }

        const rawAction = body.action as Record<string, unknown>;
        const action: GateAction = {
          ...(rawAction as unknown as GateAction),
          signal: evalAbortController.signal,
        };

        const modelOverride = readNonEmptyString(body.classifierModel) ?? state.classifierModel;
        const timeoutOverride =
          readPositiveNumber(body.classifierTimeout) ?? state.classifierTimeout;
        const baseCfg =
          state.baseConfig ??
          (state.baseConfig = loadConfig(
            {
              evalDbFile: state.evalDbFile ?? ":memory:",
              ...(state.serverUrl ? { serverUrl: state.serverUrl } : {}),
              systemOne: { enabled: false },
            },
            "opencode",
          ));
        const evalConfig: ResolvedAutoGateConfig = {
          ...baseCfg,
          ...(modelOverride ? { classifierModel: modelOverride } : {}),
          ...(timeoutOverride !== undefined ? { classifierTimeout: timeoutOverride } : {}),
          ...(state.serverUrl ? { serverUrl: state.serverUrl } : {}),
        };
        if (!state.evalStore || !state.evalStore.isOpen()) {
          state.evalStore = new AutoGateEvalStore(state.evalDbFile ?? ":memory:");
        }

        const activeClient = state.client;
        const createdSessionIds = new Set<string>();
        const removedSessionIds = new Set<string>();
        const origRemove = activeClient.session?.remove;
        const trackedClient: OpenCodeSessionClient = {
          ...activeClient,
          session: {
            ...activeClient.session,
            create: async (createOpts) => {
              const created = await activeClient.session.create(createOpts);
              const id = created?.data?.id ?? created?.id;
              if (typeof id === "string" && id.length > 0) {
                createdSessionIds.add(id);
              }
              return created;
            },
            ...(typeof origRemove === "function"
              ? {
                  remove: async (removeOpts) => {
                    if (removeOpts?.sessionID) {
                      removedSessionIds.add(removeOpts.sessionID);
                    }
                    return await origRemove(removeOpts);
                  },
                }
              : {}),
          },
        };

        const evaluator = new OpenCodeSessionEvaluator(trackedClient, evalConfig, {
          serverUrl: state.serverUrl,
          evalDbFile: evalConfig.evalDbFile,
          evalStore: state.evalStore,
          skipEvaluationRecord: true,
        });
        const t0 = performance.now();
        let result: ClassifierResult;
        try {
          result = await evaluator.evaluate(action);
        } catch (err) {
          const message = err instanceof Error ? err.message : String(err);
          return Response.json({ error: message }, { status: 500 });
        } finally {
          req.signal.removeEventListener("abort", onReqAbort);
          if (typeof origRemove === "function" && createdSessionIds.size > 0) {
            for (const sessionID of createdSessionIds) {
              if (removedSessionIds.has(sessionID)) continue;
              try {
                await origRemove({ sessionID });
              } catch {
                // Best-effort cleanup; ignore if session was already removed or still busy
              }
            }
          }
        }

        const latencyMs = Math.round(performance.now() - t0);
        return Response.json({ result, latencyMs });
      },
    });

    const port = server.port;
    if (!port || port <= 0) {
      try {
        server.stop(true);
      } catch {}
      throw new Error("Failed to bind loopback port for autogate-bench-eval plugin");
    }

    state.server = server;
    state.port = port;
    g.__autogate_bench_eval_server__ = state;

    try {
      if (readyFile) {
        writeJsonAtomic(readyFile, { port, pid: process.pid });
      }
    } catch (err) {
      try {
        server.stop(true);
      } catch {}
      if (g.__autogate_bench_eval_server__ === state) {
        delete g.__autogate_bench_eval_server__;
      }
      throw err;
    }

    let cleaned = false;
    return async () => {
      if (cleaned) return;
      cleaned = true;
      state.refcount = Math.max(0, state.refcount - 1);
      if (state.refcount === 0) {
        try {
          state.evalStore?.close();
        } catch {
          // Ignore cleanup errors on close
        }
        state.evalStore = undefined;
        try {
          state.server.stop(true);
        } catch {
          // Ignore stop errors
        }
        if (g.__autogate_bench_eval_server__ === state) {
          delete g.__autogate_bench_eval_server__;
        }
      }
    };
  },
});
