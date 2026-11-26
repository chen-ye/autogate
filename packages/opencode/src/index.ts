import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import {
  loadConfig,
  NtfyAdapter,
  AutoGateCoreEngine,
  AutoGateEvalStore,
  resolveEvalDbFile,
  recordEscalationIntent,
  isClassifierVerdict,
  isRiskLevel,
  isUserAuthorization,
  loadEvalAgentDefinition,
  parseModelRef,
  type HarnessAdapter,
  type PermissionEventData,
  type GateAction,
  type GateDecision,
  type GateEvaluator,
  type ResolvedAutoGateConfig,
  type EnvironmentConfig,
} from "@autogate/core";
import {
  OpenCodeSessionEvaluator,
  isEvaluationSession,
  recordEvaluationVerdict,
  evaluationSessions,
  type S2SessionCapturedEvent,
} from "./evaluator.js";
import { OpenCodePromptResolver } from "./prompt-resolver.js";
import { OpenCodeRuntimeSync } from "./runtime-sync.js";
import type { OpenCodeSessionClient, OpenCodeEvent, OpenCodePluginInput } from "./types.js";

export function resolveWorkspaceDirectory(val: unknown): string | undefined {
  if (typeof val === "string" && val.trim().length > 0) {
    return val.trim();
  }
  if (val && typeof val === "object") {
    const obj = val as Record<string, unknown>;
    if (typeof obj.directory === "string" && obj.directory.trim().length > 0) {
      return obj.directory.trim();
    }
  }
  return undefined;
}

export function isEventForWorkspace(event: unknown, workspaceDir?: unknown): boolean {
  const wsDirStr = resolveWorkspaceDirectory(workspaceDir);
  if (!wsDirStr) return true;
  if (!event || typeof event !== "object") return true;

  const ev = event as Record<string, unknown>;
  const normalizedWs = path.resolve(wsDirStr);

  if (ev.location && typeof ev.location === "object") {
    const locDir = resolveWorkspaceDirectory(ev.location);
    if (locDir) {
      const resolvedLoc = path.resolve(locDir);
      return resolvedLoc === normalizedWs || normalizedWs.startsWith(resolvedLoc + path.sep);
    }
  }

  const eventData = (ev.data || ev.properties) as Record<string, unknown> | undefined;
  const meta = eventData?.metadata as Record<string, unknown> | undefined;
  const dataDir =
    resolveWorkspaceDirectory(meta?.directory) ?? resolveWorkspaceDirectory(eventData?.directory);

  if (!dataDir) {
    return true;
  }

  const resolvedDataDir = path.resolve(dataDir);
  return resolvedDataDir === normalizedWs || resolvedDataDir.startsWith(normalizedWs + path.sep);
}

export {
  OpenCodeSessionEvaluator,
  isEvaluationSession,
  recordEvaluationVerdict,
  evaluationSessions,
};
export * from "./types.js";
export * from "./prompt-resolver.js";
export * from "./runtime-sync.js";

export function resolveServerPassword(configDir?: string): string {
  const envPassword = process.env.OPENCODE_SERVER_PASSWORD || process.env.OPENCODE_PASSWORD;

  const explicitDir = configDir || process.env.OPENCODE_CONFIG_DIR;
  if (explicitDir && explicitDir.trim().length > 0) {
    try {
      const serviceJsonPath = path.join(explicitDir.trim(), "service.json");
      if (fs.existsSync(serviceJsonPath)) {
        const raw = fs.readFileSync(serviceJsonPath, "utf8");
        const parsed = JSON.parse(raw);
        if (typeof parsed?.password === "string" && parsed.password.trim().length > 0) {
          return parsed.password.trim();
        }
      }
    } catch {}
    if (envPassword && envPassword.trim().length > 0) {
      return envPassword.trim();
    }
    return "";
  }

  const candidateDirs: string[] = [];
  if (process.env.XDG_STATE_HOME && process.env.XDG_STATE_HOME.trim().length > 0) {
    candidateDirs.push(path.join(process.env.XDG_STATE_HOME.trim(), "opencode"));
  }
  if (process.env.XDG_CONFIG_HOME && process.env.XDG_CONFIG_HOME.trim().length > 0) {
    candidateDirs.push(path.join(process.env.XDG_CONFIG_HOME.trim(), "opencode"));
  }
  candidateDirs.push(path.join(os.homedir(), ".local", "state", "opencode"));
  candidateDirs.push(path.join(os.homedir(), ".config", "opencode"));

  for (const dir of candidateDirs) {
    try {
      const serviceJsonPath = path.join(dir, "service.json");
      if (fs.existsSync(serviceJsonPath)) {
        const raw = fs.readFileSync(serviceJsonPath, "utf8");
        const parsed = JSON.parse(raw);
        if (typeof parsed?.password === "string" && parsed.password.trim().length > 0) {
          return parsed.password.trim();
        }
      }
    } catch {}
  }

  if (envPassword && envPassword.trim().length > 0) {
    return envPassword.trim();
  }

  return "";
}

export function resolveCurrentProcessServiceUrl(configDir?: string): string | undefined {
  const candidateDirs: string[] = [];
  const explicitDir = configDir || process.env.OPENCODE_CONFIG_DIR;
  if (explicitDir && explicitDir.trim().length > 0) {
    candidateDirs.push(explicitDir.trim());
  } else {
    if (process.env.XDG_STATE_HOME && process.env.XDG_STATE_HOME.trim().length > 0) {
      candidateDirs.push(path.join(process.env.XDG_STATE_HOME.trim(), "opencode"));
    }
    if (process.env.XDG_CONFIG_HOME && process.env.XDG_CONFIG_HOME.trim().length > 0) {
      candidateDirs.push(path.join(process.env.XDG_CONFIG_HOME.trim(), "opencode"));
    }
    candidateDirs.push(path.join(os.homedir(), ".local", "state", "opencode"));
    candidateDirs.push(path.join(os.homedir(), ".config", "opencode"));
  }

  for (const dir of candidateDirs) {
    try {
      const serviceJsonPath = path.join(dir, "service.json");
      if (!fs.existsSync(serviceJsonPath)) continue;
      const raw = fs.readFileSync(serviceJsonPath, "utf8");
      const parsed = JSON.parse(raw) as { pid?: unknown; url?: unknown };
      if (
        parsed?.pid === process.pid &&
        typeof parsed.url === "string" &&
        parsed.url.trim().length > 0
      ) {
        return parsed.url.trim().replace(/\/+$/, "");
      }
    } catch {
      // Ignore unreadable or malformed service.json while scanning candidates
    }
  }

  return undefined;
}

export function buildOpenCodeGateAction(
  request: PermissionEventData,
  context: {
    workspaceRoot: string;
    userPrompt: string;
    subagentPrompt?: string;
    environment?: EnvironmentConfig;
    signal?: AbortSignal;
  },
): GateAction {
  const nonEmptyStringList = (val: unknown): string[] | undefined => {
    if (!Array.isArray(val)) return undefined;
    const strings = val.filter(
      (item): item is string => typeof item === "string" && item.trim().length > 0,
    );
    return strings.length > 0 ? strings : undefined;
  };
  const isSoleWildcardPlaceholder = (list: string[] | undefined): boolean =>
    Boolean(list && list.length === 1 && list[0].trim() === "*");

  const rawResources = nonEmptyStringList(request.resources);
  const rawPatterns = nonEmptyStringList(request.patterns);
  const metaFiles = Array.isArray(request.metadata?.files)
    ? (request.metadata.files as Array<Record<string, unknown>>)
    : undefined;
  const hasMcpInput =
    Boolean(request.metadata) &&
    typeof request.metadata === "object" &&
    "input" in request.metadata! &&
    request.metadata!.input !== undefined;
  const hasStructuredMeta = hasMcpInput || Boolean(metaFiles && metaFiles.length > 0);

  const resources =
    hasStructuredMeta && isSoleWildcardPlaceholder(rawResources) ? undefined : rawResources;
  const patterns =
    hasStructuredMeta && isSoleWildcardPlaceholder(rawPatterns) ? undefined : rawPatterns;

  const toolName = request.action || request.permission || request.source?.type || "permission";

  const commandString =
    typeof request.metadata?.command === "string" && request.metadata.command.trim().length > 0
      ? request.metadata.command
      : typeof request.metadata?.cmd === "string" && request.metadata.cmd.trim().length > 0
        ? request.metadata.cmd
        : (resources?.join(" ") ?? patterns?.join(" "));

  const metaFilePaths = (metaFiles ?? [])
    .map((entry) => (typeof entry?.file === "string" ? entry.file.trim() : ""))
    .filter((f) => f.length > 0);
  const firstMetaFile = metaFilePaths[0];
  const isFileTool = toolName === "read" || toolName === "edit" || toolName === "write";

  const targetPath =
    typeof request.metadata?.filepath === "string" && request.metadata.filepath.trim().length > 0
      ? request.metadata.filepath
      : typeof request.metadata?.path === "string" && request.metadata.path.trim().length > 0
        ? request.metadata.path
        : typeof request.metadata?.file === "string" && request.metadata.file.trim().length > 0
          ? request.metadata.file
          : (firstMetaFile ?? (isFileTool ? (resources?.[0] ?? patterns?.[0]) : undefined));

  const allEditPaths =
    metaFiles && metaFiles.length > 0
      ? Array.from(new Set([...(resources ?? []), ...(patterns ?? []), ...metaFilePaths]))
      : [];
  const effectivePatterns = patterns ?? (allEditPaths.length > 1 ? allEditPaths : undefined);

  const rawArgs =
    metaFiles && metaFiles.length > 0
      ? { ...(targetPath ? { path: targetPath } : {}), files: metaFiles }
      : hasMcpInput
        ? resources || patterns
          ? { resources: resources ?? patterns, input: request.metadata!.input }
          : request.metadata!.input
        : (resources ?? patterns ?? request.metadata);

  const sessionID = (request.sessionID as string) || "";
  const signal = context.signal ?? (request as { signal?: AbortSignal }).signal;
  return {
    id: (request.id as string) || Math.random().toString(36).slice(2),
    harness: (request.harness as string) || "opencode",
    sessionID,
    toolName,
    commandString,
    targetPath,
    ...(effectivePatterns ? { patterns: effectivePatterns } : {}),
    rawArgs,
    workspaceRoot: (request.metadata?.directory as string) || context.workspaceRoot,
    userPrompt: context.userPrompt,
    subagentPrompt: context.subagentPrompt,
    environment: context.environment,
    metadata: request.metadata,
    ...(signal ? { signal } : {}),
  };
}

export class OpenCodeHarnessAdapter implements HarnessAdapter {
  readonly name = "opencode-harness";
  private engine: AutoGateCoreEngine;
  private promptResolver: OpenCodePromptResolver;
  private runtimeSync: OpenCodeRuntimeSync;
  private stopListener?: () => void;
  private ctx: OpenCodePluginInput;
  private config: ResolvedAutoGateConfig;
  private runtimeOptions?: Record<string, unknown>;
  private sessionEvaluator?: OpenCodeSessionEvaluator;
  private evalStore?: AutoGateEvalStore;
  private evalStorePath?: string;
  private storeClosed = false;
  private sessionControllers = new Map<string, Set<AbortController>>();
  private requestControllers = new Map<string, AbortController>();
  private allControllers = new Set<AbortController>();
  private activeEvaluations = new Set<Promise<void>>();
  private pendingS2ByActionId = new Map<string, S2SessionCapturedEvent>();
  private disposed = false;
  readonly serverUrl: string;

  constructor(ctx: OpenCodePluginInput, options?: Record<string, unknown>) {
    this.ctx = ctx;
    this.runtimeOptions = options;
    const config = loadConfig(options, "opencode");
    const configDir = typeof ctx.configDir === "string" ? ctx.configDir : undefined;
    const customConfigServerUrl =
      typeof config.serverUrl === "string" &&
      config.serverUrl.trim().length > 0 &&
      !/^https?:\/\/localhost:409[67]\/?$/i.test(config.serverUrl.trim())
        ? config.serverUrl.trim()
        : undefined;
    const explicitServerUrl =
      config.opencode?.serverUrl ||
      (typeof options?.serverUrl === "string" && options.serverUrl.trim().length > 0
        ? options.serverUrl.trim()
        : undefined) ||
      (typeof ctx.serverUrl === "string" && ctx.serverUrl.trim().length > 0
        ? ctx.serverUrl.trim()
        : undefined) ||
      process.env.OPENCODE_SERVER_URL ||
      customConfigServerUrl ||
      resolveCurrentProcessServiceUrl(configDir);
    const serverUrl = explicitServerUrl || config.serverUrl || "http://localhost:4096";
    this.serverUrl = serverUrl;
    const adapter = config.ntfyTopic
      ? new NtfyAdapter({
          server: config.ntfyServer,
          topic: config.ntfyTopic,
          token: config.ntfyToken,
        })
      : undefined;

    const workspaceRoot =
      resolveWorkspaceDirectory(ctx.directory) ??
      resolveWorkspaceDirectory(ctx.worktree) ??
      resolveWorkspaceDirectory(ctx.location) ??
      process.cwd();

    const client = (ctx.client ?? ctx) as unknown as OpenCodeSessionClient;
    this.promptResolver = new OpenCodePromptResolver(client);
    this.config = config;
    const defaultEvaluator = new OpenCodeSessionEvaluator(client, config, {
      serverUrl: explicitServerUrl,
      configDir,
      getEvalDbFile: () => this.config.evalDbFile,
      getEvalSessionCleanup: () => this.config.evalSessionCleanup,
      getEvalStore: () => (this.storeClosed ? undefined : this.getEvalStore()),
      skipEvaluationRecord: true,
      onS2SessionRecorded: (ev) => this.handleS2SessionRecorded(ev),
    });
    const evaluator = (options?.evaluator as GateEvaluator | undefined) ?? defaultEvaluator;
    if (!options?.evaluator) {
      this.sessionEvaluator = defaultEvaluator;
    }
    const remoteReviewEnabled = config.ntfyTopic
      ? typeof options?.remoteReviewEnabled === "boolean"
        ? options.remoteReviewEnabled
        : config.reviewFallbackMode !== "native"
      : false;
    this.engine = new AutoGateCoreEngine({
      config,
      adapter,
      evaluator,
      workspaceRoot,
      remoteReviewEnabled,
      onClassifierResult: ({ action, result, durationMs, startTime }) => {
        const pendingS2 = this.pendingS2ByActionId.get(action.id);
        this.pendingS2ByActionId.delete(action.id);
        if (this.storeClosed) return;
        const meta = result.metadata;
        const s2SessionId =
          (typeof meta?.s2SessionId === "string" && meta.s2SessionId.trim().length > 0
            ? meta.s2SessionId.trim()
            : null) ??
          pendingS2?.s2SessionId ??
          null;
        const s2Aborted =
          result.cascade?.s2Aborted ?? (pendingS2 ? pendingS2.status === "aborted" : false);
        try {
          this.getEvalStore().recordEvaluation({
            id: action.id,
            sourceFormat: "opencode",
            timestamp: startTime,
            sessionId: action.sessionID,
            s2SessionId,
            actionId: action.id,
            toolName: action.toolName,
            commandString:
              action.commandString ??
              (action.rawArgs !== undefined
                ? JSON.stringify(action.rawArgs)
                : action.metadata
                  ? JSON.stringify(action.metadata)
                  : ""),
            targetPath: action.targetPath ?? null,
            workspaceRoot: action.workspaceRoot ?? null,
            userPrompt: action.userPrompt,
            reasoning:
              result.reason || (typeof meta?.reasoning === "string" ? meta.reasoning : null),
            thinking: typeof meta?.thinking === "string" ? meta.thinking : null,
            verdict: result.verdict,
            riskLevel: result.risk_level ?? null,
            userAuthorization: result.user_authorization ?? null,
            durationMs,
            modelId: typeof meta?.modelId === "string" ? meta.modelId : null,
            modelProvider: typeof meta?.modelProvider === "string" ? meta.modelProvider : null,
            promptTokens: typeof meta?.promptTokens === "number" ? meta.promptTokens : null,
            outputTokens: typeof meta?.outputTokens === "number" ? meta.outputTokens : null,
            reasoningTokens:
              typeof meta?.reasoningTokens === "number" ? meta.reasoningTokens : null,
            cost: typeof meta?.cost === "number" ? meta.cost : null,
            attempts: typeof meta?.attempts === "number" ? meta.attempts : null,
            error: typeof meta?.error === "string" ? meta.error : null,
            cascade: result.cascade ?? null,
            cascadeWinner: result.cascade?.winner ?? null,
            s2Aborted,
            sourceOrigin: "live",
          });
        } catch (err) {
          console.warn("[AutoGate] Failed to persist evaluation to evals.db:", err);
        }
      },
    });
    this.runtimeSync = new OpenCodeRuntimeSync({
      engine: this.engine,
      config,
      workspaceRoot,
      options,
    });
  }

  private getEvalStore(): AutoGateEvalStore {
    const dbPath = this.config.evalDbFile || resolveEvalDbFile(this.runtimeOptions, "opencode");
    if (this.evalStore && this.evalStore.isOpen() && this.evalStorePath === dbPath) {
      return this.evalStore;
    }
    if (this.evalStore && this.evalStore.isOpen()) {
      this.evalStore.close();
    }
    this.evalStorePath = dbPath;
    this.evalStore = new AutoGateEvalStore(dbPath);
    return this.evalStore;
  }

  private handleS2SessionRecorded(event: S2SessionCapturedEvent): void {
    const actionId = event.actionId;
    if (!actionId || this.storeClosed) return;

    try {
      const linked = this.getEvalStore().linkS2SessionToEvaluation({
        actionId,
        s2SessionId: event.s2SessionId,
        targetSessionId: event.targetSessionId ?? null,
        status: event.status,
        timestamp: event.timestamp,
        toolName: event.toolName,
        commandString: event.commandString,
        targetPath: event.targetPath ?? null,
        workspaceRoot: event.workspaceRoot,
        userPrompt: event.userPrompt,
        verdict: event.verdict,
        riskLevel: event.riskLevel ?? null,
        userAuthorization: event.userAuthorization ?? null,
        reasoning: event.reasoning ?? null,
        thinking: event.thinking ?? null,
        durationMs: event.durationMs,
        modelId: event.modelId ?? null,
        modelProvider: event.modelProvider ?? null,
        promptTokens: event.promptTokens ?? null,
        outputTokens: event.outputTokens ?? null,
        reasoningTokens: event.reasoningTokens ?? null,
        cost: event.cost ?? null,
        attempts: event.attempts ?? null,
        error: event.error ?? null,
        s2Aborted: event.status === "aborted",
      });
      if (!linked && !this.disposed) {
        this.pendingS2ByActionId.set(actionId, event);
      }
    } catch (err) {
      console.warn("[AutoGate] Failed to link S2 session to evaluation in evals.db:", err);
    }
  }

  async start(): Promise<void> {
    this.disposed = false;
    this.storeClosed = false;
    this.stopListener = await this.engine.start();
    this.runtimeSync.start();
  }

  async dispose(): Promise<void> {
    this.disposed = true;
    for (const ctrl of this.allControllers) {
      ctrl.abort("adapter-disposed");
    }
    this.allControllers.clear();
    this.sessionControllers.clear();
    this.requestControllers.clear();
    if (this.activeEvaluations.size > 0) {
      await Promise.allSettled(Array.from(this.activeEvaluations));
    }
    if (this.sessionEvaluator) {
      await this.sessionEvaluator.waitForPending();
    }
    this.pendingS2ByActionId.clear();
    this.runtimeSync.dispose();
    await this.engine.stop();
    if (this.stopListener) {
      this.stopListener();
      this.stopListener = undefined;
    }
    this.storeClosed = true;
    if (this.evalStore) {
      try {
        this.evalStore.close();
      } catch {}
      this.evalStore = undefined;
      this.evalStorePath = undefined;
    }
  }

  getEngine(): AutoGateCoreEngine {
    return this.engine;
  }

  getRuntimeSync(): OpenCodeRuntimeSync {
    return this.runtimeSync;
  }

  cleanupSession(sessionID: string): void {
    if (!sessionID) return;
    this.engine.cleanupSession(sessionID);
    this.promptResolver.cleanupSession(sessionID);
    this.runtimeSync.cleanupSession(sessionID);
    const controllers = this.sessionControllers.get(sessionID);
    if (controllers) {
      this.sessionControllers.delete(sessionID);
      for (const ctrl of controllers) {
        ctrl.abort("session-cleanup");
      }
    }
  }

  async handlePermissionAsked(request: PermissionEventData): Promise<void> {
    if (this.disposed) return;
    const task = this.runPermissionAsked(request);
    this.activeEvaluations.add(task);
    try {
      await task;
    } finally {
      this.activeEvaluations.delete(task);
    }
  }

  private async runPermissionAsked(request: PermissionEventData): Promise<void> {
    const workspaceRoot =
      resolveWorkspaceDirectory(this.ctx.directory) ??
      resolveWorkspaceDirectory(this.ctx.worktree) ??
      resolveWorkspaceDirectory(this.ctx.location) ??
      process.cwd();
    const explicitWs =
      resolveWorkspaceDirectory(this.ctx.directory) ??
      resolveWorkspaceDirectory(this.ctx.worktree) ??
      resolveWorkspaceDirectory(this.ctx.location);
    const requestDir =
      resolveWorkspaceDirectory(request?.metadata?.directory) ??
      resolveWorkspaceDirectory(request?.directory);
    if (requestDir && explicitWs) {
      const normalizedReq = path.resolve(requestDir);
      const normalizedWs = path.resolve(explicitWs);
      if (normalizedReq !== normalizedWs && !normalizedReq.startsWith(normalizedWs + path.sep)) {
        return;
      }
    }

    this.runtimeSync.syncControlAndConfig();

    const sessionID = (request.sessionID as string) || "";
    const requestID = typeof request.id === "string" ? request.id : "";
    const reqController = new AbortController();
    const externalSignal = (request as { signal?: AbortSignal }).signal;
    const onExternalAbort = () => reqController.abort(externalSignal?.reason);
    if (externalSignal) {
      if (externalSignal.aborted) {
        reqController.abort(externalSignal.reason);
      } else {
        externalSignal.addEventListener("abort", onExternalAbort, { once: true });
      }
    }
    this.allControllers.add(reqController);
    if (requestID) {
      this.requestControllers.set(requestID, reqController);
    }
    if (sessionID) {
      let set = this.sessionControllers.get(sessionID);
      if (!set) {
        set = new Set();
        this.sessionControllers.set(sessionID, set);
      }
      set.add(reqController);
    }

    let actionIdForCleanup: string | undefined;
    try {
      const resolvedPrompts = await this.promptResolver.resolveSessionPrompts(
        sessionID,
        undefined,
        this.engine.getUserPrompt(sessionID),
        reqController.signal,
      );
      if (reqController.signal.aborted || this.disposed) {
        return;
      }

      const parentID = this.promptResolver.getParentSessionID(sessionID);
      if (parentID) {
        this.engine.setSessionParent(sessionID, parentID);
      }
      if (resolvedPrompts.userPrompt) {
        this.engine.setUserPrompt(sessionID, resolvedPrompts.userPrompt);
      }

      const action = buildOpenCodeGateAction(request, {
        workspaceRoot,
        userPrompt: resolvedPrompts.userPrompt,
        subagentPrompt: resolvedPrompts.subagentPrompt,
        environment: this.config.environment,
        signal: reqController.signal,
      });
      actionIdForCleanup = action.id;

      const evalStartTime = Date.now();
      this.runtimeSync.beginEvaluation({
        id: action.id,
        sessionID: action.sessionID,
        toolName: action.toolName,
        ...(action.commandString !== undefined ? { commandString: action.commandString } : {}),
        startedAt: evalStartTime,
      });

      let decision: GateDecision;
      try {
        decision = await this.engine.evaluate(action);
      } catch (err) {
        this.runtimeSync.completeEvaluation(action.id);
        throw err;
      }

      if (reqController.signal.aborted || this.disposed) {
        this.runtimeSync.completeEvaluation(action.id);
        return;
      }

      const durationMs = Date.now() - evalStartTime;
      const source = decision.cached
        ? "cache"
        : decision.reply || decision.reason.startsWith("Answered remotely")
          ? "remote"
          : decision.cascade?.winner
            ? decision.cascade.winner
            : decision.verdict === "UNSURE" && !decision.reply
              ? "native-fallback"
              : "evaluator";

      this.runtimeSync.completeEvaluation(action.id, {
        timestamp: Date.now(),
        sessionID: action.sessionID,
        toolName: action.toolName,
        ...(action.commandString !== undefined ? { commandString: action.commandString } : {}),
        verdict: decision.verdict,
        ...(decision.riskLevel !== undefined ? { riskLevel: decision.riskLevel } : {}),
        durationMs,
        reason: decision.reason,
        ...(decision.cached !== undefined ? { cached: decision.cached } : {}),
        source,
      });

      console.log(
        `[AutoGate] Evaluated decision for ${request.id}: verdict=${decision.verdict} reason=${decision.reason} userPrompt="${action.userPrompt}"`,
      );
      if (decision.verdict === "UNSURE" && !decision.reply) {
        return;
      }
      const replyVal = decision.reply || (decision.verdict === "ALLOW" ? "once" : "reject");
      await this.replyPermission(request.id as string, replyVal, action.sessionID, decision.reason);
    } finally {
      if (actionIdForCleanup) {
        this.pendingS2ByActionId.delete(actionIdForCleanup);
      }
      if (externalSignal) {
        externalSignal.removeEventListener("abort", onExternalAbort);
      }
      this.allControllers.delete(reqController);
      if (requestID && this.requestControllers.get(requestID) === reqController) {
        this.requestControllers.delete(requestID);
      }
      if (sessionID) {
        const set = this.sessionControllers.get(sessionID);
        if (set) {
          set.delete(reqController);
          if (set.size === 0) {
            this.sessionControllers.delete(sessionID);
          }
        }
      }
    }
  }

  private async replyPermission(
    requestID: string,
    reply: "once" | "always" | "reject",
    sessionID: string,
    message?: string,
  ): Promise<void> {
    if (this.ctx.permission && typeof this.ctx.permission.reply === "function") {
      try {
        await this.ctx.permission.reply({
          sessionID,
          requestID,
          decision: reply,
          message,
        });
        console.log(
          `[AutoGate] Successfully replied to permission via ctx.permission: ${requestID} -> ${reply}`,
        );
        return;
      } catch (err) {
        console.error(`[AutoGate] ctx.permission.reply failed for ${requestID}:`, err);
      }
    }

    if (this.ctx.client?.permission && typeof this.ctx.client.permission.reply === "function") {
      try {
        await this.ctx.client.permission.reply({
          sessionID,
          requestID,
          decision: reply,
          message,
        });
        return;
      } catch {}
    }

    if (!sessionID) return;
    const serverUrl = this.serverUrl || process.env.OPENCODE_SERVER_URL || "http://localhost:4096";
    const password = resolveServerPassword(
      typeof this.ctx.configDir === "string" ? this.ctx.configDir : undefined,
    );
    const authHeader = "Basic " + Buffer.from(`opencode:${password}`).toString("base64");
    const fullUrl = `${serverUrl}/api/session/${encodeURIComponent(sessionID)}/permission/${encodeURIComponent(requestID)}/reply`;
    try {
      const res = await fetch(fullUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: authHeader,
        },
        body: JSON.stringify({ decision: reply, message }),
        signal: AbortSignal.timeout(5000),
      });
      if (res.ok) {
        console.log(
          `[AutoGate] Successfully replied to permission via HTTP ${fullUrl}: ${requestID} -> ${reply}`,
        );
      } else {
        console.error(
          `[AutoGate] HTTP reply to ${fullUrl} returned ${res.status}:`,
          await res.text(),
        );
      }
    } catch (err) {
      console.error(`[AutoGate] HTTP reply to ${fullUrl} fetch error:`, err);
    }
  }

  async handlePermissionReplied(data: {
    requestID?: string;
    id?: string;
    reply?: string;
  }): Promise<void> {
    const reqID = data.requestID ?? data.id;
    this.engine.handlePermissionReplied(data);
    this.runtimeSync.markPermissionReplied(reqID);
    if (reqID) {
      const ctrl = this.requestControllers.get(reqID);
      if (ctrl) {
        this.requestControllers.delete(reqID);
        ctrl.abort("permission-replied");
      }
    }
  }

  clearTurnCache(sessionID: string): void {
    this.engine.clearTurnCache(sessionID);
  }
}

interface ActiveSubscription {
  controller: AbortController;
  adapter: OpenCodeHarnessAdapter;
}

const activeSubscriptions = new Map<string, ActiveSubscription>();

export type PluginCleanup = () => Promise<void> | void;

function isAsyncIterable<T>(val: unknown): val is AsyncIterable<T> {
  return (
    val !== null &&
    typeof val === "object" &&
    Symbol.asyncIterator in val &&
    typeof (val as Record<symbol, unknown>)[Symbol.asyncIterator] === "function"
  );
}

function isPromiseLike<T>(val: unknown): val is PromiseLike<T> {
  return (
    val !== null &&
    typeof val === "object" &&
    "then" in val &&
    typeof (val as { then?: unknown }).then === "function"
  );
}

export interface OpenCodeV2PluginDefinition {
  readonly id: string;
  readonly setup: (
    context: OpenCodePluginInput,
  ) => Promise<PluginCleanup | void> | PluginCleanup | void;
}

export function definePlugin<T extends OpenCodeV2PluginDefinition>(definition: T): T {
  return definition;
}

export const plugin = definePlugin({
  id: "auto-gate",
  setup: async (ctx: OpenCodePluginInput) => {
    const wsDir =
      resolveWorkspaceDirectory(ctx.directory) ??
      resolveWorkspaceDirectory(ctx.worktree) ??
      resolveWorkspaceDirectory(ctx.location) ??
      "__global__";

    const existing = activeSubscriptions.get(wsDir);
    if (existing) {
      existing.controller.abort();
      activeSubscriptions.delete(wsDir);
      await existing.adapter.dispose();
    }

    const controller = new AbortController();
    const signal = controller.signal;

    const opts = typeof ctx.options === "object" && ctx.options !== null ? ctx.options : undefined;
    const adapter = new OpenCodeHarnessAdapter(ctx, opts);
    await adapter.start();

    activeSubscriptions.set(wsDir, { controller, adapter });

    const config = loadConfig(opts);
    console.log(
      `AutoGate Plugin initialized (model: ${config.classifierModel}, topic: ${config.ntfyTopic ?? "disabled"})`,
    );

    if (ctx.agent && typeof ctx.agent.transform === "function") {
      const evalAgent = loadEvalAgentDefinition();
      const effectiveModel = config.classifierModel || evalAgent.model;
      const modelRef = effectiveModel ? parseModelRef(effectiveModel) : undefined;
      await ctx.agent.transform(
        (editor: {
          update: (id: string, fn: (draft: Record<string, unknown>) => void) => void;
        }) => {
          editor.update(evalAgent.id, (draft) => {
            draft.name = evalAgent.name;
            if (evalAgent.description) {
              draft.description = evalAgent.description;
            }
            draft.mode = evalAgent.mode;
            draft.hidden = evalAgent.hidden;
            draft.system = evalAgent.system;
            if (evalAgent.color) {
              draft.color = evalAgent.color;
            }
            if (evalAgent.steps !== undefined) {
              draft.steps = evalAgent.steps;
            }
            if (modelRef) {
              draft.model = modelRef.variant
                ? {
                    providerID: modelRef.providerID,
                    id: modelRef.modelID,
                    variant: modelRef.variant,
                  }
                : { providerID: modelRef.providerID, id: modelRef.modelID };
            }
            if (evalAgent.request) {
              const existingReq =
                draft.request && typeof draft.request === "object"
                  ? (draft.request as Record<string, unknown>)
                  : {};
              const existingBody =
                existingReq.body && typeof existingReq.body === "object"
                  ? (existingReq.body as Record<string, unknown>)
                  : {};
              draft.request = {
                ...existingReq,
                ...(evalAgent.request.settings ? { settings: evalAgent.request.settings } : {}),
                ...(evalAgent.request.headers ? { headers: evalAgent.request.headers } : {}),
                ...(evalAgent.request.body
                  ? { body: { ...existingBody, ...evalAgent.request.body } }
                  : {}),
              };
            }
            if (evalAgent.permissions && evalAgent.permissions.length > 0) {
              draft.permissions = evalAgent.permissions.map((p) => ({ ...p }));
            }
          });
        },
      );
    }

    if (ctx.tool && typeof ctx.tool.transform === "function") {
      await ctx.tool.transform((editor: { add(toolDef: unknown): void }) => {
        editor.add({
          name: "classify_result",
          options: { codemode: false },
          description:
            "Report the security classification result for the agent action (internal evaluation tool)",
          input: {
            type: "object",
            properties: {
              risk_level: { type: "string", enum: ["LOW", "MEDIUM", "HIGH", "CRITICAL"] },
              user_authorization: { type: "string", enum: ["NONE", "LOW", "MEDIUM", "HIGH"] },
              verdict: { type: "string", enum: ["ALLOW", "BLOCK", "UNSURE"] },
              reason: { type: "string" },
            },
            required: ["risk_level", "user_authorization", "verdict", "reason"],
          },
          async execute(args: Record<string, unknown>, context: { sessionID?: string }) {
            if (!context.sessionID || !isEvaluationSession(context.sessionID)) {
              throw new Error(
                "classify_result is an internal security tool reserved exclusively for AutoGate evaluation sessions.",
              );
            }
            const verdictStr = typeof args.verdict === "string" ? args.verdict : "UNSURE";
            const riskStr = typeof args.risk_level === "string" ? args.risk_level : undefined;
            const authStr =
              typeof args.user_authorization === "string" ? args.user_authorization : undefined;
            const reasonStr = typeof args.reason === "string" ? args.reason : "";
            recordEvaluationVerdict(context.sessionID, {
              verdict: isClassifierVerdict(verdictStr) ? verdictStr : "UNSURE",
              risk_level: isRiskLevel(riskStr) ? riskStr : undefined,
              user_authorization: isUserAuthorization(authStr) ? authStr : undefined,
              reason: reasonStr,
            });
            ctx.session
              ?.interrupt?.({ sessionID: context.sessionID, resume: false })
              .catch(() => {});
            return {
              content: JSON.stringify(args),
            };
          },
        });

        editor.add({
          name: "escalate_permission",
          options: { codemode: false },
          description:
            "Request human manual verification for a blocked or high-risk action when safe automated transformations cannot satisfy the goal.",
          input: {
            type: "object",
            properties: {
              action: {
                type: "string",
                description:
                  "The command or target path requiring human approval (e.g. '/etc/hosts' or 'rm -rf dist')",
              },
              reason: {
                type: "string",
                description:
                  "Why the safe alternative or automated transform cannot be used and human review is required",
              },
            },
            required: ["action", "reason"],
          },
          async execute(args: Record<string, unknown>, context: { sessionID?: string }) {
            adapter.getRuntimeSync().syncControlAndConfig();
            const actionStr = typeof args.action === "string" ? args.action : "";
            const reasonStr = typeof args.reason === "string" ? args.reason : "";
            const sessionID = typeof context.sessionID === "string" ? context.sessionID : "";
            if (!recordEscalationIntent(sessionID, actionStr, reasonStr)) {
              return {
                content:
                  "Unable to register manual verification intent: both a valid sessionID and a non-empty action are required.",
              };
            }
            const delivery = adapter.getEngine().isRemoteReviewEnabled()
              ? "forwarded directly to the user's phone for manual approval"
              : "handled via the native harness prompt for manual approval";
            return {
              content: `Manual verification intent registered for '${actionStr.trim()}'. Please re-issue your tool call now; it will be ${delivery}.`,
            };
          },
        });
      });
    }

    const eventObj = ctx.event;
    if (eventObj && typeof eventObj.subscribe === "function") {
      const subscribeFn = eventObj.subscribe.bind(eventObj);
      (async () => {
        try {
          const res: unknown = subscribeFn({ signal });
          const resolved = isPromiseLike<AsyncIterable<OpenCodeEvent>>(res) ? await res : res;
          if (!isAsyncIterable<OpenCodeEvent>(resolved)) {
            return;
          }
          const stream = resolved;
          for await (const event of stream) {
            if (signal.aborted) break;

            const workspaceDir =
              resolveWorkspaceDirectory(ctx.directory) ??
              resolveWorkspaceDirectory(ctx.worktree) ??
              resolveWorkspaceDirectory(ctx.location);
            if (workspaceDir && !isEventForWorkspace(event, workspaceDir)) {
              continue;
            }

            if (event.type === "permission.asked" || event.type === "permission.v2.asked") {
              const eventData = (event.data || event.properties) as PermissionEventData | undefined;
              if (eventData) {
                console.log(
                  `[AutoGate] Intercepted permission asked: ${eventData.id} for session ${eventData.sessionID}`,
                );
                void adapter.handlePermissionAsked(eventData).catch((err) => {
                  if (!signal.aborted) {
                    console.error("[AutoGate] Error handling permission.asked:", err);
                  }
                });
              }
            } else if (
              event.type === "permission.replied" ||
              event.type === "permission.v2.replied"
            ) {
              const eventData = (event.data || event.properties) as
                | { requestID?: string; id?: string; reply?: string }
                | undefined;
              if (eventData) {
                await adapter.handlePermissionReplied(eventData);
              }
            } else if (
              event.type === "session.idle" ||
              (event.type === "session.status" &&
                (event.data?.status === "idle" || event.properties?.status === "idle"))
            ) {
              const sessionID = event.data?.sessionID || event.properties?.sessionID;
              if (typeof sessionID === "string" && sessionID.length > 0) {
                adapter.clearTurnCache(sessionID);
              }
            } else if (event.type === "session.deleted" || event.type === "session.archived") {
              const sessionID = event.data?.sessionID || event.properties?.sessionID;
              if (
                typeof sessionID === "string" &&
                sessionID.length > 0 &&
                !isEvaluationSession(sessionID)
              ) {
                adapter.cleanupSession(sessionID);
              }
            }
          }
        } catch (err) {
          if (!signal.aborted) {
            console.error("[AutoGate] Event stream error:", err);
          }
        }
      })();
    }

    return async () => {
      controller.abort();
      await adapter.dispose();
      if (activeSubscriptions.get(wsDir)?.controller === controller) {
        activeSubscriptions.delete(wsDir);
      }
    };
  },
});

export default plugin;
