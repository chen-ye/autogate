import {
  AutoGateEvalStore,
  type AutoGateCoreEngine,
  type RecordEvaluationInput,
} from "../../core/src/index.ts";
import type { GateAction, GateDecision } from "../../core/src/types.ts";

export const verdictStore = new Map<
  string,
  { verdict: string; policy: "allow" | "deny" | "prompt"; reason?: string }
>();

function recordCascadeEval(entry: RecordEvaluationInput, evalDbFile?: string): void {
  let store: AutoGateEvalStore | undefined;
  try {
    store = new AutoGateEvalStore(evalDbFile);
    store.recordEvaluation(entry);
  } catch {
    // Best-effort evaluation persistence
  } finally {
    try {
      store?.close();
    } catch {}
  }
}

export function registerToolCallHook(
  pi: unknown,
  engine: AutoGateCoreEngine,
  store = verdictStore,
  setContext?: (ctx: Record<string, unknown>) => void,
  evalDbFile?: string,
  skipCascadeLog = false,
): void {
  const p = pi as
    | {
        on?(event: string, handler: (e: unknown, c: unknown) => Promise<unknown>): void;
        logger?: { debug?(m: string, d?: unknown): void };
      }
    | undefined;
  if (typeof p?.on !== "function") {
    return;
  }

  p.on("tool_call", async (event: unknown, ctx: unknown) => {
    const cx = ctx as Record<string, unknown> | undefined;
    const ev = event as Record<string, unknown> | undefined;
    if (cx && typeof setContext === "function") {
      setContext(cx);
    }
    if (!engine.isEnabled()) {
      return;
    }

    const toolCallId =
      typeof ev?.toolCallId === "string" ? ev.toolCallId : typeof ev?.id === "string" ? ev.id : "";
    if (!toolCallId) {
      return;
    }

    const sm = cx?.sessionManager as { getSessionId?: () => string } | undefined;
    const sessionID =
      (typeof sm?.getSessionId === "function" ? sm.getSessionId() : undefined) ||
      (typeof ev?.sessionID === "string" ? ev.sessionID : undefined) ||
      (typeof ev?.sessionId === "string" ? ev.sessionId : undefined) ||
      (typeof cx?.sessionID === "string" ? cx.sessionID : undefined) ||
      (typeof cx?.sessionId === "string" ? cx.sessionId : undefined) ||
      "";
    const toolName =
      typeof ev?.toolName === "string" ? ev.toolName : typeof ev?.name === "string" ? ev.name : "";

    const evInput = ev?.input as Record<string, unknown> | undefined;
    const commandString =
      typeof evInput?.command === "string"
        ? evInput.command
        : typeof evInput?.code === "string"
          ? evInput.code
          : typeof ev?.commandString === "string"
            ? ev.commandString
            : typeof ev?.input === "string"
              ? ev.input
              : undefined;
    const targetPath =
      typeof evInput?.path === "string"
        ? evInput.path
        : typeof evInput?.filepath === "string"
          ? evInput.filepath
          : typeof ev?.targetPath === "string"
            ? ev.targetPath
            : "";
    const workspaceRoot =
      typeof cx?.cwd === "string"
        ? (cx.cwd as string)
        : typeof cx?.directory === "string"
          ? (cx.directory as string)
          : typeof ev?.workspaceRoot === "string"
            ? ev.workspaceRoot
            : process.cwd();

    const isInternalTool = [
      "todo",
      "list_pending_permissions",
      "escalate_permission",
      "hub",
    ].includes(toolName);
    const isVirtualUri =
      typeof targetPath === "string" &&
      (targetPath.startsWith("skill://") || targetPath.startsWith("omp://"));
    if (isInternalTool || isVirtualUri) {
      const record = { verdict: "ALLOW", policy: "allow" as const };
      store.set(toolCallId, record);
      if (commandString) store.set(commandString, record);
      return undefined;
    }

    const action: GateAction = {
      id: toolCallId,
      harness: "omp",
      sessionID,
      toolName,
      commandString,
      targetPath,
      rawArgs: ev?.input || ev?.args,
      workspaceRoot,
      userPrompt: engine.getUserPrompt(sessionID),
      metadata: (ev?.metadata || ev?.input) as Record<string, unknown> | undefined,
      signal: (cx?.signal || ev?.signal) as AbortSignal | undefined,
    };

    const hookStartTime = performance.now();
    let decision: GateDecision;
    try {
      decision = await engine.evaluate(action);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      decision = {
        verdict: "BLOCK",
        reason: `Evaluation error: ${msg}`,
      };
    }
    const hookDurationMs = Math.round(performance.now() - hookStartTime);
    try {
      const logFn = p?.logger?.debug ?? console.debug;
      logFn.call(p?.logger ?? console, "[AutoGate OMP Hook] Evaluated tool call", {
        toolName,
        toolCallId,
        verdict: decision.verdict,
        durationMs: hookDurationMs,
        ...(decision.cascade ? { cascade: decision.cascade } : {}),
      });
    } catch {}
    if (decision.cascade && !skipCascadeLog) {
      const metaModel =
        decision.metadata?.model && typeof decision.metadata.model === "object"
          ? (decision.metadata.model as Record<string, unknown>)
          : undefined;
      const metaInference =
        decision.metadata?.inference && typeof decision.metadata.inference === "object"
          ? (decision.metadata.inference as Record<string, unknown>)
          : undefined;
      recordCascadeEval(
        {
          sourceFormat: "omp",
          timestamp: Date.now(),
          sessionId: sessionID,
          actionId: String(action.id),
          toolName: action.toolName,
          commandString: action.commandString ?? "",
          targetPath: action.targetPath || null,
          workspaceRoot: action.workspaceRoot,
          userPrompt: action.userPrompt,
          modelId: typeof metaModel?.id === "string" ? metaModel.id : null,
          modelProvider: typeof metaModel?.provider === "string" ? metaModel.provider : null,
          durationMs: hookDurationMs,
          promptTokens:
            typeof metaInference?.promptTokens === "number" ? metaInference.promptTokens : null,
          outputTokens:
            typeof metaInference?.outputTokens === "number" ? metaInference.outputTokens : null,
          reasoningTokens:
            typeof metaInference?.reasoningTokens === "number"
              ? metaInference.reasoningTokens
              : null,
          thinking: typeof metaInference?.thinking === "string" ? metaInference.thinking : null,
          attempts: typeof metaInference?.attempts === "number" ? metaInference.attempts : null,
          verdict: decision.verdict,
          riskLevel: decision.riskLevel ?? null,
          userAuthorization: decision.userAuthorization ?? null,
          reasoning: decision.reason,
          cascade: decision.cascade,
        },
        evalDbFile,
      );
    }

    if (decision.verdict === "ALLOW") {
      const record = { verdict: "ALLOW", policy: "allow" as const };
      store.set(toolCallId, record);
      if (commandString) store.set(commandString, record);
      return undefined;
    } else if (decision.verdict === "BLOCK") {
      const record = {
        verdict: "BLOCK",
        policy: "deny" as const,
        reason: decision.reason,
      };
      store.set(toolCallId, record);
      if (commandString) store.set(commandString, record);
      return { block: true, reason: decision.reason };
    } else {
      const record = {
        verdict: "UNSURE",
        policy: "prompt" as const,
        reason: decision.reason,
      };
      store.set(toolCallId, record);
      if (commandString) store.set(commandString, record);
      return undefined;
    }
  });
}
