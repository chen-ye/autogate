import type { AutoGateCoreEngine } from "../../core/src/index.ts"
import type { GateAction, GateDecision } from "../../core/src/types.ts"

export const verdictStore = new Map<
  string,
  { verdict: string; policy: "allow" | "deny" | "prompt"; reason?: string }
>()

export function registerToolCallHook(
  pi: any,
  engine: AutoGateCoreEngine,
  store = verdictStore,
  setContext?: (ctx: any) => void
): void {
  if (typeof pi?.on !== "function") {
    return
  }

  pi.on("tool_call", async (event: any, ctx: any) => {
    if (ctx && typeof setContext === "function") {
      setContext(ctx);
    } else if (ctx && typeof (engine as any).setContext === "function") {
      (engine as any).setContext(ctx);
    }
    if (!engine.isEnabled()) {
      return
    }

    const toolCallId = event?.toolCallId || event?.id
    if (!toolCallId) {
      return
    }

    const sessionID =
      ctx?.sessionManager?.getSessionId?.() ||
      event?.sessionID ||
      event?.sessionId ||
      ctx?.sessionID ||
      ctx?.sessionId ||
      ""
    const toolName = event?.toolName || event?.name || ""
    const commandString =
      event?.input?.command ||
      event?.input?.code ||
      event?.commandString ||
      (typeof event?.input === "string" ? event.input : undefined)
    const targetPath =
      event?.input?.path ||
      event?.input?.filepath ||
      event?.targetPath ||
      ""
    const workspaceRoot =
      ctx?.cwd || ctx?.directory || event?.workspaceRoot || process.cwd()

    const isInternalTool = ["todo", "list_pending_permissions", "escalate_permission", "hub"].includes(toolName);
    const isVirtualUri = typeof targetPath === "string" && (targetPath.startsWith("skill://") || targetPath.startsWith("omp://"));
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
      rawArgs: event?.input || event?.args,
      workspaceRoot,
      userPrompt: engine.getUserPrompt(sessionID),
      metadata: event?.metadata || event?.input,
      signal: ctx?.signal || event?.signal,
    }

    const hookStartTime = performance.now();
    let decision: GateDecision
    try {
      decision = await engine.evaluate(action)
    } catch (err: any) {
      decision = {
        verdict: "BLOCK",
        reason: `Evaluation error: ${err?.message || err}`,
      }
    }
    const hookDurationMs = Math.round(performance.now() - hookStartTime);
    try {
      const logFn = pi?.logger?.debug ?? console.debug;
      logFn.call(pi?.logger ?? console, "[AutoGate OMP Hook] Evaluated tool call", {
        toolName,
        toolCallId,
        verdict: decision.verdict,
        durationMs: hookDurationMs,
      });
    } catch {}

    if (decision.verdict === "ALLOW") {
      const record = { verdict: "ALLOW", policy: "allow" as const }
      store.set(toolCallId, record)
      if (commandString) store.set(commandString, record)
      return undefined
    } else if (decision.verdict === "BLOCK") {
      const record = {
        verdict: "BLOCK",
        policy: "deny" as const,
        reason: decision.reason,
      }
      store.set(toolCallId, record)
      if (commandString) store.set(commandString, record)
      return { block: true, reason: decision.reason }
    } else {
      const record = {
        verdict: "UNSURE",
        policy: "prompt" as const,
        reason: decision.reason,
      }
      store.set(toolCallId, record)
      if (commandString) store.set(commandString, record)
      return undefined
    }
  })
}
