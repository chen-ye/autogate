import type { AutoGateCoreEngine } from "../../core/src/index.ts"
import type { GateAction, GateDecision } from "../../core/src/types.ts"

export const verdictStore = new Map<
  string,
  { verdict: string; policy: "allow" | "deny" | "prompt"; reason?: string }
>()

export function registerToolCallHook(
  pi: any,
  engine: AutoGateCoreEngine,
  store = verdictStore
): void {
  if (typeof pi?.on !== "function") {
    return
  }

  pi.on("tool_call", async (event: any, ctx: any) => {
    if (!engine.isEnabled()) {
      return
    }

    const toolCallId = event?.toolCallId || event?.id
    if (!toolCallId) {
      return
    }

    const sessionID =
      event?.sessionID ||
      event?.sessionId ||
      ctx?.sessionID ||
      ctx?.sessionId ||
      ""
    const toolName = event?.toolName || event?.name || ""
    const commandString =
      event?.input?.command ||
      event?.commandString ||
      (typeof event?.input === "string" ? event.input : undefined)
    const workspaceRoot =
      ctx?.cwd || ctx?.directory || event?.workspaceRoot || process.cwd()

    const action: GateAction = {
      id: toolCallId,
      harness: "omp",
      sessionID,
      toolName,
      commandString,
      targetPath: event?.input?.path || event?.input?.filepath || event?.targetPath,
      rawArgs: event?.input || event?.args,
      workspaceRoot,
      userPrompt: engine.getUserPrompt(sessionID),
      metadata: event?.metadata || event?.input,
    }

    let decision: GateDecision
    try {
      decision = await engine.evaluate(action)
    } catch (err: any) {
      decision = {
        verdict: "BLOCK",
        reason: `Evaluation error: ${err?.message || err}`,
      }
    }

    if (decision.verdict === "ALLOW") {
      store.set(toolCallId, { verdict: "ALLOW", policy: "allow" })
      return undefined
    } else if (decision.verdict === "BLOCK") {
      store.set(toolCallId, {
        verdict: "BLOCK",
        policy: "deny",
        reason: decision.reason,
      })
      return { block: true, reason: decision.reason }
    } else {
      store.set(toolCallId, {
        verdict: "UNSURE",
        policy: "prompt",
        reason: decision.reason,
      })
      return undefined
    }
  })
}
