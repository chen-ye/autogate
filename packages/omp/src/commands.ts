import type { AutoGateCoreEngine } from "../../core/src/index.ts"

function notifyCtx(ctx: any, msg: string) {
  if (ctx?.ui?.notify) {
    ctx.ui.notify(msg, "info")
  } else if (ctx?.notify) {
    ctx.notify(msg, "info")
  }
}

export function registerAutogateClassifierCommand(pi: any, engine: AutoGateCoreEngine): void {
  if (typeof pi?.registerCommand !== "function") {
    return
  }

  const handler = async (args: string, ctx: any) => {
    const arg = (typeof args === "string" ? args : (args as any)?.arguments || "").trim().toLowerCase()

    let msg = ""
    if (arg === "off" || arg === "disable" || arg === "false" || arg === "0") {
      engine.setEnabled(false)
      msg = "AutoGate Classifier: DISABLED"
    } else if (arg === "on" || arg === "enable" || arg === "true" || arg === "1") {
      engine.setEnabled(true)
      msg = "AutoGate Classifier: ENABLED"
    } else if (arg === "status") {
      msg = `AutoGate Classifier: ${engine.isEnabled() ? "ENABLED" : "DISABLED"} | Fallback Mode: ${engine.getFallbackMode()}`
    } else if (arg === "toggle" || !arg) {
      const nextState = !engine.isEnabled()
      engine.setEnabled(nextState)
      msg = `AutoGate Classifier: ${nextState ? "ENABLED" : "DISABLED"}`
    } else {
      const nextState = !engine.isEnabled()
      engine.setEnabled(nextState)
      msg = `AutoGate Classifier: ${nextState ? "ENABLED" : "DISABLED"}`
    }

    notifyCtx(ctx, msg)
  }

  pi.registerCommand("autogate-classifier", {
    description: "Enable, disable, or check AutoGate classifier status",
    handler,
  })
}

export function registerAutogateFallbackCommand(pi: any, engine: AutoGateCoreEngine): void {
  if (typeof pi?.registerCommand !== "function") {
    return
  }

  const handler = async (args: string, ctx: any) => {
    const arg = (typeof args === "string" ? args : (args as any)?.arguments || "").trim().toLowerCase()

    let msg = ""
    if (arg === "native" || arg === "desk" || arg === "terminal") {
      engine.setFallbackMode("native")
      msg = "AutoGate Fallback Mode: NATIVE (immediate terminal prompt)"
    } else if (arg === "ntfy" || arg === "mobile" || arg === "remote") {
      engine.setFallbackMode("ntfy")
      msg = "AutoGate Fallback Mode: NTFY (mobile push approval)"
    } else if (arg === "status") {
      msg = `AutoGate Fallback Mode: ${engine.getFallbackMode()} | Classifier: ${engine.isEnabled() ? "ENABLED" : "DISABLED"}`
    } else if (arg === "toggle" || !arg) {
      const current = engine.getFallbackMode()
      const nextMode = current === "native" ? "ntfy" : "native"
      engine.setFallbackMode(nextMode)
      if (nextMode === "native") {
        msg = "AutoGate Fallback Mode: NATIVE (immediate terminal prompt)"
      } else {
        msg = "AutoGate Fallback Mode: NTFY (mobile push approval)"
      }
    } else {
      const current = engine.getFallbackMode()
      const nextMode = current === "native" ? "ntfy" : "native"
      engine.setFallbackMode(nextMode)
      if (nextMode === "native") {
        msg = "AutoGate Fallback Mode: NATIVE (immediate terminal prompt)"
      } else {
        msg = "AutoGate Fallback Mode: NTFY (mobile push approval)"
      }
    }

    notifyCtx(ctx, msg)
  }

  pi.registerCommand("autogate-fallback", {
    description: "Set or check AutoGate review fallback mode (native or ntfy)",
    handler,
  })
}

export function registerAutomodeCommand(pi: any, engine: AutoGateCoreEngine): void {
  if (typeof pi?.registerCommand !== "function") {
    return
  }

  const handler = async (args: string, ctx: any) => {
    const arg = (typeof args === "string" ? args : (args as any)?.arguments || "").trim().toLowerCase()

    let msg = ""
    if (arg === "off" || arg === "disable" || arg === "false" || arg === "0") {
      engine.setEnabled(false)
      msg = "AutoGate Classifier: DISABLED"
    } else if (arg === "on" || arg === "enable" || arg === "true" || arg === "1") {
      engine.setEnabled(true)
      msg = "AutoGate Classifier: ENABLED"
    } else if (arg === "status") {
      msg = `AutoGate Classifier: ${engine.isEnabled() ? "ENABLED" : "DISABLED"} | Fallback Mode: ${engine.getFallbackMode()}`
    } else if (arg === "toggle" || !arg) {
      const nextState = !engine.isEnabled()
      engine.setEnabled(nextState)
      msg = `AutoGate Classifier: ${nextState ? "ENABLED" : "DISABLED"}`
    } else {
      const nextState = !engine.isEnabled()
      engine.setEnabled(nextState)
      msg = `AutoGate Classifier: ${nextState ? "ENABLED" : "DISABLED"}`
    }

    notifyCtx(ctx, msg)
  }

  pi.registerCommand("automode", {
    description: "Toggle or check AutoGate AutoMode status (alias for autogate-classifier)",
    handler,
  })
}

export function registerEscalatePermissionTool(pi: any, engine: AutoGateCoreEngine): void {
  if (typeof pi?.registerTool !== "function") {
    return
  }

  const parameters = pi?.zod?.object
    ? pi.zod.object({
        action: pi.zod.string().describe("The command or target path requiring human approval (e.g. '/etc/hosts' or 'rm -rf dist')"),
        reason: pi.zod.string().describe("Why the safe alternative or automated transform cannot be used and human review is required"),
      })
    : {
        type: "object",
        properties: {
          action: { type: "string", description: "The command or target path requiring human approval" },
          reason: { type: "string", description: "Why the safe alternative or automated transform cannot be used and human review is required" },
        },
        required: ["action", "reason"],
      };

  pi.registerTool({
    name: "escalate_permission",
    label: "Escalate Permission",
    description: "Request human manual verification for a blocked or high-risk action when safe automated transformations cannot satisfy the goal.",
    approval: "read",
    parameters,
    async execute(toolCallId: string, params: any, signal: AbortSignal, onUpdate: any, ctx: any) {
      const sessionID = ctx?.sessionID || ctx?.sessionId || params?.sessionID || "";
      const actionParam = params?.action || "";
      const reasonParam = params?.reason || "";
      engine.recordEscalationIntent(sessionID, actionParam, reasonParam);
      return {
        output: `Manual verification intent registered for '${actionParam}'. Please re-issue your tool call now; it will be forwarded directly to the user's phone for manual approval.`,
      };
    },
  })
}
