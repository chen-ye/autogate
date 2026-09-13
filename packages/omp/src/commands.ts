import type { AutoGateCoreEngine } from "../../core/src/index.ts"

export function registerAutomodeCommand(pi: any, engine: AutoGateCoreEngine): void {
  if (typeof pi?.registerCommand !== "function") {
    return
  }

  const handler = async (args: string, ctx: any) => {
    const arg = (typeof args === "string" ? args : (args as any)?.arguments || "").trim().toLowerCase()

    let msg = ""
    if (arg === "off" || arg === "disable" || arg === "false" || arg === "0") {
      engine.setEnabled(false)
      msg = "Auto Mode is now DISABLED (all requests route to ntfy)."
    } else if (arg === "on" || arg === "enable" || arg === "true" || arg === "1") {
      engine.setEnabled(true)
      msg = "Auto Mode is now ENABLED (classifier active)."
    } else if (arg === "status" || !arg) {
      const status = engine.isEnabled() ? "ENABLED (classifier active)" : "DISABLED (routing to remote)"
      msg = `Auto Mode status: ${status}`
    } else if (arg === "toggle") {
      const nextState = !engine.isEnabled()
      engine.setEnabled(nextState)
      msg = `Auto Mode toggled to: ${nextState ? "ENABLED" : "DISABLED"}`
    } else {
      const nextState = !engine.isEnabled()
      engine.setEnabled(nextState)
      msg = `Auto Mode toggled to: ${nextState ? "ENABLED" : "DISABLED"}`
    }

    if (ctx?.ui?.notify) {
      ctx.ui.notify(msg, "info")
    } else if (ctx?.notify) {
      ctx.notify(msg, "info")
    }
  }

  pi.registerCommand("automode", {
    description: "Toggle or check AutoGate AutoMode status",
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
