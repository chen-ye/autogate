import type { AutoGateCoreEngine } from "../../core/src/index.ts";

function notifyCtx(ctx: unknown, msg: string) {
  if (!ctx || typeof ctx !== "object") return;
  const c = ctx as {
    ui?: { notify?: (m: string, l: string) => void };
    notify?: (m: string, l: string) => void;
  };
  if (c.ui?.notify) {
    c.ui.notify(msg, "info");
  } else if (c.notify) {
    c.notify(msg, "info");
  }
}

function parseArgString(args: unknown): string {
  if (typeof args === "string") return args.trim().toLowerCase();
  if (
    typeof args === "object" &&
    args !== null &&
    "arguments" in args &&
    typeof (args as { arguments: unknown }).arguments === "string"
  ) {
    return (args as { arguments: string }).arguments.trim().toLowerCase();
  }
  return "";
}

export function registerAutogateClassifierCommand(pi: unknown, engine: AutoGateCoreEngine): void {
  const p = pi as { registerCommand?: (name: string, def: unknown) => void } | undefined;
  if (typeof p?.registerCommand !== "function") {
    return;
  }

  const handler = async (args: string, ctx: unknown) => {
    const arg = parseArgString(args);

    let msg = "";
    if (arg === "off" || arg === "disable" || arg === "false" || arg === "0") {
      engine.setEnabled(false);
      msg = "AutoGate Classifier: DISABLED";
    } else if (arg === "on" || arg === "enable" || arg === "true" || arg === "1") {
      engine.setEnabled(true);
      msg = "AutoGate Classifier: ENABLED";
    } else if (arg === "status") {
      msg = `AutoGate Classifier: ${engine.isEnabled() ? "ENABLED" : "DISABLED"} | Fallback Mode: ${engine.getFallbackMode()}`;
    } else if (arg === "toggle" || !arg) {
      const nextState = !engine.isEnabled();
      engine.setEnabled(nextState);
      msg = `AutoGate Classifier: ${nextState ? "ENABLED" : "DISABLED"}`;
    } else {
      const nextState = !engine.isEnabled();
      engine.setEnabled(nextState);
      msg = `AutoGate Classifier: ${nextState ? "ENABLED" : "DISABLED"}`;
    }

    notifyCtx(ctx, msg);
  };

  p.registerCommand("autogate-classifier", {
    description: "Enable, disable, or check AutoGate classifier status",
    handler,
  });
}

export function registerAutogateFallbackCommand(pi: unknown, engine: AutoGateCoreEngine): void {
  const p = pi as { registerCommand?: (name: string, def: unknown) => void } | undefined;
  if (typeof p?.registerCommand !== "function") {
    return;
  }

  const handler = async (args: string, ctx: unknown) => {
    const arg = parseArgString(args);

    let msg = "";
    if (arg === "native" || arg === "desk" || arg === "terminal") {
      engine.setFallbackMode("native");
      msg = "AutoGate Fallback Mode: NATIVE (immediate terminal prompt)";
    } else if (arg === "ntfy" || arg === "mobile" || arg === "remote") {
      engine.setFallbackMode("ntfy");
      msg = "AutoGate Fallback Mode: NTFY (mobile push approval)";
    } else if (arg === "status") {
      msg = `AutoGate Fallback Mode: ${engine.getFallbackMode()} | Classifier: ${engine.isEnabled() ? "ENABLED" : "DISABLED"}`;
    } else if (arg === "toggle" || !arg) {
      const current = engine.getFallbackMode();
      const nextMode = current === "native" ? "ntfy" : "native";
      engine.setFallbackMode(nextMode);
      if (nextMode === "native") {
        msg = "AutoGate Fallback Mode: NATIVE (immediate terminal prompt)";
      } else {
        msg = "AutoGate Fallback Mode: NTFY (mobile push approval)";
      }
    } else {
      const current = engine.getFallbackMode();
      const nextMode = current === "native" ? "ntfy" : "native";
      engine.setFallbackMode(nextMode);
      if (nextMode === "native") {
        msg = "AutoGate Fallback Mode: NATIVE (immediate terminal prompt)";
      } else {
        msg = "AutoGate Fallback Mode: NTFY (mobile push approval)";
      }
    }

    notifyCtx(ctx, msg);
  };

  p.registerCommand("autogate-fallback", {
    description: "Set or check AutoGate review fallback mode (native or ntfy)",
    handler,
  });
}

export function registerEscalatePermissionTool(pi: unknown, engine: AutoGateCoreEngine): void {
  const p = pi as
    | {
        registerTool?(tool: unknown): void;
        zod?: {
          object?(s: unknown): unknown;
          string?(): { describe(d: string): unknown };
        };
      }
    | undefined;
  if (typeof p?.registerTool !== "function") {
    return;
  }

  const parameters = p?.zod?.object
    ? p.zod.object({
        action: p.zod
          .string?.()
          .describe(
            "The command or target path requiring human approval (e.g. '/etc/hosts' or 'rm -rf dist')",
          ),
        reason: p.zod
          .string?.()
          .describe(
            "Why the safe alternative or automated transform cannot be used and human review is required",
          ),
      })
    : {
        type: "object",
        properties: {
          action: {
            type: "string",
            description: "The command or target path requiring human approval",
          },
          reason: {
            type: "string",
            description:
              "Why the safe alternative or automated transform cannot be used and human review is required",
          },
        },
        required: ["action", "reason"],
      };

  p.registerTool({
    name: "escalate_permission",
    label: "Escalate Permission",
    description:
      "Request human manual verification for a blocked or high-risk action when safe automated transformations cannot satisfy the goal.",
    approval: "read",
    parameters,
    async execute(
      toolCallId: string,
      params: unknown,
      signal: AbortSignal,
      onUpdate: unknown,
      ctx: unknown,
    ) {
      const cx = ctx as Record<string, unknown> | undefined;
      const par = params as Record<string, unknown> | undefined;
      const sm = cx?.sessionManager as { getSessionId?: () => string } | undefined;
      const sessionID =
        (typeof sm?.getSessionId === "function" ? sm.getSessionId() : undefined) ||
        (typeof cx?.sessionID === "string" ? cx.sessionID : undefined) ||
        (typeof cx?.sessionId === "string" ? cx.sessionId : undefined) ||
        (typeof par?.sessionID === "string" ? par.sessionID : "") ||
        "";
      const actionParam = typeof par?.action === "string" ? par.action : "";
      const reasonParam = typeof par?.reason === "string" ? par.reason : "";
      if (!engine.recordEscalationIntent(sessionID, actionParam, reasonParam)) {
        return {
          output:
            "Unable to register manual verification intent: both a valid sessionID and a non-empty action are required.",
        };
      }
      const delivery = engine.isRemoteReviewEnabled()
        ? "forwarded directly to the user's phone for manual approval"
        : "handled via the native harness prompt for manual approval";
      return {
        output: `Manual verification intent registered for '${actionParam.trim()}'. Please re-issue your tool call now; it will be ${delivery}.`,
      };
    },
  });
}
