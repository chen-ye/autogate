import {
  AutoGateCoreEngine,
  NtfyAdapter,
  DirectApiEvaluator,
  loadConfig,
  type HarnessAdapter,
  type GateAction,
  type GateDecision,
  type GateEvaluator,
  type ReviewFallbackMode
} from "@autogate/core"
import { registerToolCallHook, verdictStore } from "./hook.ts"
import { resolveShadowedApproval } from "./approval-bridge.ts"
import { registerAutogateClassifierCommand, registerAutogateFallbackCommand, registerEscalatePermissionTool } from "./commands.ts"
import { OmpNativeEvaluator } from "./evaluator.ts"

export class OmpHarnessAdapter implements HarnessAdapter {
  readonly name = "omp-harness"
  private engine: AutoGateCoreEngine
  private evaluator: GateEvaluator
  private currentCtx: any = null

  constructor(pi: any, options?: Record<string, unknown>) {
    const config = loadConfig(options)
    const fallbackMode =
      (options as any)?.reviewFallbackMode ??
      (options as any)?.config?.reviewFallbackMode ??
      config.omp?.reviewFallbackMode ??
      (config as any)?.reviewFallbackMode ??
      "ntfy"
    const adapter = new NtfyAdapter({
      server: config.ntfyServer,
      topic: config.ntfyTopic,
      token: config.ntfyToken,
    })
    this.evaluator =
      (options as any)?.evaluator ??
      new OmpNativeEvaluator(
        () => this.currentCtx,
        (options as any)?.classifierModel || config.classifierModel,
        process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY || process.env.AUTOGATE_API_KEY,
        {
          logger: pi?.logger,
          classifierTimeout: config.classifierTimeout,
          evalLogFile: config.evalLogFile,
        }
      )
    this.engine = new AutoGateCoreEngine({
      config,
      adapter,
      evaluator: this.evaluator,
      remoteReviewEnabled: fallbackMode !== "native",
    })
  }

  setContext(ctx: any) {
    if (ctx) {
      this.currentCtx = ctx
      if (this.evaluator && typeof (this.evaluator as any).setContext === "function") {
        (this.evaluator as any).setContext(ctx)
      }
    }
  }
  setFallbackMode(mode: ReviewFallbackMode): void {
    this.engine.setFallbackMode(mode)
    this.engine.setRemoteReviewEnabled(mode !== "native")
  }

  getFallbackMode(): ReviewFallbackMode {
    return this.engine.getFallbackMode()
  }

  setRemoteReviewEnabled(enabled: boolean): void {
    this.engine.setRemoteReviewEnabled(enabled)
  }

  isRemoteReviewEnabled(): boolean {
    return this.engine.isRemoteReviewEnabled()
  }


  async start(): Promise<void> {
    await this.engine.start()
  }

  async dispose(): Promise<void> {
    await this.engine.stop()
  }

  getEngine(): AutoGateCoreEngine {
    return this.engine
  }
}

export function registerShadowedBashTool(pi: any, engine: AutoGateCoreEngine, adapter?: any): void {
  const parameters = pi?.zod?.object
    ? pi.zod.object({
        command: pi.zod.string(),
        timeout: pi.zod.number().optional(),
        workdir: pi.zod.string().optional(),
      })
    : {
        type: "object",
        properties: {
          command: { type: "string" },
          timeout: { type: "number" },
          workdir: { type: "string" },
        },
        required: ["command"],
      };

  pi.registerTool({
    name: "bash",
    label: "Bash",
    description: "Execute a bash command in a persistent shell session",
    approval: (args: any) => resolveShadowedApproval(args),
    parameters,
    async execute(toolCallId: string, params: any, signal: AbortSignal, onUpdate: any, ctx: any) {
      if (ctx && adapter && typeof adapter.setContext === "function") {
        adapter.setContext(ctx);
      } else if (ctx && typeof (engine as any).setContext === "function") {
        (engine as any).setContext(ctx);
      }
      if (!ctx?.invokeTool) {
        throw new Error("ctx.invokeTool is unavailable for shadowed bash delegation");
      }
      return await ctx.invokeTool(params, { signal, onUpdate });
    },
  });
}

export function registerShadowedEvalTool(pi: any, engine: AutoGateCoreEngine, adapter?: any): void {
  const parameters = pi?.zod?.object
    ? pi.zod.object({
        code: pi.zod.string(),
        language: pi.zod.string().optional(),
        timeout: pi.zod.number().optional(),
      })
    : {
        type: "object",
        properties: {
          code: { type: "string" },
          language: { type: "string" },
          timeout: { type: "number" },
        },
        required: ["code"],
      };

  pi.registerTool({
    name: "eval",
    label: "Eval",
    description: "Execute Python or JavaScript code",
    approval: (args: any) => resolveShadowedApproval(args),
    parameters,
    async execute(toolCallId: string, params: any, signal: AbortSignal, onUpdate: any, ctx: any) {
      if (ctx && adapter && typeof adapter.setContext === "function") {
        adapter.setContext(ctx);
      } else if (ctx && typeof (engine as any).setContext === "function") {
        (engine as any).setContext(ctx);
      }
      if (!ctx?.invokeTool) {
        throw new Error("ctx.invokeTool is unavailable for shadowed eval delegation");
      }
      return await ctx.invokeTool(params, { signal, onUpdate });
    },
  });
}

export default function autoGateOmpExtension(pi: any, options?: Record<string, unknown>): { adapter: OmpHarnessAdapter; engine: AutoGateCoreEngine } {
  pi.setLabel?.("AutoGate Security")
  const adapter = new OmpHarnessAdapter(pi, options)
  const engine = adapter.getEngine()
  adapter.start().catch(() => {})

  pi.on?.("input", (event: any, ctx: any) => {
    const text = event?.text || event?.input || (typeof event === "string" ? event : "");
    const sessionID =
      ctx?.sessionManager?.getSessionId?.() ||
      event?.sessionID ||
      event?.sessionId ||
      "";
    if (text) {
      if (sessionID) {
        engine.setUserPrompt(sessionID, text);
      } else {
        engine.setUserPrompt(text);
      }
    }
  })

  pi.on?.("turn_end", (event: any, ctx: any) => {
    const sessionID =
      ctx?.sessionManager?.getSessionId?.() ||
      event?.sessionID ||
      event?.sessionId ||
      "";
    if (sessionID) {
      engine.clearTurnCache(sessionID);
    }
  })

  registerToolCallHook(pi, engine, verdictStore, (ctx) => adapter.setContext(ctx))
  registerAutogateClassifierCommand(pi, engine)
  registerAutogateFallbackCommand(pi, engine)
  registerEscalatePermissionTool(pi, engine)
  registerShadowedBashTool(pi, engine, adapter)
  registerShadowedEvalTool(pi, engine, adapter)

  return { adapter, engine }
}
