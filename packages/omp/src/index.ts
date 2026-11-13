import {
  AutoGateCoreEngine,
  NtfyAdapter,
  loadConfig,
  type HarnessAdapter,
  type GateEvaluator,
  type ReviewFallbackMode,
} from "@autogate/core";
import { registerToolCallHook, verdictStore } from "./hook.ts";
import { resolveShadowedApproval } from "./approval-bridge.ts";
import {
  registerAutogateClassifierCommand,
  registerAutogateFallbackCommand,
  registerEscalatePermissionTool,
} from "./commands.ts";
import { OmpNativeEvaluator } from "./evaluator.ts";

import type { OmpContext, OmpLogger } from "./types.js";
import { isRecord } from "@autogate/core";

export class OmpHarnessAdapter implements HarnessAdapter {
  readonly name = "omp-harness";
  private engine: AutoGateCoreEngine;
  private evaluator: GateEvaluator;
  private nativeEvaluator?: OmpNativeEvaluator;
  private evalLogFile?: string;
  private currentCtx: OmpContext | null = null;

  constructor(pi: unknown, options?: Record<string, unknown>) {
    const config = loadConfig(options);
    const optObj = isRecord(options) ? options : undefined;
    this.evalLogFile = config.evalLogFile;
    const fallbackMode: ReviewFallbackMode =
      (typeof optObj?.reviewFallbackMode === "string" &&
      (optObj.reviewFallbackMode === "native" || optObj.reviewFallbackMode === "ntfy")
        ? optObj.reviewFallbackMode
        : undefined) ??
      config.omp?.reviewFallbackMode ??
      config.reviewFallbackMode ??
      "ntfy";
    const adapter = new NtfyAdapter({
      server: config.ntfyServer,
      topic: config.ntfyTopic,
      token: config.ntfyToken,
    });
    const piObj = (pi && typeof pi === "object" ? pi : {}) as { logger?: OmpLogger };

    let evaluator: GateEvaluator;
    if (optObj?.evaluator) {
      evaluator = optObj.evaluator as GateEvaluator;
      if (evaluator instanceof OmpNativeEvaluator) {
        this.nativeEvaluator = evaluator;
      }
    } else {
      const nativeEval = new OmpNativeEvaluator({
        getCtx: () => this.currentCtx,
        model: optObj?.classifierModel || config.classifierModel,
        apiKey:
          process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY || process.env.AUTOGATE_API_KEY,
        logger: piObj.logger,
        classifierTimeout: config.classifierTimeout,
        evalLogFile: config.evalLogFile,
        suppressEvalLog: Boolean(config.systemOne?.enabled),
      });
      this.nativeEvaluator = nativeEval;
      evaluator = nativeEval;
    }

    this.evaluator = evaluator;
    this.engine = new AutoGateCoreEngine({
      config,
      adapter,
      evaluator,
      remoteReviewEnabled: fallbackMode !== "native",
    });
  }

  public getEvalLogFile(): string | undefined {
    return this.evalLogFile;
  }

  setContext(ctx: OmpContext) {
    if (ctx) {
      this.currentCtx = ctx;
      this.nativeEvaluator?.setContext(ctx);
    }
  }
  setFallbackMode(mode: ReviewFallbackMode): void {
    this.engine.setFallbackMode(mode);
    this.engine.setRemoteReviewEnabled(mode !== "native");
  }

  getFallbackMode(): ReviewFallbackMode {
    return this.engine.getFallbackMode();
  }

  setRemoteReviewEnabled(enabled: boolean): void {
    this.engine.setRemoteReviewEnabled(enabled);
  }

  isRemoteReviewEnabled(): boolean {
    return this.engine.isRemoteReviewEnabled();
  }

  async start(): Promise<void> {
    await this.engine.start();
  }

  async dispose(): Promise<void> {
    await this.engine.stop();
  }

  getEngine(): AutoGateCoreEngine {
    return this.engine;
  }
}

export function registerShadowedBashTool(
  pi: unknown,
  engine: AutoGateCoreEngine,
  adapter?: OmpHarnessAdapter,
): void {
  const p = pi as {
    registerTool(tool: unknown): void;
    zod?: {
      object?(schema: unknown): unknown;
      string?(): { optional(): unknown; describe?(d: string): unknown };
      number?(): { optional(): unknown };
    };
  };
  const parameters = p?.zod?.object
    ? p.zod.object({
        command: p.zod.string?.(),
        timeout: p.zod.number?.().optional(),
        workdir: p.zod.string?.().optional(),
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

  p.registerTool({
    name: "bash",
    label: "Bash",
    description: "Execute a bash command in a persistent shell session",
    approval: (args: unknown) => resolveShadowedApproval(args),
    parameters,
    async execute(
      toolCallId: string,
      params: unknown,
      signal: AbortSignal,
      onUpdate: unknown,
      ctx: unknown,
    ) {
      const cx = ctx as OmpContext | undefined;
      if (cx && adapter && typeof adapter.setContext === "function") {
        adapter.setContext(cx);
      }
      const cxInvoke = ctx as
        | { invokeTool?: (p: unknown, o: unknown) => Promise<unknown> }
        | undefined;
      if (!cxInvoke?.invokeTool) {
        throw new Error("ctx.invokeTool is unavailable for shadowed bash delegation");
      }
      return await cxInvoke.invokeTool(params, { signal, onUpdate });
    },
  });
}

export function registerShadowedEvalTool(
  pi: unknown,
  engine: AutoGateCoreEngine,
  adapter?: OmpHarnessAdapter,
): void {
  const p = pi as {
    registerTool(tool: unknown): void;
    zod?: {
      object?(schema: unknown): unknown;
      string?(): { optional(): unknown; describe?(d: string): unknown };
      number?(): { optional(): unknown };
    };
  };
  const parameters = p?.zod?.object
    ? p.zod.object({
        code: p.zod.string?.(),
        language: p.zod.string?.().optional(),
        timeout: p.zod.number?.().optional(),
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

  p.registerTool({
    name: "eval",
    label: "Eval",
    description: "Execute Python or JavaScript code",
    approval: (args: unknown) => resolveShadowedApproval(args),
    parameters,
    async execute(
      toolCallId: string,
      params: unknown,
      signal: AbortSignal,
      onUpdate: unknown,
      ctx: unknown,
    ) {
      const cx = ctx as OmpContext | undefined;
      if (cx && adapter && typeof adapter.setContext === "function") {
        adapter.setContext(cx);
      }
      const cxInvoke = ctx as
        | { invokeTool?: (p: unknown, o: unknown) => Promise<unknown> }
        | undefined;
      if (!cxInvoke?.invokeTool) {
        throw new Error("ctx.invokeTool is unavailable for shadowed eval delegation");
      }
      return await cxInvoke.invokeTool(params, { signal, onUpdate });
    },
  });
}

export default function autoGateOmpExtension(
  pi: unknown,
  options?: Record<string, unknown>,
): { adapter: OmpHarnessAdapter; engine: AutoGateCoreEngine } {
  const p = pi as
    | {
        setLabel?(l: string): void;
        on?(event: string, handler: (e: unknown, c: unknown) => void): void;
      }
    | undefined;
  p?.setLabel?.("AutoGate Security");
  const adapter = new OmpHarnessAdapter(pi, options);
  const engine = adapter.getEngine();
  adapter.start().catch(() => {});

  p?.on?.("input", (event: unknown, ctx: unknown) => {
    const ev = event as Record<string, unknown> | undefined;
    const cx = ctx as Record<string, unknown> | undefined;
    const text =
      typeof ev?.text === "string"
        ? ev.text
        : typeof ev?.input === "string"
          ? ev.input
          : typeof event === "string"
            ? event
            : "";
    const sm = cx?.sessionManager as { getSessionId?: () => string } | undefined;
    const sessionID =
      (typeof sm?.getSessionId === "function" ? sm.getSessionId() : undefined) ||
      (typeof ev?.sessionID === "string" ? ev.sessionID : undefined) ||
      (typeof ev?.sessionId === "string" ? ev.sessionId : undefined) ||
      "";
    if (text) {
      if (sessionID) {
        engine.setUserPrompt(sessionID, text);
      } else {
        engine.setUserPrompt(text);
      }
    }
  });

  p?.on?.("turn_end", (event: unknown, ctx: unknown) => {
    const ev = event as Record<string, unknown> | undefined;
    const cx = ctx as Record<string, unknown> | undefined;
    const sm = cx?.sessionManager as { getSessionId?: () => string } | undefined;
    const sessionID =
      (typeof sm?.getSessionId === "function" ? sm.getSessionId() : undefined) ||
      (typeof ev?.sessionID === "string" ? ev.sessionID : undefined) ||
      (typeof ev?.sessionId === "string" ? ev.sessionId : undefined) ||
      "";
    if (sessionID) {
      engine.clearTurnCache(sessionID);
    }
  });

  registerToolCallHook(
    pi,
    engine,
    verdictStore,
    (ctx) => adapter.setContext(ctx),
    adapter.getEvalLogFile(),
  );
  registerAutogateClassifierCommand(pi, engine);
  registerAutogateFallbackCommand(pi, engine);
  registerEscalatePermissionTool(pi, engine);
  registerShadowedBashTool(pi, engine, adapter);
  registerShadowedEvalTool(pi, engine, adapter);

  return { adapter, engine };
}
