import type { GateEvaluator, GateAction, ClassifierResult } from "@autogate/core";
import { buildClassifierPrompt, parseVerdict } from "@autogate/core";
import { completeSimple } from "@oh-my-pi/pi-ai";

export class OmpNativeEvaluator implements GateEvaluator {
  readonly name = "omp-native-evaluator";
  private getCtx?: () => any;
  private fallbackModel?: any;
  private fallbackApiKey?: string;
  private fallbackSessionId?: string;
  private currentCtx: any = null;

  constructor(
    arg1?: (() => any) | any,
    arg2?: string | any,
    arg3?: string
  ) {
    if (typeof arg1 === "function") {
      this.getCtx = arg1;
      this.fallbackModel = arg2;
      this.fallbackApiKey = arg3;
    } else {
      this.fallbackModel = arg1;
      this.fallbackApiKey = arg2;
      this.fallbackSessionId = arg3;
    }
  }

  setContext(ctx: any) {
    if (ctx) {
      this.currentCtx = ctx;
    }
  }

  async evaluate(action: GateAction): Promise<ClassifierResult> {
    try {
      const promptText = buildClassifierPrompt({
        userPrompt: action.userPrompt,
        subagentPrompt: action.subagentPrompt,
        actionName: action.toolName,
        actionArgs: action.rawArgs ?? action.metadata ?? action.commandString,
        workspaceRoot: action.workspaceRoot,
        environment: action.environment,
      });

      const ctx = this.getCtx?.() || this.currentCtx;
      let model: any = this.fallbackModel;
      try {
        if (ctx?.models?.resolve) {
          model = ctx.models.resolve("@smol") || ctx.models.resolve("default") || ctx.model || model;
        } else if (ctx?.model) {
          model = ctx.model || model;
        }
      } catch {}

      const sessionId = action.sessionID || ctx?.sessionID || ctx?.sessionId || this.fallbackSessionId;

      let apiKey = this.fallbackApiKey;
      try {
        if (ctx?.modelRegistry?.getApiKey && model) {
          const resolvedKey = await ctx.modelRegistry.getApiKey(model, sessionId)
          if (resolvedKey) apiKey = resolvedKey
        } else if (ctx?.model?.apiKey) {
          apiKey = ctx.modelRegistry.getApiKey(model, sessionId) || apiKey;
        } else if (ctx?.model?.apiKey) {
          apiKey = ctx.model.apiKey || apiKey;
        }
      } catch {}

      apiKey = apiKey || process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY || process.env.AUTOGATE_API_KEY;

      if (!model) {
        return {
          verdict: "UNSURE",
          reason: "OmpNativeEvaluator error: No model resolved in OMP context",
        };
      }

      const response = await completeSimple(
        model,
        {
          messages: [{ role: "user", content: promptText, timestamp: Date.now() }],
        },
        {
          apiKey,
          sessionId,
          maxTokens: 1024,
        }
      );

      if (response.stopReason === "error") {
        return {
          verdict: "UNSURE",
          reason: `OmpNativeEvaluator error: ${response.errorMessage ?? "unknown error"}`,
        };
      }

      const candidateText = response.content
        .filter((c: any) => c.type === "text")
        .map((c: any) => c.text)
        .join("\n");

      return parseVerdict(candidateText);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        verdict: "UNSURE",
        reason: `OmpNativeEvaluator error: ${message}`,
      };
    }
  }
}
