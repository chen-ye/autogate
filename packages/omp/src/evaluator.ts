import type { GateEvaluator, GateAction, ClassifierResult } from "@autogate/core";
import { buildClassifierSystemPrompt, buildClassifierUserPrompt } from "@autogate/core";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import { completeSimple } from "@oh-my-pi/pi-ai";

export const CLASSIFY_RESULT_TOOL: any = {
  name: "classify_result",
  description: "Report the security classification result for the proposed action",
  parameters: {
    type: "object",
    properties: {
      risk_level: { type: "string", enum: ["LOW", "MEDIUM", "HIGH", "CRITICAL"] },
      user_authorization: { type: "string", enum: ["NONE", "LOW", "MEDIUM", "HIGH"] },
      verdict: { type: "string", enum: ["ALLOW", "BLOCK", "UNSURE"] },
      reason: { type: "string" },
    },
    required: ["risk_level", "user_authorization", "verdict", "reason"],
  },
};
export class OmpNativeEvaluator implements GateEvaluator {
  readonly name = "omp-native-evaluator";
  private getCtx?: () => any;
  private fallbackModel?: any;
  private fallbackApiKey?: string;
  private fallbackSessionId?: string;
  private currentCtx: any = null;
  private classifierTimeout?: number;
  private logger?: any;
  private evalLogFile?: string;

  constructor(
    arg1?: (() => any) | any | Record<string, any>,
    arg2?: string | any | Record<string, any>,
    arg3?: string | number | Record<string, any>,
    arg4?: number | Record<string, any>,
  ) {
    this.evalLogFile =
      (arg1 as any)?.evalLogFile ??
      (arg2 as any)?.evalLogFile ??
      (arg3 as any)?.evalLogFile ??
      (arg4 as any)?.evalLogFile;
    if (
      typeof arg1 === "object" &&
      arg1 !== null &&
      !Array.isArray(arg1) &&
      typeof (arg1 as any).evaluate !== "function" &&
      !(arg1 as any).api &&
      !(arg1 as any).id &&
      typeof arg1 !== "function" &&
      ("classifierTimeout" in arg1 ||
        "model" in arg1 ||
        "fallbackModel" in arg1 ||
        "logger" in arg1 ||
        "evalLogFile" in arg1)
    ) {
      this.fallbackModel = (arg1 as any).model ?? (arg1 as any).fallbackModel;
      this.fallbackApiKey = (arg1 as any).apiKey ?? (arg1 as any).fallbackApiKey;
      this.fallbackSessionId = (arg1 as any).sessionId ?? (arg1 as any).fallbackSessionId;
      this.classifierTimeout = (arg1 as any).classifierTimeout;
      this.getCtx = (arg1 as any).getCtx;
      this.logger = (arg1 as any).logger;
      if ((arg1 as any).evalLogFile) this.evalLogFile = (arg1 as any).evalLogFile;
    } else if (typeof arg1 === "function") {
      this.getCtx = arg1;
      this.fallbackModel = arg2;
      if (typeof arg3 === "string") {
        this.fallbackApiKey = arg3;
      } else if (typeof arg3 === "number") {
        this.classifierTimeout = arg3;
      } else if (typeof arg3 === "object" && arg3 !== null) {
        this.classifierTimeout = (arg3 as any).classifierTimeout ?? this.classifierTimeout;
        if ((arg3 as any).apiKey) this.fallbackApiKey = (arg3 as any).apiKey;
        if ((arg3 as any).logger) this.logger = (arg3 as any).logger;
      }
      if (typeof arg4 === "number") {
        this.classifierTimeout = arg4;
      } else if (typeof arg4 === "object" && arg4 !== null) {
        this.classifierTimeout = (arg4 as any).classifierTimeout ?? this.classifierTimeout;
        if ((arg4 as any).logger) this.logger = (arg4 as any).logger;
      }
    } else {
      this.fallbackModel = arg1;
      if (typeof arg2 === "string") {
        this.fallbackApiKey = arg2;
      } else if (typeof arg2 === "object" && arg2 !== null) {
        this.classifierTimeout = (arg2 as any).classifierTimeout ?? this.classifierTimeout;
        if ((arg2 as any).apiKey) this.fallbackApiKey = (arg2 as any).apiKey;
        if ((arg2 as any).sessionId) this.fallbackSessionId = (arg2 as any).sessionId;
        if ((arg2 as any).logger) this.logger = (arg2 as any).logger;
      }
      if (typeof arg3 === "string") {
        this.fallbackSessionId = arg3;
      } else if (typeof arg3 === "number") {
        this.classifierTimeout = arg3;
      } else if (typeof arg3 === "object" && arg3 !== null) {
        this.classifierTimeout = (arg3 as any).classifierTimeout ?? this.classifierTimeout;
        if ((arg3 as any).logger) this.logger = (arg3 as any).logger;
      }
      if (typeof arg4 === "number") {
        this.classifierTimeout = arg4;
      } else if (typeof arg4 === "object" && arg4 !== null) {
        if ("logger" in arg4) this.logger = (arg4 as any).logger;
        if ("evalLogFile" in arg4) this.evalLogFile = (arg4 as any).evalLogFile;
      }
    }

    if (!this.logger) {
      this.logger = console;
    }
  }

  private async appendEvalLog(entry: Record<string, any>): Promise<void> {
    const targetFile =
      this.evalLogFile || path.join(os.homedir(), ".omp", "logs", "autogate-evals.jsonl");
    try {
      await fs.mkdir(path.dirname(targetFile), { recursive: true });
      await fs.appendFile(targetFile, JSON.stringify(entry) + "\n", "utf8");
    } catch {}
  }

  private log(
    level: "debug" | "info" | "warn" | "error",
    message: string,
    data?: Record<string, any>,
  ) {
    const logFn = this.logger?.[level] ?? console[level] ?? console.log;
    try {
      logFn.call(this.logger ?? console, message, data);
    } catch {}
  }

  setContext(ctx: any) {
    if (ctx) {
      this.currentCtx = ctx;
    }
  }

  async evaluate(action: GateAction): Promise<ClassifierResult> {
    const startTime = performance.now();
    const timeoutMs = this.classifierTimeout ?? 45000;
    const timeoutSignal = AbortSignal.timeout(timeoutMs);
    const combinedSignal = action.signal
      ? AbortSignal.any([action.signal, timeoutSignal])
      : timeoutSignal;

    let sessionId: any = action.sessionID;
    let lastResponse: any = null;
    let attempts = 0;
    let thinking: string | undefined = undefined;
    let reasoningTokens = 0;
    let model: any = this.fallbackModel;
    let ctx: any = null;
    if (combinedSignal.aborted) {
      const durationMs = Math.round(performance.now() - startTime);
      const isTimeout = timeoutSignal.aborted;
      this.log("error", "[AutoGate OMP Evaluator] Inference failed or timed out", {
        durationMs,
        error: "Inference aborted by signal",
        timedOut: combinedSignal.aborted,
        isTimeout,
      });
      return {
        verdict: "UNSURE",
        reason: isTimeout
          ? `OmpNativeEvaluator error: Inference timed out after ${timeoutMs}ms`
          : `OmpNativeEvaluator error: Inference aborted by signal`,
      };
    }

    try {
      const systemPrompt = buildClassifierSystemPrompt();
      const userPrompt = buildClassifierUserPrompt({
        userPrompt: action.userPrompt,
        subagentPrompt: action.subagentPrompt,
        actionName: action.toolName,
        actionArgs: action.rawArgs ?? action.metadata ?? action.commandString,
        workspaceRoot: action.workspaceRoot,
        environment: action.environment,
      });

      ctx = this.getCtx?.() || this.currentCtx;
      try {
        if (ctx?.models?.resolve) {
          model =
            ctx.models.resolve("@smol") || ctx.models.resolve("default") || ctx.model || model;
        } else if (ctx?.model) {
          model = ctx.model || model;
        }
      } catch {}

      sessionId =
        action.sessionID ||
        ctx?.sessionManager?.getSessionId?.() ||
        ctx?.sessionID ||
        ctx?.sessionId ||
        this.fallbackSessionId;

      this.log("debug", "[AutoGate OMP Evaluator] Evaluating action", {
        toolName: action.toolName,
        targetPath: action.targetPath,
        command: action.commandString,
        model: model?.id,
        provider: model?.provider,
        sessionId,
      });

      let apiKey = this.fallbackApiKey;
      try {
        if (ctx?.modelRegistry?.getApiKey && model) {
          const resolvedKey = await ctx.modelRegistry.getApiKey(model, sessionId);
          if (resolvedKey) apiKey = resolvedKey;
        } else if (ctx?.model?.apiKey) {
          apiKey = ctx.model.apiKey || apiKey;
        }
      } catch {}

      apiKey =
        apiKey ||
        process.env.GEMINI_API_KEY ||
        process.env.GOOGLE_API_KEY ||
        process.env.AUTOGATE_API_KEY;

      this.log("debug", "[AutoGate OMP Evaluator] Resolved API key", {
        provider: model?.provider,
        hasKey: Boolean(apiKey),
      });

      if (!model) {
        this.log("warn", "[AutoGate OMP Evaluator] No model resolved in OMP context", {
          actionId: action.id,
        });
        return {
          verdict: "UNSURE",
          reason: "OmpNativeEvaluator error: No model resolved in OMP context",
        };
      }

      this.log("debug", "[AutoGate OMP Evaluator] Starting completeSimple inference", {
        promptLength: userPrompt.length + systemPrompt.length,
        timeoutMs,
      });

      const messages: any[] = [{ role: "user", content: userPrompt, timestamp: Date.now() }];
      const maxRetries = 2;
      let validResult: ClassifierResult | null = null;

      for (let attempt = 0; attempt <= maxRetries; attempt++) {
        const response = await completeSimple(
          model,
          {
            systemPrompt: [systemPrompt],
            messages,
            tools: [CLASSIFY_RESULT_TOOL],
          },
          {
            apiKey,
            sessionId,
            maxTokens: 1024,
            signal: combinedSignal,
            toolChoice: { type: "function", name: "classify_result" },
          },
        );
        lastResponse = response;
        if (timeoutSignal.aborted) {
          const durationMs = Math.round(performance.now() - startTime);
          return {
            verdict: "UNSURE",
            reason: `OmpNativeEvaluator error: Inference timed out after ${timeoutMs}ms`,
          };
        }
        if (action.signal?.aborted) {
          const durationMs = Math.round(performance.now() - startTime);
          return {
            verdict: "UNSURE",
            reason: `OmpNativeEvaluator error: Inference aborted by signal`,
          };
        }
        if (response.stopReason === "error") {
          const durationMs = Math.round(performance.now() - startTime);
          const errReason = response.errorMessage ?? "unknown error";
          const isTimeout = timeoutSignal.aborted;
          this.log("error", "[AutoGate OMP Evaluator] Inference failed or timed out", {
            durationMs,
            error: errReason,
            timedOut: combinedSignal.aborted,
            isTimeout,
          });
          return {
            verdict: "UNSURE",
            reason: isTimeout
              ? `OmpNativeEvaluator error: Inference timed out after ${timeoutMs}ms`
              : `OmpNativeEvaluator error: ${errReason}`,
          };
        }
        const toolCall = Array.isArray(response.content)
          ? response.content.find(
              (c: any) =>
                c &&
                c.type === "toolCall" &&
                (c.name === "classify_result" || c.function?.name === "classify_result"),
            )
          : undefined;

        if (toolCall) {
          let args: any = toolCall.arguments ?? toolCall.function?.arguments;
          if (typeof args === "string") {
            try {
              args = JSON.parse(args);
            } catch {
              args = null;
            }
          }

          if (args && typeof args === "object") {
            const verdictRaw = String(args.verdict ?? "")
              .toUpperCase()
              .trim();
            const reason = typeof args.reason === "string" ? args.reason : undefined;
            const riskRaw = String(args.risk_level ?? "")
              .toUpperCase()
              .trim();
            const authRaw = String(args.user_authorization ?? "")
              .toUpperCase()
              .trim();
            const risk_level = ["LOW", "MEDIUM", "HIGH", "CRITICAL"].includes(riskRaw)
              ? (riskRaw as any)
              : undefined;
            const user_authorization = ["NONE", "LOW", "MEDIUM", "HIGH"].includes(authRaw)
              ? (authRaw as any)
              : undefined;

            if (verdictRaw === "ALLOW" || verdictRaw === "BLOCK" || verdictRaw === "UNSURE") {
              validResult = {
                verdict: verdictRaw as any,
                risk_level,
                user_authorization,
                reason,
              };
              break;
            }
          }
        }

        this.log(
          "warn",
          "[AutoGate OMP Evaluator] Model did not invoke classify_result tool call; re-prompting",
          { attempt },
        );
        messages.push(response);
        messages.push({
          role: "user",
          content:
            "You must record your decision by calling the classify_result tool with { risk_level, user_authorization, verdict, reason }.",
          timestamp: Date.now(),
        });
      }
      const durationMs = Math.round(performance.now() - startTime);
      const rawThinking = Array.isArray(lastResponse?.content)
        ? lastResponse.content
            .filter(
              (c: any) =>
                c &&
                (c.type === "thinking" || c.type === "reasoning" || c.type === "reasoning_text"),
            )
            .map((c: any) => c.thinking ?? c.text ?? c.reasoning ?? c.reasoning_content)
            .filter(Boolean)
            .join("\n") || undefined
        : undefined;
      const thinking =
        rawThinking ||
        lastResponse?.reasoning_content ||
        lastResponse?.reasoning ||
        lastResponse?.reasoningContent ||
        (lastResponse as any)?.thinking ||
        undefined;

      reasoningTokens =
        lastResponse?.reasoningTokens ??
        lastResponse?.reasoning_tokens ??
        lastResponse?.usage?.reasoningTokens ??
        (lastResponse?.usage as any)?.reasoning_tokens ??
        (lastResponse?.usage as any)?.completionTokensDetails?.reasoningTokens ??
        (lastResponse?.usage as any)?.completion_tokens_details?.reasoning_tokens ??
        (lastResponse as any)?.rawResponse?.usage?.reasoning_tokens ??
        (lastResponse as any)?.rawResponse?.usage?.completion_tokens_details?.reasoning_tokens ??
        0;

      if (!validResult) {
        this.appendEvalLog({
          timestamp: new Date().toISOString(),
          action: {
            id: action.id,
            toolName: action.toolName,
            command: action.commandString,
            targetPath: action.targetPath,
            sessionID: sessionId,
          },
          model: {
            id: model?.id,
            provider: model?.provider,
          },
          inference: {
            durationMs,
            promptTokens: lastResponse?.usage?.input,
            outputTokens: lastResponse?.usage?.output,
            reasoningTokens,
            thinking,
            attempts,
          },
          decision: {
            verdict: "UNSURE",
            reason: "Model failed to invoke classify_result tool call after retries",
          },
          error: "Model failed to invoke classify_result tool call after retries",
        }).catch(() => {});
        return {
          verdict: "UNSURE",
          reason: "Model failed to invoke classify_result tool call after retries",
        };
      }

      this.appendEvalLog({
        timestamp: new Date().toISOString(),
        action: {
          id: action.id,
          toolName: action.toolName,
          command: action.commandString,
          targetPath: action.targetPath,
          sessionID: sessionId,
        },
        model: {
          id: model?.id,
          provider: model?.provider,
        },
        inference: {
          durationMs,
          promptTokens: lastResponse?.usage?.input,
          outputTokens: lastResponse?.usage?.output,
          reasoningTokens,
          thinking,
          attempts,
        },
        decision: {
          verdict: validResult.verdict,
          riskLevel: validResult.risk_level,
          userAuthorization: validResult.user_authorization,
          reason: validResult.reason,
        },
      }).catch(() => {});

      this.log("info", "[AutoGate OMP Evaluator] Inference finished", {
        durationMs,
        verdict: validResult.verdict,
        reason: validResult.reason,
      });

      return validResult;
    } catch (err: unknown) {
      const durationMs = Math.round(performance.now() - startTime);
      const isTimeout = timeoutSignal.aborted;
      const errorMsg = err instanceof Error ? err.message : String(err);
      this.log("error", "[AutoGate OMP Evaluator] Inference failed or timed out", {
        durationMs,
        error: errorMsg,
        stack: err instanceof Error ? err.stack : undefined,
        timedOut: combinedSignal.aborted,
        isTimeout,
      });

      this.appendEvalLog({
        timestamp: new Date().toISOString(),
        action: {
          id: action.id,
          toolName: action.toolName,
          command: action.commandString,
          targetPath: action.targetPath,
          sessionID: sessionId,
        },
        model: {
          id: model?.id,
          provider: model?.provider,
        },
        inference: {
          durationMs,
          attempts: typeof attempts !== "undefined" ? attempts : 0,
        },
        decision: {
          verdict: "UNSURE",
          reason: errorMsg,
        },
        error: errorMsg,
      }).catch(() => {});

      if (combinedSignal.aborted) {
        return {
          verdict: "UNSURE",
          reason: isTimeout
            ? `OmpNativeEvaluator error: Inference timed out after ${timeoutMs}ms`
            : `OmpNativeEvaluator error: Inference aborted by signal`,
        };
      }
      const message = err instanceof Error ? err.message : String(err);
      return {
        verdict: "UNSURE",
        reason: `OmpNativeEvaluator error: ${message}`,
      };
    }
  }
}
