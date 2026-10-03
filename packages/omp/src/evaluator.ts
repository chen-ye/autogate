import type { GateEvaluator, GateAction, ClassifierResult } from "@autogate/core";
import {
  buildClassifierSystemPrompt,
  buildClassifierUserPrompt,
  isClassifierVerdict,
  isRiskLevel,
  isUserAuthorization,
} from "@autogate/core";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import { completeSimple } from "@oh-my-pi/pi-ai";
import type { OmpEvaluatorOptions, OmpLogger, OmpContext } from "./types.js";

export const CLASSIFY_RESULT_TOOL = {
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
  private getCtx?: () => unknown;
  private fallbackModel?: unknown;
  private fallbackApiKey?: string;
  private fallbackSessionId?: string;
  private currentCtx: OmpContext | null = null;
  private classifierTimeout?: number;
  private logger?: OmpLogger;
  private evalLogFile?: string;

  constructor(
    arg1?: (() => unknown) | unknown | OmpEvaluatorOptions,
    arg2?: unknown,
    arg3?: unknown,
    arg4?: unknown,
  ) {
    if (
      typeof arg1 === "object" &&
      arg1 !== null &&
      !Array.isArray(arg1) &&
      typeof (arg1 as { evaluate?: unknown }).evaluate !== "function" &&
      !("api" in arg1) &&
      !("id" in arg1) &&
      typeof arg1 !== "function"
    ) {
      const opts = arg1 as OmpEvaluatorOptions;
      this.fallbackModel = opts.model ?? opts.fallbackModel;
      this.fallbackApiKey = opts.apiKey ?? opts.fallbackApiKey;
      this.fallbackSessionId = opts.sessionId ?? opts.fallbackSessionId;
      this.classifierTimeout = opts.classifierTimeout;
      this.getCtx = opts.getCtx;
      this.logger = opts.logger;
      this.evalLogFile = opts.evalLogFile;
    } else if (typeof arg1 === "function") {
      this.getCtx = arg1 as () => unknown;
      this.fallbackModel = arg2;
      if (typeof arg3 === "string") {
        this.fallbackApiKey = arg3;
      } else if (typeof arg3 === "number") {
        this.classifierTimeout = arg3;
      } else if (typeof arg3 === "object" && arg3 !== null) {
        const o = arg3 as OmpEvaluatorOptions;
        this.classifierTimeout = o.classifierTimeout ?? this.classifierTimeout;
        if (o.apiKey) this.fallbackApiKey = o.apiKey;
        if (o.logger) this.logger = o.logger;
      }
      if (typeof arg4 === "number") {
        this.classifierTimeout = arg4;
      } else if (typeof arg4 === "object" && arg4 !== null) {
        const o = arg4 as OmpEvaluatorOptions;
        this.classifierTimeout = o.classifierTimeout ?? this.classifierTimeout;
        if (o.logger) this.logger = o.logger;
        if (o.evalLogFile) this.evalLogFile = o.evalLogFile;
      }
    } else {
      this.fallbackModel = arg1;
      if (typeof arg2 === "string") {
        this.fallbackApiKey = arg2;
      } else if (typeof arg2 === "object" && arg2 !== null) {
        const o = arg2 as OmpEvaluatorOptions;
        this.classifierTimeout = o.classifierTimeout ?? this.classifierTimeout;
        if (o.apiKey) this.fallbackApiKey = o.apiKey;
        if (o.sessionId) this.fallbackSessionId = o.sessionId;
        if (o.logger) this.logger = o.logger;
        if (o.evalLogFile) this.evalLogFile = o.evalLogFile;
      }
      if (typeof arg3 === "string") {
        this.fallbackSessionId = arg3;
      } else if (typeof arg3 === "number") {
        this.classifierTimeout = arg3;
      } else if (typeof arg3 === "object" && arg3 !== null) {
        const o = arg3 as OmpEvaluatorOptions;
        this.classifierTimeout = o.classifierTimeout ?? this.classifierTimeout;
        if (o.logger) this.logger = o.logger;
        if (o.evalLogFile) this.evalLogFile = o.evalLogFile;
      }
      if (typeof arg4 === "number") {
        this.classifierTimeout = arg4;
      } else if (typeof arg4 === "object" && arg4 !== null) {
        const o = arg4 as OmpEvaluatorOptions;
        if (o.logger) this.logger = o.logger;
        if (o.evalLogFile) this.evalLogFile = o.evalLogFile;
      }
    }

    if (!this.logger) {
      this.logger = console;
    }
  }

  public setContext(ctx: OmpContext): void {
    this.currentCtx = ctx;
  }

  private async appendEvalLog(entry: Record<string, unknown>): Promise<void> {
    const targetFile =
      this.evalLogFile || path.join(os.homedir(), ".omp", "logs", "autogate-evals.jsonl");
    try {
      await fs.mkdir(path.dirname(targetFile), { recursive: true });
      await fs.appendFile(targetFile, JSON.stringify(entry) + "\n", "utf8");
    } catch {}
  }

  private log(level: "debug" | "info" | "warn" | "error", message: string, data?: unknown) {
    const logFn = this.logger?.[level] ?? console[level] ?? console.log;
    try {
      logFn.call(this.logger ?? console, message, data);
    } catch {}
  }

  async evaluate(action: GateAction): Promise<ClassifierResult> {
    const startTime = performance.now();
    const timeoutMs = this.classifierTimeout ?? 45000;
    const timeoutSignal = AbortSignal.timeout(timeoutMs);
    const combinedSignal = action.signal
      ? AbortSignal.any([action.signal, timeoutSignal])
      : timeoutSignal;

    let sessionId: string = String(action.sessionID);
    let lastResponse: unknown = null;
    let attempts = 0;
    let thinking: string | undefined = undefined;
    let reasoningTokens = 0;
    let model: unknown = this.fallbackModel;
    let ctx: OmpContext | null = null;
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

      ctx = (this.getCtx?.() || this.currentCtx) as OmpContext | null;
      try {
        const rawModels = ctx?.models as { resolve?(name: string): unknown } | undefined;
        if (typeof rawModels?.resolve === "function") {
          model = rawModels.resolve("@smol") || rawModels.resolve("default") || ctx?.model || model;
        } else if (ctx?.model) {
          model = ctx.model || model;
        }
      } catch {}

      sessionId =
        action.sessionID ||
        ctx?.sessionManager?.getSessionId?.() ||
        (typeof ctx?.sessionID === "string" ? ctx.sessionID : undefined) ||
        (typeof ctx?.sessionId === "string" ? ctx.sessionId : undefined) ||
        this.fallbackSessionId ||
        "";

      const modelObj = (model && typeof model === "object" ? model : {}) as Record<string, unknown>;

      this.log("debug", "[AutoGate OMP Evaluator] Evaluating action", {
        toolName: action.toolName,
        targetPath: action.targetPath,
        command: action.commandString,
        model: modelObj.id,
        provider: modelObj.provider,
        sessionId,
      });

      let apiKey = this.fallbackApiKey;
      try {
        const rawRegistry = ctx?.modelRegistry as
          | { getApiKey?(m: unknown, s?: string): Promise<string | undefined> }
          | undefined;
        if (typeof rawRegistry?.getApiKey === "function" && model) {
          const resolvedKey = await rawRegistry.getApiKey(model, sessionId);
          if (resolvedKey) apiKey = resolvedKey;
        } else if (typeof modelObj.apiKey === "string") {
          apiKey = modelObj.apiKey || apiKey;
        }
      } catch {}

      apiKey =
        apiKey ||
        process.env.GEMINI_API_KEY ||
        process.env.GOOGLE_API_KEY ||
        process.env.AUTOGATE_API_KEY;

      this.log("debug", "[AutoGate OMP Evaluator] Resolved API key", {
        provider: modelObj.provider,
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

      const messages: Parameters<typeof completeSimple>[1]["messages"] = [
        { role: "user", content: userPrompt, timestamp: Date.now() },
      ];
      const maxRetries = 2;
      let validResult: ClassifierResult | null = null;

      for (let attempt = 0; attempt <= maxRetries; attempt++) {
        const response = await completeSimple(
          model as Parameters<typeof completeSimple>[0],
          {
            systemPrompt: [systemPrompt],
            messages,
            tools: [
              CLASSIFY_RESULT_TOOL as unknown as NonNullable<
                Parameters<typeof completeSimple>[1]["tools"]
              >[number],
            ],
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
          ? response.content.find((item: unknown) => {
              if (!item || typeof item !== "object") return false;
              const c = item as unknown as Record<string, unknown>;
              const fn =
                c.function && typeof c.function === "object"
                  ? (c.function as Record<string, unknown>)
                  : undefined;
              return (
                c.type === "toolCall" &&
                (c.name === "classify_result" || fn?.name === "classify_result")
              );
            })
          : undefined;

        if (toolCall && typeof toolCall === "object") {
          const tc = toolCall as unknown as Record<string, unknown>;
          const fn =
            tc.function && typeof tc.function === "object"
              ? (tc.function as Record<string, unknown>)
              : undefined;
          let args: unknown = tc.arguments ?? fn?.arguments;
          if (typeof args === "string") {
            try {
              args = JSON.parse(args);
            } catch {
              args = null;
            }
          }

          if (args && typeof args === "object" && !Array.isArray(args)) {
            const argsObj = args as Record<string, unknown>;
            const verdictRaw = String(argsObj.verdict ?? "")
              .toUpperCase()
              .trim();
            const reason = typeof argsObj.reason === "string" ? argsObj.reason : undefined;
            const riskRaw = String(argsObj.risk_level ?? "")
              .toUpperCase()
              .trim();
            const authRaw = String(argsObj.user_authorization ?? "")
              .toUpperCase()
              .trim();
            const risk_level = isRiskLevel(riskRaw) ? riskRaw : undefined;
            const user_authorization = isUserAuthorization(authRaw) ? authRaw : undefined;

            if (isClassifierVerdict(verdictRaw)) {
              validResult = {
                verdict: verdictRaw,
                risk_level,
                user_authorization,
                reason: reason || "",
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
      const lastContent =
        lastResponse && typeof lastResponse === "object" && "content" in lastResponse
          ? (lastResponse as { content?: unknown[] }).content
          : undefined;
      const rawThinking = Array.isArray(lastContent)
        ? lastContent
            .filter((item: unknown) => {
              if (!item || typeof item !== "object") return false;
              const c = item as unknown as Record<string, unknown>;
              return c.type === "thinking" || c.type === "reasoning" || c.type === "reasoning_text";
            })
            .map((item: unknown) => {
              const c = item as unknown as Record<string, unknown>;
              const val = c.thinking ?? c.text ?? c.reasoning ?? c.reasoning_content;
              return typeof val === "string" ? val : "";
            })
            .filter(Boolean)
            .join("\n") || undefined
        : undefined;

      const lastObj = (
        lastResponse && typeof lastResponse === "object" ? lastResponse : {}
      ) as Record<string, unknown>;
      const usageObj = (
        lastObj.usage && typeof lastObj.usage === "object" ? lastObj.usage : {}
      ) as Record<string, unknown>;
      const rawRespObj = (
        lastObj.rawResponse && typeof lastObj.rawResponse === "object" ? lastObj.rawResponse : {}
      ) as Record<string, unknown>;
      const rawUsageObj = (
        rawRespObj.usage && typeof rawRespObj.usage === "object" ? rawRespObj.usage : {}
      ) as Record<string, unknown>;

      const thinking =
        rawThinking ||
        (typeof lastObj.reasoning_content === "string" ? lastObj.reasoning_content : undefined) ||
        (typeof lastObj.reasoning === "string" ? lastObj.reasoning : undefined) ||
        (typeof lastObj.reasoningContent === "string" ? lastObj.reasoningContent : undefined) ||
        (typeof lastObj.thinking === "string" ? lastObj.thinking : undefined);

      reasoningTokens =
        (typeof lastObj.reasoningTokens === "number" ? lastObj.reasoningTokens : undefined) ??
        (typeof lastObj.reasoning_tokens === "number" ? lastObj.reasoning_tokens : undefined) ??
        (typeof usageObj.reasoningTokens === "number" ? usageObj.reasoningTokens : undefined) ??
        (typeof usageObj.reasoning_tokens === "number" ? usageObj.reasoning_tokens : undefined) ??
        (typeof (usageObj.completionTokensDetails as { reasoningTokens?: number } | undefined)
          ?.reasoningTokens === "number"
          ? (usageObj.completionTokensDetails as { reasoningTokens: number }).reasoningTokens
          : undefined) ??
        (typeof rawUsageObj.reasoning_tokens === "number"
          ? rawUsageObj.reasoning_tokens
          : undefined) ??
        0;

      const respObj = (
        lastResponse && typeof lastResponse === "object" ? lastResponse : {}
      ) as Record<string, unknown>;
      const respUsage = (
        respObj.usage && typeof respObj.usage === "object" ? respObj.usage : {}
      ) as Record<string, unknown>;

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
            id: typeof modelObj.id === "string" ? modelObj.id : undefined,
            provider: typeof modelObj.provider === "string" ? modelObj.provider : undefined,
          },
          inference: {
            durationMs,
            promptTokens: typeof respUsage.input === "number" ? respUsage.input : undefined,
            outputTokens: typeof respUsage.output === "number" ? respUsage.output : undefined,
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
          id: typeof modelObj.id === "string" ? modelObj.id : undefined,
          provider: typeof modelObj.provider === "string" ? modelObj.provider : undefined,
        },
        inference: {
          durationMs,
          promptTokens: typeof respUsage.input === "number" ? respUsage.input : undefined,
          outputTokens: typeof respUsage.output === "number" ? respUsage.output : undefined,
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

      const modelObj = (model && typeof model === "object" ? model : {}) as Record<string, unknown>;

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
          id: typeof modelObj.id === "string" ? modelObj.id : undefined,
          provider: typeof modelObj.provider === "string" ? modelObj.provider : undefined,
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
