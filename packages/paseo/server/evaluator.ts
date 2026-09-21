import fs from "fs";
import type {
  GateEvaluator,
  GateAction,
  ClassifierResult,
  AutoGateConfig,
} from "@autogate/core";
import {
  CLASSIFIER_JSON_SCHEMA,
  buildClassifierSystemPrompt,
  buildClassifierUserPrompt,
  parseVerdict,
} from "@autogate/core";

export const DEFAULT_EVAL_CWD = "/tmp/autogate-eval";
export const DEFAULT_TIMEOUT_MS = 45000;

/**
 * Ensures that the isolated sandbox directory for evaluation agents exists.
 */
export function ensureEvaluationDirectory(dir: string = DEFAULT_EVAL_CWD): string {
  try {
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    return dir;
  } catch {
    return "/tmp";
  }
}

/**
 * Options for configuring PaseoNativeEvaluator.
 */
export interface PaseoNativeEvaluatorOptions {
  /**
   * Overrides the provider string passed to paseo.agents.create()
   */
  provider?: string;
  /**
   * Alias for provider
   */
  evaluatorProvider?: string;
  /**
   * Timeout in milliseconds for evaluation completion. Defaults to 45000ms.
   */
  classifierTimeout?: number;
  /**
   * Alias for classifierTimeout
   */
  timeoutMs?: number;
  /**
   * Optional fallback evaluator when Paseo agent creation fails or is unsupported.
   */
  fallbackEvaluator?: GateEvaluator;
  /**
   * Sandbox working directory for the evaluation agent. Defaults to /tmp/autogate-eval.
   */
  cwd?: string;
  /**
   * Global AutoGateConfig for extracting timeouts or provider overrides.
   */
  config?: AutoGateConfig;
  [key: string]: unknown;
}

/**
 * Helper to safely extract candidate output text from various Paseo agent completion structures.
 */
function extractCandidateText(finishResult: any): string {
  if (!finishResult) return "";
  if (typeof finishResult === "string") return finishResult;

  if (typeof finishResult.lastMessage === "string") {
    return finishResult.lastMessage;
  }
  if (finishResult.lastMessage && typeof finishResult.lastMessage === "object") {
    if (typeof finishResult.lastMessage.text === "string") {
      return finishResult.lastMessage.text;
    }
    if (typeof finishResult.lastMessage.content === "string") {
      return finishResult.lastMessage.content;
    }
    return JSON.stringify(finishResult.lastMessage);
  }

  if (typeof finishResult.final?.lastMessage === "string") {
    return finishResult.final.lastMessage;
  }
  if (typeof finishResult.text === "string") {
    return finishResult.text;
  }
  if (typeof finishResult.content === "string") {
    return finishResult.content;
  }

  return "";
}

/**
 * Native Paseo Security Evaluator.
 *
 * Evaluates gate actions by spawning an ephemeral, completely isolated agent
 * inside Paseo. Guarantees:
 * 1. Zero parentage: `parent: undefined` (strictly prevents message leaks or turn interruption).
 * 2. Pure reasoning: `toolPolicy: { tools: {} }` (no tool calls or bash execution permitted).
 * 3. Soft archive: `autoArchive: true` and `notifyOnFinish: false`.
 */
export class PaseoNativeEvaluator implements GateEvaluator {
  readonly name = "paseo-native-evaluator";

  constructor(
    private paseoSource: any | (() => any),
    private options?: PaseoNativeEvaluatorOptions
  ) {}

  private async resolvePaseo(): Promise<any> {
    if (typeof this.paseoSource === "function") {
      return await this.paseoSource();
    }
    if (this.paseoSource && typeof this.paseoSource.getPaseo === "function") {
      return await this.paseoSource.getPaseo();
    }
    return this.paseoSource;
  }

  private async resolveProvider(
    paseo: any,
    runtimeOptions?: Record<string, unknown>
  ): Promise<string> {
    const explicitProvider =
      (runtimeOptions?.provider as string) ||
      (runtimeOptions?.evaluatorProvider as string) ||
      this.options?.provider ||
      this.options?.evaluatorProvider ||
      this.options?.config?.paseo?.evaluatorProvider;

    if (explicitProvider && typeof explicitProvider === "string" && explicitProvider.trim()) {
      return explicitProvider.trim();
    }

    // Check daemon metadata provider
    const metaProvider =
      paseo?.metadataGeneration?.providers?.[0] ||
      paseo?.daemonConfig?.metadataGeneration?.providers?.[0] ||
      paseo?.config?.metadataGeneration?.providers?.[0];

    if (metaProvider) {
      if (typeof metaProvider === "string" && metaProvider.trim()) {
        return metaProvider.trim();
      }
      if (typeof metaProvider === "object" && metaProvider !== null) {
        const str = metaProvider.provider || metaProvider.id || metaProvider.name;
        if (typeof str === "string" && str.trim()) {
          const model = metaProvider.model;
          if (model && typeof model === "string" && model.trim()) {
            return `${str.trim()}/${model.trim()}`;
          }
          return str.trim();
        }
      }
    }

    if (typeof paseo?.config?.get === "function") {
      try {
        const res = await paseo.config.get();
        const cfg = res?.config ?? res;
        const cfgMeta = cfg?.metadataGeneration?.providers?.[0];
        if (cfgMeta) {
          if (typeof cfgMeta === "string" && cfgMeta.trim()) {
            return cfgMeta.trim();
          }
          if (typeof cfgMeta === "object" && cfgMeta !== null) {
            const str = cfgMeta.provider || cfgMeta.id || cfgMeta.name;
            if (typeof str === "string" && str.trim()) {
              const model = cfgMeta.model;
              if (model && typeof model === "string" && model.trim()) {
                return `${str.trim()}/${model.trim()}`;
              }
              return str.trim();
            }
          }
        }
      } catch {}
    }

    return "omp";
  }

  async evaluate(
    action: GateAction,
    runtimeOptions?: Record<string, unknown>
  ): Promise<ClassifierResult> {
    const fallback =
      (runtimeOptions?.fallbackEvaluator as GateEvaluator | undefined) ??
      this.options?.fallbackEvaluator;

    let evalAgentId: string | undefined;

    try {
      const paseo = await this.resolvePaseo();
      console.log("[AutoGate Native] resolvePaseo found:", Boolean(paseo?.agents?.create));

      if (!paseo?.agents || typeof paseo.agents.create !== "function") {
        if (fallback && typeof fallback.evaluate === "function") {
          return await fallback.evaluate(action, runtimeOptions);
        }
        return {
          verdict: "UNSURE",
          reason: "PaseoNativeEvaluator error: Paseo SDK agents.create is not available",
        };
      }

      const resolvedProvider = await this.resolveProvider(paseo, runtimeOptions);
      const cwd = ensureEvaluationDirectory(this.options?.cwd || DEFAULT_EVAL_CWD);

      const userPromptText = buildClassifierUserPrompt({
        userPrompt: action.userPrompt,
        subagentPrompt: action.subagentPrompt,
        actionName: action.toolName,
        actionArgs: action.rawArgs ?? action.metadata ?? action.commandString,
        workspaceRoot: action.workspaceRoot,
        environment: action.environment,
      });

      const createOptions: any = {
        cwd,
        parent: undefined,
        title: `[auto-gate-eval] ${action.toolName || "permission"}`,
        config: {
          provider: resolvedProvider,
          systemPrompt: buildClassifierSystemPrompt(),
          internal: true,
        },
        prompt: userPromptText,
        outputSchema: CLASSIFIER_JSON_SCHEMA,
        autoArchive: true,
        notifyOnFinish: false,
        labels: {
          "autogate.role": "evaluator",
          "autogate.targetAgentId": (action as any).sessionId || action.sessionID || "",
        },
      };

      let evalAgent: any;
      try {
        evalAgent = await paseo.agents.create(createOptions);
        console.log("[AutoGate Native] created evalAgent:", evalAgent?.id);
      } catch (createErr: any) {
        console.error("[AutoGate Native] createAgent error:", createErr?.message || createErr);
        if (fallback && typeof fallback.evaluate === "function") {
          return await fallback.evaluate(action, runtimeOptions);
        }
        const msg = createErr instanceof Error ? createErr.message : String(createErr);
        return {
          verdict: "UNSURE",
          reason: `PaseoNativeEvaluator error: Failed to create evaluation agent: ${msg}`,
        };
      }

      evalAgentId = evalAgent?.id;

      if (!evalAgent || typeof evalAgent.waitForFinish !== "function") {
        if (fallback && typeof fallback.evaluate === "function") {
          return await fallback.evaluate(action, runtimeOptions);
        }
        return {
          verdict: "UNSURE",
          reason: "PaseoNativeEvaluator error: Evaluation agent missing waitForFinish method",
          ...(evalAgentId ? { metadata: { evalAgentId } } : {}),
        };
      }

      const timeoutMs =
        (runtimeOptions?.classifierTimeout as number) ??
        (runtimeOptions?.timeoutMs as number) ??
        this.options?.classifierTimeout ??
        this.options?.timeoutMs ??
        this.options?.config?.classifierTimeout ??
        DEFAULT_TIMEOUT_MS;

      const controller = new AbortController();
      let timeoutId: any;

      const onActionAbort = () => {
        controller.abort(action.signal?.reason || new Error("Action evaluation aborted"));
      };

      if (action.signal) {
        if (action.signal.aborted) {
          onActionAbort();
        } else {
          action.signal.addEventListener("abort", onActionAbort, { once: true });
        }
      }

      timeoutId = setTimeout(() => {
        controller.abort(new Error(`Classifier evaluation timed out after ${timeoutMs}ms`));
      }, timeoutMs);

      let finishResult: any;
      try {
        const timeoutOrAbortPromise = new Promise<never>((_, reject) => {
          if (controller.signal.aborted) {
            reject(controller.signal.reason || new Error(`Classifier evaluation timed out after ${timeoutMs}ms`));
            return;
          }
          controller.signal.addEventListener(
            "abort",
            () => {
              reject(controller.signal.reason || new Error(`Classifier evaluation timed out after ${timeoutMs}ms`));
            },
            { once: true }
          );
        });

        const finishPromise = Promise.resolve().then(() => evalAgent.waitForFinish({ timeoutMs }));
        finishResult = await Promise.race([finishPromise, timeoutOrAbortPromise]);
      } finally {
        clearTimeout(timeoutId);
        if (action.signal) {
          try {
            action.signal.removeEventListener("abort", onActionAbort);
          } catch {}
        }
      }

      if (finishResult?.status === "timeout") {
        return {
          verdict: "UNSURE",
          reason: `PaseoNativeEvaluator error: Classifier evaluation timed out after ${timeoutMs}ms`,
          ...(evalAgentId ? { metadata: { evalAgentId } } : {}),
        };
      }

      if (finishResult?.status === "error" && finishResult?.error && !finishResult?.lastMessage) {
        return {
          verdict: "UNSURE",
          reason: `PaseoNativeEvaluator error: ${finishResult.error}`,
          ...(evalAgentId ? { metadata: { evalAgentId } } : {}),
        };
      }

      const candidateText = extractCandidateText(finishResult);
      const parsed = parseVerdict(candidateText);

      const result: ClassifierResult & { metadata?: Record<string, unknown> } = {
        verdict: parsed.verdict,
        risk_level: parsed.risk_level,
        user_authorization: parsed.user_authorization,
        reason: parsed.reason,
      };

      if (evalAgentId) {
        result.metadata = { evalAgentId };
      }

      return result;
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        verdict: "UNSURE",
        reason: `PaseoNativeEvaluator error: ${message}`,
        ...(evalAgentId ? { metadata: { evalAgentId } } : {}),
      };
    }
  }
}
