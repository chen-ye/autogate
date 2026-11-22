import fs from "fs";
import type { GateEvaluator, GateAction, ClassifierResult, AutoGateConfig } from "@autogate/core";
import {
  CLASSIFIER_JSON_SCHEMA,
  buildClassifierSystemPrompt,
  buildClassifierUserPrompt,
  parseVerdict,
  resolveClassifierActionArgs,
} from "@autogate/core";
import type { PaseoClient, PaseoAgentInstance } from "./types.js";

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
function extractCandidateText(finishResult: unknown): string {
  if (!finishResult) return "";
  if (typeof finishResult === "string") return finishResult;

  const res = finishResult as Record<string, unknown>;
  if (typeof res.lastMessage === "string") {
    return res.lastMessage;
  }
  if (res.lastMessage && typeof res.lastMessage === "object") {
    const lm = res.lastMessage as Record<string, unknown>;
    if (typeof lm.text === "string") {
      return lm.text;
    }
    if (typeof lm.content === "string") {
      return lm.content;
    }
    return JSON.stringify(res.lastMessage);
  }

  const finalObj =
    res.final && typeof res.final === "object" ? (res.final as Record<string, unknown>) : undefined;
  if (typeof finalObj?.lastMessage === "string") {
    return finalObj.lastMessage;
  }
  if (typeof res.text === "string") {
    return res.text;
  }
  if (typeof res.content === "string") {
    return res.content;
  }

  return "";
}

function cancelEvalAgent(agent: PaseoAgentInstance | undefined): void {
  if (!agent) return;
  try {
    if (typeof agent.abort === "function") {
      Promise.resolve(agent.abort()).catch(() => {});
    } else if (typeof agent.stop === "function") {
      Promise.resolve(agent.stop()).catch(() => {});
    } else if (typeof agent.cancel === "function") {
      Promise.resolve(agent.cancel()).catch(() => {});
    }
  } catch {}
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
    private paseoSource:
      | PaseoClient
      | (() => PaseoClient | undefined | Promise<PaseoClient | undefined>)
      | { getPaseo?(): PaseoClient | Promise<PaseoClient> },
    private options?: PaseoNativeEvaluatorOptions,
  ) {}

  private async resolvePaseo(): Promise<PaseoClient | undefined> {
    if (typeof this.paseoSource === "function") {
      return await this.paseoSource();
    }
    if (
      this.paseoSource &&
      typeof (this.paseoSource as { getPaseo?: unknown }).getPaseo === "function"
    ) {
      return await (
        this.paseoSource as { getPaseo(): PaseoClient | Promise<PaseoClient> }
      ).getPaseo();
    }
    return this.paseoSource as PaseoClient | undefined;
  }

  private async resolveProvider(
    paseo?: PaseoClient,
    runtimeOptions?: Record<string, unknown>,
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
        const mp = metaProvider as Record<string, unknown>;
        const str = mp.provider || mp.id || mp.name;
        if (typeof str === "string" && str.trim()) {
          const model = mp.model;
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
        const cfg = (res?.config ?? res) as Record<string, unknown> | undefined;
        const mg = cfg?.metadataGeneration as Record<string, unknown> | undefined;
        const providers = Array.isArray(mg?.providers) ? mg.providers : undefined;
        const cfgMeta = providers?.[0];
        if (cfgMeta) {
          if (typeof cfgMeta === "string" && cfgMeta.trim()) {
            return cfgMeta.trim();
          }
          if (typeof cfgMeta === "object" && cfgMeta !== null) {
            const cm = cfgMeta as Record<string, unknown>;
            const str = cm.provider || cm.id || cm.name;
            if (typeof str === "string" && str.trim()) {
              const model = cm.model;
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
    runtimeOptions?: Record<string, unknown>,
  ): Promise<ClassifierResult> {
    const fallback =
      (runtimeOptions?.fallbackEvaluator as GateEvaluator | undefined) ??
      this.options?.fallbackEvaluator;

    let evalAgentId: string | undefined;

    if (action.signal?.aborted) {
      return {
        verdict: "UNSURE",
        reason: "PaseoNativeEvaluator error: Action evaluation aborted by signal",
      };
    }

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
      if (action.signal?.aborted) {
        return {
          verdict: "UNSURE",
          reason: "PaseoNativeEvaluator error: Action evaluation aborted by signal",
        };
      }
      const cwd = ensureEvaluationDirectory(this.options?.cwd || DEFAULT_EVAL_CWD);

      const userPromptText = buildClassifierUserPrompt({
        userPrompt: action.userPrompt,
        subagentPrompt: action.subagentPrompt,
        actionName: action.toolName,
        actionArgs: resolveClassifierActionArgs(action),
        workspaceRoot: action.workspaceRoot,
        environment: action.environment,
      });

      const createOptions: Record<string, unknown> = {
        cwd,
        parent: undefined,
        title: `[auto-gate-eval] ${action.toolName || "permission"}`,
        config: {
          provider: resolvedProvider,
          systemPrompt: buildClassifierSystemPrompt(),
          internal: true,
          modeId: "ask",
        },
        prompt: userPromptText,
        outputSchema: CLASSIFIER_JSON_SCHEMA,
        autoArchive: true,
        notifyOnFinish: false,
        labels: {
          "autogate.role": "evaluator",
          "autogate.targetAgentId":
            (action as unknown as { sessionId?: string }).sessionId || action.sessionID || "",
        },
      };

      let evalAgent: PaseoAgentInstance | undefined;
      try {
        if (!paseo?.agents?.create) {
          throw new Error("Paseo agents.create API not available");
        }
        evalAgent = await paseo.agents.create(createOptions);
        console.log("[AutoGate Native] created evalAgent:", evalAgent?.id);
      } catch (createErr: unknown) {
        const errObj = createErr as { message?: string } | undefined;
        console.error("[AutoGate Native] createAgent error:", errObj?.message || createErr);
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
      let timeoutId: ReturnType<typeof setTimeout> | undefined;

      const onActionAbort = () => {
        cancelEvalAgent(evalAgent);
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
        cancelEvalAgent(evalAgent);
        controller.abort(new Error(`Classifier evaluation timed out after ${timeoutMs}ms`));
      }, timeoutMs);

      let finishResult: unknown;
      try {
        const timeoutOrAbortPromise = new Promise<never>((_, reject) => {
          if (controller.signal.aborted) {
            reject(
              controller.signal.reason ||
                new Error(`Classifier evaluation timed out after ${timeoutMs}ms`),
            );
            return;
          }
          controller.signal.addEventListener(
            "abort",
            () => {
              reject(
                controller.signal.reason ||
                  new Error(`Classifier evaluation timed out after ${timeoutMs}ms`),
              );
            },
            { once: true },
          );
        });

        const finishPromise = Promise.resolve().then(() => {
          if (evalAgent && typeof evalAgent.waitForFinish === "function") {
            return evalAgent.waitForFinish({ timeoutMs });
          }
          return undefined;
        });
        finishResult = await Promise.race([finishPromise, timeoutOrAbortPromise]);
      } finally {
        clearTimeout(timeoutId);
        if (action.signal) {
          try {
            action.signal.removeEventListener("abort", onActionAbort);
          } catch {}
        }
      }

      const res = finishResult as Record<string, unknown> | undefined;
      if (res?.status === "timeout") {
        return {
          verdict: "UNSURE",
          reason: `PaseoNativeEvaluator error: Classifier evaluation timed out after ${timeoutMs}ms`,
          ...(evalAgentId ? { metadata: { evalAgentId } } : {}),
        };
      }

      if (res?.status === "error" && res?.error && !res?.lastMessage) {
        return {
          verdict: "UNSURE",
          reason: `PaseoNativeEvaluator error: ${res.error}`,
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
