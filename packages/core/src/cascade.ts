import crypto from "node:crypto";
import type {
  CascadeTrace,
  ClassifierResult,
  ContextFingerprint,
  EnvironmentConfig,
  EscalationReason,
  GateAction,
  GateEvaluator,
  SystemOneConfig,
  SystemOneExecutionMode,
  SystemOneThresholds,
} from "./types.js";

export function computeContextFingerprint(
  userPrompt: string,
  environment?: EnvironmentConfig,
): ContextFingerprint {
  const canonical = JSON.stringify({
    userPrompt: userPrompt || "",
    trustedDomains: environment?.trustedDomains ?? [],
    trustedGitRemotes: environment?.trustedGitRemotes ?? [],
    trustedPaths: environment?.trustedPaths ?? [],
  });
  return crypto.createHash("sha256").update(canonical).digest("hex") as ContextFingerprint;
}

export type SystemOneOutcome =
  | {
      readonly ok: true;
      readonly allowProb: number;
      readonly blockProb: number;
      readonly inScopeScore: number;
      readonly injectionScore: number;
      readonly latencyMs: number;
      readonly fingerprint: ContextFingerprint;
      readonly truncatedPayload?: boolean;
    }
  | {
      readonly ok: false;
      readonly reason: "s1_error" | "s1_timeout" | "s1_invalid_output" | "s1_circuit_open";
      readonly message: string;
      readonly latencyMs: number;
      readonly isTransportError: boolean;
    };

export interface SystemOneRawEvaluator {
  evaluateRaw(
    action: GateAction,
    options?: { signal?: AbortSignal; fingerprint?: ContextFingerprint },
  ): Promise<SystemOneOutcome>;
}

export type CascadePolicyDecision =
  | {
      readonly kind: "accept";
      readonly result: ClassifierResult;
    }
  | {
      readonly kind: "escalate";
      readonly reason: EscalationReason;
      readonly trace: CascadeTrace;
    };

function isUnitProbability(val: number): boolean {
  return typeof val === "number" && Number.isFinite(val) && val >= 0 && val <= 1;
}

export function evaluateCascadePolicy(
  s1Outcome: SystemOneOutcome,
  thresholds: SystemOneThresholds,
  options?: {
    mode?: SystemOneExecutionMode;
    currentFingerprint?: ContextFingerprint;
  },
): CascadePolicyDecision {
  const mode: SystemOneExecutionMode = options?.mode ?? "race";

  if (!s1Outcome.ok) {
    return {
      kind: "escalate",
      reason: s1Outcome.reason,
      trace: {
        mode,
        winner: "system2",
        escalationReason: s1Outcome.reason,
        s1LatencyMs: s1Outcome.latencyMs,
      },
    };
  }

  const {
    allowProb,
    blockProb,
    inScopeScore,
    injectionScore,
    latencyMs,
    fingerprint,
    truncatedPayload,
  } = s1Outcome;

  if (truncatedPayload) {
    return {
      kind: "escalate",
      reason: "out_of_scope",
      trace: {
        mode,
        winner: "system2",
        escalationReason: "out_of_scope",
        s1LatencyMs: latencyMs,
      },
    };
  }

  if (
    !isUnitProbability(allowProb) ||
    !isUnitProbability(blockProb) ||
    !isUnitProbability(inScopeScore) ||
    !isUnitProbability(injectionScore)
  ) {
    return {
      kind: "escalate",
      reason: "s1_invalid_output",
      trace: {
        mode,
        winner: "system2",
        escalationReason: "s1_invalid_output",
        s1LatencyMs: latencyMs,
      },
    };
  }

  const s1Probs: Readonly<Record<string, number>> = {
    ALLOW: allowProb,
    BLOCK: blockProb,
  };

  if (options?.currentFingerprint && options.currentFingerprint !== fingerprint) {
    return {
      kind: "escalate",
      reason: "context_drifted",
      trace: {
        mode,
        winner: "system2",
        escalationReason: "context_drifted",
        s1LatencyMs: latencyMs,
        s1Probs,
        inScopeScore,
        injectionScore,
      },
    };
  }

  if (injectionScore >= thresholds.maxInjectionNoul) {
    return {
      kind: "escalate",
      reason: "injection_flagged",
      trace: {
        mode,
        winner: "system2",
        escalationReason: "injection_flagged",
        s1LatencyMs: latencyMs,
        s1Probs,
        inScopeScore,
        injectionScore,
      },
    };
  }

  if (inScopeScore < thresholds.minInScopeNoul) {
    return {
      kind: "escalate",
      reason: "out_of_scope",
      trace: {
        mode,
        winner: "system2",
        escalationReason: "out_of_scope",
        s1LatencyMs: latencyMs,
        s1Probs,
        inScopeScore,
        injectionScore,
      },
    };
  }

  if (allowProb >= blockProb) {
    if (allowProb < thresholds.allowMinProb) {
      return {
        kind: "escalate",
        reason: "low_allow_prob",
        trace: {
          mode,
          winner: "system2",
          escalationReason: "low_allow_prob",
          s1LatencyMs: latencyMs,
          s1Probs,
          inScopeScore,
          injectionScore,
        },
      };
    }

    const oddsRatio = blockProb > 0 ? allowProb / blockProb : Number.POSITIVE_INFINITY;
    if (oddsRatio < thresholds.minOddsRatio) {
      return {
        kind: "escalate",
        reason: "low_odds_ratio",
        trace: {
          mode,
          winner: "system2",
          escalationReason: "low_odds_ratio",
          s1LatencyMs: latencyMs,
          s1Probs,
          inScopeScore,
          injectionScore,
        },
      };
    }

    return {
      kind: "accept",
      result: {
        verdict: "ALLOW",
        risk_level: "LOW",
        user_authorization: "HIGH",
        reason: `System 1 ALLOW (p=${allowProb.toFixed(3)}, in_scope=${inScopeScore.toFixed(2)}, inj=${injectionScore.toFixed(2)})`,
        cascade: {
          mode,
          winner: "system1",
          s1LatencyMs: latencyMs,
          s1Probs,
          inScopeScore,
          injectionScore,
        },
      },
    };
  }

  if (blockProb < thresholds.blockMinProb) {
    return {
      kind: "escalate",
      reason: "low_block_prob",
      trace: {
        mode,
        winner: "system2",
        escalationReason: "low_block_prob",
        s1LatencyMs: latencyMs,
        s1Probs,
        inScopeScore,
        injectionScore,
      },
    };
  }

  const oddsRatio = allowProb > 0 ? blockProb / allowProb : Number.POSITIVE_INFINITY;
  if (oddsRatio < thresholds.minOddsRatio) {
    return {
      kind: "escalate",
      reason: "low_odds_ratio",
      trace: {
        mode,
        winner: "system2",
        escalationReason: "low_odds_ratio",
        s1LatencyMs: latencyMs,
        s1Probs,
        inScopeScore,
        injectionScore,
      },
    };
  }

  return {
    kind: "accept",
    result: {
      verdict: "BLOCK",
      risk_level: "CRITICAL",
      user_authorization: "NONE",
      reason: `System 1 BLOCK (p=${blockProb.toFixed(3)}, in_scope=${inScopeScore.toFixed(2)}, inj=${injectionScore.toFixed(2)})`,
      cascade: {
        mode,
        winner: "system1",
        s1LatencyMs: latencyMs,
        s1Probs,
        inScopeScore,
        injectionScore,
      },
    },
  };
}

export interface CascadeEvaluatorOptions {
  readonly systemOne: SystemOneRawEvaluator;
  readonly system2: GateEvaluator;
  readonly config: SystemOneConfig;
  readonly circuitFailureThreshold?: number;
  readonly circuitCooldownMs?: number;
  readonly now?: () => number;
  readonly getContextFingerprint?: (action: GateAction) => ContextFingerprint;
  readonly refreshAction?: (action: GateAction) => GateAction;
}

export class CascadeEvaluator implements GateEvaluator {
  readonly name = "cascade-evaluator";

  private readonly systemOne: SystemOneRawEvaluator;
  private readonly system2: GateEvaluator;
  private readonly config: SystemOneConfig;
  private readonly circuitFailureThreshold: number;
  private readonly circuitCooldownMs: number;
  private readonly now: () => number;
  private readonly getContextFingerprint?: (action: GateAction) => ContextFingerprint;
  private readonly refreshAction?: (action: GateAction) => GateAction;

  private consecutiveTransportFailures = 0;
  private circuitOpenUntilMs = 0;

  constructor(options: CascadeEvaluatorOptions) {
    this.systemOne = options.systemOne;
    this.system2 = options.system2;
    this.config = options.config;
    this.circuitFailureThreshold = options.circuitFailureThreshold ?? 3;
    this.circuitCooldownMs = options.circuitCooldownMs ?? 30000;
    this.now = options.now ?? (() => Date.now());
    this.getContextFingerprint = options.getContextFingerprint;
    this.refreshAction = options.refreshAction;
  }

  public getCircuitState(): { consecutiveFailures: number; isOpen: boolean; openUntilMs: number } {
    const nowMs = this.now();
    return {
      consecutiveFailures: this.consecutiveTransportFailures,
      isOpen: nowMs < this.circuitOpenUntilMs,
      openUntilMs: this.circuitOpenUntilMs,
    };
  }

  public resetCircuit(): void {
    this.consecutiveTransportFailures = 0;
    this.circuitOpenUntilMs = 0;
  }

  private recordS1Outcome(outcome: SystemOneOutcome): void {
    if (outcome.ok || (!outcome.isTransportError && outcome.reason === "s1_invalid_output")) {
      this.consecutiveTransportFailures = 0;
      this.circuitOpenUntilMs = 0;
      return;
    }

    if (outcome.isTransportError) {
      this.consecutiveTransportFailures++;
      if (this.consecutiveTransportFailures >= this.circuitFailureThreshold) {
        this.circuitOpenUntilMs = this.now() + this.circuitCooldownMs;
      }
    }
  }

  private snapshotFingerprint(action: GateAction): ContextFingerprint {
    return this.getContextFingerprint
      ? this.getContextFingerprint(action)
      : computeContextFingerprint(action.userPrompt, action.environment);
  }

  private async runSystem2(
    action: GateAction,
    runtimeOptions?: Record<string, unknown>,
  ): Promise<{ result: ClassifierResult; latencyMs: number }> {
    const t0 = performance.now();
    try {
      const result = await this.system2.evaluate(action, runtimeOptions);
      return {
        result,
        latencyMs: Math.round(performance.now() - t0),
      };
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        result: {
          verdict: "UNSURE",
          reason: `System 2 evaluator error: ${message}`,
        },
        latencyMs: Math.round(performance.now() - t0),
      };
    }
  }

  private withCascadeTrace(result: ClassifierResult, cascade: CascadeTrace): ClassifierResult {
    return {
      ...result,
      cascade,
    };
  }

  async evaluate(
    action: GateAction,
    runtimeOptions?: Record<string, unknown>,
  ): Promise<ClassifierResult> {
    const mode = this.config.executionMode;

    if (action.signal?.aborted) {
      return {
        verdict: "UNSURE",
        reason: "Cascade evaluation aborted by signal",
      };
    }

    // S1 outage bypass: if consecutive S1 transport failures tripped the circuit, run S2 directly
    if (this.now() < this.circuitOpenUntilMs) {
      const s2 = await this.runSystem2(action, runtimeOptions);
      return this.withCascadeTrace(s2.result, {
        mode,
        winner: "system2",
        escalationReason: "s1_circuit_open",
        s2LatencyMs: s2.latencyMs,
        s2Aborted: false,
      });
    }

    const startFingerprint = this.snapshotFingerprint(action);

    if (mode === "cascade") {
      const s1Outcome = await this.systemOne.evaluateRaw(action, {
        signal: action.signal,
        fingerprint: startFingerprint,
      });
      this.recordS1Outcome(s1Outcome);

      if (action.signal?.aborted) {
        return {
          verdict: "UNSURE",
          reason: "Cascade evaluation aborted by signal",
        };
      }

      const currentFingerprint = this.snapshotFingerprint(action);
      const policy = evaluateCascadePolicy(s1Outcome, this.config.thresholds, {
        mode: "cascade",
        currentFingerprint,
      });

      if (policy.kind === "accept") {
        return this.withCascadeTrace(policy.result, {
          ...policy.result.cascade!,
          s2Aborted: false,
        });
      }

      const s2Action =
        policy.reason === "context_drifted" && this.refreshAction
          ? this.refreshAction(action)
          : action;
      const s2 = await this.runSystem2(s2Action, runtimeOptions);
      return this.withCascadeTrace(s2.result, {
        ...policy.trace,
        s2LatencyMs: s2.latencyMs,
        s2Aborted: false,
      });
    }

    // Concurrent race mode
    const s1Controller = new AbortController();
    const s2Controller = new AbortController();

    const onParentAbort = () => {
      const reason = action.signal?.reason || new Error("Action evaluation aborted");
      s1Controller.abort(reason);
      s2Controller.abort(reason);
    };

    if (action.signal) {
      if (action.signal.aborted) {
        onParentAbort();
      } else {
        action.signal.addEventListener("abort", onParentAbort, { once: true });
      }
    }

    const s2Action: GateAction = {
      ...action,
      signal: s2Controller.signal,
    };

    const s1Promise = this.systemOne
      .evaluateRaw(action, {
        signal: s1Controller.signal,
        fingerprint: startFingerprint,
      })
      .catch((err: unknown): SystemOneOutcome => ({
        ok: false,
        reason: "s1_error",
        message: err instanceof Error ? err.message : String(err),
        latencyMs: 0,
        isTransportError: true,
      }));

    const s2Promise = this.runSystem2(s2Action, runtimeOptions);
    // Ensure background loser rejection cannot surface as unhandled
    s1Promise.catch(() => {});
    s2Promise.catch(() => {});

    type RaceWinner =
      | { readonly who: "s1"; readonly outcome: SystemOneOutcome }
      | { readonly who: "s2"; readonly outcome: { result: ClassifierResult; latencyMs: number } };

    try {
      const first = await Promise.race<RaceWinner>([
        s1Promise.then((outcome) => ({ who: "s1" as const, outcome })),
        s2Promise.then((outcome) => ({ who: "s2" as const, outcome })),
      ]);

      if (first.who === "s1") {
        this.recordS1Outcome(first.outcome);
        const currentFingerprint = this.snapshotFingerprint(action);
        const policy = evaluateCascadePolicy(first.outcome, this.config.thresholds, {
          mode: "race",
          currentFingerprint,
        });

        if (policy.kind === "accept") {
          s2Controller.abort("system1-won-race");
          return this.withCascadeTrace(policy.result, {
            ...policy.result.cascade!,
            s2Aborted: true,
          });
        }

        if (policy.reason === "context_drifted") {
          s2Controller.abort("context-drifted");
          const refreshed = this.refreshAction ? this.refreshAction(action) : action;
          const s2Res = await this.runSystem2(
            { ...refreshed, signal: action.signal },
            runtimeOptions,
          );
          return this.withCascadeTrace(s2Res.result, {
            ...policy.trace,
            s2LatencyMs: s2Res.latencyMs,
            s2Aborted: true,
          });
        }

        // Escalate: await the already-in-flight System 2 evaluation
        const s2Res = await s2Promise;
        return this.withCascadeTrace(s2Res.result, {
          ...policy.trace,
          s2LatencyMs: s2Res.latencyMs,
          s2Aborted: false,
        });
      }

      // System 2 finished before System 1: abort System 1 cleanly
      s1Controller.abort("system2-finished-first");
      return this.withCascadeTrace(first.outcome.result, {
        mode: "race",
        winner: "system2",
        escalationReason: "s2_finished_first",
        s2LatencyMs: first.outcome.latencyMs,
        s2Aborted: false,
      });
    } finally {
      if (action.signal) {
        action.signal.removeEventListener("abort", onParentAbort);
      }
    }
  }
}
