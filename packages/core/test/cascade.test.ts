import { describe, it, expect } from "bun:test";
import {
  CascadeEvaluator,
  computeContextFingerprint,
  evaluateCascadePolicy,
  type SystemOneOutcome,
  type SystemOneRawEvaluator,
} from "../src/cascade.js";
import { AutoGateCoreEngine } from "../src/engine.js";
import { DEFAULT_SYSTEM_ONE_THRESHOLDS } from "../src/config.js";
import type {
  ClassifierResult,
  GateAction,
  GateEvaluator,
  NotifierAdapter,
  ReviewRequest,
  ReviewResponse,
  SystemOneConfig,
} from "../src/types.js";

function makeAction(overrides?: Partial<GateAction>): GateAction {
  return {
    id: "act-cascade-1",
    harness: "opencode",
    sessionID: "ses-cascade",
    toolName: "bash",
    commandString: "git status",
    workspaceRoot: "/tmp",
    userPrompt: "Check git status",
    ...overrides,
  };
}

function makeConfig(overrides?: Partial<SystemOneConfig>): SystemOneConfig {
  return {
    enabled: true,
    executionMode: "race",
    endpoint: "http://127.0.0.1:4006/v1/systemone",
    model: "gemini-decision-1",
    timeoutMs: 4000,
    thresholds: DEFAULT_SYSTEM_ONE_THRESHOLDS,
    ...overrides,
  };
}

describe("evaluateCascadePolicy (pure)", () => {
  const fp = computeContextFingerprint("Check git status");

  it("accepts confident ALLOW and BLOCK", () => {
    const allowRes = evaluateCascadePolicy(
      {
        ok: true,
        allowProb: 0.96,
        blockProb: 0.04,
        inScopeScore: 0.9,
        injectionScore: 0.05,
        latencyMs: 35,
        fingerprint: fp,
      },
      DEFAULT_SYSTEM_ONE_THRESHOLDS,
      { mode: "race", currentFingerprint: fp },
    );
    expect(allowRes.kind).toBe("accept");
    if (allowRes.kind === "accept") {
      expect(allowRes.result.verdict).toBe("ALLOW");
      expect(allowRes.result.cascade?.winner).toBe("system1");
    }

    const blockRes = evaluateCascadePolicy(
      {
        ok: true,
        allowProb: 0.05,
        blockProb: 0.95,
        inScopeScore: 0.9,
        injectionScore: 0.05,
        latencyMs: 32,
        fingerprint: fp,
      },
      DEFAULT_SYSTEM_ONE_THRESHOLDS,
      { mode: "race", currentFingerprint: fp },
    );
    expect(blockRes.kind).toBe("accept");
    if (blockRes.kind === "accept") {
      expect(blockRes.result.verdict).toBe("BLOCK");
    }
  });

  it("escalates on injection_flagged, out_of_scope, low_allow_prob, low_block_prob, low_odds_ratio, context_drifted, and failures", () => {
    const cases: Array<{
      name: string;
      outcome: SystemOneOutcome;
      currentFp?: typeof fp;
      expected: string;
    }> = [
      {
        name: "injection_flagged",
        outcome: {
          ok: true,
          allowProb: 0.99,
          blockProb: 0.01,
          inScopeScore: 0.95,
          injectionScore: 0.55,
          latencyMs: 20,
          fingerprint: fp,
        },
        expected: "injection_flagged",
      },
      {
        name: "out_of_scope",
        outcome: {
          ok: true,
          allowProb: 0.99,
          blockProb: 0.01,
          inScopeScore: 0.65,
          injectionScore: 0.05,
          latencyMs: 20,
          fingerprint: fp,
        },
        expected: "out_of_scope",
      },
      {
        name: "low_allow_prob",
        outcome: {
          ok: true,
          allowProb: 0.88,
          blockProb: 0.12,
          inScopeScore: 0.95,
          injectionScore: 0.05,
          latencyMs: 20,
          fingerprint: fp,
        },
        expected: "low_allow_prob",
      },
      {
        name: "low_block_prob",
        outcome: {
          ok: true,
          allowProb: 0.18,
          blockProb: 0.82,
          inScopeScore: 0.95,
          injectionScore: 0.05,
          latencyMs: 20,
          fingerprint: fp,
        },
        expected: "low_block_prob",
      },
      {
        name: "low_odds_ratio",
        outcome: {
          ok: true,
          allowProb: 0.86,
          blockProb: 0.25,
          inScopeScore: 0.95,
          injectionScore: 0.05,
          latencyMs: 20,
          fingerprint: fp,
        },
        thresholds: { ...DEFAULT_SYSTEM_ONE_THRESHOLDS, allowMinProb: 0.8 },
        expected: "low_odds_ratio",
      } as never,
      {
        name: "context_drifted",
        outcome: {
          ok: true,
          allowProb: 0.99,
          blockProb: 0.01,
          inScopeScore: 0.95,
          injectionScore: 0.01,
          latencyMs: 20,
          fingerprint: fp,
        },
        currentFp: computeContextFingerprint("Different prompt"),
        expected: "context_drifted",
      },
      {
        name: "s1_timeout",
        outcome: {
          ok: false,
          reason: "s1_timeout",
          message: "Timed out",
          latencyMs: 4000,
          isTransportError: true,
        },
        expected: "s1_timeout",
      },
    ];

    for (const c of cases) {
      const thresholds =
        (c as { thresholds?: typeof DEFAULT_SYSTEM_ONE_THRESHOLDS }).thresholds ??
        DEFAULT_SYSTEM_ONE_THRESHOLDS;
      const decision = evaluateCascadePolicy(c.outcome, thresholds, {
        mode: "race",
        currentFingerprint: c.currentFp ?? fp,
      });
      expect(decision.kind).toBe("escalate");
      if (decision.kind === "escalate") {
        expect(decision.reason).toBe(c.expected as never);
      }
    }
  });
});

describe("CascadeEvaluator race & circuit-breaker semantics", () => {
  it("S1 wins race -> aborts S2 signal immediately and returns S1 result", async () => {
    let s2SignalAborted = false;
    let s2Resolve!: (r: ClassifierResult) => void;

    const systemOne: SystemOneRawEvaluator = {
      async evaluateRaw(_action, opts) {
        return {
          ok: true,
          allowProb: 0.97,
          blockProb: 0.03,
          inScopeScore: 0.92,
          injectionScore: 0.01,
          latencyMs: 12,
          fingerprint: opts!.fingerprint!,
        };
      },
    };

    const system2: GateEvaluator = {
      name: "slow-s2",
      evaluate(action) {
        return new Promise<ClassifierResult>((resolve) => {
          s2Resolve = resolve;
          action.signal?.addEventListener("abort", () => {
            s2SignalAborted = true;
            resolve({ verdict: "UNSURE", reason: "aborted" });
          });
        });
      },
    };

    const cascade = new CascadeEvaluator({
      systemOne,
      system2,
      config: makeConfig({ executionMode: "race" }),
    });

    const res = await cascade.evaluate(makeAction());
    expect(res.verdict).toBe("ALLOW");
    expect(res.cascade?.winner).toBe("system1");
    expect(res.cascade?.s2Aborted).toBe(true);
    expect(s2SignalAborted).toBe(true);
    s2Resolve({ verdict: "UNSURE", reason: "cleanup" });
  });

  it("S1 uncertain -> escalates to already-in-flight S2 without restarting S2", async () => {
    let s2Calls = 0;

    const systemOne: SystemOneRawEvaluator = {
      async evaluateRaw(_action, opts) {
        await new Promise((r) => setTimeout(r, 5));
        return {
          ok: true,
          allowProb: 0.72,
          blockProb: 0.28,
          inScopeScore: 0.9,
          injectionScore: 0.05,
          latencyMs: 5,
          fingerprint: opts!.fingerprint!,
        };
      },
    };

    const system2: GateEvaluator = {
      name: "in-flight-s2",
      async evaluate() {
        s2Calls++;
        await new Promise((r) => setTimeout(r, 25));
        return { verdict: "BLOCK", risk_level: "HIGH", reason: "S2 caught subtle risk" };
      },
    };

    const cascade = new CascadeEvaluator({
      systemOne,
      system2,
      config: makeConfig({ executionMode: "race" }),
    });

    const res = await cascade.evaluate(makeAction());
    expect(s2Calls).toBe(1);
    expect(res.verdict).toBe("BLOCK");
    expect(res.reason).toBe("S2 caught subtle risk");
    expect(res.cascade?.winner).toBe("system2");
    expect(res.cascade?.escalationReason).toBe("low_allow_prob");
    expect(res.cascade?.s2Aborted).toBe(false);
  });

  it("S2 finishes first -> aborts S1 signal cleanly and returns S2 result", async () => {
    let s1SignalAborted = false;

    const systemOne: SystemOneRawEvaluator = {
      evaluateRaw(_action, opts) {
        return new Promise((resolve) => {
          opts?.signal?.addEventListener("abort", () => {
            s1SignalAborted = true;
            resolve({
              ok: false,
              reason: "s1_error",
              message: "aborted",
              latencyMs: 5,
              isTransportError: false,
            });
          });
        });
      },
    };

    const system2: GateEvaluator = {
      name: "fast-s2",
      async evaluate() {
        await new Promise((r) => setTimeout(r, 5));
        return { verdict: "ALLOW", reason: "Fast S2 allow" };
      },
    };

    const cascade = new CascadeEvaluator({
      systemOne,
      system2,
      config: makeConfig({ executionMode: "race" }),
    });

    const res = await cascade.evaluate(makeAction());
    expect(res.verdict).toBe("ALLOW");
    expect(res.cascade?.winner).toBe("system2");
    expect(res.cascade?.escalationReason).toBe("s2_finished_first");
    expect(s1SignalAborted).toBe(true);
  });

  it("rejects stale S1 result when context drifts mid-flight", async () => {
    const action = makeAction({ userPrompt: "Initial prompt" });

    const systemOne: SystemOneRawEvaluator = {
      async evaluateRaw(act, opts) {
        await new Promise((r) => setTimeout(r, 10));
        // Mutate prompt mid-flight
        act.userPrompt = "Changed prompt mid-flight";
        return {
          ok: true,
          allowProb: 0.99,
          blockProb: 0.01,
          inScopeScore: 0.99,
          injectionScore: 0.0,
          latencyMs: 10,
          fingerprint: opts!.fingerprint!,
        };
      },
    };

    const system2: GateEvaluator = {
      name: "s2-drift",
      async evaluate() {
        await new Promise((r) => setTimeout(r, 25));
        return { verdict: "UNSURE", reason: "S2 reviewed changed prompt" };
      },
    };

    const cascade = new CascadeEvaluator({
      systemOne,
      system2,
      config: makeConfig({ executionMode: "race" }),
    });

    const res = await cascade.evaluate(action);
    expect(res.verdict).toBe("UNSURE");
    expect(res.cascade?.winner).toBe("system2");
    expect(res.cascade?.escalationReason).toBe("context_drifted");
  });

  it("trips S1 outage bypass after consecutive transport failures and recovers after cooldown", async () => {
    let nowMs = 1000;
    let s1Calls = 0;

    const systemOne: SystemOneRawEvaluator = {
      async evaluateRaw() {
        s1Calls++;
        return {
          ok: false,
          reason: "s1_error",
          message: "ECONNREFUSED",
          latencyMs: 2,
          isTransportError: true,
        };
      },
    };

    const system2: GateEvaluator = {
      name: "s2-fallback",
      async evaluate() {
        await new Promise((r) => setTimeout(r, 5));
        return { verdict: "ALLOW", reason: "S2 evaluated" };
      },
    };

    const cascade = new CascadeEvaluator({
      systemOne,
      system2,
      config: makeConfig({ executionMode: "cascade" }),
      circuitFailureThreshold: 3,
      circuitCooldownMs: 30000,
      now: () => nowMs,
    });

    // 3 transport failures trip circuit
    await cascade.evaluate(makeAction({ id: "1" }));
    await cascade.evaluate(makeAction({ id: "2" }));
    await cascade.evaluate(makeAction({ id: "3" }));
    expect(s1Calls).toBe(3);
    expect(cascade.getCircuitState().isOpen).toBe(true);

    // 4th call bypasses S1 completely
    const bypassRes = await cascade.evaluate(makeAction({ id: "4" }));
    expect(s1Calls).toBe(3);
    expect(bypassRes.cascade?.escalationReason).toBe("s1_circuit_open");

    // Advance past cooldown -> probes S1 again
    nowMs += 31000;
    await cascade.evaluate(makeAction({ id: "5" }));
    expect(s1Calls).toBe(4);
  });

  it("resets circuit failures on HTTP 200 s1_invalid_output and aborts/restarts S2 with refreshed prompt on context_drifted", async () => {
    let nowMs = 1000;
    let probeIdx = 0;

    const cascadeCircuit = new CascadeEvaluator({
      systemOne: {
        async evaluateRaw() {
          probeIdx++;
          if (probeIdx <= 3 || probeIdx === 5) {
            return {
              ok: false,
              reason: "s1_error",
              message: "ECONNREFUSED",
              latencyMs: 2,
              isTransportError: true,
            };
          }
          // Post-cooldown HTTP 200 invalid output (reachable!)
          return {
            ok: false,
            reason: "s1_invalid_output",
            message: "Bad JSON",
            latencyMs: 3,
            isTransportError: false,
          };
        },
      },
      system2: {
        name: "s2",
        async evaluate() {
          return { verdict: "ALLOW", reason: "ok" };
        },
      },
      config: makeConfig({ executionMode: "cascade" }),
      circuitFailureThreshold: 3,
      circuitCooldownMs: 10000,
      now: () => nowMs,
    });

    await cascadeCircuit.evaluate(makeAction({ id: "c1" }));
    await cascadeCircuit.evaluate(makeAction({ id: "c2" }));
    await cascadeCircuit.evaluate(makeAction({ id: "c3" }));
    expect(cascadeCircuit.getCircuitState().isOpen).toBe(true);

    nowMs += 11000;
    // Probe 4 returns s1_invalid_output -> resets consecutiveFailures to 0
    await cascadeCircuit.evaluate(makeAction({ id: "c4" }));
    expect(cascadeCircuit.getCircuitState().consecutiveFailures).toBe(0);
    expect(cascadeCircuit.getCircuitState().isOpen).toBe(false);

    // Probe 5 single transport error should NOT re-open circuit
    await cascadeCircuit.evaluate(makeAction({ id: "c5" }));
    expect(cascadeCircuit.getCircuitState().consecutiveFailures).toBe(1);
    expect(cascadeCircuit.getCircuitState().isOpen).toBe(false);

    // Verify race-mode context_drifted aborts stale S2 and re-runs S2 with refreshed userPrompt
    const s2Prompts: string[] = [];
    let staleS2Aborted = false;
    let engineRef!: AutoGateCoreEngine;

    const origFetch = globalThis.fetch;
    globalThis.fetch = (async () => {
      // Simulate user sending a new prompt while S1 is in flight
      engineRef.setUserPrompt("ses-drift", "Updated user prompt");
      return new Response(
        JSON.stringify({
          answers: {
            verdict: { probabilities: { ALLOW: 0.99, BLOCK: 0.01 } },
            in_scope: { noul: 0.95 },
            injection_risk: { noul: 0.01 },
          },
        }),
        { status: 200 },
      );
    }) as typeof fetch;

    try {
      engineRef = new AutoGateCoreEngine({
        config: {
          autoMode: true,
          ntfyTopic: "test",
          ntfyServer: "https://ntfy.sh",
          classifierModel: "test",
          notifyOnVerdict: false,
          environment: { trustedDomains: ["custom.example.com"] },
          systemOne: makeConfig({ executionMode: "race" }),
        },
        evaluator: {
          name: "drift-s2",
          evaluate(act) {
            s2Prompts.push(act.userPrompt);
            if (act.userPrompt === "Initial user prompt") {
              return new Promise<ClassifierResult>((resolve) => {
                act.signal?.addEventListener("abort", () => {
                  staleS2Aborted = true;
                  resolve({ verdict: "UNSURE", reason: "stale aborted" });
                });
              });
            }
            return Promise.resolve({
              verdict: "ALLOW",
              reason: `Evaluated: ${act.userPrompt}`,
            });
          },
        },
        remoteReviewEnabled: false,
      });

      engineRef.setUserPrompt("ses-drift", "Initial user prompt");
      const action = makeAction({
        id: "act-drift-live",
        sessionID: "ses-drift",
        userPrompt: "",
        environment: undefined,
      });
      const decision = await engineRef.evaluate(action);

      expect(action.environment?.trustedDomains).toEqual(["custom.example.com"]);
      expect(staleS2Aborted).toBe(true);
      expect(s2Prompts).toEqual(["Initial user prompt", "Updated user prompt"]);
      expect(decision.verdict).toBe("ALLOW");
      expect(decision.reason).toContain("Updated user prompt");
      expect(decision.cascade?.escalationReason).toBe("context_drifted");
    } finally {
      globalThis.fetch = origFetch;
    }
  });

  it("cascade mode does not invoke S2 when S1 accepts", async () => {
    let s2Calls = 0;
    const cascade = new CascadeEvaluator({
      systemOne: {
        async evaluateRaw(_action, opts) {
          return {
            ok: true,
            allowProb: 0.98,
            blockProb: 0.02,
            inScopeScore: 0.95,
            injectionScore: 0.01,
            latencyMs: 10,
            fingerprint: opts!.fingerprint!,
          };
        },
      },
      system2: {
        name: "s2-unused",
        async evaluate() {
          s2Calls++;
          return { verdict: "ALLOW", reason: "S2" };
        },
      },
      config: makeConfig({ executionMode: "cascade" }),
    });

    const res = await cascade.evaluate(makeAction());
    expect(res.verdict).toBe("ALLOW");
    expect(s2Calls).toBe(0);
    expect(res.cascade?.mode).toBe("cascade");
    expect(res.cascade?.s2Aborted).toBe(false);
  });

  it("AutoGateCoreEngine propagates CascadeTrace to GateDecision and NtfyAdapter message", async () => {
    const published: ReviewRequest[] = [];
    const mockAdapter: NotifierAdapter = {
      name: "mock-ntfy",
      async publish(req) {
        published.push(req);
      },
      async listen() {
        return () => {};
      },
      async updateStatus() {},
    };

    const cascadeEval = new CascadeEvaluator({
      systemOne: {
        async evaluateRaw() {
          return {
            ok: false,
            reason: "s1_timeout",
            message: "Timeout",
            latencyMs: 4000,
            isTransportError: true,
          };
        },
      },
      system2: {
        name: "s2-unsure",
        async evaluate() {
          return {
            verdict: "UNSURE",
            risk_level: "MEDIUM",
            user_authorization: "LOW",
            reason: "Needs human review",
          };
        },
      },
      config: makeConfig({ executionMode: "cascade" }),
    });

    const engine = new AutoGateCoreEngine({
      config: {
        autoMode: true,
        ntfyTopic: "test",
        ntfyServer: "https://ntfy.sh",
        classifierModel: "test",
        notifyOnVerdict: false,
        systemOne: makeConfig({ executionMode: "cascade" }),
      },
      adapter: mockAdapter,
      evaluator: cascadeEval,
      remoteReviewEnabled: true,
    });

    const evalPromise = engine.evaluate(makeAction());
    await new Promise((r) => setTimeout(r, 20));

    expect(published.length).toBe(1);
    expect(published[0].message).toContain("Cascade: cascade -> system2 | reason=s1_timeout");

    engine.resolveReviewResponse({ req_id: "act-cascade-1", reply: "once" });
    const decision = await evalPromise;
    expect(decision.verdict).toBe("ALLOW");
    expect(decision.cascade?.winner).toBe("system2");
    expect(decision.cascade?.escalationReason).toBe("s1_timeout");

    // Verify ALLOW with cascade trace when remoteReviewEnabled is false on UNSURE
    engine.setRemoteReviewEnabled(false);
    const unsureDecision = await engine.evaluate(makeAction({ id: "act-cascade-2" }));
    expect(unsureDecision.verdict).toBe("UNSURE");
    expect(unsureDecision.cascade?.winner).toBe("system2");
    expect(unsureDecision.cascade?.escalationReason).toBe("s1_timeout");
  });
});
