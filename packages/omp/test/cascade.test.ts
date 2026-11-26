import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import {
  AutoGateCoreEngine,
  AutoGateEvalStore,
  createConfiguredEvaluator,
  loadConfig,
} from "@autogate/core";
import type { GateEvaluator, ClassifierResult } from "@autogate/core";
import { registerToolCallHook } from "../src/hook.ts";

describe("OMP cascade hook integration & AutoGateEvalStore observability", () => {
  let tempDir: string;
  const origFetch = globalThis.fetch;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "autogate-omp-cascade-"));
  });

  afterEach(() => {
    globalThis.fetch = origFetch;
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  });

  it("logs cascade trace to evalDbFile and aborts System 2 when System 1 wins", async () => {
    const evalDbFile = path.join(tempDir, "omp-cascade.db");
    let s2Aborted = false;

    globalThis.fetch = (async () =>
      new Response(
        JSON.stringify({
          answers: {
            verdict: { probabilities: { ALLOW: 0.97, BLOCK: 0.03 } },
            in_scope: { noul: 0.94 },
            injection_risk: { noul: 0.01 },
          },
        }),
        { status: 200 },
      )) as typeof fetch;

    const slowS2: GateEvaluator = {
      name: "slow-omp-s2",
      evaluate(action) {
        return new Promise<ClassifierResult>((resolve) => {
          action.signal?.addEventListener("abort", () => {
            s2Aborted = true;
            resolve({ verdict: "UNSURE", reason: "aborted" });
          });
        });
      },
    };

    const config = loadConfig({
      evalDbFile,
      notifyOnVerdict: false,
      reviewFallbackMode: "native",
      systemOne: {
        enabled: true,
        executionMode: "race",
        endpoint: "http://127.0.0.1:4006/v1/systemone",
        model: "gemini-decision-1",
        timeoutMs: 2000,
      },
    });

    const evaluator = createConfiguredEvaluator(config, slowS2);
    const engine = new AutoGateCoreEngine({
      config,
      evaluator,
      remoteReviewEnabled: false,
    });
    engine.setUserPrompt("ses-omp-1", "Check git status in repo");

    const listeners = new Map<string, (e: unknown, c: unknown) => Promise<unknown>>();
    const mockPi = {
      on(event: string, cb: (e: unknown, c: unknown) => Promise<unknown>) {
        listeners.set(event, cb);
      },
    };
    const store = new Map<
      string,
      { verdict: string; policy: "allow" | "deny" | "prompt"; reason?: string }
    >();
    registerToolCallHook(mockPi, engine, store, undefined, evalDbFile);

    const handler = listeners.get("tool_call")!;
    const res = await handler(
      {
        toolCallId: "omp-call-1",
        toolName: "bash",
        input: { command: "git status" },
      },
      { sessionID: "ses-omp-1", cwd: tempDir },
    );

    expect(res).toBeUndefined();
    expect(s2Aborted).toBe(true);
    expect(store.get("omp-call-1")?.verdict).toBe("ALLOW");

    const evalStore = new AutoGateEvalStore(evalDbFile, { readonly: true });
    try {
      const records = evalStore.queryEvaluations();
      expect(records.length).toBe(1);
      const rec = records[0]!;
      expect(rec.sourceFormat).toBe("omp");
      expect(rec.actionId).toBe("omp-call-1");
      expect(rec.sessionId).toBe("ses-omp-1");
      expect(rec.userPrompt).toBe("Check git status in repo");
      expect(rec.cascade?.mode).toBe("race");
      expect(rec.cascade?.winner).toBe("system1");
      expect(rec.cascade?.s2Aborted).toBe(true);
    } finally {
      evalStore.close();
    }
  });
});
