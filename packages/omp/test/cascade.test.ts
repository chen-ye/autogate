import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { AutoGateCoreEngine, createConfiguredEvaluator, loadConfig } from "@autogate/core";
import type { GateEvaluator, ClassifierResult } from "@autogate/core";
import { registerToolCallHook } from "../src/hook.ts";

describe("OMP cascade hook integration & JSONL observability", () => {
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

  it("logs cascade trace to JSONL evalLogFile and aborts System 2 when System 1 wins", async () => {
    const evalLogFile = path.join(tempDir, "omp-cascade.jsonl");
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
      evalLogFile,
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
    registerToolCallHook(mockPi, engine, store, undefined, evalLogFile);

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

    await new Promise((r) => setTimeout(r, 30));
    const lines = fs.readFileSync(evalLogFile, "utf8").trim().split("\n");
    expect(lines.length).toBe(1);
    const parsed = JSON.parse(lines[0]);
    expect(parsed.userPrompt).toBe("Check git status in repo");
    expect(parsed.cascade.mode).toBe("race");
    expect(parsed.cascade.winner).toBe("system1");
    expect(parsed.cascade.s2Aborted).toBe(true);
  });
});
