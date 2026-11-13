import { describe, it, expect } from "bun:test";
import { DirectApiEvaluator } from "../src/evaluator";
import type { GateAction } from "../src/types";

describe("DirectApiEvaluator", () => {
  const sampleAction: GateAction = {
    id: "act-eval-1",
    harness: "opencode",
    sessionID: "ses-1",
    toolName: "bash",
    commandString: "npm test",
    workspaceRoot: "/tmp",
    userPrompt: "run tests",
  };

  it("resolves ALLOW verdict from mock Gemini JSON response", async () => {
    const mockFetch: typeof fetch = async (_input: RequestInfo | URL, _init?: RequestInit) => {
      const responseBody = {
        candidates: [
          {
            content: {
              parts: [
                {
                  text: JSON.stringify({
                    risk_level: "LOW",
                    user_authorization: "HIGH",
                    verdict: "ALLOW",
                    reason: "Safe test command",
                  }),
                },
              ],
            },
          },
        ],
      };
      return new Response(JSON.stringify(responseBody), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    };

    const evaluator = new DirectApiEvaluator({
      apiKey: "test-api-key",
      fetchImpl: mockFetch,
    });

    const result = await evaluator.evaluate(sampleAction);
    expect(result.verdict).toBe("ALLOW");
    expect(result.risk_level).toBe("LOW");
    expect(result.user_authorization).toBe("HIGH");
    expect(result.reason).toContain("Safe test command");
  });

  it("catches network failure and safely falls back to UNSURE", async () => {
    const mockFetch: typeof fetch = async () => {
      throw new Error("Network connection refused");
    };

    const evaluator = new DirectApiEvaluator({
      apiKey: "test-api-key",
      fetchImpl: mockFetch,
    });

    const result = await evaluator.evaluate(sampleAction);
    expect(result.verdict).toBe("UNSURE");
    expect(result.reason).toContain("DirectApiEvaluator error: Network connection refused");
  });

  it("catches timeout / abort error and safely falls back to UNSURE", async () => {
    const mockFetch: typeof fetch = async (_input, init) => {
      // Simulate abort signal aborting
      return new Promise((_, reject) => {
        if (init?.signal) {
          init.signal.addEventListener("abort", () => {
            const err = new Error("The operation was aborted");
            err.name = "AbortError";
            reject(err);
          });
        }
      });
    };

    const evaluator = new DirectApiEvaluator({
      apiKey: "test-api-key",
      timeoutMs: 10, // very short timeout
      fetchImpl: mockFetch,
    });

    const result = await evaluator.evaluate(sampleAction);
    expect(result.verdict).toBe("UNSURE");
    expect(result.reason).toContain("DirectApiEvaluator error");
  });

  it("aborts in-flight fetch immediately when action.signal aborts", async () => {
    const controller = new AbortController();
    let fetchAborted = false;

    const mockFetch: typeof fetch = async (_input, init) => {
      return new Promise((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => {
          fetchAborted = true;
          const err = new Error("Aborted by cascade");
          err.name = "AbortError";
          reject(err);
        });
      });
    };

    const evaluator = new DirectApiEvaluator({
      apiKey: "test-api-key",
      timeoutMs: 30000,
      fetchImpl: mockFetch,
    });

    setTimeout(() => controller.abort("system1-won-race"), 10);

    const start = performance.now();
    const result = await evaluator.evaluate({
      ...sampleAction,
      signal: controller.signal,
    });
    const elapsed = performance.now() - start;

    expect(fetchAborted).toBe(true);
    expect(result.verdict).toBe("UNSURE");
    expect(elapsed).toBeLessThan(200);
  });
});
