import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { MockInferenceProvider } from "../opencode/mock-provider";
import { completeSimple } from "@oh-my-pi/pi-ai";
import { buildModel } from "@oh-my-pi/pi-catalog/build";
import { GateEvaluator, GateAction, ClassifierResult } from "@autogate/core";
import { buildClassifierPrompt, parseVerdict } from "@autogate/core";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import * as os from "node:os";

export class OmpNativeEvaluator implements GateEvaluator {
  readonly name = "omp-native-evaluator";

  constructor(
    private model: any,
    private apiKey?: string,
    private sessionId?: string
  ) {}

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

      const response = await completeSimple(
        this.model,
        {
          messages: [{ role: "user", content: promptText, timestamp: Date.now() }],
        },
        {
          apiKey: this.apiKey,
          sessionId: this.sessionId,
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

describe("OmpNativeEvaluator and completeSimple Test Suite", () => {
  let mockProvider: MockInferenceProvider;
  let sandboxDir: string;

  beforeEach(async () => {
    mockProvider = new MockInferenceProvider(0);
    sandboxDir = await fs.mkdtemp(path.join(os.tmpdir(), "omp-evaluator-test-"));
  });

  afterEach(async () => {
    await mockProvider.stop();
    try {
      await fs.rm(sandboxDir, { recursive: true, force: true });
    } catch {}
  });

  it("invokes completeSimple directly and parses verdict via OmpNativeEvaluator", async () => {
    const verdictJson = JSON.stringify({
      risk_level: "LOW",
      user_authorization: "HIGH",
      verdict: "ALLOW",
      reason: "Safe test command via completeSimple",
    });

    mockProvider.pushResponse({
      text: verdictJson,
    });

    const model = buildModel({
      id: "mock-model",
      name: "Mock Model",
      api: "openai-completions",
      provider: "mock-provider",
      baseUrl: `${mockProvider.url}/v1`,
      reasoning: false,
      input: ["text"],
      cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
      contextWindow: 128000,
      maxTokens: 8192,
    });

    const evaluator = new OmpNativeEvaluator(model, "test-key", "ses-eval-1");

    const sampleAction: GateAction = {
      id: "act-1",
      harness: "omp",
      sessionID: "ses-eval-1",
      toolName: "bash",
      commandString: "echo 'hello omp native evaluator'",
      workspaceRoot: sandboxDir,
      userPrompt: "run echo",
    };

    const result = await evaluator.evaluate(sampleAction);

    expect(result.verdict).toBe("ALLOW");
    expect(result.risk_level).toBe("LOW");
    expect(result.user_authorization).toBe("HIGH");
    expect(result.reason).toContain("Safe test command via completeSimple");

    const requests = mockProvider.getRequests();
    expect(requests.length).toBeGreaterThan(0);
  });
});
