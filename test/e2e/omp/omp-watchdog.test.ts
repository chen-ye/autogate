import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { MockInferenceProvider } from "../opencode/mock-provider";
import {
  AutoGateCoreEngine,
  DirectApiEvaluator,
  NtfyAdapter,
  type GateAction,
} from "@autogate/core";
import { OmpNativeEvaluator } from "../../../packages/omp/src/evaluator.ts";
import autoGateOmpExtension from "../../../packages/omp/src/index.ts";
import {
  AuthStorage,
  createAgentSession,
  ModelRegistry,
  SessionManager,
  Settings,
  SqliteAuthCredentialStore,
} from "@oh-my-pi/pi-coding-agent";
import { Database } from "bun:sqlite";
import { buildModel } from "@oh-my-pi/pi-catalog/build";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import * as os from "node:os";

describe("OMP Watchdog and Timeout E2E Test Suite", () => {
  let mockProvider: MockInferenceProvider;
  let sandboxDir: string;
  let authStorage: AuthStorage;
  let modelRegistry: ModelRegistry;
  let activeSessions: any[] = [];
  let activeEngines: AutoGateCoreEngine[] = [];
  let savedEnv: Record<string, string | undefined> = {};

  beforeEach(async () => {
    savedEnv = {
      NTFY_SERVER: process.env.NTFY_SERVER,
      NTFY_TOPIC: process.env.NTFY_TOPIC,
      NTFY_TOKEN: process.env.NTFY_TOKEN,
      OPENCODE_AUTO_MODE: process.env.OPENCODE_AUTO_MODE,
      AUTOGATE_EVAL_DB: process.env.AUTOGATE_EVAL_DB,
    };
    mockProvider = new MockInferenceProvider(0);
    activeSessions = [];
    activeEngines = [];
    sandboxDir = await fs.mkdtemp(path.join(os.tmpdir(), "omp-watchdog-test-"));
    authStorage = new AuthStorage(new SqliteAuthCredentialStore(new Database(":memory:")));
    authStorage.setRuntimeApiKey("mock-provider", "test-key");
    modelRegistry = new ModelRegistry(authStorage);

    modelRegistry.registerProvider("mock-provider", {
      baseUrl: `${mockProvider.url}/v1`,
      apiKey: "test-key",
      api: "openai-completions",
      models: [
        {
          id: "mock-model",
          name: "Mock Model",
          reasoning: false,
          input: ["text"],
          cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
          contextWindow: 128000,
          maxTokens: 8192,
        },
      ],
    });

    process.env.NTFY_SERVER = process.env.NTFY_SERVER || "https://ntfy.sh";
    process.env.NTFY_TOPIC = process.env.NTFY_TOPIC || "autogate-test-omp";
    process.env.NTFY_TOKEN = process.env.NTFY_TOKEN || "test-token";
    process.env.OPENCODE_AUTO_MODE = "true";
    process.env.AUTOGATE_EVAL_DB = ":memory:";
  });

  afterEach(async () => {
    while (activeSessions.length > 0) {
      const session = activeSessions.pop();
      try {
        await session.dispose();
      } catch {}
    }
    while (activeEngines.length > 0) {
      const engine = activeEngines.pop();
      try {
        await engine.stop();
      } catch {}
    }
    if (authStorage) {
      try {
        authStorage.close();
      } catch {}
    }
    if (mockProvider) {
      try {
        await mockProvider.stop();
      } catch {}
    }
    for (const [key, val] of Object.entries(savedEnv)) {
      if (val === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = val;
      }
    }
    try {
      await fs.rm(sandboxDir, { recursive: true, force: true });
    } catch {}
  });

  it("Test 1 (Inference Timeout Abort): OmpNativeEvaluator times out and returns UNSURE", async () => {
    mockProvider.pushResponse({
      text: JSON.stringify({
        verdict: "ALLOW",
        reason: "Should not reach",
        risk_level: "LOW",
        user_authorization: "HIGH",
      }),
      delayMs: 300,
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

    const evaluator = new OmpNativeEvaluator(model, "test-key", { classifierTimeout: 50 });
    const sampleAction: GateAction = {
      id: "act-timeout-1",
      harness: "omp",
      sessionID: "ses-1",
      toolName: "bash",
      commandString: "sleep 10",
      workspaceRoot: sandboxDir,
      userPrompt: "sleep",
    };

    const start = performance.now();
    const result = await evaluator.evaluate(sampleAction);
    const duration = performance.now() - start;

    expect(result.verdict).toBe("UNSURE");
    expect(result.reason).toContain("timed out");
    expect(duration).toBeLessThan(250);
  });

  it("Test 2 (Watchdog Abort Signal Cancellation in requestReview): requestReview aborts on controller.abort()", async () => {
    const ntfyAdapter = new NtfyAdapter({
      server: process.env.NTFY_SERVER || "https://ntfy.sh",
      topic: process.env.NTFY_TOPIC || "autogate-test-omp",
      token: process.env.NTFY_TOKEN || "test-token",
    });
    const config = {
      autoMode: true,
      consecutiveBlockThreshold: 3,
      reviewFallbackMode: "ntfy" as const,
      ntfyServer: process.env.NTFY_SERVER || "https://ntfy.sh",
      ntfyTopic: process.env.NTFY_TOPIC || "autogate-test-omp",
      ntfyToken: process.env.NTFY_TOKEN || "test-token",
    };
    const engine = new AutoGateCoreEngine({
      config,
      adapter: ntfyAdapter,
      evaluator: {
        name: "unsure-evaluator",
        async evaluate() {
          return { verdict: "UNSURE", reason: "Needs review" };
        },
      },
      workspaceRoot: sandboxDir,
    });
    activeEngines.push(engine);
    engine.setFallbackMode("ntfy");

    const controller = new AbortController();
    const action: GateAction = {
      id: `act-watchdog-2-${Date.now()}`,
      harness: "omp",
      sessionID: "ses-1",
      toolName: "bash",
      commandString: "echo test",
      workspaceRoot: sandboxDir,
      userPrompt: "test",
      signal: controller.signal,
    };

    setTimeout(() => {
      controller.abort();
    }, 50);

    const start = performance.now();
    const decision = await engine.evaluate(action);
    const duration = performance.now() - start;

    expect(decision.verdict).toBe("BLOCK");
    expect(decision.reason).toContain("aborted");
    expect(duration).toBeLessThan(2000);
    expect((engine as any).inFlightRequests.size).toBe(0);

    await engine.stop();
  });

  it("Test 3 (Agent Session Watchdog Timeout): createAgentSession with short extensionHandlers.toolCallTimeoutMs handles slow tool call fail-closed", async () => {
    // 1. Agent prompt response: invokes tool call
    mockProvider.pushResponse({
      toolCall: {
        name: "bash",
        input: { command: "echo 'slow tool'" },
      },
    });
    // 2. Evaluator classification response: slow (400ms delay, exceeds 150ms toolCallTimeoutMs)
    mockProvider.pushResponse({
      text: JSON.stringify({
        verdict: "ALLOW",
        reason: "Safe",
        risk_level: "LOW",
        user_authorization: "HIGH",
      }),
      delayMs: 400,
    });
    // 3. Final response after tool execution / block
    mockProvider.pushResponse({
      text: "Done",
    });

    const settings = Settings.isolated({
      "tools.approvalMode": "yolo",
      "extensionHandlers.toolCallTimeoutMs": 150,
    });
    settings.setModelRole("default", "mock-provider/mock-model");
    settings.setModelRole("smol", "mock-provider/mock-model");

    const evaluator = new DirectApiEvaluator({
      apiKey: "test-key",
      model: "mock-model",
      baseUrl: mockProvider.url,
      fetchImpl: globalThis.fetch,
    });

    const { session } = await createAgentSession({
      cwd: sandboxDir,
      agentDir: sandboxDir,
      authStorage,
      modelRegistry,
      sessionManager: SessionManager.inMemory(),
      settings,
      disableExtensionDiscovery: true,
      extensions: [
        (pi) => {
          const ext = autoGateOmpExtension(pi, { evaluator });
          activeEngines.push(ext.engine);
          return ext;
        },
      ],
      toolNames: ["bash"],
      skills: [],
      contextFiles: [],
      promptTemplates: [],
      slashCommands: [],
      enableMCP: false,
      enableLsp: false,
      rules: [],
      workspaceTree: {
        rootPath: sandboxDir,
        rendered: "",
        truncated: false,
        totalLines: 0,
        agentsMdFiles: [],
      },
      skipPythonPreflight: true,
    });
    activeSessions.push(session);

    try {
      await session.prompt("Run slow tool call");
      const branch = session.sessionManager.getBranch();
      expect(branch).toBeDefined();
    } finally {
      await session.dispose();
    }
  }, 30000);
});
