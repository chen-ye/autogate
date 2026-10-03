import { describe, it, expect, beforeEach, afterEach, spyOn } from "bun:test";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import { MockInferenceProvider } from "../../../test/e2e/opencode/mock-provider.ts";
import { buildModel } from "@oh-my-pi/pi-catalog/build";
import { resolveShadowedApproval } from "../src/approval-bridge.ts";
import { registerShadowedEvalTool } from "../src/index.ts";
import { registerToolCallHook } from "../src/hook.ts";
import { formatActionDetails, loadConfig } from "@autogate/core";
import { OmpNativeEvaluator } from "../src/evaluator.ts";
import autoGateOmpExtension, { OmpHarnessAdapter } from "../src/index.ts";
import * as piAi from "@oh-my-pi/pi-ai";

describe("shadowed eval tool & approval support & OmpNativeEvaluator strict tool calls", () => {
  let store: Map<string, any>;
  let mockProvider: MockInferenceProvider;

  const originalEnv = { ...process.env };

  beforeEach(() => {
    store = new Map();
    mockProvider = new MockInferenceProvider(0);
    process.env.XDG_CONFIG_HOME = path.join(os.tmpdir(), `empty-xdg-omp-${Date.now()}`);
  });

  afterEach(async () => {
    process.env = { ...originalEnv };
    await mockProvider.stop();
  });

  const getModel = (reasoning = false) =>
    buildModel({
      id: "mock-model",
      name: "Mock Model",
      api: "openai-completions",
      provider: "mock-provider",
      baseUrl: `${mockProvider.url}/v1`,
      reasoning,
      input: ["text"],
      cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
      contextWindow: 128000,
      maxTokens: 8192,
    });

  it("1. resolveShadowedApproval resolves code argument and toolCallId verdicts", () => {
    // Allow via toolCallId
    store.set("tool-1", { verdict: "ALLOW", policy: "allow" });
    expect(resolveShadowedApproval({ code: "print('test')", toolCallId: "tool-1" }, store)).toEqual(
      {
        tier: "write",
        policy: "allow",
      },
    );

    // Allow via code string
    store.set("print('hello')", { verdict: "ALLOW", policy: "allow" });
    expect(resolveShadowedApproval({ code: "print('hello')" }, store)).toEqual({
      tier: "write",
      policy: "allow",
    });

    // Deny verdict
    store.set("tool-deny", { verdict: "BLOCK", policy: "deny", reason: "Unsafe code" });
    expect(
      resolveShadowedApproval(
        { code: "import os; os.system('rm -rf /')", toolCallId: "tool-deny" },
        store,
      ),
    ).toEqual({
      tier: "exec",
      policy: "deny",
      override: true,
      reason: "Unsafe code",
    });

    // Prompt verdict
    store.set("tool-prompt", { verdict: "UNSURE", policy: "prompt", reason: "Needs review" });
    expect(
      resolveShadowedApproval({ code: "eval('bad')", toolCallId: "tool-prompt" }, store),
    ).toEqual({
      tier: "exec",
      policy: "prompt",
      override: true,
      reason: "Needs review",
    });

    // No record defaults to write
    expect(resolveShadowedApproval({ code: "print('unknown')" }, store)).toEqual({
      tier: "write",
    });
  });

  it("2. registerShadowedEvalTool registers 'eval' tool with approval function and delegates to ctx.invokeTool", async () => {
    const registeredTools: any[] = [];
    const mockPi = {
      registerTool(tool: any) {
        registeredTools.push(tool);
      },
    };

    const mockEngine = {
      isEnabled: () => true,
    };

    registerShadowedEvalTool(mockPi, mockEngine as any);

    expect(registeredTools.length).toBe(1);
    const evalTool = registeredTools[0];
    expect(evalTool.name).toBe("eval");
    expect(typeof evalTool.approval).toBe("function");
    expect(typeof evalTool.execute).toBe("function");

    // Test execution delegation
    let invoked = false;
    const mockCtx = {
      invokeTool: async (params: any, options: any) => {
        invoked = true;
        expect(params).toEqual({ code: "2 + 2", language: "py" });
        return { result: "4" };
      },
    };

    const result = await evalTool.execute(
      "call-123",
      { code: "2 + 2", language: "py" },
      null,
      null,
      mockCtx,
    );
    expect(invoked).toBe(true);
    expect(result).toEqual({ result: "4" });

    // Test missing invokeTool error
    await expect(evalTool.execute("call-123", { code: "2 + 2" }, null, null, {})).rejects.toThrow(
      "ctx.invokeTool is unavailable for shadowed eval delegation",
    );
  });

  it("3. formatActionDetails produces fenced code block for eval action", () => {
    const formatted = formatActionDetails("eval", { code: "print('hello world')", language: "py" });
    expect(formatted).toContain("```py");
    expect(formatted).toContain("print('hello world')");
    expect(formatted).toContain("- **Eval Code (py)**:");
  });

  it("4. tool_call hook extracts event.input.code into action payload", async () => {
    const listeners = new Map<string, Function>();
    const mockPi = {
      on(event: string, cb: Function) {
        listeners.set(event, cb);
      },
    };

    let evaluatedAction: any = null;
    const testStore = new Map();
    const mockEngine = {
      isEnabled: () => true,
      getUserPrompt: () => "user instruction",
      evaluate: async (action: any) => {
        evaluatedAction = action;
        return { verdict: "ALLOW" };
      },
    };

    registerToolCallHook(mockPi, mockEngine as any, testStore);

    const toolCallHandler = listeners.get("tool_call");
    expect(typeof toolCallHandler).toBe("function");

    await toolCallHandler(
      {
        toolCallId: "eval-call-1",
        toolName: "eval",
        input: { code: "import math; math.pi", language: "py" },
      },
      { sessionID: "ses-test" },
    );

    expect(evaluatedAction).not.toBeNull();
    expect(evaluatedAction.toolName).toBe("eval");
    expect(evaluatedAction.commandString).toBe("import math; math.pi");
    expect(evaluatedAction.rawArgs).toEqual({ code: "import math; math.pi", language: "py" });
    expect(evaluatedAction.sessionID).toBe("ses-test");
    expect(evaluatedAction.userPrompt).toBe("user instruction");
  });

  it("OmpNativeEvaluator.evaluate() aborts immediately with already-aborted signal", async () => {
    const controller = new AbortController();
    controller.abort();

    const evaluator = new OmpNativeEvaluator(null, "test-key");
    const result = await evaluator.evaluate({
      id: "act-1",
      harness: "omp",
      toolName: "bash",
      commandString: "echo test",
      signal: controller.signal,
    });

    expect(result.verdict).toBe("UNSURE");
    expect(result.reason).toContain("aborted");
  });

  it("OmpNativeEvaluator emits logs via mock logger on evaluate", async () => {
    const logs: { level: string; message: string; data?: any }[] = [];
    const mockLogger = {
      debug: (msg: string, data?: any) => logs.push({ level: "debug", message: msg, data }),
      info: (msg: string, data?: any) => logs.push({ level: "info", message: msg, data }),
      warn: (msg: string, data?: any) => logs.push({ level: "warn", message: msg, data }),
      error: (msg: string, data?: any) => logs.push({ level: "error", message: msg, data }),
    };

    const evaluator = new OmpNativeEvaluator({
      model: null,
      logger: mockLogger,
    });

    const result = await evaluator.evaluate({
      id: "act-log-1",
      harness: "omp",
      toolName: "bash",
      commandString: "echo log-test",
    });

    expect(result.verdict).toBe("UNSURE");
    expect(logs.some((l) => l.level === "warn" && l.message.includes("No model resolved"))).toBe(
      true,
    );
  });

  it("OmpNativeEvaluator emits error log on inference failure or abort", async () => {
    const logs: { level: string; message: string; data?: any }[] = [];
    const mockLogger = {
      debug: (msg: string, data?: any) => logs.push({ level: "debug", message: msg, data }),
      info: (msg: string, data?: any) => logs.push({ level: "info", message: msg, data }),
      warn: (msg: string, data?: any) => logs.push({ level: "warn", message: msg, data }),
      error: (msg: string, data?: any) => logs.push({ level: "error", message: msg, data }),
    };

    const controller = new AbortController();
    controller.abort();

    const evaluator = new OmpNativeEvaluator({
      model: getModel(),
      logger: mockLogger,
      classifierTimeout: 40000,
    });

    const result = await evaluator.evaluate({
      id: "act-log-2",
      harness: "omp",
      toolName: "bash",
      commandString: "echo abort-test",
      signal: controller.signal,
    });

    expect(result.verdict).toBe("UNSURE");
    expect(
      logs.some((l) => l.level === "error" && l.message.includes("Inference failed or timed out")),
    ).toBe(true);
  });

  it("input event with ctx.sessionManager.getSessionId() stores prompt keyed by session ID in engine", async () => {
    const listeners = new Map<string, Function>();
    const mockPi = {
      setLabel: () => {},
      registerTool: () => {},
      on(event: string, cb: Function) {
        listeners.set(event, cb);
      },
    };

    const { engine } = autoGateOmpExtension(mockPi, { autoMode: true });
    const inputHandler = listeners.get("input");
    expect(typeof inputHandler).toBe("function");

    const mockCtx = {
      sessionManager: {
        getSessionId: () => "test-sess",
      },
    };

    await inputHandler({ text: "Hello from session manager" }, mockCtx);
    expect(engine.getUserPrompt("test-sess")).toBe("Hello from session manager");
  });

  it("turn_end event with ctx.sessionManager.getSessionId() clears turn cache for that session ID", async () => {
    const listeners = new Map<string, Function>();
    const mockPi = {
      setLabel: () => {},
      registerTool: () => {},
      on(event: string, cb: Function) {
        listeners.set(event, cb);
      },
    };

    const { engine } = autoGateOmpExtension(mockPi, { autoMode: true });
    const turnEndHandler = listeners.get("turn_end");
    expect(typeof turnEndHandler).toBe("function");

    const mockCtx = {
      sessionManager: {
        getSessionId: () => "test-sess",
      },
    };

    turnEndHandler({}, mockCtx);
    expect(true).toBe(true);
  });

  it("OmpHarnessAdapter passes pi.logger to OmpNativeEvaluator and preserves reviewFallbackMode default", async () => {
    const logs: string[] = [];
    const mockLogger = {
      debug: (msg: string) => logs.push(msg),
      info: () => {},
      warn: () => {},
      error: () => {},
    };
    const mockPi = {
      logger: mockLogger,
      setLabel: () => {},
      registerTool: () => {},
      on: () => {},
    };

    mockProvider.pushResponse({
      toolCall: {
        name: "classify_result",
        input: { risk_level: "LOW", user_authorization: "HIGH", verdict: "ALLOW", reason: "ok" },
      },
    });

    const evaluator = Object.assign(new OmpNativeEvaluator(getModel(), "test-key"), {
      logger: mockLogger,
    });
    const adapter = new OmpHarnessAdapter(mockPi, { reviewFallbackMode: "native", evaluator });

    await adapter.getEngine().evaluate({
      id: "act-log-test",
      harness: "omp",
      toolName: "bash",
      commandString: "echo test",
    });

    expect(logs.some((m) => m.includes("Evaluating action"))).toBe(true);

    const configDefault = loadConfig();
    expect(configDefault.reviewFallbackMode).toBe("ntfy");

    const configNative = loadConfig({ reviewFallbackMode: "native" });
    expect(configNative.reviewFallbackMode).toBe("native");
  });

  it("registerToolCallHook fast-paths internal tool 'todo' without calling engine.evaluate", async () => {
    const listeners = new Map<string, Function>();
    const mockPi = {
      on(event: string, cb: Function) {
        listeners.set(event, cb);
      },
    };

    let evaluateCalled = false;
    const mockEngine = {
      isEnabled: () => true,
      getUserPrompt: () => "",
      evaluate: async () => {
        evaluateCalled = true;
        return { verdict: "BLOCK" };
      },
    };

    const testStore = new Map();
    registerToolCallHook(mockPi, mockEngine as any, testStore);

    const toolCallHandler = listeners.get("tool_call");
    expect(typeof toolCallHandler).toBe("function");

    const res = await toolCallHandler({
      toolCallId: "call-todo-1",
      toolName: "todo",
      input: { action: "list" },
    });

    expect(res).toBeUndefined();
    expect(evaluateCalled).toBe(false);
    expect(testStore.get("call-todo-1")?.verdict).toBe("ALLOW");
  });

  it("registerToolCallHook fast-paths virtual URI 'skill://customize-omo' without calling engine.evaluate", async () => {
    const listeners = new Map<string, Function>();
    const mockPi = {
      on(event: string, cb: Function) {
        listeners.set(event, cb);
      },
    };

    let evaluateCalled = false;
    const mockEngine = {
      isEnabled: () => true,
      getUserPrompt: () => "",
      evaluate: async () => {
        evaluateCalled = true;
        return { verdict: "BLOCK" };
      },
    };

    const testStore = new Map();
    registerToolCallHook(mockPi, mockEngine as any, testStore);

    const toolCallHandler = listeners.get("tool_call");
    expect(typeof toolCallHandler).toBe("function");

    const res = await toolCallHandler({
      toolCallId: "call-skill-1",
      toolName: "read",
      input: { path: "skill://customize-omo" },
    });

    expect(res).toBeUndefined();
    expect(evaluateCalled).toBe(false);
    expect(testStore.get("call-skill-1")?.verdict).toBe("ALLOW");
  });

  it("OmpNativeEvaluator successfully parses valid classify_result tool call", async () => {
    mockProvider.pushResponse({
      toolCall: {
        name: "classify_result",
        input: {
          risk_level: "LOW",
          user_authorization: "HIGH",
          verdict: "ALLOW",
          reason: "Safe check",
        },
      },
    });

    const evaluator = new OmpNativeEvaluator(getModel(), "test-key");
    const result = await evaluator.evaluate({
      id: "act-tool-1",
      harness: "omp",
      toolName: "bash",
      commandString: "echo safe",
    });

    expect(result).toEqual({
      verdict: "ALLOW",
      risk_level: "LOW",
      user_authorization: "HIGH",
      reason: "Safe check",
    });
  });

  it("OmpNativeEvaluator re-prompts on text-only response and returns UNSURE after max retries", async () => {
    mockProvider.pushResponse({ text: "Thinking 1" });
    mockProvider.pushResponse({ text: "Thinking 2" });
    mockProvider.pushResponse({ text: "Thinking 3" });

    const evaluator = new OmpNativeEvaluator(getModel(), "test-key");
    const result = await evaluator.evaluate({
      id: "act-reprompt-1",
      harness: "omp",
      toolName: "bash",
      commandString: "rm -rf /",
    });

    expect(result.verdict).toBe("UNSURE");
    expect(result.reason).toBe("Model failed to invoke classify_result tool call after retries");
  });

  it("OmpNativeEvaluator re-prompts on text-only response and succeeds when tool call is provided on retry", async () => {
    mockProvider.pushResponse({ text: "Thinking 1" });
    mockProvider.pushResponse({
      toolCall: {
        name: "classify_result",
        input: {
          risk_level: "MEDIUM",
          user_authorization: "LOW",
          verdict: "BLOCK",
          reason: "Unsafe operation detected on retry",
        },
      },
    });

    const evaluator = new OmpNativeEvaluator(getModel(), "test-key");
    const result = await evaluator.evaluate({
      id: "act-retry-success",
      harness: "omp",
      toolName: "bash",
      commandString: "rm -rf ./build",
    });

    expect(result).toEqual({
      verdict: "BLOCK",
      risk_level: "MEDIUM",
      user_authorization: "LOW",
      reason: "Unsafe operation detected on retry",
    });
  });

  it("OmpNativeEvaluator appends valid JSON line to evalLogFile with action and decision details", async () => {
    const tmpLog = path.join(os.tmpdir(), `autogate-eval-${Date.now()}.jsonl`);
    try {
      mockProvider.pushResponse({
        toolCall: {
          name: "classify_result",
          input: {
            risk_level: "LOW",
            user_authorization: "HIGH",
            verdict: "ALLOW",
            reason: "Logging test success",
          },
        },
      });

      const evaluator = new OmpNativeEvaluator({
        model: getModel(),
        apiKey: "test-key",
        evalLogFile: tmpLog,
      });

      const result = await evaluator.evaluate({
        id: "act-log-1",
        harness: "omp",
        toolName: "bash",
        commandString: "echo test-log",
      });
      expect(result.verdict).toBe("ALLOW");

      await new Promise((r) => setTimeout(r, 50));

      const content = await fs.readFile(tmpLog, "utf8");
      const lines = content.trim().split("\n");
      expect(lines.length).toBeGreaterThan(0);
      const parsed = JSON.parse(lines[lines.length - 1]);
      expect(parsed.action.toolName).toBe("bash");
      expect(parsed.action.command).toBe("echo test-log");
      expect(parsed.decision.verdict).toBe("ALLOW");
      expect(parsed.decision.reason).toBe("Logging test success");
    } finally {
      try {
        await fs.unlink(tmpLog);
      } catch {}
    }
  });

  it("OmpNativeEvaluator captures thinking trace and reasoning tokens in evalLogFile", async () => {
    const tmpLog = path.join(os.tmpdir(), `autogate-eval-thinking-${Date.now()}.jsonl`);
    try {
      const spy = spyOn(piAi, "completeSimple").mockResolvedValueOnce({
        role: "assistant",
        content: [
          { type: "thinking", thinking: "Analyzing potential risk..." },
          {
            type: "toolCall",
            name: "classify_result",
            arguments: {
              risk_level: "LOW",
              user_authorization: "HIGH",
              verdict: "ALLOW",
              reason: "Thinking captured",
            },
          },
        ],
        usage: {
          input: 10,
          output: 10,
          reasoningTokens: 42,
        },
        stopReason: "toolUse",
      } as any);

      const evaluator = new OmpNativeEvaluator({
        model: { id: "test-model" },
        apiKey: "test-key",
        evalLogFile: tmpLog,
      });

      const result = await evaluator.evaluate({
        id: "act-thinking-1",
        harness: "omp",
        toolName: "bash",
        commandString: "echo thinking",
      });

      expect(result.verdict).toBe("ALLOW");

      await new Promise((r) => setTimeout(r, 50));

      const content = await fs.readFile(tmpLog, "utf8");
      const lines = content.trim().split("\n");
      const parsed = JSON.parse(lines[lines.length - 1]);
      expect(parsed.inference.thinking).toBe("Analyzing potential risk...");
      expect(parsed.inference.reasoningTokens).toBe(42);
      spy.mockRestore();
    } finally {
      try {
        await fs.unlink(tmpLog);
      } catch {}
    }
  });

  it("OmpNativeEvaluator completes normally when evalLogFile is unwritable or invalid", async () => {
    const invalidLogPath = os.tmpdir();

    mockProvider.pushResponse({
      toolCall: {
        name: "classify_result",
        input: {
          risk_level: "LOW",
          user_authorization: "HIGH",
          verdict: "ALLOW",
          reason: "Unwritable log test",
        },
      },
    });

    const evaluator = new OmpNativeEvaluator({
      model: getModel(),
      apiKey: "test-key",
      evalLogFile: invalidLogPath,
    });

    const result = await evaluator.evaluate({
      id: "act-unwritable-1",
      harness: "omp",
      toolName: "bash",
      commandString: "echo unwritable",
    });

    expect(result.verdict).toBe("ALLOW");
  });
});
