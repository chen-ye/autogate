import { describe, it, expect, beforeEach } from "bun:test";
import { AutoGateCoreEngine } from "../src/engine";
import type {
  GateEvaluator,
  GateAction,
  ClassifierResult,
  NotifierAdapter,
  ReviewRequest,
  ReviewResponse,
} from "../src/types";
import type { AutoGateConfig } from "../src/config";

class MockEvaluator implements GateEvaluator {
  readonly name = "mock-evaluator";
  public evaluateCallCount = 0;
  public nextResult: ClassifierResult = { verdict: "ALLOW", reason: "Allowed" };

  async evaluate(_action: GateAction): Promise<ClassifierResult> {
    this.evaluateCallCount++;
    return this.nextResult;
  }
}

class MockAdapter implements NotifierAdapter {
  readonly name = "mock-adapter";
  public publishedRequests: ReviewRequest[] = [];

  constructor(
    private autoReply?: "once" | "always" | "reject",
    private engineRef?: AutoGateCoreEngine,
  ) {}

  async publish(request: ReviewRequest, _signal?: AbortSignal): Promise<void> {
    this.publishedRequests.push(request);
    if (this.autoReply && this.engineRef) {
      setTimeout(() => {
        this.engineRef?.resolveReviewResponse({
          req_id: request.id,
          reply: this.autoReply!,
        });
      }, 5);
    }
  }

  async listen(_onResponse: (resp: ReviewResponse) => Promise<void>): Promise<() => void> {
    return () => {};
  }

  async updateStatus(_requestId: string, _status: string, _details?: string): Promise<void> {}
}

describe("AutoGateCoreEngine", () => {
  let mockEvaluator: MockEvaluator;
  let mockAdapter: MockAdapter;
  let config: AutoGateConfig;
  let engine: AutoGateCoreEngine;

  beforeEach(() => {
    mockEvaluator = new MockEvaluator();
    mockAdapter = new MockAdapter("reject");
    config = {
      autoMode: true,
      consecutiveBlockThreshold: 3,
      notifyOnVerdict: false,
      reviewTimeout: 1000,
    };
    engine = new AutoGateCoreEngine({
      config,
      evaluator: mockEvaluator,
      adapter: mockAdapter,
    });
    // Attach engineRef to adapter for mock auto-reply
    (mockAdapter as any).engineRef = engine;
  });

  it("evaluates ALLOW -> caches action in turn cache, resets block count", async () => {
    mockEvaluator.nextResult = { verdict: "ALLOW", reason: "Safe action" };
    const action: GateAction = {
      id: "act-1",
      harness: "opencode",
      sessionID: "ses-1",
      toolName: "bash",
      commandString: "echo hello",
      workspaceRoot: "/tmp",
      userPrompt: "do task",
    };

    const decision1 = await engine.evaluate(action);
    expect(decision1.verdict).toBe("ALLOW");
    expect(decision1.cached).toBe(false);
    expect(mockEvaluator.evaluateCallCount).toBe(1);
    expect(engine.getConsecutiveBlocks()).toBe(0);

    // Second call should hit turn decision cache
    const start = performance.now();
    const decision2 = await engine.evaluate(action);
    const duration = performance.now() - start;

    expect(decision2.verdict).toBe("ALLOW");
    expect(decision2.cached).toBe(true);
    expect(duration).toBeLessThan(1); // <1ms
    expect(mockEvaluator.evaluateCallCount).toBe(1); // Evaluator NOT called again
  });

  it("evaluates BLOCK -> increments consecutive blocks, appends safe alternative, caches in sharedRecentlyRejected", async () => {
    mockEvaluator.nextResult = { verdict: "BLOCK", reason: "Destructive rm command" };
    const action: GateAction = {
      id: "act-2",
      harness: "opencode",
      sessionID: "ses-1",
      toolName: "bash",
      commandString: "rm -rf src/",
      workspaceRoot: "/tmp",
      userPrompt: "cleanup",
    };

    expect(engine.getConsecutiveBlocks()).toBe(0);
    const decision = await engine.evaluate(action);

    expect(decision.verdict).toBe("BLOCK");
    expect(decision.safeTransformAlternative).toBeDefined();
    expect(decision.safeTransformAlternative).toContain("SAFE_TRANSFORM_REJECT");
    expect(engine.getConsecutiveBlocks()).toBe(1);
  });

  it("circuit breaker -> trips after 3 consecutive blocks and forces review / UNSURE", async () => {
    mockEvaluator.nextResult = { verdict: "BLOCK", reason: "Blocked" };
    const action: GateAction = {
      id: "act-3",
      harness: "opencode",
      sessionID: "ses-1",
      toolName: "bash",
      commandString: "rm -rf node_modules",
      workspaceRoot: "/tmp",
      userPrompt: "cleanup",
    };

    // Trigger 3 consecutive blocks
    await engine.evaluate(action);
    await engine.evaluate({ ...action, id: "act-3b", commandString: "rm -rf dist" });
    await engine.evaluate({ ...action, id: "act-3c", commandString: "rm -rf build" });

    expect(engine.getConsecutiveBlocks()).toBe(3);

    // 4th evaluation should trip circuit breaker and request review (mock adapter replies 'reject' -> BLOCK)
    const decision = await engine.evaluate({
      ...action,
      id: "act-3d",
      commandString: "rm -rf web",
    });
    expect(decision.verdict).toBe("BLOCK");
    expect(mockAdapter.publishedRequests.length).toBeGreaterThan(0);
  });

  it("escalation -> AUTOGATE_ESCALATE=1 triggers review", async () => {
    mockEvaluator.nextResult = { verdict: "ALLOW", reason: "Allowed" };
    const action: GateAction = {
      id: "act-4",
      harness: "opencode",
      sessionID: "ses-escalate",
      toolName: "bash",
      commandString: "AUTOGATE_ESCALATE=1 sensitive_command",
      workspaceRoot: "/tmp",
      userPrompt: "escalate",
    };

    const decision = await engine.evaluate(action);
    expect(decision.verdict).toBe("BLOCK"); // replied reject via mock adapter
    expect(mockAdapter.publishedRequests.length).toBe(1);
  });

  it("disabled engine -> requests review", async () => {
    engine.setEnabled(false);
    expect(engine.isEnabled()).toBe(false);

    const action: GateAction = {
      id: "act-5",
      harness: "opencode",
      sessionID: "ses-1",
      toolName: "bash",
      commandString: "ls",
      workspaceRoot: "/tmp",
      userPrompt: "list",
    };

    const decision = await engine.evaluate(action);
    expect(decision.verdict).toBe("BLOCK"); // replied reject via mock adapter
    expect(mockAdapter.publishedRequests.length).toBe(1);
  });

  it("native fallback mode on UNSURE -> returns UNSURE immediately without calling adapter.publish", async () => {
    engine.setFallbackMode("native");
    mockEvaluator.nextResult = {
      verdict: "UNSURE",
      reason: "Unsure action",
      risk_level: "MEDIUM",
      user_authorization: "LOW",
    };
    const action: GateAction = {
      id: "act-native",
      harness: "opencode",
      sessionID: "ses-1",
      toolName: "bash",
      commandString: "custom_command",
      workspaceRoot: "/tmp",
      userPrompt: "test",
    };

    const decision = await engine.evaluate(action);
    expect(decision.verdict).toBe("UNSURE");
    expect(decision.reason).toBe("Unsure action");
    expect(decision.riskLevel).toBe("MEDIUM");
    expect(decision.userAuthorization).toBe("LOW");
    expect(mockAdapter.publishedRequests.length).toBe(0);
  });

  it("aborted signal -> returns BLOCK immediately without calling evaluator", async () => {
    const controller = new AbortController();
    controller.abort();

    const action: GateAction = {
      id: "act-aborted",
      harness: "opencode",
      sessionID: "ses-1",
      toolName: "bash",
      commandString: "echo test",
      workspaceRoot: "/tmp",
      userPrompt: "test",
      signal: controller.signal,
    };

    const decision = await engine.evaluate(action);
    expect(decision.verdict).toBe("BLOCK");
    expect(decision.reason).toBe("Action evaluation aborted by signal");
    expect(mockEvaluator.evaluateCallCount).toBe(0);
  });

  it("native fallback mode when disabled -> returns UNSURE immediately without calling adapter.publish", async () => {
    engine.setFallbackMode("native");
    engine.setEnabled(false);
    const action: GateAction = {
      id: "act-disabled-native",
      harness: "opencode",
      sessionID: "ses-1",
      toolName: "bash",
      commandString: "ls",
      workspaceRoot: "/tmp",
      userPrompt: "list",
    };
    const decision = await engine.evaluate(action);
    expect(decision.verdict).toBe("UNSURE");
    expect(decision.reason).toBe("AutoMode is disabled (local harness fallback)");
    expect(mockAdapter.publishedRequests.length).toBe(0);
  });

  it("native fallback mode on circuit breaker -> returns UNSURE immediately without calling adapter.publish", async () => {
    engine.setFallbackMode("native");
    mockEvaluator.nextResult = { verdict: "BLOCK", reason: "Blocked" };
    const action: GateAction = {
      id: "act-cb-native",
      harness: "opencode",
      sessionID: "ses-cb-native",
      toolName: "bash",
      commandString: "rm -rf unique_dir_1",
      workspaceRoot: "/tmp",
      userPrompt: "cleanup",
    };
    await engine.evaluate(action);
    await engine.evaluate({
      ...action,
      id: "act-cb-native-2",
      commandString: "rm -rf unique_dir_2",
    });
    await engine.evaluate({
      ...action,
      id: "act-cb-native-3",
      commandString: "rm -rf unique_dir_3",
    });
    expect(engine.getConsecutiveBlocks()).toBe(3);

    const decision = await engine.evaluate({
      ...action,
      id: "act-cb-native-4",
      commandString: "rm -rf unique_dir_4",
    });
    expect(decision.verdict).toBe("UNSURE");
    expect(decision.reason).toContain("Circuit breaker tripped");
    expect(mockAdapter.publishedRequests.length).toBe(0);
  });

  it("native fallback mode on escalation -> returns UNSURE immediately without calling adapter.publish", async () => {
    engine.setFallbackMode("native");
    mockEvaluator.nextResult = { verdict: "ALLOW", reason: "Allowed" };
    const action: GateAction = {
      id: "act-esc-native",
      harness: "opencode",
      sessionID: "ses-esc",
      toolName: "bash",
      commandString: "AUTOGATE_ESCALATE=1 sensitive_command",
      workspaceRoot: "/tmp",
      userPrompt: "escalate",
    };
    const decision = await engine.evaluate(action);
    expect(decision.verdict).toBe("UNSURE");
    expect(decision.reason).toContain("Escalated");
    expect(mockAdapter.publishedRequests.length).toBe(0);
  });

  it("requestReview with pre-aborted signal -> returns BLOCK immediately without publishing", async () => {
    const controller = new AbortController();
    controller.abort();

    mockEvaluator.nextResult = { verdict: "UNSURE", reason: "Need review" };
    const action: GateAction = {
      id: "act-pre-aborted",
      harness: "opencode",
      sessionID: "ses-1",
      toolName: "bash",
      commandString: "sleep 1",
      workspaceRoot: "/tmp",
      userPrompt: "test",
      signal: controller.signal,
    };

    const start = performance.now();
    const decision = await engine.evaluate(action);
    const duration = performance.now() - start;

    expect(decision.verdict).toBe("BLOCK");
    expect(decision.reason).toContain("aborted");
    expect(duration).toBeLessThan(50);
    expect(mockAdapter.publishedRequests.length).toBe(0);
  });

  it("requestReview with dynamically aborted signal -> aborts and resolves to BLOCK", async () => {
    const silentAdapter = new MockAdapter();
    const silentEngine = new AutoGateCoreEngine({
      config,
      evaluator: mockEvaluator,
      adapter: silentAdapter,
    });
    (silentAdapter as any).engineRef = silentEngine;
    silentEngine.setFallbackMode("ntfy");

    const controller = new AbortController();
    mockEvaluator.nextResult = { verdict: "UNSURE", reason: "Need review" };
    const action: GateAction = {
      id: "act-dyn-aborted",
      harness: "opencode",
      sessionID: "ses-1",
      toolName: "bash",
      commandString: "sleep 1",
      workspaceRoot: "/tmp",
      userPrompt: "test",
      signal: controller.signal,
    };

    setTimeout(() => {
      controller.abort();
    }, 30);

    const start = performance.now();
    const decision = await silentEngine.evaluate(action);
    const duration = performance.now() - start;

    expect(decision.verdict).toBe("BLOCK");
    expect(decision.reason).toContain("aborted");
    expect(duration).toBeLessThan(200);
  });

  it("remoteReviewEnabled initialization, getter/setter, and backward compatibility", () => {
    // Default is true
    const engDefault = new AutoGateCoreEngine({
      config,
      evaluator: mockEvaluator,
      adapter: mockAdapter,
    });
    expect(engDefault.isRemoteReviewEnabled()).toBe(true);
    expect(engDefault.getFallbackMode()).toBe("ntfy");

    // Explicit remoteReviewEnabled: false
    const engDisabled = new AutoGateCoreEngine({
      config,
      evaluator: mockEvaluator,
      adapter: mockAdapter,
      remoteReviewEnabled: false,
    });
    expect(engDisabled.isRemoteReviewEnabled()).toBe(false);
    expect(engDisabled.getFallbackMode()).toBe("native");

    // Explicit remoteReviewEnabled: true
    const engExplicitTrue = new AutoGateCoreEngine({
      config,
      evaluator: mockEvaluator,
      adapter: mockAdapter,
      remoteReviewEnabled: true,
    });
    expect(engExplicitTrue.isRemoteReviewEnabled()).toBe(true);
    expect(engExplicitTrue.getFallbackMode()).toBe("ntfy");

    // Backward compatibility: reviewFallbackMode === "native" in config
    const engLegacyNative = new AutoGateCoreEngine({
      config: { ...config, reviewFallbackMode: "native" },
      evaluator: mockEvaluator,
      adapter: mockAdapter,
    });
    expect(engLegacyNative.isRemoteReviewEnabled()).toBe(false);
    expect(engLegacyNative.getFallbackMode()).toBe("native");

    // setRemoteReviewEnabled changes state and syncs fallbackMode
    engDefault.setRemoteReviewEnabled(false);
    expect(engDefault.isRemoteReviewEnabled()).toBe(false);
    expect(engDefault.getFallbackMode()).toBe("native");

    engDefault.setRemoteReviewEnabled(true);
    expect(engDefault.isRemoteReviewEnabled()).toBe(true);
    expect(engDefault.getFallbackMode()).toBe("ntfy");

    // setFallbackMode("native") aliases to setRemoteReviewEnabled(false)
    engDefault.setFallbackMode("native");
    expect(engDefault.isRemoteReviewEnabled()).toBe(false);
    expect(engDefault.getFallbackMode()).toBe("native");

    // setFallbackMode("ntfy") aliases to setRemoteReviewEnabled(true)
    engDefault.setFallbackMode("ntfy");
    expect(engDefault.isRemoteReviewEnabled()).toBe(true);
    expect(engDefault.getFallbackMode()).toBe("ntfy");
  });

  it("remoteReviewEnabled: false on UNSURE -> returns UNSURE immediately without calling adapter.publish", async () => {
    engine.setRemoteReviewEnabled(false);
    mockEvaluator.nextResult = {
      verdict: "UNSURE",
      reason: "Action needs review",
      risk_level: "HIGH",
      user_authorization: "NONE",
    };
    const action: GateAction = {
      id: "act-remote-disabled-unsure",
      harness: "generic",
      sessionID: "ses-1",
      toolName: "bash",
      commandString: "sudo dangerous_tool",
      workspaceRoot: "/tmp",
      userPrompt: "run tool",
    };

    const decision = await engine.evaluate(action);
    expect(decision.verdict).toBe("UNSURE");
    expect(decision.reason).toBe("Action needs review");
    expect(decision.riskLevel).toBe("HIGH");
    expect(decision.userAuthorization).toBe("NONE");
    expect(mockAdapter.publishedRequests.length).toBe(0);
  });

  it("remoteReviewEnabled: false on UNSURE with undefined reason -> defaults to local harness fallback reason", async () => {
    engine.setRemoteReviewEnabled(false);
    mockEvaluator.nextResult = { verdict: "UNSURE" };
    const action: GateAction = {
      id: "act-remote-disabled-no-reason",
      harness: "generic",
      sessionID: "ses-1",
      toolName: "bash",
      commandString: "some_command",
      workspaceRoot: "/tmp",
      userPrompt: "run",
    };

    const decision = await engine.evaluate(action);
    expect(decision.verdict).toBe("UNSURE");
    expect(decision.reason).toBe("Manual review required (local harness fallback)");
    expect(mockAdapter.publishedRequests.length).toBe(0);
  });

  it("remoteReviewEnabled: true on UNSURE -> delegates to adapter.publish", async () => {
    engine.setRemoteReviewEnabled(true);
    mockEvaluator.nextResult = { verdict: "UNSURE", reason: "Action needs review" };
    const action: GateAction = {
      id: "act-remote-enabled-unsure",
      harness: "generic",
      sessionID: "ses-1",
      toolName: "bash",
      commandString: "some_command",
      workspaceRoot: "/tmp",
      userPrompt: "run",
    };

    const decision = await engine.evaluate(action);
    expect(decision.verdict).toBe("BLOCK"); // MockAdapter was initialized with autoReply = "reject"
    expect(mockAdapter.publishedRequests.length).toBe(1);
    expect(mockAdapter.publishedRequests[0].id).toBe("act-remote-enabled-unsure");
  });
});
