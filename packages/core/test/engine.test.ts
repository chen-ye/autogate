import { describe, it, expect, beforeEach } from "bun:test"
import { AutoGateCoreEngine } from "../src/engine"
import type { GateEvaluator, GateAction, ClassifierResult, NotifierAdapter, ReviewRequest, ReviewResponse } from "../src/types"
import type { AutoGateConfig } from "../src/config"

class MockEvaluator implements GateEvaluator {
  readonly name = "mock-evaluator"
  public evaluateCallCount = 0
  public nextResult: ClassifierResult = { verdict: "ALLOW", reason: "Allowed" }

  async evaluate(_action: GateAction): Promise<ClassifierResult> {
    this.evaluateCallCount++
    return this.nextResult
  }
}

class MockAdapter implements NotifierAdapter {
  readonly name = "mock-adapter"
  public publishedRequests: ReviewRequest[] = []

  constructor(private autoReply?: "once" | "always" | "reject", private engineRef?: AutoGateCoreEngine) {}

  async publish(request: ReviewRequest, _signal?: AbortSignal): Promise<void> {
    this.publishedRequests.push(request)
    if (this.autoReply && this.engineRef) {
      setTimeout(() => {
        this.engineRef?.resolveReviewResponse({
          req_id: request.id,
          reply: this.autoReply!,
        })
      }, 5)
    }
  }

  async listen(_onResponse: (resp: ReviewResponse) => Promise<void>): Promise<() => void> {
    return () => {}
  }

  async updateStatus(_requestId: string, _status: string, _details?: string): Promise<void> {}
}

describe("AutoGateCoreEngine", () => {
  let mockEvaluator: MockEvaluator
  let mockAdapter: MockAdapter
  let config: AutoGateConfig
  let engine: AutoGateCoreEngine

  beforeEach(() => {
    mockEvaluator = new MockEvaluator()
    mockAdapter = new MockAdapter("reject")
    config = {
      autoMode: true,
      consecutiveBlockThreshold: 3,
      notifyOnVerdict: false,
      reviewTimeout: 1000,
    }
    engine = new AutoGateCoreEngine({
      config,
      evaluator: mockEvaluator,
      adapter: mockAdapter,
    })
    // Attach engineRef to adapter for mock auto-reply
    ;(mockAdapter as any).engineRef = engine
  })

  it("evaluates ALLOW -> caches action in turn cache, resets block count", async () => {
    mockEvaluator.nextResult = { verdict: "ALLOW", reason: "Safe action" }
    const action: GateAction = {
      id: "act-1",
      harness: "opencode",
      sessionID: "ses-1",
      toolName: "bash",
      commandString: "echo hello",
      workspaceRoot: "/tmp",
      userPrompt: "do task",
    }

    const decision1 = await engine.evaluate(action)
    expect(decision1.verdict).toBe("ALLOW")
    expect(decision1.cached).toBe(false)
    expect(mockEvaluator.evaluateCallCount).toBe(1)
    expect(engine.getConsecutiveBlocks()).toBe(0)

    // Second call should hit turn decision cache
    const start = performance.now()
    const decision2 = await engine.evaluate(action)
    const duration = performance.now() - start

    expect(decision2.verdict).toBe("ALLOW")
    expect(decision2.cached).toBe(true)
    expect(duration).toBeLessThan(1) // <1ms
    expect(mockEvaluator.evaluateCallCount).toBe(1) // Evaluator NOT called again
  })

  it("evaluates BLOCK -> increments consecutive blocks, appends safe alternative, caches in sharedRecentlyRejected", async () => {
    mockEvaluator.nextResult = { verdict: "BLOCK", reason: "Destructive rm command" }
    const action: GateAction = {
      id: "act-2",
      harness: "opencode",
      sessionID: "ses-1",
      toolName: "bash",
      commandString: "rm -rf src/",
      workspaceRoot: "/tmp",
      userPrompt: "cleanup",
    }

    expect(engine.getConsecutiveBlocks()).toBe(0)
    const decision = await engine.evaluate(action)

    expect(decision.verdict).toBe("BLOCK")
    expect(decision.safeTransformAlternative).toBeDefined()
    expect(decision.safeTransformAlternative).toContain("SAFE_TRANSFORM_REJECT")
    expect(engine.getConsecutiveBlocks()).toBe(1)
  })

  it("circuit breaker -> trips after 3 consecutive blocks and forces review / UNSURE", async () => {
    mockEvaluator.nextResult = { verdict: "BLOCK", reason: "Blocked" }
    const action: GateAction = {
      id: "act-3",
      harness: "opencode",
      sessionID: "ses-1",
      toolName: "bash",
      commandString: "rm -rf node_modules",
      workspaceRoot: "/tmp",
      userPrompt: "cleanup",
    }

    // Trigger 3 consecutive blocks
    await engine.evaluate(action)
    await engine.evaluate({ ...action, id: "act-3b", commandString: "rm -rf dist" })
    await engine.evaluate({ ...action, id: "act-3c", commandString: "rm -rf build" })

    expect(engine.getConsecutiveBlocks()).toBe(3)

    // 4th evaluation should trip circuit breaker and request review (mock adapter replies 'reject' -> BLOCK)
    const decision = await engine.evaluate({ ...action, id: "act-3d", commandString: "rm -rf web" })
    expect(decision.verdict).toBe("BLOCK")
    expect(mockAdapter.publishedRequests.length).toBeGreaterThan(0)
  })

  it("escalation -> AUTOGATE_ESCALATE=1 triggers review", async () => {
    mockEvaluator.nextResult = { verdict: "ALLOW", reason: "Allowed" }
    const action: GateAction = {
      id: "act-4",
      harness: "opencode",
      sessionID: "ses-escalate",
      toolName: "bash",
      commandString: "AUTOGATE_ESCALATE=1 sensitive_command",
      workspaceRoot: "/tmp",
      userPrompt: "escalate",
    }

    const decision = await engine.evaluate(action)
    expect(decision.verdict).toBe("BLOCK") // replied reject via mock adapter
    expect(mockAdapter.publishedRequests.length).toBe(1)
  })

  it("disabled engine -> requests review", async () => {
    engine.setEnabled(false)
    expect(engine.isEnabled()).toBe(false)

    const action: GateAction = {
      id: "act-5",
      harness: "opencode",
      sessionID: "ses-1",
      toolName: "bash",
      commandString: "ls",
      workspaceRoot: "/tmp",
      userPrompt: "list",
    }

    const decision = await engine.evaluate(action)
    expect(decision.verdict).toBe("BLOCK") // replied reject via mock adapter
    expect(mockAdapter.publishedRequests.length).toBe(1)
  })

  it("native fallback mode on UNSURE -> returns UNSURE immediately without calling adapter.publish", async () => {
    engine.setFallbackMode("native")
    mockEvaluator.nextResult = { verdict: "UNSURE", reason: "Unsure action", risk_level: "MEDIUM", user_authorization: "LOW" }
    const action: GateAction = {
      id: "act-native",
      harness: "opencode",
      sessionID: "ses-1",
      toolName: "bash",
      commandString: "custom_command",
      workspaceRoot: "/tmp",
      userPrompt: "test",
    }

    const decision = await engine.evaluate(action)
    expect(decision.verdict).toBe("UNSURE")
    expect(decision.reason).toBe("Unsure action")
    expect(decision.riskLevel).toBe("MEDIUM")
    expect(decision.userAuthorization).toBe("LOW")
    expect(mockAdapter.publishedRequests.length).toBe(0)
})
});
