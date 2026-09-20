import { describe, it } from "node:test";
import assert from "node:assert";
import { PaseoHarnessAdapter } from "../server/adapter.js";
import type {
  GateAction,
  GateDecision,
  NotifierAdapter,
  ReviewRequest,
  ReviewResponse,
  GateEvaluator,
  ClassifierResult,
} from "@autogate/core";

// Mock Paseo PluginServerContext
class MockServer {
  public listeners = new Map<string, ((event: any, context?: any) => Promise<void> | void)[]>();
  public offCalls: { eventName: string; listener: any }[] = [];
  public unregisterCalls: string[] = [];

  on(eventName: string, listener: (event: any, context?: any) => Promise<void> | void) {
    let list = this.listeners.get(eventName);
    if (!list) {
      list = [];
      this.listeners.set(eventName, list);
    }
    list.push(listener);

    return () => {
      this.unregisterCalls.push(eventName);
      const current = this.listeners.get(eventName);
      if (current) {
        this.listeners.set(
          eventName,
          current.filter((fn) => fn !== listener)
        );
      }
    };
  }

  off(eventName: string, listener: any) {
    this.offCalls.push({ eventName, listener });
    const current = this.listeners.get(eventName);
    if (current) {
      this.listeners.set(
        eventName,
        current.filter((fn) => fn !== listener)
      );
    }
  }

  async emit(eventName: string, event: any, context?: any) {
    const list = this.listeners.get(eventName);
    if (list) {
      for (const listener of [...list]) {
        await listener(event, context);
      }
    }
  }
}

// Mock Agent
class MockAgent {
  public responses: any[] = [];
  public throwOnRespond: Error | null = null;

  constructor(public id: string = "agent-1") {}

  async respondToPermission(data: any) {
    if (this.throwOnRespond) {
      throw this.throwOnRespond;
    }
    this.responses.push(data);
  }
}

// Mock NotifierAdapter
class MockNotifierAdapter implements NotifierAdapter {
  readonly name = "mock-notifier";
  public published: ReviewRequest[] = [];
  public listenerCallback?: (resp: ReviewResponse) => Promise<void>;
  public listenCalled = false;
  public listenStopCalled = false;
  public updatedStatuses: { requestId: string; status: string; details?: string }[] = [];

  async publish(request: ReviewRequest, _signal?: AbortSignal): Promise<void> {
    this.published.push(request);
  }

  async listen(
    onResponse: (resp: ReviewResponse) => Promise<void>,
    _signal?: AbortSignal
  ): Promise<() => void> {
    this.listenCalled = true;
    this.listenerCallback = onResponse;
    return () => {
      this.listenStopCalled = true;
      this.listenerCallback = undefined;
    };
  }

  async updateStatus(requestId: string, status: string, details?: string): Promise<void> {
    this.updatedStatuses.push({ requestId, status, details });
  }

  async simulateReply(resp: ReviewResponse) {
    if (this.listenerCallback) {
      await this.listenerCallback(resp);
    }
  }
}

// Mock GateEvaluator
class MockGateEvaluator implements GateEvaluator {
  readonly name = "mock-evaluator";
  public evaluateResult: ClassifierResult = { verdict: "ALLOW", reason: "All good" };
  public evaluatedActions: GateAction[] = [];

  async evaluate(action: GateAction): Promise<ClassifierResult> {
    this.evaluatedActions.push(action);
    return this.evaluateResult;
  }
}

describe("PaseoHarnessAdapter", () => {
  it("initializes AutoGateCoreEngine with remoteReviewEnabled: true and pure dual-channel mode", () => {
    const server = new MockServer();
    const adapter = new PaseoHarnessAdapter(server);
    const engine = adapter.getEngine();

    assert.strictEqual(engine.isRemoteReviewEnabled(), true);
    assert.strictEqual(engine.getFallbackMode(), "ntfy");
    assert.strictEqual(adapter.name, "paseo");
    assert.ok(adapter.getPendingRequests());
  });

  it("supports config.paseo?.notifyOnVerdict override", () => {
    const server = new MockServer();

    // Default global notifyOnVerdict is true, override via paseo.notifyOnVerdict = false
    const adapterDisabled = new PaseoHarnessAdapter(server, {
      paseo: { notifyOnVerdict: false },
    });
    assert.strictEqual(
      (adapterDisabled.getEngine() as any).config.notifyOnVerdict,
      false
    );

    // Explicitly set paseo.notifyOnVerdict = true
    const adapterEnabled = new PaseoHarnessAdapter(server, {
      notifyOnVerdict: false,
      paseo: { notifyOnVerdict: true },
    });
    assert.strictEqual(
      (adapterEnabled.getEngine() as any).config.notifyOnVerdict,
      true
    );
  });

  it("handles ALLOW: calls agent.respondToPermission with behavior allow and does NOT track pending", async () => {
    const server = new MockServer();
    const agent = new MockAgent("agent-42");
    const mockEvaluator = new MockGateEvaluator();
    mockEvaluator.evaluateResult = { verdict: "ALLOW", reason: "Safe git status" };

    const adapter = new PaseoHarnessAdapter(server, {
      evaluator: mockEvaluator,
    });

    const event = {
      agent,
      request: {
        id: "req-101",
        name: "bash",
        input: { command: "git status" },
      },
    };

    await server.emit("agent.permission_requested", event);

    assert.strictEqual(agent.responses.length, 1);
    assert.deepStrictEqual(agent.responses[0], {
      requestId: "req-101",
      response: { behavior: "allow" },
    });
    assert.strictEqual(adapter.getPendingRequests().has("req-101"), false);
  });

  it("handles BLOCK: calls agent.respondToPermission with behavior deny and message", async () => {
    const server = new MockServer();
    const agent = new MockAgent("agent-42");
    const mockEvaluator = new MockGateEvaluator();
    mockEvaluator.evaluateResult = {
      verdict: "BLOCK",
      reason: "Dangerous command rm -rf /",
    };

    const adapter = new PaseoHarnessAdapter(server, {
      evaluator: mockEvaluator,
    });

    const event = {
      agent,
      request: {
        id: "req-102",
        name: "bash",
        input: { command: "rm -rf /" },
      },
    };

    await server.emit("agent.permission_requested", event);

    assert.strictEqual(agent.responses.length, 1);
    assert.strictEqual(agent.responses[0].requestId, "req-102");
    assert.strictEqual(agent.responses[0].response.behavior, "deny");
    assert.ok(agent.responses[0].response.message.includes("Dangerous command"));
    assert.strictEqual(adapter.getPendingRequests().has("req-102"), false);
  });

  it("handles UNSURE: records in pendingRequests and does NOT call respondToPermission", async () => {
    const server = new MockServer();
    const agent = new MockAgent("agent-42");

    // Create a mock engine that evaluates to UNSURE
    const mockEngine: any = {
      evaluate: async () => ({
        verdict: "UNSURE" as const,
        reason: "Needs human review",
      }),
      isRemoteReviewEnabled: () => true,
      getFallbackMode: () => "ntfy",
      stop: async () => {},
      resolveReviewResponse: () => {},
      handlePermissionReplied: () => {},
    };

    const adapter = new PaseoHarnessAdapter(server, {
      engine: mockEngine,
    });

    const event = {
      agent,
      request: {
        id: "req-unsure-1",
        name: "bash",
        input: { command: "sudo reboot" },
      },
    };

    await server.emit("agent.permission_requested", event);

    // Does NOT call agent.respondToPermission (leaves it pending in Paseo UI)
    assert.strictEqual(agent.responses.length, 0);

    // Records in pendingRequests
    assert.strictEqual(adapter.getPendingRequests().has("req-unsure-1"), true);
    const pending = adapter.getPendingRequests().get("req-unsure-1");
    assert.strictEqual(pending?.agentId, "agent-42");
    assert.strictEqual(pending?.action.id, "req-unsure-1");
    assert.strictEqual(pending?.action.commandString, "sudo reboot");
  });

  it("reverse webhook listener: replies allow for once/always and deletes from pendingRequests", async () => {
    const server = new MockServer();
    const agent = new MockAgent("agent-42");
    const mockNotifier = new MockNotifierAdapter();

    const mockEngine: any = {
      evaluate: async () => ({ verdict: "UNSURE" as const, reason: "Needs review" }),
      resolveReviewResponse: (resp: any) => {},
      handlePermissionReplied: () => {},
      stop: async () => {},
    };

    const adapter = new PaseoHarnessAdapter(server, {
      engine: mockEngine,
      adapter: mockNotifier,
    });

    await adapter.start();

    // 1. Initial permission requested -> UNSURE
    await server.emit("agent.permission_requested", {
      agent,
      request: { id: "req-rev-1", name: "bash", input: { command: "curl https://example.com" } },
    });
    assert.strictEqual(adapter.getPendingRequests().has("req-rev-1"), true);

    // 2. Remote reply arrives via Ntfy listener -> "once"
    await mockNotifier.simulateReply({
      req_id: "req-rev-1",
      reply: "once",
    });

    // 3. Agent is responded with allow and removed from pending
    assert.strictEqual(agent.responses.length, 1);
    assert.deepStrictEqual(agent.responses[0], {
      requestId: "req-rev-1",
      response: { behavior: "allow" },
    });
    assert.strictEqual(adapter.getPendingRequests().has("req-rev-1"), false);
  });

  it("reverse webhook listener: replies deny for reject and deletes from pendingRequests", async () => {
    const server = new MockServer();
    const agent = new MockAgent("agent-42");
    const mockNotifier = new MockNotifierAdapter();

    const mockEngine: any = {
      evaluate: async () => ({ verdict: "UNSURE" as const, reason: "Needs review" }),
      resolveReviewResponse: () => {},
      handlePermissionReplied: () => {},
      stop: async () => {},
    };

    const adapter = new PaseoHarnessAdapter(server, {
      engine: mockEngine,
      adapter: mockNotifier,
    });

    await adapter.start();

    await server.emit("agent.permission_requested", {
      agent,
      request: { id: "req-rev-2", name: "bash", input: { command: "dropdb production" } },
    });

    assert.strictEqual(adapter.getPendingRequests().has("req-rev-2"), true);

    await mockNotifier.simulateReply({
      req_id: "req-rev-2",
      reply: "reject",
    });

    assert.strictEqual(agent.responses.length, 1);
    assert.deepStrictEqual(agent.responses[0], {
      requestId: "req-rev-2",
      response: { behavior: "deny" },
    });
    assert.strictEqual(adapter.getPendingRequests().has("req-rev-2"), false);
  });

  it("reverse webhook listener: safely ignores reply when requestId is not in pendingRequests (already answered in Paseo UI)", async () => {
    const server = new MockServer();
    const mockNotifier = new MockNotifierAdapter();

    const adapter = new PaseoHarnessAdapter(server, {
      adapter: mockNotifier,
    });
    await adapter.start();

    // Simulate reply for unknown requestId
    await mockNotifier.simulateReply({
      req_id: "already-resolved-req",
      reply: "once",
    });

    // No exception thrown, pending requests intact
    assert.strictEqual(adapter.getPendingRequests().size, 0);
  });

  it("subscribes to agent.permission_resolved: updates Ntfy status and deletes from pendingRequests", async () => {
    const server = new MockServer();
    const agent = new MockAgent("agent-42");

    let repliedPayload: any = null;
    const mockEngine: any = {
      evaluate: async () => ({ verdict: "UNSURE" as const, reason: "Needs review" }),
      handlePermissionReplied: (data: any) => {
        repliedPayload = data;
      },
      resolveReviewResponse: () => {},
      stop: async () => {},
    };

    const adapter = new PaseoHarnessAdapter(server, {
      engine: mockEngine,
    });

    await server.emit("agent.permission_requested", {
      agent,
      request: { id: "req-local-ui", name: "bash", input: { command: "ls" } },
    });

    assert.strictEqual(adapter.getPendingRequests().has("req-local-ui"), true);

    // User approves in Paseo UI
    await server.emit("agent.permission_resolved", {
      agent,
      requestId: "req-local-ui",
      resolution: { behavior: "allow" },
    });

    assert.deepStrictEqual(repliedPayload, {
      id: "req-local-ui",
      requestID: "req-local-ui",
      reply: "once",
    });
    assert.strictEqual(adapter.getPendingRequests().has("req-local-ui"), false);
  });

  it("double-resolution race: resolution in Paseo UI followed by late reverse webhook reply is safely ignored", async () => {
    const server = new MockServer();
    const agent = new MockAgent("agent-42");
    const mockNotifier = new MockNotifierAdapter();

    const mockEngine: any = {
      evaluate: async () => ({ verdict: "UNSURE" as const, reason: "Needs review" }),
      handlePermissionReplied: () => {},
      resolveReviewResponse: () => {},
      stop: async () => {},
    };

    const adapter = new PaseoHarnessAdapter(server, {
      engine: mockEngine,
      adapter: mockNotifier,
    });
    await adapter.start();

    await server.emit("agent.permission_requested", {
      agent,
      request: { id: "req-race-1", name: "bash", input: { command: "echo test" } },
    });

    // 1. First answered in Paseo UI
    await server.emit("agent.permission_resolved", {
      agent,
      requestId: "req-race-1",
      resolution: { behavior: "allow" },
    });

    assert.strictEqual(adapter.getPendingRequests().has("req-race-1"), false);

    // 2. Late reverse webhook reply arrives
    await mockNotifier.simulateReply({
      req_id: "req-race-1",
      reply: "reject",
    });

    // agent.respondToPermission should NOT be called by the adapter
    assert.strictEqual(agent.responses.length, 0);
  });

  it("does NOT crash on deleted agent or double-resolution error in respondToPermission", async () => {
    const server = new MockServer();
    const agent = new MockAgent("agent-deleted");
    agent.throwOnRespond = new Error("Agent was closed or destroyed");
    const mockNotifier = new MockNotifierAdapter();

    const mockEngine: any = {
      evaluate: async () => ({ verdict: "UNSURE" as const, reason: "Needs review" }),
      handlePermissionReplied: () => {},
      resolveReviewResponse: () => {},
      stop: async () => {},
    };

    const adapter = new PaseoHarnessAdapter(server, {
      engine: mockEngine,
      adapter: mockNotifier,
    });
    await adapter.start();

    await server.emit("agent.permission_requested", {
      agent,
      request: { id: "req-deleted", name: "bash", input: { command: "test" } },
    });

    // Remote reply arrives and agent throws
    assert.doesNotThrow(async () => {
      await mockNotifier.simulateReply({
        req_id: "req-deleted",
        reply: "once",
      });
    });
  });

  it("resolves agent via context.paseo.agents.ref or server.paseo.agents.ref", async () => {
    const agent = new MockAgent("agent-sdk");
    const server = new MockServer();
    (server as any).paseo = {
      agents: {
        ref: (id: string) => (id === "agent-sdk" ? agent : null),
      },
    };

    const mockEvaluator = new MockGateEvaluator();
    mockEvaluator.evaluateResult = { verdict: "ALLOW", reason: "Safe" };

    const adapter = new PaseoHarnessAdapter(server, {
      evaluator: mockEvaluator,
    });

    // Event where event.agent has no respondToPermission directly
    const event = {
      agent: { id: "agent-sdk" },
      request: { id: "req-ref-test", name: "bash", input: { command: "pwd" } },
    };

    await server.emit("agent.permission_requested", event);

    assert.strictEqual(agent.responses.length, 1);
    assert.strictEqual(agent.responses[0].requestId, "req-ref-test");
    assert.strictEqual(agent.responses[0].response.behavior, "allow");
  });

  it("dispose cleanly unregisters listeners, stops remote listen, and clears pending map", async () => {
    const server = new MockServer();
    const mockNotifier = new MockNotifierAdapter();
    let engineStopCalled = false;
    const mockEngine: any = {
      evaluate: async () => ({ verdict: "UNSURE" as const, reason: "Needs review" }),
      stop: async () => {
        engineStopCalled = true;
      },
      resolveReviewResponse: () => {},
      handlePermissionReplied: () => {},
    };

    const adapter = new PaseoHarnessAdapter(server, {
      engine: mockEngine,
      adapter: mockNotifier,
    });
    await adapter.start();

    // Populate a pending request
    adapter.getPendingRequests().set("req-dispose", {
      agentId: "a1",
      action: { id: "req-dispose" } as any,
    });

    assert.strictEqual(adapter.getPendingRequests().size, 1);

    await adapter.dispose();

    assert.strictEqual(adapter.getPendingRequests().size, 0);
    assert.strictEqual(mockNotifier.listenStopCalled, true);
    assert.strictEqual(engineStopCalled, true);
    assert.strictEqual(server.unregisterCalls.length, 2);
  });
});
