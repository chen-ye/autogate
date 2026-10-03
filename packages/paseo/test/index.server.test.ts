import { describe, it } from "node:test";
import assert from "node:assert";
import contributeDefault, {
  contribute,
  PaseoHarnessAdapter,
  extractActionFromRequest,
  shellCommand,
} from "../index.server.js";
import { PaseoHarnessAdapter as OriginalAdapter } from "../server/adapter.js";
import {
  extractActionFromRequest as originalExtract,
  shellCommand as originalShell,
} from "../server/inspect.js";
import type { NotifierAdapter, ReviewRequest, ReviewResponse } from "@autogate/core";

class MockServer {
  public listeners = new Map<string, ((event: any, context?: any) => Promise<void> | void)[]>();
  public unregisterCalls: string[] = [];
  public offCalls: { eventName: string; listener: any }[] = [];

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
          current.filter((fn) => fn !== listener),
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
        current.filter((fn) => fn !== listener),
      );
    }
  }

  listenerCount(eventName: string): number {
    return this.listeners.get(eventName)?.length ?? 0;
  }
}

class MockNotifier implements NotifierAdapter {
  readonly name = "mock-notifier";
  public listenCalled = false;
  public listenStopCalled = false;

  async publish(_request: ReviewRequest, _signal?: AbortSignal): Promise<void> {}

  async listen(
    _onResponse: (resp: ReviewResponse) => Promise<void>,
    _signal?: AbortSignal,
  ): Promise<() => void> {
    this.listenCalled = true;
    return () => {
      this.listenStopCalled = true;
    };
  }

  async updateStatus(_requestId: string, _status: string, _details?: string): Promise<void> {}
}

describe("index.server.ts entrypoint exports and lifecycle", () => {
  it("exports contribute as default and named export", () => {
    assert.strictEqual(typeof contributeDefault, "function");
    assert.strictEqual(typeof contribute, "function");
    assert.strictEqual(contributeDefault, contribute);
  });

  it("exports PaseoHarnessAdapter named export matching class", () => {
    assert.strictEqual(typeof PaseoHarnessAdapter, "function");
    assert.strictEqual(PaseoHarnessAdapter, OriginalAdapter);
  });

  it("exports extractActionFromRequest and shellCommand matching server/inspect", () => {
    assert.strictEqual(typeof extractActionFromRequest, "function");
    assert.strictEqual(extractActionFromRequest, originalExtract);
    assert.strictEqual(typeof shellCommand, "function");
    assert.strictEqual(shellCommand, originalShell);
  });

  it("contribute(server) registers listeners and returns an async cleanup function", async () => {
    const server = new MockServer();
    const mockNotifier = new MockNotifier();
    let engineStopped = false;
    const mockEngine: any = {
      evaluate: async () => ({ verdict: "ALLOW" as const }),
      stop: async () => {
        engineStopped = true;
      },
    };

    const cleanup = contribute(server, {
      adapter: mockNotifier,
      engine: mockEngine,
    });

    assert.strictEqual(typeof cleanup, "function");
    assert.strictEqual(server.listenerCount("agent.permission_requested"), 1);
    assert.strictEqual(server.listenerCount("agent.permission_resolved"), 1);

    // Call cleanup
    await cleanup();

    // Verify listeners unregistered, remote listen stopped, engine stopped
    assert.strictEqual(server.listenerCount("agent.permission_requested"), 0);
    assert.strictEqual(server.listenerCount("agent.permission_resolved"), 0);
    assert.strictEqual(server.unregisterCalls.length, 2);
    assert.strictEqual(mockNotifier.listenStopCalled, true);
    assert.strictEqual(engineStopped, true);
  });

  it("handles plugin reload cycle without leaking listeners or timers", async () => {
    const server = new MockServer();
    const mockNotifier1 = new MockNotifier();
    const mockNotifier2 = new MockNotifier();
    let engine1Stopped = false;
    let engine2Stopped = false;

    // Load plugin turn 1
    const cleanup1 = contributeDefault(server, {
      adapter: mockNotifier1,
      engine: {
        evaluate: async () => ({ verdict: "ALLOW" as const }),
        stop: async () => {
          engine1Stopped = true;
        },
      },
    });

    assert.strictEqual(server.listenerCount("agent.permission_requested"), 1);
    assert.strictEqual(server.listenerCount("agent.permission_resolved"), 1);

    // Unload / Reload
    await cleanup1();
    assert.strictEqual(engine1Stopped, true);
    assert.strictEqual(mockNotifier1.listenStopCalled, true);
    assert.strictEqual(server.listenerCount("agent.permission_requested"), 0);
    assert.strictEqual(server.listenerCount("agent.permission_resolved"), 0);

    // Load plugin turn 2 (simulating reload)
    const cleanup2 = contributeDefault(server, {
      adapter: mockNotifier2,
      engine: {
        evaluate: async () => ({ verdict: "ALLOW" as const }),
        stop: async () => {
          engine2Stopped = true;
        },
      },
    });

    assert.strictEqual(server.listenerCount("agent.permission_requested"), 1);
    assert.strictEqual(server.listenerCount("agent.permission_resolved"), 1);

    // Cleanup turn 2
    await cleanup2();
    assert.strictEqual(engine2Stopped, true);
    assert.strictEqual(mockNotifier2.listenStopCalled, true);
    assert.strictEqual(server.listenerCount("agent.permission_requested"), 0);
    assert.strictEqual(server.listenerCount("agent.permission_resolved"), 0);
  });
});
