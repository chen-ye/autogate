import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";
import type { ClassifierResult, GateAction, GateEvaluator } from "@autogate/core";
import { OpenCodeHarnessAdapter, type OpenCodeRuntimeState } from "../src/index.js";

class MockEvaluator implements GateEvaluator {
  readonly name = "mock-evaluator";
  public nextResult: ClassifierResult = {
    verdict: "ALLOW",
    reason: "Allowed by mock",
    risk_level: "LOW",
    user_authorization: "HIGH",
  };
  public delayMs = 0;

  async evaluate(_action: GateAction): Promise<ClassifierResult> {
    if (this.delayMs > 0) {
      await new Promise((resolve) => setTimeout(resolve, this.delayMs));
    }
    return this.nextResult;
  }
}

describe("@autogate/opencode runtime sync", () => {
  const origEnv = { ...process.env };
  let tempDir: string;
  let xdgConfigHome: string;
  let autogateDir: string;
  let configFilePath: string;
  let controlFilePath: string;
  let runtimeDir: string;
  let evalDbFile: string;
  let workspaceDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "autogate-runtime-sync-"));
    xdgConfigHome = path.join(tempDir, "xdg");
    autogateDir = path.join(xdgConfigHome, "autogate");
    configFilePath = path.join(autogateDir, "config.json");
    controlFilePath = path.join(autogateDir, "control.json");
    runtimeDir = path.join(autogateDir, "runtime");
    evalDbFile = path.join(tempDir, "evals.db");
    workspaceDir = path.join(tempDir, "workspace");

    fs.mkdirSync(autogateDir, { recursive: true });
    fs.mkdirSync(workspaceDir, { recursive: true });

    delete process.env.AUTOGATE_CONFIG;
    delete process.env.AUTOGATE_AUTO_MODE;
    delete process.env.OPENCODE_AUTO_MODE;
    delete process.env.AUTOGATE_FALLBACK;
    delete process.env.NTFY_TOPIC;
    delete process.env.AUTOGATE_NTFY_TOPIC;
    delete process.env.OPENCODE_NTFY_TOPIC;
    delete process.env.AUTOGATE_EVAL_DB;
    delete process.env.AUTOGATE_EVAL_SESSION_CLEANUP;
    process.env.XDG_CONFIG_HOME = xdgConfigHome;
  });

  afterEach(() => {
    process.env = { ...origEnv };
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  function readRuntimeState(statePath: string): OpenCodeRuntimeState {
    return JSON.parse(fs.readFileSync(statePath, "utf8")) as OpenCodeRuntimeState;
  }

  it("1. writes per-instance runtime state file on start() and removes it on dispose()", async () => {
    const mockEvaluator = new MockEvaluator();
    const adapter = new OpenCodeHarnessAdapter(
      { directory: workspaceDir },
      {
        evaluator: mockEvaluator,
        ntfyServer: "http://127.0.0.1:59999",
        ntfyTopic: "test-runtime-sync-topic",
        notifyOnVerdict: false,
        evalDbFile,
      },
    );

    const expectedHash = crypto
      .createHash("sha256")
      .update(`${process.pid}:${workspaceDir}`)
      .digest("hex")
      .slice(0, 16);
    const expectedPath = path.join(runtimeDir, `opencode-${expectedHash}.json`);

    expect(adapter.getRuntimeSync().getStateFilePath()).toBe(expectedPath);
    expect(fs.existsSync(expectedPath)).toBe(false);

    await adapter.start();

    expect(fs.existsSync(expectedPath)).toBe(true);
    const state = readRuntimeState(expectedPath);
    expect(state.version).toBe(1);
    expect(state.pid).toBe(process.pid);
    expect(state.workspaceRoot).toBe(workspaceDir);
    expect(state.autoMode).toBe(true);
    expect(state.reviewFallbackMode).toBe("ntfy");
    expect(state.remoteReviewEnabled).toBe(true);
    expect(state.consecutiveBlocks).toBe(0);
    expect(state.consecutiveBlockThreshold).toBe(3);
    expect(state.evalDbFile).toBe(evalDbFile);
    expect(state.evalSessionCleanup).toBe("export-and-delete");
    expect("evalLogFile" in state).toBe(false);
    expect(state.inFlight).toEqual([]);
    expect(typeof state.startedAt).toBe("number");
    expect(typeof state.updatedAt).toBe("number");

    await adapter.dispose();
    expect(fs.existsSync(expectedPath)).toBe(false);
  });

  it("2. changing autoMode and reviewFallbackMode in config.json updates engine and runtime state", async () => {
    fs.writeFileSync(
      configFilePath,
      JSON.stringify({ autoMode: true, reviewFallbackMode: "ntfy" }),
      "utf8",
    );

    const mockEvaluator = new MockEvaluator();
    const replies: Array<{ requestID: string; decision: string }> = [];
    const adapter = new OpenCodeHarnessAdapter(
      {
        directory: workspaceDir,
        permission: {
          reply: async (args) => {
            replies.push({ requestID: args.requestID, decision: args.decision });
          },
        },
      },
      {
        evaluator: mockEvaluator,
        ntfyServer: "http://127.0.0.1:59999",
        ntfyTopic: "test-runtime-sync-topic",
        notifyOnVerdict: false,
        evalDbFile,
      },
    );

    await adapter.start();
    try {
      const statePath = adapter.getRuntimeSync().getStateFilePath();
      expect(adapter.getEngine().isEnabled()).toBe(true);
      expect(adapter.getEngine().getFallbackMode()).toBe("ntfy");

      // Update config.json on disk
      fs.writeFileSync(
        configFilePath,
        JSON.stringify({ autoMode: false, reviewFallbackMode: "native" }),
        "utf8",
      );

      adapter.getRuntimeSync().syncControlAndConfig();

      expect(adapter.getEngine().isEnabled()).toBe(false);
      expect(adapter.getEngine().getFallbackMode()).toBe("native");
      expect(adapter.getEngine().isRemoteReviewEnabled()).toBe(false);

      const updatedState = readRuntimeState(statePath);
      expect(updatedState.autoMode).toBe(false);
      expect(updatedState.reviewFallbackMode).toBe("native");
      expect(updatedState.remoteReviewEnabled).toBe(false);

      // Flip back to autoMode: true, reviewFallbackMode: "ntfy" before handlePermissionAsked
      fs.writeFileSync(
        configFilePath,
        JSON.stringify({ autoMode: true, reviewFallbackMode: "ntfy" }),
        "utf8",
      );

      mockEvaluator.nextResult = {
        verdict: "ALLOW",
        reason: "Safe read",
        risk_level: "LOW",
        user_authorization: "HIGH",
      };

      await adapter.handlePermissionAsked({
        id: "perm-cfg-1",
        sessionID: "ses-cfg-1",
        action: "read",
        metadata: { directory: workspaceDir, filepath: path.join(workspaceDir, "README.md") },
      });

      expect(adapter.getEngine().isEnabled()).toBe(true);
      expect(adapter.getEngine().getFallbackMode()).toBe("ntfy");
      expect(replies).toEqual([{ requestID: "perm-cfg-1", decision: "once" }]);

      const postEvalState = readRuntimeState(statePath);
      expect(postEvalState.autoMode).toBe(true);
      expect(postEvalState.reviewFallbackMode).toBe("ntfy");
      expect(postEvalState.inFlight).toEqual([]);
      expect(postEvalState.lastVerdict?.verdict).toBe("ALLOW");
      expect(postEvalState.lastVerdict?.sessionID).toBe("ses-cfg-1");
      expect(postEvalState.lastVerdict?.toolName).toBe("read");
    } finally {
      await adapter.dispose();
    }
  });

  it("3. writing resetCircuitBreakerAt in control.json resets consecutiveBlocks to 0 and updates runtime state", async () => {
    const mockEvaluator = new MockEvaluator();
    mockEvaluator.nextResult = {
      verdict: "BLOCK",
      reason: "Dangerous command",
      risk_level: "HIGH",
      user_authorization: "NONE",
    };

    // Pre-existing stale control timestamp from prior run should not consume future resets
    const staleTs = Date.now() - 60_000;
    fs.writeFileSync(controlFilePath, JSON.stringify({ resetCircuitBreakerAt: staleTs }), "utf8");

    const replies: Array<{ requestID: string; decision: string }> = [];
    const adapter = new OpenCodeHarnessAdapter(
      {
        directory: workspaceDir,
        permission: {
          reply: async (args) => {
            replies.push({ requestID: args.requestID, decision: args.decision });
          },
        },
      },
      {
        evaluator: mockEvaluator,
        ntfyServer: "http://127.0.0.1:59999",
        notifyOnVerdict: false,
        evalDbFile,
        consecutiveBlockThreshold: 2,
      },
    );

    await adapter.start();
    try {
      const statePath = adapter.getRuntimeSync().getStateFilePath();

      await adapter.handlePermissionAsked({
        id: "perm-blk-1",
        sessionID: "ses-blk-1",
        action: "bash",
        metadata: { directory: workspaceDir, command: "rm -rf /tmp/a" },
      });
      await adapter.handlePermissionAsked({
        id: "perm-blk-2",
        sessionID: "ses-blk-1",
        action: "bash",
        metadata: { directory: workspaceDir, command: "rm -rf /tmp/b" },
      });

      expect(adapter.getEngine().getConsecutiveBlocks()).toBe(2);
      expect(readRuntimeState(statePath).consecutiveBlocks).toBe(2);

      // Write fresh resetCircuitBreakerAt timestamp
      const freshTs = Math.max(Date.now(), staleTs + 1000);
      fs.writeFileSync(controlFilePath, JSON.stringify({ resetCircuitBreakerAt: freshTs }), "utf8");

      adapter.getRuntimeSync().syncControlAndConfig();

      expect(adapter.getEngine().getConsecutiveBlocks()).toBe(0);
      expect(readRuntimeState(statePath).consecutiveBlocks).toBe(0);
      expect(replies.length).toBe(2);
    } finally {
      await adapter.dispose();
    }
  });

  it("4. native fallback (reviewFallbackMode: native + UNSURE) does not call replyPermission", async () => {
    fs.writeFileSync(
      configFilePath,
      JSON.stringify({ autoMode: true, reviewFallbackMode: "native" }),
      "utf8",
    );

    const mockEvaluator = new MockEvaluator();
    mockEvaluator.nextResult = {
      verdict: "UNSURE",
      reason: "Needs manual review",
      risk_level: "MEDIUM",
      user_authorization: "LOW",
    };

    const replies: Array<{ requestID: string; decision: string; message?: string }> = [];
    const adapter = new OpenCodeHarnessAdapter(
      {
        directory: workspaceDir,
        permission: {
          reply: async (args) => {
            replies.push({
              requestID: args.requestID,
              decision: args.decision,
              message: args.message,
            });
          },
        },
      },
      {
        evaluator: mockEvaluator,
        ntfyServer: "http://127.0.0.1:59999",
        ntfyTopic: "test-runtime-sync-topic",
        notifyOnVerdict: false,
        evalDbFile,
      },
    );

    await adapter.start();
    try {
      const statePath = adapter.getRuntimeSync().getStateFilePath();
      expect(adapter.getEngine().getFallbackMode()).toBe("native");
      expect(adapter.getEngine().isRemoteReviewEnabled()).toBe(false);

      await adapter.handlePermissionAsked({
        id: "perm-native-1",
        sessionID: "ses-native-1",
        action: "bash",
        metadata: { directory: workspaceDir, command: "npm publish" },
      });

      expect(replies).toEqual([]);

      const state = readRuntimeState(statePath);
      expect(state.inFlight).toEqual([]);
      expect(state.lastVerdict?.verdict).toBe("UNSURE");
      expect(state.lastVerdict?.commandString).toBe("npm publish");
      expect(state.lastVerdict?.source).toBe("native-fallback");
    } finally {
      await adapter.dispose();
    }
  });

  it("5. tracks in-flight evaluation and awaiting-review transition and clears on handlePermissionReplied", async () => {
    const mockEvaluator = new MockEvaluator();
    mockEvaluator.delayMs = 40;
    mockEvaluator.nextResult = {
      verdict: "UNSURE",
      reason: "Ambiguous action",
      risk_level: "MEDIUM",
      user_authorization: "LOW",
    };

    const adapter = new OpenCodeHarnessAdapter(
      {
        directory: workspaceDir,
        permission: {
          reply: async () => {},
        },
      },
      {
        evaluator: mockEvaluator,
        ntfyServer: "http://127.0.0.1:59999",
        ntfyTopic: "test-runtime-sync-topic",
        notifyOnVerdict: false,
        evalDbFile,
        reviewFallbackMode: "ntfy",
      },
    );

    await adapter.start();
    try {
      const statePath = adapter.getRuntimeSync().getStateFilePath();
      const pendingEval = adapter.handlePermissionAsked({
        id: "perm-inflight-1",
        sessionID: "ses-inflight-1",
        action: "bash",
        metadata: { directory: workspaceDir, command: "curl https://example.com" },
      });

      // Wait briefly for evaluating stage
      await new Promise((resolve) => setTimeout(resolve, 15));
      const midState = readRuntimeState(statePath);
      expect(midState.inFlight.length).toBe(1);
      expect(midState.inFlight[0]?.id).toBe("perm-inflight-1");
      expect(midState.inFlight[0]?.stage).toBe("evaluating");

      // Wait for evaluator to finish and enter requestReview (awaiting-review)
      await new Promise((resolve) => setTimeout(resolve, 160));
      const reviewState = readRuntimeState(statePath);
      expect(reviewState.inFlight.length).toBe(1);
      expect(reviewState.inFlight[0]?.stage).toBe("awaiting-review");

      // Resolve via remote review response
      adapter.getEngine().resolveReviewResponse({
        req_id: "perm-inflight-1",
        reply: "once",
        source: "ntfy",
      });
      await pendingEval;

      const doneState = readRuntimeState(statePath);
      expect(doneState.inFlight).toEqual([]);
      expect(doneState.lastVerdict?.verdict).toBe("ALLOW");
      expect(doneState.lastVerdict?.source).toBe("remote");

      // Also verify handlePermissionReplied clears in-flight state cleanly
      await adapter.handlePermissionReplied({ requestID: "perm-inflight-1", reply: "once" });
      expect(readRuntimeState(statePath).inFlight).toEqual([]);
    } finally {
      await adapter.dispose();
    }
  });

  it("6. live config reload honors process.env overrides, dispose() is idempotent, and native reply resets circuit breaker", async () => {
    fs.writeFileSync(
      configFilePath,
      JSON.stringify({ autoMode: true, reviewFallbackMode: "ntfy" }),
      "utf8",
    );
    process.env.AUTOGATE_AUTO_MODE = "false";

    const mockEvaluator = new MockEvaluator();
    mockEvaluator.nextResult = {
      verdict: "BLOCK",
      reason: "Blocked",
      risk_level: "HIGH",
      user_authorization: "NONE",
    };

    const adapter1 = new OpenCodeHarnessAdapter(
      { directory: workspaceDir },
      {
        evaluator: mockEvaluator,
        ntfyServer: "http://127.0.0.1:59999",
        notifyOnVerdict: false,
        evalDbFile,
        consecutiveBlockThreshold: 1,
      },
    );

    await adapter1.start();
    const statePath = adapter1.getRuntimeSync().getStateFilePath();
    expect(adapter1.getEngine().isEnabled()).toBe(false);

    // Changing config.json while AUTOGATE_AUTO_MODE=false is set must NOT clobber env override
    fs.writeFileSync(
      configFilePath,
      JSON.stringify({ autoMode: true, reviewFallbackMode: "native" }),
      "utf8",
    );
    adapter1.getRuntimeSync().syncControlAndConfig();
    expect(adapter1.getEngine().isEnabled()).toBe(false);
    expect(adapter1.getEngine().getFallbackMode()).toBe("native");

    // Verify native fallback approval resets tripped circuit breaker
    delete process.env.AUTOGATE_AUTO_MODE;
    adapter1.getEngine().setEnabled(true);
    await adapter1.handlePermissionAsked({
      id: "perm-cb-1",
      sessionID: "ses-cb-1",
      action: "bash",
      metadata: { directory: workspaceDir, command: "rm -rf /tmp/x" },
    });
    expect(adapter1.getEngine().getConsecutiveBlocks()).toBe(1);

    await adapter1.handlePermissionAsked({
      id: "perm-cb-2",
      sessionID: "ses-cb-1",
      action: "bash",
      metadata: { directory: workspaceDir, command: "ls" },
    });
    // Native approval resets consecutiveBlocks
    await adapter1.handlePermissionReplied({ requestID: "perm-cb-2", reply: "once" });
    expect(adapter1.getEngine().getConsecutiveBlocks()).toBe(0);

    // Dispose adapter1, start adapter2 (same pid+workspace -> same statePath), then call adapter1.dispose() again
    await adapter1.dispose();
    const adapter2 = new OpenCodeHarnessAdapter(
      { directory: workspaceDir },
      {
        evaluator: mockEvaluator,
        ntfyServer: "http://127.0.0.1:59999",
        ntfyTopic: "test-runtime-sync-topic",
        notifyOnVerdict: false,
        evalDbFile,
      },
    );
    await adapter2.start();
    expect(fs.existsSync(statePath)).toBe(true);

    // Second dispose() on stale adapter1 must be a no-op and NOT delete adapter2's state file
    await adapter1.dispose();
    expect(fs.existsSync(statePath)).toBe(true);

    await adapter2.dispose();
    expect(fs.existsSync(statePath)).toBe(false);
  });

  it("7. disables ntfy and forces native fallback when ntfyTopic is omitted", async () => {
    fs.writeFileSync(
      configFilePath,
      JSON.stringify({ autoMode: true, reviewFallbackMode: "ntfy" }),
      "utf8",
    );

    const mockEvaluator = new MockEvaluator();
    const adapter = new OpenCodeHarnessAdapter(
      { directory: workspaceDir },
      {
        evaluator: mockEvaluator,
        ntfyServer: "http://127.0.0.1:59999",
        notifyOnVerdict: false,
        evalDbFile,
      },
    );

    await adapter.start();
    try {
      expect(adapter.getEngine().isRemoteReviewEnabled()).toBe(false);
      expect(adapter.getEngine().getFallbackMode()).toBe("native");

      adapter.getRuntimeSync().syncControlAndConfig();
      expect(adapter.getEngine().isRemoteReviewEnabled()).toBe(false);
      expect(adapter.getEngine().getFallbackMode()).toBe("native");

      const state = readRuntimeState(adapter.getRuntimeSync().getStateFilePath());
      expect(state.remoteReviewEnabled).toBe(false);
      expect(state.reviewFallbackMode).toBe("native");
    } finally {
      await adapter.dispose();
    }
  });

  it("8. hot-reloads evalSessionCleanup from config.json and respects AUTOGATE_EVAL_SESSION_CLEANUP env override", async () => {
    fs.writeFileSync(
      configFilePath,
      JSON.stringify({
        autoMode: true,
        reviewFallbackMode: "native",
        evalSessionCleanup: "export-and-delete",
      }),
      "utf8",
    );

    const mockEvaluator = new MockEvaluator();
    const adapter = new OpenCodeHarnessAdapter(
      { directory: workspaceDir },
      {
        evaluator: mockEvaluator,
        ntfyServer: "http://127.0.0.1:59999",
        notifyOnVerdict: false,
        evalDbFile,
      },
    );

    await adapter.start();
    try {
      const statePath = adapter.getRuntimeSync().getStateFilePath();
      expect(readRuntimeState(statePath).evalSessionCleanup).toBe("export-and-delete");

      fs.writeFileSync(
        configFilePath,
        JSON.stringify({
          autoMode: true,
          reviewFallbackMode: "native",
          evalSessionCleanup: "archive",
        }),
        "utf8",
      );
      adapter.getRuntimeSync().syncControlAndConfig();
      expect(readRuntimeState(statePath).evalSessionCleanup).toBe("archive");

      process.env.AUTOGATE_EVAL_SESSION_CLEANUP = "export-and-delete";
      fs.writeFileSync(
        configFilePath,
        JSON.stringify({
          autoMode: true,
          reviewFallbackMode: "native",
          evalSessionCleanup: "archive",
          consecutiveBlockThreshold: 4,
        }),
        "utf8",
      );
      adapter.getRuntimeSync().syncControlAndConfig();
      expect(readRuntimeState(statePath).evalSessionCleanup).toBe("export-and-delete");
    } finally {
      await adapter.dispose();
    }
  });
});
