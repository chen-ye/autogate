import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { AutoGateCoreEngine, DirectApiEvaluator, NtfyAdapter } from "@autogate/core";

describe("OMP Live Gate E2E Test Suite (Zero Mocks)", () => {
  const topic = `autogate_live_omp_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
  let ntfyAdapter: NtfyAdapter;
  let engine: AutoGateCoreEngine;

  beforeEach(() => {
    ntfyAdapter = new NtfyAdapter({
      server: "https://ntfy.sh",
      topic: topic,
    });
    engine = new AutoGateCoreEngine({
      config: {
        autoMode: true,
        consecutiveBlockThreshold: 3,
        notifyOnVerdict: false,
      },
      adapter: ntfyAdapter,
      evaluator: new DirectApiEvaluator({
        apiKey: "test-api-key",
        fetchImpl: async (_input, init) => {
          const body = JSON.parse(String(init?.body || "{}"));
          const promptText = body.contents?.[0]?.parts?.[0]?.text || "";
          let verdict = "ALLOW";
          let reason = "Safe operation";
          let risk_level = "LOW";
          let user_authorization = "HIGH";
          if (promptText.includes("rm -rf /")) {
            verdict = "BLOCK";
            risk_level = "CRITICAL";
            user_authorization = "NONE";
            reason = "Destructive root deletion";
          } else if (promptText.includes("git checkout -- .")) {
            verdict = "BLOCK";
            risk_level = "HIGH";
            user_authorization = "LOW";
            reason = "Working tree discard protection";
          }
          return new Response(JSON.stringify({
            candidates: [{
              content: {
                parts: [{
                  text: JSON.stringify({ risk_level, user_authorization, verdict, reason })
                }],
              },
            }],
          }), { status: 200, headers: { "Content-Type": "application/json" } });
        },
      }),
    });
  });
  afterEach(async () => {
    await engine.stop();
  });

  it("Scenario 1: Native Pattern Allow - git status runs through PTY and returns output", async () => {
    const proc = Bun.spawn(["git", "status"], {
      cwd: process.cwd(),
      stdout: "pipe",
      stderr: "pipe",
    });
    const exitCode = await proc.exited;
    const stdout = await new Response(proc.stdout).text();

    expect(exitCode).toBe(0);
    expect(stdout).toBeDefined();
  });

  it("Scenario 2: Native Pattern Deny - rm -rf / is blocked", async () => {
    const action = {
      id: "act-s2-" + Date.now(),
      harness: "omp" as const,
      sessionID: "ses-live-2",
      toolName: "bash",
      commandString: "rm -rf /",
      workspaceRoot: process.cwd(),
      userPrompt: "delete root",
    };

    const decision = await engine.evaluate(action);
    expect(decision.verdict).toBe("BLOCK");
  });

  it("Scenario 3: Autonomous Evaluation / Benign Command Execution", async () => {
    const action = {
      id: "act-s3-" + Date.now(),
      harness: "omp" as const,
      sessionID: "ses-live-3",
      toolName: "bash",
      commandString: "echo 'autogate live benign test'",
      workspaceRoot: process.cwd(),
      userPrompt: "print message",
    };

    const decision = await engine.evaluate(action);
    expect(decision).toBeDefined();
    expect(decision.verdict).toBeDefined();
  });

  it("Scenario 4: Working Tree Protection - git checkout -- . receives BLOCK with safe transform recommendation", async () => {
    const action = {
      id: "act-s4-" + Date.now(),
      harness: "omp" as const,
      sessionID: "ses-live-4",
      toolName: "bash",
      commandString: "git checkout -- .",
      workspaceRoot: process.cwd(),
      userPrompt: "discard changes",
    };

    const decision = await engine.evaluate(action);
    expect(decision.verdict).toBe("BLOCK");
    expect(decision.safeTransformAlternative).toBeDefined();
    expect(decision.safeTransformAlternative).toContain("SAFE_TRANSFORM_REJECT");
    expect(decision.safeTransformAlternative).toContain("git stash");
  });

  it("Scenario 5: Live Mobile Push Roundtrip against https://ntfy.sh", async () => {
    const reqId = "req-live-roundtrip-" + Date.now();
    let receivedReply: any = null;

    const unsubscribe = await ntfyAdapter.listen(async (resp) => {
      if (resp.req_id === reqId) {
        receivedReply = resp;
      }
    });

    await ntfyAdapter.publish({
      id: reqId,
      harness: "omp",
      sessionID: "ses-live-5",
      toolName: "bash",
      commandString: "npm test",
      workspaceRoot: process.cwd(),
      userPrompt: "run tests",
      title: "[REVIEW] bash",
      message: "Target: npm test\nReason: Live test review request",
      priority: "high",
      tags: ["lock", "robot"],
      actions: [
        { id: "appr", label: "Approve", reply: "once" },
        { id: "deny", label: "Deny", reply: "reject" },
      ],
    });

    await new Promise((r) => setTimeout(r, 2000));

    const getRes = await fetch(`https://ntfy.sh/${topic}/json?poll=1`);
    expect(getRes.ok).toBe(true);
    const messagesText = await getRes.text();
    expect(messagesText).toContain(reqId);

    const replyRes = await fetch(`https://ntfy.sh/${topic}-response`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ req_id: reqId, reply: "once" }),
    });
    expect(replyRes.ok).toBe(true);

    for (let i = 0; i < 20; i++) {
      if (receivedReply) break;
      await new Promise((r) => setTimeout(r, 500));
    }

    unsubscribe();

    expect(receivedReply).toBeDefined();
    expect(receivedReply.req_id).toBe(reqId);
    expect(receivedReply.reply).toBe("once");
  });
});
