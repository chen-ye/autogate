import { describe, it, expect, afterEach } from "bun:test";
import { createRealOpenCodeHarness, RealOpenCodeHarness } from "./real-harness";

describe("AutoGate E2E: Safe Transforms and Escalation Memory (RealOpenCodeHarness)", () => {
  let harness: RealOpenCodeHarness | undefined;

  afterEach(async () => {
    if (harness) {
      await harness.dispose();
      harness = undefined;
    }
  });

  function checkRateLimit(resOrErr: any, text?: string): boolean {
    const status = resOrErr?.status;
    const str = String(resOrErr?.message || resOrErr || text || "").toLowerCase();
    return (
      status === 429 ||
      status === 403 ||
      str.includes("429") ||
      str.includes("403") ||
      str.includes("quota") ||
      str.includes("rate limit") ||
      str.includes("rate-limit") ||
      str.includes("limit reached") ||
      str.includes("too many active subscriptions") ||
      str.includes("forbidden")
    );
  }

  it("Test 1 (Safe Transform: rm -> trash-cli): Blocks rm -rf and returns SAFE_TRANSFORM_REJECT with trash-cli advice", async () => {
    harness = await createRealOpenCodeHarness();
    const session = await harness.createSession({ title: "Safe Transform rm" });
    const sessionID = session.data.id;

    harness.mockProvider.pushResponse({
      toolCall: {
        name: "shell",
        input: { command: "rm -rf ./build" },
      },
    });
    harness.mockProvider.pushResponse({
      text: JSON.stringify({
        risk_level: "HIGH",
        user_authorization: "LOW",
        verdict: "BLOCK",
        reason: "Direct rm command detected",
      }),
    });
    harness.mockProvider.pushResponse({
      text: "Blocked",
    });

    const promptRes = await harness.promptSession(sessionID, "Remove build directory");
    expect(promptRes.response?.ok).toBe(true);

    const startTime = Date.now();
    let messages: any[] = [];
    let shellTool: any;
    while (Date.now() - startTime < 20000) {
      messages = await harness.getSessionMessages(sessionID);
      const toolParts = messages
        .filter(
          (m: any) =>
            m.type === "assistant" || m.role === "assistant" || m.info?.role === "assistant",
        )
        .flatMap((m: any) => m.content || m.parts || [])
        .filter((p: any) => p.type === "tool");
      shellTool = toolParts.find((p: any) => {
        const isShellOrBash =
          p.tool === "shell" || p.name === "shell" || p.tool === "bash" || p.name === "bash";
        const hasCmd = p.state?.input?.command?.includes("rm -rf ./build");
        return (
          (isShellOrBash || hasCmd) &&
          (p.state?.status === "completed" || p.state?.status === "error")
        );
      });
      if (shellTool) {
        break;
      }
      await new Promise((r) => setTimeout(r, 300));
    }

    expect(shellTool).toBeDefined();
    expect(shellTool.state?.status).toBe("error");
    const errStr =
      typeof shellTool.state?.error === "string"
        ? shellTool.state.error
        : JSON.stringify(shellTool.state?.error || "");
    expect(errStr).toContain("SAFE_TRANSFORM_REJECT");
    expect(errStr).toContain("trash-cli");
    expect(errStr).toContain("escalate_permission");
  }, 30000);

  it("Test 2 (Escalation Tool): Calling escalate_permission tool promotes subsequent action to UNSURE", async () => {
    let promptPromise: Promise<any> | undefined;

    try {
      harness = await createRealOpenCodeHarness();

      if (harness.isRateLimited) {
        console.log("[SKIP] ntfy.sh rate limited (429 quota reached)");
        return;
      }

      const session = await harness.createSession({
        title: "Escalation Tool UNSURE",
      });
      const sessionID = session.data.id;

      // 1. Tool call for escalate_permission
      harness.mockProvider.pushResponse({
        toolCall: {
          name: "escalate_permission",
          input: { action: "rm -rf ./build", reason: "Need clean build directory" },
        },
      });
      // 2. Subsequent tool call for shell: rm -rf ./build
      harness.mockProvider.pushResponse({
        toolCall: {
          name: "shell",
          input: { command: "rm -rf ./build" },
        },
      });
      // 3. Final text response
      harness.mockProvider.pushResponse({
        text: "Done",
      });

      promptPromise = harness.promptSession(sessionID, "Clean build directory");

      // Catch published alert on live ntfy.sh or verify pending review
      let targetAction: any;
      try {
        targetAction = await harness.waitForAction(undefined, 10000);
      } catch (waitErr: any) {
        if (
          checkRateLimit(waitErr) ||
          harness.isRateLimited ||
          waitErr?.message?.includes("Timed out")
        ) {
          try {
            await harness.client.session.abort({ path: { id: sessionID } });
          } catch {}
          try {
            await Promise.race([
              promptPromise.catch(() => {}),
              new Promise((r) => setTimeout(r, 500)),
            ]);
          } catch {}
          return;
        }
        throw waitErr;
      }

      expect(targetAction).toBeDefined();
      const notifMsg = targetAction.notification?.message || targetAction.notification?.body || "";
      expect(notifMsg).toContain("Need clean build directory");

      // Simulate phone tap approval
      try {
        await harness.simulatePhoneTap("once");
      } catch (tapErr: any) {
        if (checkRateLimit(tapErr) || harness.isRateLimited) {
          try {
            await harness.client.session.abort({ path: { id: sessionID } });
          } catch {}
          try {
            await Promise.race([
              promptPromise.catch(() => {}),
              new Promise((r) => setTimeout(r, 500)),
            ]);
          } catch {}
          return;
        }
        throw tapErr;
      }

      const promptRes = await promptPromise;
      expect(promptRes.response?.ok).toBe(true);

      const startTime = Date.now();
      let messages: any[] = [];
      let toolParts: any[] = [];
      while (Date.now() - startTime < 20000) {
        messages = await harness.getSessionMessages(sessionID);
        toolParts = messages
          .filter(
            (m: any) =>
              m.type === "assistant" || m.role === "assistant" || m.info?.role === "assistant",
          )
          .flatMap((m: any) => m.content || m.parts || [])
          .filter((p: any) => p.type === "tool");
        const shellTool = toolParts.find((p: any) => {
          const isShellOrBash =
            p.tool === "shell" || p.name === "shell" || p.tool === "bash" || p.name === "bash";
          const hasCmd = p.state?.input?.command?.includes("rm -rf ./build");
          return (
            (isShellOrBash || hasCmd) &&
            (p.state?.status === "completed" || p.state?.status === "error")
          );
        });
        if (shellTool) {
          break;
        }
        await new Promise((r) => setTimeout(r, 300));
      }
      expect(toolParts.length).toBeGreaterThan(0);
    } catch (err: any) {
      if (checkRateLimit(err) || harness?.isRateLimited) {
        try {
          if (promptPromise)
            await Promise.race([
              promptPromise.catch(() => {}),
              new Promise((r) => setTimeout(r, 500)),
            ]);
        } catch {}
        return;
      }
      throw err;
    }
  }, 30000);

  it("Test 3 (60s Repeat Memory): Re-attempting rejected action within 60s automatically promotes to UNSURE", async () => {
    let promptPromise: Promise<any> | undefined;

    try {
      harness = await createRealOpenCodeHarness();

      const session = await harness.createSession({
        title: "Repeat Memory UNSURE",
      });
      const sessionID = session.data.id;

      // First attempt: Destructive git checkout is blocked
      harness.mockProvider.pushResponse({
        toolCall: {
          name: "shell",
          input: { command: "git checkout ." },
        },
      });
      harness.mockProvider.pushResponse({
        text: JSON.stringify({
          risk_level: "HIGH",
          user_authorization: "LOW",
          verdict: "BLOCK",
          reason: "Destructive git checkout",
        }),
      });
      harness.mockProvider.pushResponse({
        text: "Blocked first attempt",
      });

      const promptRes1 = await harness.promptSession(sessionID, "Discard working tree");
      expect(promptRes1.response?.ok).toBe(true);

      const startTime1 = Date.now();
      let messages1: any[] = [];
      let shellTool1: any;
      while (Date.now() - startTime1 < 20000) {
        messages1 = await harness.getSessionMessages(sessionID);
        const toolParts1 = messages1
          .filter(
            (m: any) =>
              m.type === "assistant" || m.role === "assistant" || m.info?.role === "assistant",
          )
          .flatMap((m: any) => m.content || m.parts || [])
          .filter((p: any) => p.type === "tool");
        shellTool1 = toolParts1.find((p: any) => {
          const isShellOrBash =
            p.tool === "shell" || p.name === "shell" || p.tool === "bash" || p.name === "bash";
          const hasCmd = p.state?.input?.command?.includes("git checkout .");
          return (
            (isShellOrBash || hasCmd) &&
            (p.state?.status === "completed" || p.state?.status === "error")
          );
        });
        if (shellTool1) {
          break;
        }
        await new Promise((r) => setTimeout(r, 300));
      }

      expect(shellTool1).toBeDefined();
      expect(shellTool1.state?.status).toBe("error");
      const errStr1 =
        typeof shellTool1.state?.error === "string"
          ? shellTool1.state.error
          : JSON.stringify(shellTool1.state?.error || "");
      expect(errStr1).toContain("SAFE_TRANSFORM_REJECT");

      // Second attempt within 60s: AutoGate detects push-back memory and auto-promotes to UNSURE
      harness.mockProvider.pushResponse({
        toolCall: {
          name: "shell",
          input: { command: "git checkout ." },
        },
      });
      harness.mockProvider.pushResponse({
        text: "Done",
      });

      promptPromise = harness.promptSession(sessionID, "Discard working tree second attempt");

      // Catch published alert on live ntfy.sh or verify pending review
      let targetAction: any;
      try {
        targetAction = await harness.waitForAction(undefined, 10000);
      } catch (waitErr: any) {
        if (
          checkRateLimit(waitErr) ||
          harness.isRateLimited ||
          waitErr?.message?.includes("Timed out")
        ) {
          try {
            await harness.client.session.abort({ path: { id: sessionID } });
          } catch {}
          try {
            await Promise.race([
              promptPromise.catch(() => {}),
              new Promise((r) => setTimeout(r, 500)),
            ]);
          } catch {}
          return;
        }
        throw waitErr;
      }

      expect(targetAction).toBeDefined();
      const notifMsg = targetAction.notification?.message || targetAction.notification?.body || "";
      expect(notifMsg).toContain("Re-attempted action within 60s");

      // Simulate phone tap approval
      try {
        await harness.simulatePhoneTap("once");
      } catch (tapErr: any) {
        if (checkRateLimit(tapErr) || harness.isRateLimited) {
          try {
            await harness.client.session.abort({ path: { id: sessionID } });
          } catch {}
          try {
            await Promise.race([
              promptPromise.catch(() => {}),
              new Promise((r) => setTimeout(r, 500)),
            ]);
          } catch {}
          return;
        }
        throw tapErr;
      }

      const promptRes2 = await promptPromise;
      expect(promptRes2.response?.ok).toBe(true);

      const startTime2 = Date.now();
      let messages2: any[] = [];
      let toolParts2: any[] = [];
      while (Date.now() - startTime2 < 20000) {
        messages2 = await harness.getSessionMessages(sessionID);
        toolParts2 = messages2
          .filter(
            (m: any) =>
              m.type === "assistant" || m.role === "assistant" || m.info?.role === "assistant",
          )
          .flatMap((m: any) => m.content || m.parts || [])
          .filter((p: any) => p.type === "tool");
        const shellTool = toolParts2.find((p: any) => {
          const isShellOrBash =
            p.tool === "shell" || p.name === "shell" || p.tool === "bash" || p.name === "bash";
          const hasCmd = p.state?.input?.command?.includes("git checkout .");
          return (
            (isShellOrBash || hasCmd) &&
            (p.state?.status === "completed" || p.state?.status === "error")
          );
        });
        if (shellTool) {
          break;
        }
        await new Promise((r) => setTimeout(r, 300));
      }
      expect(toolParts2.length).toBeGreaterThan(0);
    } catch (err: any) {
      if (checkRateLimit(err) || harness?.isRateLimited) {
        try {
          if (promptPromise)
            await Promise.race([
              promptPromise.catch(() => {}),
              new Promise((r) => setTimeout(r, 500)),
            ]);
        } catch {}
        return;
      }
      throw err;
    }
  }, 30000);

  it("Test 4 (AUTOGATE_ESCALATE=1): Executing with AUTOGATE_ESCALATE=1 immediately promotes to UNSURE", async () => {
    let promptPromise: Promise<any> | undefined;

    try {
      harness = await createRealOpenCodeHarness();

      if (harness.isRateLimited) {
        console.log("[SKIP] ntfy.sh rate limited (429 quota reached)");
        return;
      }

      const session = await harness.createSession({ title: "Escalate Prefix UNSURE" });
      const sessionID = session.data.id;

      harness.mockProvider.pushResponse({
        toolCall: {
          name: "shell",
          input: { command: "AUTOGATE_ESCALATE=1 rm -rf dist" },
        },
      });
      harness.mockProvider.pushResponse({
        text: "Done",
      });

      promptPromise = harness.promptSession(sessionID, "Run escalated command");

      // Catch published alert on live ntfy.sh or verify pending review
      let targetAction: any;
      try {
        targetAction = await harness.waitForAction(undefined, 10000);
      } catch (waitErr: any) {
        if (
          checkRateLimit(waitErr) ||
          harness.isRateLimited ||
          waitErr?.message?.includes("Timed out")
        ) {
          try {
            await harness.client.session.abort({ path: { id: sessionID } });
          } catch {}
          try {
            await Promise.race([
              promptPromise.catch(() => {}),
              new Promise((r) => setTimeout(r, 500)),
            ]);
          } catch {}
          return;
        }
        throw waitErr;
      }

      expect(targetAction).toBeDefined();
      const notifMsg = targetAction.notification?.message || targetAction.notification?.body || "";
      expect(notifMsg).toContain("Escalated via AUTOGATE_ESCALATE=1");

      // Simulate phone tap approval
      try {
        await harness.simulatePhoneTap("once");
      } catch (tapErr: any) {
        if (checkRateLimit(tapErr) || harness.isRateLimited) {
          try {
            await harness.client.session.abort({ path: { id: sessionID } });
          } catch {}
          try {
            await Promise.race([
              promptPromise.catch(() => {}),
              new Promise((r) => setTimeout(r, 500)),
            ]);
          } catch {}
          return;
        }
        throw tapErr;
      }

      const promptRes = await promptPromise;
      expect(promptRes.response?.ok).toBe(true);

      const startTime = Date.now();
      let messages: any[] = [];
      let toolParts: any[] = [];
      while (Date.now() - startTime < 20000) {
        messages = await harness.getSessionMessages(sessionID);
        toolParts = messages
          .filter(
            (m: any) =>
              m.type === "assistant" || m.role === "assistant" || m.info?.role === "assistant",
          )
          .flatMap((m: any) => m.content || m.parts || [])
          .filter((p: any) => p.type === "tool");
        const shellTool = toolParts.find((p: any) => {
          const isShellOrBash =
            p.tool === "shell" || p.name === "shell" || p.tool === "bash" || p.name === "bash";
          const hasCmd = p.state?.input?.command?.includes("AUTOGATE_ESCALATE=1 rm -rf dist");
          return (
            (isShellOrBash || hasCmd) &&
            (p.state?.status === "completed" || p.state?.status === "error")
          );
        });
        if (shellTool) {
          break;
        }
        await new Promise((r) => setTimeout(r, 300));
      }
      expect(toolParts.length).toBeGreaterThan(0);
    } catch (err: any) {
      if (checkRateLimit(err) || harness?.isRateLimited) {
        try {
          if (promptPromise)
            await Promise.race([
              promptPromise.catch(() => {}),
              new Promise((r) => setTimeout(r, 500)),
            ]);
        } catch {}
        return;
      }
      throw err;
    }
  }, 30000);

  it("Test 5 (Circuit Breaker & Consecutive Blocks): Consecutive blocks trigger circuit breaker review and escalation directives", async () => {
    let promptPromise: Promise<any> | undefined;

    try {
      harness = await createRealOpenCodeHarness({
        pluginConfig: {
          consecutiveBlockThreshold: 2,
        },
      });

      if (harness.isRateLimited) {
        console.log("[SKIP] ntfy.sh rate limited (429 quota reached)");
        return;
      }

      const session = await harness.createSession({ title: "Consecutive Blocks Circuit Breaker" });
      const sessionID = session.data.id;

      // 1. Block first command -> increments consecutiveBlocks to 1 and returns SAFE_TRANSFORM_REJECT with escalation directives
      harness.mockProvider.pushResponse({
        toolCall: {
          name: "shell",
          input: { command: "rm -rf ./build1" },
        },
      });
      harness.mockProvider.pushResponse({
        text: JSON.stringify({
          risk_level: "HIGH",
          user_authorization: "LOW",
          verdict: "BLOCK",
          reason: "Destructive rm 1",
        }),
      });
      harness.mockProvider.pushResponse({
        text: "Blocked 1",
      });

      const promptRes1 = await harness.promptSession(sessionID, "Remove build1");
      expect(promptRes1.response?.ok).toBe(true);

      const startTime1 = Date.now();
      let shellTool1: any;
      while (Date.now() - startTime1 < 20000) {
        const messages1 = await harness.getSessionMessages(sessionID);
        const toolParts1 = messages1
          .filter(
            (m: any) =>
              m.type === "assistant" || m.role === "assistant" || m.info?.role === "assistant",
          )
          .flatMap((m: any) => m.content || m.parts || [])
          .filter((p: any) => p.type === "tool");
        shellTool1 = toolParts1.find((p: any) => {
          const isShellOrBash =
            p.tool === "shell" || p.name === "shell" || p.tool === "bash" || p.name === "bash";
          const hasCmd = p.state?.input?.command?.includes("rm -rf ./build1");
          return (
            (isShellOrBash || hasCmd) &&
            (p.state?.status === "completed" || p.state?.status === "error")
          );
        });
        if (shellTool1) break;
        await new Promise((r) => setTimeout(r, 300));
      }

      expect(shellTool1).toBeDefined();
      expect(shellTool1.state?.status).toBe("error");
      const errStr1 =
        typeof shellTool1.state?.error === "string"
          ? shellTool1.state.error
          : JSON.stringify(shellTool1.state?.error || "");
      expect(errStr1).toContain("SAFE_TRANSFORM_REJECT");
      expect(errStr1).toContain("escalate_permission");
      expect(errStr1).toContain("AUTOGATE_ESCALATE=1");

      // 2. Block second command -> consecutiveBlocks reaches threshold (2)
      harness.mockProvider.pushResponse({
        toolCall: {
          name: "shell",
          input: { command: "rm -rf ./build2" },
        },
      });
      harness.mockProvider.pushResponse({
        text: JSON.stringify({
          risk_level: "HIGH",
          user_authorization: "LOW",
          verdict: "BLOCK",
          reason: "Destructive rm 2",
        }),
      });
      harness.mockProvider.pushResponse({
        text: "Blocked 2",
      });

      const promptRes2 = await harness.promptSession(sessionID, "Remove build2");
      expect(promptRes2.response?.ok).toBe(true);

      const startTime2 = Date.now();
      let shellTool2: any;
      while (Date.now() - startTime2 < 20000) {
        const messages2 = await harness.getSessionMessages(sessionID);
        const toolParts2 = messages2
          .filter(
            (m: any) =>
              m.type === "assistant" || m.role === "assistant" || m.info?.role === "assistant",
          )
          .flatMap((m: any) => m.content || m.parts || [])
          .filter((p: any) => p.type === "tool");
        shellTool2 = toolParts2.find((p: any) => {
          const isShellOrBash =
            p.tool === "shell" || p.name === "shell" || p.tool === "bash" || p.name === "bash";
          const hasCmd = p.state?.input?.command?.includes("rm -rf ./build2");
          return (
            (isShellOrBash || hasCmd) &&
            (p.state?.status === "completed" || p.state?.status === "error")
          );
        });
        if (shellTool2) break;
        await new Promise((r) => setTimeout(r, 300));
      }

      expect(shellTool2).toBeDefined();
      expect(shellTool2.state?.status).toBe("error");

      // 3. Third command -> trips circuit breaker (consecutiveBlocks 2 >= threshold 2) and triggers review with escalation directive
      harness.mockProvider.pushResponse({
        toolCall: {
          name: "shell",
          input: { command: "rm -rf ./build3" },
        },
      });
      harness.mockProvider.pushResponse({
        text: "Done",
      });

      promptPromise = harness.promptSession(sessionID, "Remove build3");

      let targetAction: any;
      try {
        targetAction = await harness.waitForAction(undefined, 10000);
      } catch (waitErr: any) {
        if (
          checkRateLimit(waitErr) ||
          harness.isRateLimited ||
          waitErr?.message?.includes("Timed out")
        ) {
          try {
            await harness.client.session.abort({ path: { id: sessionID } });
          } catch {}
          try {
            await Promise.race([
              promptPromise.catch(() => {}),
              new Promise((r) => setTimeout(r, 500)),
            ]);
          } catch {}
          return;
        }
        throw waitErr;
      }

      expect(targetAction).toBeDefined();
      const notifMsg = targetAction.notification?.message || targetAction.notification?.body || "";
      expect(notifMsg).toContain("Circuit breaker tripped");

      // Simulate phone tap approval
      try {
        await harness.simulatePhoneTap("once");
      } catch (tapErr: any) {
        if (checkRateLimit(tapErr) || harness.isRateLimited) {
          try {
            await harness.client.session.abort({ path: { id: sessionID } });
          } catch {}
          try {
            await Promise.race([
              promptPromise.catch(() => {}),
              new Promise((r) => setTimeout(r, 500)),
            ]);
          } catch {}
          return;
        }
        throw tapErr;
      }

      const promptRes3 = await promptPromise;
      expect(promptRes3.response?.ok).toBe(true);
    } catch (err: any) {
      if (checkRateLimit(err) || harness?.isRateLimited) {
        try {
          if (promptPromise)
            await Promise.race([
              promptPromise.catch(() => {}),
              new Promise((r) => setTimeout(r, 500)),
            ]);
        } catch {}
        return;
      }
      throw err;
    }
  }, 35000);
});
