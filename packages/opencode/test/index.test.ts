import { describe, it, expect, beforeEach, afterEach, spyOn } from "bun:test";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import {
  sharedExplicitEscalations,
  sharedRecentlyRejected,
  type GateEvaluator,
} from "@autogate/core";
import {
  resolveServerPassword,
  resolveCurrentProcessServiceUrl,
  formatOpenCodePromptHierarchy,
  isEventForWorkspace,
  OpenCodeHarnessAdapter,
  plugin,
} from "../src/index.js";
import {
  evaluationSessions,
  registerEvaluationSession,
  clearEvaluationSession,
} from "../src/evaluator.js";

describe("@autogate/opencode resolveServerPassword", () => {
  const origEnv = { ...process.env };
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "autogate-opencode-test-"));
    delete process.env.OPENCODE_CONFIG_DIR;
    delete process.env.OPENCODE_SERVER_PASSWORD;
    delete process.env.OPENCODE_PASSWORD;
    delete process.env.XDG_CONFIG_HOME;
    delete process.env.XDG_STATE_HOME;
  });

  afterEach(() => {
    process.env = { ...origEnv };
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  });

  it("prioritizes service.json over OPENCODE_SERVER_PASSWORD when service.json exists", () => {
    process.env.OPENCODE_CONFIG_DIR = tempDir;
    fs.writeFileSync(
      path.join(tempDir, "service.json"),
      JSON.stringify({ password: "service-json-password" }),
    );
    process.env.OPENCODE_SERVER_PASSWORD = "env-server-password";

    expect(resolveServerPassword()).toBe("service-json-password");
  });

  it("falls back to OPENCODE_SERVER_PASSWORD and OPENCODE_PASSWORD when service.json is absent", () => {
    process.env.OPENCODE_CONFIG_DIR = tempDir;
    process.env.OPENCODE_SERVER_PASSWORD = "env-server-password";
    expect(resolveServerPassword()).toBe("env-server-password");

    delete process.env.OPENCODE_SERVER_PASSWORD;
    process.env.OPENCODE_PASSWORD = "env-password";
    expect(resolveServerPassword()).toBe("env-password");
  });

  it("resolves password from service.json in OPENCODE_CONFIG_DIR when env vars are unset", () => {
    process.env.OPENCODE_CONFIG_DIR = tempDir;
    fs.writeFileSync(
      path.join(tempDir, "service.json"),
      JSON.stringify({ password: "  config-dir-pw-123  " }),
    );

    expect(resolveServerPassword()).toBe("config-dir-pw-123");
  });

  it("resolves password from service.json in explicitly passed configDir", () => {
    fs.writeFileSync(
      path.join(tempDir, "service.json"),
      JSON.stringify({ password: "explicit-config-dir-pw" }),
    );

    expect(resolveServerPassword(tempDir)).toBe("explicit-config-dir-pw");
  });

  it("resolves password from service.json in default config dir when env vars and OPENCODE_CONFIG_DIR are unset", () => {
    const defaultDir = path.join(tempDir, ".config", "opencode");
    fs.mkdirSync(defaultDir, { recursive: true });
    fs.writeFileSync(
      path.join(defaultDir, "service.json"),
      JSON.stringify({ password: "default-config-pw" }),
    );

    const homedirSpy = spyOn(os, "homedir").mockReturnValue(tempDir);
    try {
      expect(resolveServerPassword()).toBe("default-config-pw");
    } finally {
      homedirSpy.mockRestore();
    }
  });

  it("resolves password from service.json in XDG_CONFIG_HOME when env vars and OPENCODE_CONFIG_DIR are unset", () => {
    const xdgDir = path.join(tempDir, "xdg-config");
    const opencodeDir = path.join(xdgDir, "opencode");
    fs.mkdirSync(opencodeDir, { recursive: true });
    fs.writeFileSync(
      path.join(opencodeDir, "service.json"),
      JSON.stringify({ password: "xdg-password" }),
    );
    process.env.XDG_CONFIG_HOME = xdgDir;

    const homedirSpy = spyOn(os, "homedir").mockReturnValue(tempDir);
    try {
      expect(resolveServerPassword()).toBe("xdg-password");
    } finally {
      homedirSpy.mockRestore();
    }
  });

  it("returns empty string when no env var and no service.json exists", () => {
    const homedirSpy = spyOn(os, "homedir").mockReturnValue(tempDir);
    try {
      expect(resolveServerPassword()).toBe("");
    } finally {
      homedirSpy.mockRestore();
    }
  });

  it("returns empty string when service.json has empty or invalid password", () => {
    process.env.OPENCODE_CONFIG_DIR = tempDir;
    fs.writeFileSync(path.join(tempDir, "service.json"), JSON.stringify({ password: "   " }));

    expect(resolveServerPassword()).toBe("");
  });
});

describe("@autogate/opencode isEventForWorkspace", () => {
  it("matches workspace correctly", () => {
    expect(isEventForWorkspace({}, undefined)).toBe(true);
    expect(
      isEventForWorkspace({ location: { directory: "/home/user/project" } }, "/home/user/project"),
    ).toBe(true);
    expect(
      isEventForWorkspace({ location: { directory: "/other/dir" } }, "/home/user/project"),
    ).toBe(false);
  });
});

describe("@autogate/opencode runtime agent injection", () => {
  it("registers auto-gate-eval via ctx.agent.transform in OpenCode v2 setup without filesystem symlink", async () => {
    const updatedAgents: Record<string, Record<string, unknown>> = {};
    const cleanup = await plugin.setup({
      directory: "/tmp/test-ws",
      options: {
        classifierModel: "google/gemini-3.5-flash-lite",
        ntfyServer: "http://127.0.0.1:59999",
      },
      agent: {
        transform: async (
          fn: (editor: {
            update: (id: string, cb: (draft: Record<string, unknown>) => void) => void;
          }) => void,
        ) => {
          fn({
            update(id, cb) {
              const draft: Record<string, unknown> = {};
              cb(draft);
              updatedAgents[id] = draft;
            },
          });
        },
      },
    });

    try {
      const evalAgent = updatedAgents["auto-gate-eval"];
      expect(evalAgent).toBeDefined();
      expect(evalAgent?.name).toBe("auto-gate-eval");
      expect(evalAgent?.description).toBe("Autonomous security evaluation classifier for AutoGate");
      expect(evalAgent?.mode).toBe("subagent");
      expect(evalAgent?.hidden).toBe(true);
      expect(evalAgent?.steps).toBe(3);
      expect(evalAgent?.model).toEqual({
        providerID: "google",
        id: "gemini-3.5-flash-lite",
      });
      expect(evalAgent?.request).toEqual({
        body: {
          temperature: 0.1,
        },
      });
      expect(evalAgent?.permissions).toEqual([
        { action: "*", resource: "*", effect: "deny" },
        { action: "classify_result", resource: "*", effect: "allow" },
      ]);
      expect(typeof evalAgent?.system).toBe("string");
      expect(String(evalAgent?.system ?? "").length).toBeGreaterThan(100);
    } finally {
      if (typeof cleanup === "function") await cleanup();
    }
  });

  it("allows classifierModel option with #variant to override auto-gate-eval.md default model", async () => {
    const updatedAgents: Record<string, Record<string, unknown>> = {};
    const cleanup = await plugin.setup({
      directory: "/tmp/test-ws-override",
      options: {
        classifierModel: "anthropic/claude-haiku-4-5#low",
        ntfyServer: "http://127.0.0.1:59999",
      },
      agent: {
        transform: async (
          fn: (editor: {
            update: (id: string, cb: (draft: Record<string, unknown>) => void) => void;
          }) => void,
        ) => {
          fn({
            update(id, cb) {
              const draft: Record<string, unknown> = {
                request: { headers: { "x-existing": "1" }, body: { maxTokens: 500 } },
              };
              cb(draft);
              updatedAgents[id] = draft;
            },
          });
        },
      },
    });

    try {
      const evalAgent = updatedAgents["auto-gate-eval"];
      expect(evalAgent?.model).toEqual({
        providerID: "anthropic",
        id: "claude-haiku-4-5",
        variant: "low",
      });
      expect(evalAgent?.request).toEqual({
        headers: { "x-existing": "1" },
        body: { maxTokens: 500, temperature: 0.1 },
      });
    } finally {
      if (typeof cleanup === "function") await cleanup();
    }
  });
});

describe("@autogate/opencode escalate_permission v2", () => {
  const origEnv = { ...process.env };
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "autogate-esc-v2-"));
    process.env.XDG_CONFIG_HOME = path.join(tempDir, "xdg");
    fs.mkdirSync(path.join(process.env.XDG_CONFIG_HOME, "autogate"), { recursive: true });
    delete process.env.AUTOGATE_CONFIG;
    delete process.env.AUTOGATE_FALLBACK;
    delete process.env.NTFY_TOPIC;
    delete process.env.AUTOGATE_NTFY_TOPIC;
    delete process.env.OPENCODE_NTFY_TOPIC;
    sharedExplicitEscalations.clear();
    sharedRecentlyRejected.clear();
  });

  afterEach(() => {
    process.env = { ...origEnv };
    sharedExplicitEscalations.clear();
    sharedRecentlyRejected.clear();
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  it("reports native vs ntfy delivery mode in escalate_permission tool response", async () => {
    const configPath = path.join(process.env.XDG_CONFIG_HOME!, "autogate", "config.json");
    fs.writeFileSync(configPath, JSON.stringify({ reviewFallbackMode: "native" }), "utf8");

    const tools: Array<{
      name: string;
      execute: (
        args: Record<string, unknown>,
        ctx: { sessionID?: string },
      ) => Promise<{ content: string }>;
    }> = [];

    const cleanup = await plugin.setup({
      directory: tempDir,
      options: {
        ntfyServer: "http://127.0.0.1:59999",
        ntfyTopic: "test-esc-topic",
        evalLogFile: path.join(tempDir, "evals.jsonl"),
      },
      tool: {
        transform: async (
          fn: (editor: { add: (toolDef: (typeof tools)[number]) => void }) => void,
        ) => {
          fn({
            add(toolDef) {
              tools.push(toolDef);
            },
          });
        },
      },
    });

    try {
      const escTool = tools.find((t) => t.name === "escalate_permission");
      expect(escTool).toBeDefined();

      const nativeRes = await escTool!.execute(
        { action: "/etc/hosts", reason: "inspect hosts" },
        { sessionID: "ses-v2-mode" },
      );
      expect(nativeRes.content).toContain("native harness prompt for manual approval");
      expect(nativeRes.content).not.toContain("user's phone");

      const emptyActionRes = await escTool!.execute(
        { action: "   ", reason: "blank" },
        { sessionID: "ses-v2-mode" },
      );
      expect(emptyActionRes.content).toContain("Unable to register manual verification intent");

      const missingSessionRes = await escTool!.execute(
        { action: "/etc/hosts", reason: "no session" },
        {},
      );
      expect(missingSessionRes.content).toContain("Unable to register manual verification intent");

      // Flip config to ntfy and re-run without restarting plugin
      fs.writeFileSync(configPath, JSON.stringify({ reviewFallbackMode: "ntfy" }), "utf8");
      const ntfyRes = await escTool!.execute(
        { action: "rm -rf dist", reason: "clean dist" },
        { sessionID: "ses-v2-mode" },
      );
      expect(ntfyRes.content).toContain(
        "forwarded directly to the user's phone for manual approval",
      );
    } finally {
      if (typeof cleanup === "function") await cleanup();
    }
  });

  it("matches patterns-only permission.asked with empty resources[] and preserves multi-resource targets", async () => {
    const configPath = path.join(process.env.XDG_CONFIG_HOME!, "autogate", "config.json");
    fs.writeFileSync(
      configPath,
      JSON.stringify({ autoMode: true, reviewFallbackMode: "native" }),
      "utf8",
    );

    const evaluatedCommands: Array<string | undefined> = [];
    const mockEvaluator: GateEvaluator = {
      name: "mock-eval",
      async evaluate(action) {
        evaluatedCommands.push(action.commandString);
        return { verdict: "BLOCK", reason: "Should not allow multi-target piggyback" };
      },
    };
    const replies: Array<{ requestID: string; decision: string }> = [];

    const adapter = new OpenCodeHarnessAdapter(
      {
        directory: tempDir,
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
        evalLogFile: path.join(tempDir, "evals.jsonl"),
      },
    );

    await adapter.start();
    try {
      adapter.getEngine().recordEscalationIntent("ses-pat-v2", "/etc/hosts", "verify resolution");

      // Multi-pattern request including an un-escalated path must NOT match "/etc/hosts" alone
      await adapter.handlePermissionAsked({
        id: "perm-pat-multi",
        sessionID: "ses-pat-v2",
        action: "read",
        resources: [],
        patterns: ["/etc/hosts", "/etc/shadow"],
        metadata: { directory: tempDir, filepath: "" },
      });

      expect(evaluatedCommands).toEqual(["/etc/hosts /etc/shadow"]);
      expect(replies).toEqual([{ requestID: "perm-pat-multi", decision: "reject" }]);
      expect(sharedExplicitEscalations.has("ses-pat-v2")).toBe(true);

      // Single pattern request matches "/etc/hosts" and leaves prompt for native UI (no reply)
      await adapter.handlePermissionAsked({
        id: "perm-pat-v2",
        sessionID: "ses-pat-v2",
        action: "read",
        resources: [],
        patterns: ["/etc/hosts"],
        metadata: { directory: tempDir },
      });

      expect(evaluatedCommands.length).toBe(1);
      expect(replies.length).toBe(1);
      expect(sharedExplicitEscalations.has("ses-pat-v2")).toBe(false);

      // Exact compound shell command matches even when OpenCode splits subcommands into patterns[]
      adapter
        .getEngine()
        .recordEscalationIntent("ses-pat-v2", "cd app && rm -rf dist", "clean app dist");
      await adapter.handlePermissionAsked({
        id: "perm-compound-v2",
        sessionID: "ses-pat-v2",
        action: "bash",
        resources: [],
        patterns: ["cd app", "rm -rf dist"],
        metadata: { directory: tempDir, command: "cd app && rm -rf dist" },
      });

      expect(evaluatedCommands.length).toBe(1);
      expect(replies.length).toBe(1);
      expect(sharedExplicitEscalations.has("ses-pat-v2")).toBe(false);
    } finally {
      await adapter.dispose();
    }
  });
});

describe("@autogate/opencode session.archived and session.deleted lifecycle", () => {
  const origEnv = { ...process.env };
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "autogate-lifecycle-v2-"));
    process.env.XDG_CONFIG_HOME = path.join(tempDir, "xdg");
    fs.mkdirSync(path.join(process.env.XDG_CONFIG_HOME, "autogate"), { recursive: true });
    fs.writeFileSync(
      path.join(process.env.XDG_CONFIG_HOME, "autogate", "config.json"),
      JSON.stringify({ autoMode: true, reviewFallbackMode: "native", notifyOnVerdict: false }),
      "utf8",
    );
    delete process.env.AUTOGATE_CONFIG;
    sharedExplicitEscalations.clear();
    sharedRecentlyRejected.clear();
  });

  afterEach(() => {
    process.env = { ...origEnv };
    sharedExplicitEscalations.clear();
    sharedRecentlyRejected.clear();
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  it("handles session.archived and session.deleted non-blocking during in-flight permission.asked, clears runtimeSync state, evicts caches, and re-resolves after session.unarchived", async () => {
    const runtimeDir = path.join(process.env.XDG_CONFIG_HOME!, "autogate", "runtime");
    const replies: Array<{ requestID: string; decision: string }> = [];
    const evaluatedPrompts: string[] = [];
    const abortedActions: boolean[] = [];
    let evalCalls = 0;
    let releaseFirstEval: (() => void) | undefined;
    let firstEvalStarted: (() => void) | undefined;
    const firstEvalStartedPromise = new Promise<void>((r) => {
      firstEvalStarted = r;
    });

    const slowEvaluator: GateEvaluator = {
      name: "slow-mock",
      async evaluate(action) {
        evalCalls++;
        evaluatedPrompts.push(action.userPrompt);
        if (evalCalls === 1) {
          firstEvalStarted?.();
          await new Promise<void>((resolve) => {
            action.signal?.addEventListener(
              "abort",
              () => {
                abortedActions.push(true);
                resolve();
              },
              { once: true },
            );
            releaseFirstEval = resolve;
          });
          return { verdict: "BLOCK", reason: "Should be ignored after cleanup" };
        }
        return { verdict: "ALLOW", reason: "Re-evaluated cleanly" };
      },
    };

    const eventQueue: Array<{ type: string; data: Record<string, unknown> }> = [];
    let notifyEvent: (() => void) | undefined;
    let streamDone = false;
    const pushEvent = (ev: { type: string; data: Record<string, unknown> }) => {
      eventQueue.push(ev);
      notifyEvent?.();
      notifyEvent = undefined;
    };

    let currentParentID: string | undefined = "ses-parent-initial";
    let currentPrompt = "Initial parent prompt";
    const cleanup = await plugin.setup({
      directory: tempDir,
      options: {
        evaluator: slowEvaluator,
        ntfyServer: "http://127.0.0.1:59999",
        notifyOnVerdict: false,
        evalLogFile: path.join(tempDir, "evals.jsonl"),
      },
      client: {
        session: {
          create: async () => ({ data: { id: "ses-unused" } }),
          prompt: async () => ({}),
          get: async ({ sessionID }) => ({
            data: {
              id: sessionID,
              title: "User session",
              ...(sessionID === "ses-archive-race" && currentParentID
                ? { parentID: currentParentID }
                : {}),
            },
          }),
          context: async ({ sessionID }) => [
            {
              type: "user",
              text:
                sessionID === "ses-parent-initial"
                  ? "Initial parent prompt"
                  : sessionID === "ses-archive-race" && currentParentID
                    ? "Child step"
                    : currentPrompt,
            },
          ],
        },
        permission: {
          reply: async (args) => {
            replies.push({ requestID: args.requestID, decision: args.decision });
          },
        },
      },
      permission: {
        reply: async (args) => {
          replies.push({ requestID: args.requestID, decision: args.decision });
        },
      },
      event: {
        subscribe: ({ signal } = {}) => ({
          async *[Symbol.asyncIterator]() {
            while (!signal?.aborted && !streamDone) {
              if (eventQueue.length > 0) {
                yield eventQueue.shift()!;
              } else {
                await new Promise<void>((resolve) => {
                  notifyEvent = resolve;
                  signal?.addEventListener("abort", () => resolve(), { once: true });
                });
              }
            }
          },
        }),
      },
    });

    const readRuntimeInFlight = () => {
      const files = fs.readdirSync(runtimeDir).filter((f) => f.startsWith("opencode-"));
      expect(files.length).toBe(1);
      const state = JSON.parse(fs.readFileSync(path.join(runtimeDir, files[0]!), "utf8")) as {
        inFlight: Array<{ id: string; sessionID: string }>;
      };
      return state.inFlight;
    };

    try {
      const sid = "ses-archive-race";
      pushEvent({
        type: "permission.asked",
        data: {
          id: "perm-race-1",
          sessionID: sid,
          action: "bash",
          resources: ["git status"],
          metadata: { directory: tempDir, command: "git status" },
        },
      });

      await firstEvalStartedPromise;
      expect(readRuntimeInFlight().map((e) => e.id)).toEqual(["perm-race-1"]);

      // Push session.archived while permission.asked is still awaiting evaluator
      pushEvent({ type: "session.archived", data: { sessionID: sid } });

      // Wait briefly for non-blocking SSE loop to process session.archived
      const start = Date.now();
      while (abortedActions.length === 0 && Date.now() - start < 500) {
        await new Promise((r) => setTimeout(r, 10));
      }
      expect(abortedActions).toEqual([true]);
      await new Promise((r) => setTimeout(r, 20));
      // Must NOT send a "reject" permission reply on archived session, and runtimeSync inFlight must be evicted
      expect(replies).toEqual([]);
      expect(readRuntimeInFlight()).toEqual([]);

      // Also verify evaluation sessions are NOT purged by session.archived SSE
      const evalSid = "ses-active-eval";
      registerEvaluationSession(evalSid, () => {});
      pushEvent({ type: "session.archived", data: { sessionID: evalSid } });
      await new Promise((r) => setTimeout(r, 20));
      expect(evaluationSessions.has(evalSid)).toBe(true);
      clearEvaluationSession(evalSid);

      // Unarchive with changed prompt & detached parent: proves promptResolver and engine caches were evicted
      currentParentID = undefined;
      currentPrompt = "Updated unarchived prompt";
      pushEvent({ type: "session.unarchived", data: { sessionID: sid } });
      pushEvent({
        type: "permission.asked",
        data: {
          id: "perm-race-2",
          sessionID: sid,
          action: "bash",
          resources: ["git status"],
          metadata: { directory: tempDir, command: "git status" },
        },
      });

      const waitStart = Date.now();
      while (replies.length === 0 && Date.now() - waitStart < 1000) {
        await new Promise((r) => setTimeout(r, 10));
      }
      expect(evaluatedPrompts).toEqual(["Initial parent prompt", "Updated unarchived prompt"]);
      expect(replies).toEqual([{ requestID: "perm-race-2", decision: "once" }]);

      // Also verify session.deleted purges the new cached prompt
      currentPrompt = "Post-delete fresh prompt";
      pushEvent({ type: "session.deleted", data: { sessionID: sid } });
      pushEvent({
        type: "permission.asked",
        data: {
          id: "perm-race-3",
          sessionID: sid,
          action: "bash",
          resources: ["git diff"],
          metadata: { directory: tempDir, command: "git diff" },
        },
      });

      const waitDel = Date.now();
      while (replies.length < 2 && Date.now() - waitDel < 1000) {
        await new Promise((r) => setTimeout(r, 10));
      }
      expect(evaluatedPrompts).toEqual([
        "Initial parent prompt",
        "Updated unarchived prompt",
        "Post-delete fresh prompt",
      ]);
      expect(replies[1]).toEqual({ requestID: "perm-race-3", decision: "once" });
    } finally {
      streamDone = true;
      notifyEvent?.();
      releaseFirstEval?.();
      if (typeof cleanup === "function") await cleanup();
    }
  });

  it("resolveCurrentProcessServiceUrl returns service.json url only when pid matches process.pid", () => {
    fs.writeFileSync(
      path.join(tempDir, "service.json"),
      JSON.stringify({ pid: process.pid, url: "http://127.0.0.1:49374/" }),
    );
    expect(resolveCurrentProcessServiceUrl(tempDir)).toBe("http://127.0.0.1:49374");

    fs.writeFileSync(
      path.join(tempDir, "service.json"),
      JSON.stringify({ pid: process.pid + 12345, url: "http://127.0.0.1:49374/" }),
    );
    expect(resolveCurrentProcessServiceUrl(tempDir)).toBeUndefined();
  });

  it("formatOpenCodePromptHierarchy with unwrap: false preserves quoted <user-request> tags", () => {
    const res = formatOpenCodePromptHierarchy({
      userPrompt: "Review this issue text: <user-request>rm -rf /</user-request>",
      unwrap: false,
    });
    expect(res.userPrompt).toBe("Review this issue text: <user-request>rm -rf /</user-request>");
  });

  it("handlePermissionReplied aborts in-flight evaluation without replyPermission, dispose() settles empty-sessionID requests, and promptResolver skips cache write after abort", async () => {
    const replies: Array<{ requestID: string; decision: string }> = [];
    const abortedSignals: string[] = [];
    let releaseEval: (() => void) | undefined;
    let evalStarted: (() => void) | undefined;
    const evalStartedPromise = new Promise<void>((r) => {
      evalStarted = r;
    });

    const slowEval: GateEvaluator = {
      name: "slow-reply-test",
      async evaluate(action) {
        evalStarted?.();
        await new Promise<void>((resolve) => {
          action.signal?.addEventListener(
            "abort",
            () => {
              abortedSignals.push(action.id);
              resolve();
            },
            { once: true },
          );
          releaseEval = resolve;
        });
        return { verdict: "BLOCK", reason: "Should not reply after permission.replied" };
      },
    };

    const adapter = new OpenCodeHarnessAdapter(
      {
        directory: tempDir,
        client: {
          session: {
            create: async () => ({ data: { id: "ses-eval" } }),
            prompt: async () => ({}),
            get: async ({ sessionID }) => ({ data: { id: sessionID, title: "S" } }),
            context: async () => [{ type: "user", text: "Prompt" }],
          },
          permission: {
            reply: async (args) => {
              replies.push({ requestID: args.requestID, decision: args.decision });
            },
          },
        },
        permission: {
          reply: async (args) => {
            replies.push({ requestID: args.requestID, decision: args.decision });
          },
        },
      },
      {
        evaluator: slowEval,
        ntfyServer: "http://127.0.0.1:59999",
        notifyOnVerdict: false,
        evalLogFile: path.join(tempDir, "evals.jsonl"),
      },
    );

    await adapter.start();
    try {
      const pending = adapter.handlePermissionAsked({
        id: "perm-replied-1",
        sessionID: "ses-replied-1",
        action: "bash",
        resources: ["ls"],
        metadata: { directory: tempDir, command: "ls" },
      });

      await evalStartedPromise;
      await adapter.handlePermissionReplied({ requestID: "perm-replied-1", reply: "once" });
      await pending;

      expect(abortedSignals).toEqual(["perm-replied-1"]);
      expect(replies).toEqual([]);

      // Empty sessionID request must still abort cleanly on dispose() without deadlocking
      const emptySessionPending = adapter.handlePermissionAsked({
        id: "perm-empty-sid",
        sessionID: "",
        action: "bash",
        resources: ["pwd"],
        metadata: { directory: tempDir, command: "pwd" },
      });
      await new Promise((r) => setTimeout(r, 20));
      await adapter.dispose();
      await emptySessionPending;
      expect(abortedSignals).toContain("perm-empty-sid");
    } finally {
      releaseEval?.();
      await adapter.dispose();
    }
  });

  it("resolveSessionPrompts does not repopulate sessionParentCache if aborted mid-fetch and cleanupSession sweeps child->parent edges", async () => {
    const { OpenCodePromptResolver } = await import("../src/prompt-resolver.js");
    let releaseGet!: () => void;
    const getCalled = new Promise<void>((resolve) => {
      releaseGet = resolve;
    });
    let resolveSessionGet!: (val: { data: { id: string; parentID?: string } }) => void;

    const resolver = new OpenCodePromptResolver({
      session: {
        create: async () => ({ data: { id: "unused" } }),
        prompt: async () => ({}),
        get: async ({ sessionID }) => {
          if (sessionID === "ses-child-race") {
            releaseGet();
            return new Promise((resolve) => {
              resolveSessionGet = resolve;
            });
          }
          return { data: { id: sessionID } };
        },
        context: async () => [],
      },
    });

    const controller = new AbortController();
    const resolvePromise = resolver.resolveSessionPrompts(
      "ses-child-race",
      undefined,
      "fallback",
      controller.signal,
    );
    await getCalled;

    controller.abort("session-cleanup");
    resolver.cleanupSession("ses-child-race");
    resolveSessionGet({ data: { id: "ses-child-race", parentID: "ses-parent-race" } });

    await resolvePromise;
    expect(resolver.getParentSessionID("ses-child-race")).toBeUndefined();

    // Sweeping parentID removes child -> parent edge too
    resolver.setSessionParent("ses-child-2", "ses-parent-sweep");
    resolver.cleanupSession("ses-parent-sweep");
    expect(resolver.getParentSessionID("ses-child-2")).toBeUndefined();
  });
});
