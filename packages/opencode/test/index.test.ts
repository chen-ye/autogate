import { describe, it, expect, beforeEach, afterEach, spyOn } from "bun:test";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import {
  AutoGateEvalStore,
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
        evalDbFile: path.join(os.tmpdir(), "autogate-agent-inj-test-1.db"),
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
        evalDbFile: path.join(os.tmpdir(), "autogate-agent-inj-test-2.db"),
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
        evalDbFile: path.join(tempDir, "evals.db"),
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
        evalDbFile: path.join(tempDir, "evals.db"),
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
        evalDbFile: path.join(tempDir, "evals.db"),
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
        evalDbFile: path.join(tempDir, "evals.db"),
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

describe("@autogate/opencode evals.db persistence, cascade race, and evalSessionCleanup hot-reload", () => {
  const origEnv = { ...process.env };
  const origFetch = globalThis.fetch;
  let tempDir: string;
  let configPath: string;
  let evalDbFile: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "autogate-evaldb-v2-"));
    process.env.XDG_CONFIG_HOME = path.join(tempDir, "xdg");
    fs.mkdirSync(path.join(process.env.XDG_CONFIG_HOME, "autogate"), { recursive: true });
    configPath = path.join(process.env.XDG_CONFIG_HOME, "autogate", "config.json");
    evalDbFile = path.join(tempDir, "evals.db");
    delete process.env.AUTOGATE_CONFIG;
    delete process.env.AUTOGATE_EVAL_DB;
    delete process.env.AUTOGATE_EVAL_SESSION_CLEANUP;
    delete process.env.OPENCODE_SERVER_URL;
    sharedExplicitEscalations.clear();
    sharedRecentlyRejected.clear();
  });

  afterEach(() => {
    globalThis.fetch = origFetch;
    process.env = { ...origEnv };
    sharedExplicitEscalations.clear();
    sharedRecentlyRejected.clear();
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  it("records S2-only evaluations in evals.db without double-writing and closes store on dispose()", async () => {
    fs.writeFileSync(
      configPath,
      JSON.stringify({
        autoMode: true,
        reviewFallbackMode: "native",
        evalDbFile,
        evalSessionCleanup: "export-and-delete",
      }),
      "utf8",
    );

    const replies: Array<{ requestID: string; decision: string }> = [];
    const removedS2: string[] = [];
    const { recordEvaluationVerdict } = await import("../src/evaluator.js");

    const adapter = new OpenCodeHarnessAdapter(
      {
        directory: tempDir,
        client: {
          agent: { list: async () => ({ data: [{ id: "auto-gate-eval" }] }) },
          session: {
            create: async () => ({ data: { id: "ses_s2_only_1" } }),
            get: async ({ sessionID }) => ({
              data: {
                id: sessionID,
                title: sessionID === "ses_coding_s2only" ? "Coding Task" : "[auto-gate-eval] bash",
                agent: "auto-gate-eval",
                model: { providerID: "google", id: "gemini-3.5-flash-lite" },
                tokens: {
                  input: 310,
                  output: 42,
                  reasoning: 18,
                  cache: { read: 80, write: 5 },
                },
                cost: 0.00029,
                outcome: "succeeded",
              },
            }),
            context: async ({ sessionID }) => {
              if (sessionID === "ses_coding_s2only") {
                return [{ type: "user", text: "Check git status in repo" }];
              }
              return [
                { type: "user", text: "Evaluate git status" },
                {
                  type: "assistant",
                  agent: "auto-gate-eval",
                  model: { providerID: "google", id: "gemini-3.5-flash-lite" },
                  content: [
                    { type: "reasoning", text: "Read-only git status inside workspace." },
                    {
                      type: "tool",
                      id: "tool-1",
                      name: "classify_result",
                      state: {
                        status: "completed",
                        input: {
                          verdict: "ALLOW",
                          risk_level: "LOW",
                          user_authorization: "HIGH",
                          reason: "Safe git status check",
                        },
                      },
                    },
                  ],
                },
              ];
            },
            prompt: async ({ sessionID }) => {
              recordEvaluationVerdict(sessionID, {
                verdict: "ALLOW",
                risk_level: "LOW",
                user_authorization: "HIGH",
                reason: "Safe git status check",
              });
              return { data: { parts: [] } };
            },
            remove: async ({ sessionID }) => {
              removedS2.push(sessionID);
            },
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
        ntfyServer: "http://127.0.0.1:59999",
        notifyOnVerdict: false,
      },
    );

    await adapter.start();
    try {
      await adapter.handlePermissionAsked({
        id: "perm-s2-only-1",
        sessionID: "ses_coding_s2only",
        action: "bash",
        resources: ["git status"],
        metadata: { directory: tempDir, command: "git status" },
      });
    } finally {
      await adapter.dispose();
    }

    expect(replies).toEqual([{ requestID: "perm-s2-only-1", decision: "once" }]);
    expect(removedS2).toEqual(["ses_s2_only_1"]);

    const store = new AutoGateEvalStore(evalDbFile, { readonly: true });
    try {
      const rows = store.queryEvaluations();
      expect(rows.length).toBe(1);
      expect(rows[0]?.id).toBe("perm-s2-only-1");
      expect(rows[0]?.sessionId).toBe("ses_coding_s2only");
      expect(rows[0]?.s2SessionId).toBe("ses_s2_only_1");
      expect(rows[0]?.verdict).toBe("ALLOW");
      expect(rows[0]?.modelId).toBe("gemini-3.5-flash-lite");
      expect(rows[0]?.modelProvider).toBe("google");
      expect(rows[0]?.promptTokens).toBe(310);
      expect(rows[0]?.outputTokens).toBe(42);
      expect(rows[0]?.reasoningTokens).toBe(18);
      expect(rows[0]?.cost).toBeCloseTo(0.00029, 8);
      expect(rows[0]?.thinking).toBe("Read-only git status inside workspace.");
      expect(rows[0]?.hasS2Session).toBe(true);
    } finally {
      store.close();
    }
  });

  it("records System 1 race-win in evals.db, archives aborted S2 session, and links s2SessionId on teardown", async () => {
    const s1Endpoint = "http://127.0.0.1:49991/v1/systemone";
    fs.writeFileSync(
      configPath,
      JSON.stringify({
        autoMode: true,
        reviewFallbackMode: "native",
        evalDbFile,
        evalSessionCleanup: "export-and-delete",
        systemOne: {
          enabled: true,
          executionMode: "race",
          endpoint: s1Endpoint,
          model: "gemini-decision-1",
          timeoutMs: 2000,
        },
      }),
      "utf8",
    );

    globalThis.fetch = (async (input: string | URL | Request) => {
      if (String(input) === s1Endpoint) {
        return new Response(
          JSON.stringify({
            answers: {
              verdict: { probabilities: { ALLOW: 0.98, BLOCK: 0.02 } },
              in_scope: { noul: 0.95 },
              injection_risk: { noul: 0.01 },
            },
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
      }
      throw new Error(`Unexpected fetch URL: ${String(input)}`);
    }) as typeof fetch;

    const replies: Array<{ requestID: string; decision: string }> = [];
    const removedS2: string[] = [];

    const adapter = new OpenCodeHarnessAdapter(
      {
        directory: tempDir,
        client: {
          agent: { list: async () => ({ data: [{ id: "auto-gate-eval" }] }) },
          session: {
            create: async () => ({ data: { id: "ses_s2_aborted_race" } }),
            get: async ({ sessionID }) => ({
              data: {
                id: sessionID,
                title: sessionID === "ses-race-coding" ? "Coding Session" : "[auto-gate-eval] bash",
              },
            }),
            context: async ({ sessionID }) =>
              sessionID === "ses-race-coding"
                ? [{ type: "user", text: "Run pwd in workspace" }]
                : [{ type: "user", text: "Evaluate pwd" }],
            interrupt: async () => ({}),
            prompt: async () => {
              await new Promise((r) => setTimeout(r, 80));
              return { data: { reasoning: "Aborted mid-thought", parts: [] } };
            },
            remove: async ({ sessionID }) => {
              removedS2.push(sessionID);
            },
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
        ntfyServer: "http://127.0.0.1:59999",
        notifyOnVerdict: false,
      },
    );

    await adapter.start();
    try {
      await adapter.handlePermissionAsked({
        id: "perm-race-s1-win",
        sessionID: "ses-race-coding",
        action: "bash",
        resources: ["pwd"],
        metadata: { directory: tempDir, command: "pwd" },
      });
    } finally {
      // dispose() waits for the background aborted S2 archiving & linking before closing evalStore
      await adapter.dispose();
    }

    expect(replies).toEqual([{ requestID: "perm-race-s1-win", decision: "once" }]);
    expect(removedS2).toEqual(["ses_s2_aborted_race"]);

    const store = new AutoGateEvalStore(evalDbFile, { readonly: true });
    try {
      const rows = store.queryEvaluations();
      expect(rows.length).toBe(1);
      expect(rows[0]?.id).toBe("perm-race-s1-win");
      expect(rows[0]?.sessionId).toBe("ses-race-coding");
      expect(rows[0]?.verdict).toBe("ALLOW");
      expect(rows[0]?.cascadeWinner).toBe("system1");
      expect(rows[0]?.s2Aborted).toBe(true);
      expect(rows[0]?.s2SessionId).toBe("ses_s2_aborted_race");
      expect(rows[0]?.hasS2Session).toBe(true);

      const s2 = store.getS2Session("ses_s2_aborted_race");
      expect(s2?.status).toBe("aborted");
      expect(s2?.targetSessionId).toBe("ses-race-coding");
    } finally {
      store.close();
    }
  });

  it("records System 2 cascade win with full S2 metadata and hot-reloads evalSessionCleanup across evaluations", async () => {
    const s1Endpoint = "http://127.0.0.1:49992/v1/systemone";
    fs.writeFileSync(
      configPath,
      JSON.stringify({
        autoMode: true,
        reviewFallbackMode: "native",
        evalDbFile,
        evalSessionCleanup: "export-and-delete",
        systemOne: {
          enabled: true,
          executionMode: "cascade",
          endpoint: s1Endpoint,
          model: "gemini-decision-1",
          timeoutMs: 2000,
        },
      }),
      "utf8",
    );

    globalThis.fetch = (async (input: string | URL | Request) => {
      if (String(input) === s1Endpoint) {
        return new Response(
          JSON.stringify({
            answers: {
              verdict: { probabilities: { ALLOW: 0.6, BLOCK: 0.4 } },
              in_scope: { noul: 0.9 },
              injection_risk: { noul: 0.05 },
            },
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
      }
      throw new Error(`Unexpected fetch URL: ${String(input)}`);
    }) as typeof fetch;

    const replies: Array<{ requestID: string; decision: string }> = [];
    const removedS2: string[] = [];
    const archivedS2: string[] = [];
    let s2Seq = 0;
    const { recordEvaluationVerdict } = await import("../src/evaluator.js");

    const adapter = new OpenCodeHarnessAdapter(
      {
        directory: tempDir,
        client: {
          agent: { list: async () => ({ data: [{ id: "auto-gate-eval" }] }) },
          session: {
            create: async () => ({ data: { id: `ses_s2_cas_${++s2Seq}` } }),
            get: async ({ sessionID }) => ({
              data: {
                id: sessionID,
                title: sessionID === "ses-cas-coding" ? "Coding" : "[auto-gate-eval] bash",
                model: { providerID: "anthropic", id: "claude-haiku-4-5" },
                tokens: { input: 500, output: 70, reasoning: 30, cache: { read: 0, write: 0 } },
                cost: 0.0012,
                outcome: "succeeded",
              },
            }),
            context: async ({ sessionID }) =>
              sessionID === "ses-cas-coding"
                ? [{ type: "user", text: "Delete temp files" }]
                : [
                    { type: "user", text: "Evaluate rm" },
                    {
                      type: "assistant",
                      content: [{ type: "reasoning", text: "Dangerous unrequested deletion." }],
                    },
                  ],
            prompt: async ({ sessionID }) => {
              recordEvaluationVerdict(sessionID, {
                verdict: "BLOCK",
                risk_level: "HIGH",
                user_authorization: "NONE",
                reason: "Blocked dangerous deletion",
              });
              return { data: { parts: [] } };
            },
            remove: async ({ sessionID }) => {
              removedS2.push(sessionID);
            },
            update: async ({ sessionID }) => {
              archivedS2.push(sessionID);
            },
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
        ntfyServer: "http://127.0.0.1:59999",
        notifyOnVerdict: false,
      },
    );

    await adapter.start();
    try {
      // Eval 1: export-and-delete -> session.remove called
      await adapter.handlePermissionAsked({
        id: "perm-cas-1",
        sessionID: "ses-cas-coding",
        action: "bash",
        resources: ["rm -rf /tmp/foo"],
        metadata: { directory: tempDir, command: "rm -rf /tmp/foo" },
      });

      expect(removedS2).toEqual(["ses_s2_cas_1"]);
      expect(archivedS2).toEqual([]);

      // Hot-reload evalSessionCleanup -> "archive" in config.json without restarting adapter
      fs.writeFileSync(
        configPath,
        JSON.stringify({
          autoMode: true,
          reviewFallbackMode: "native",
          evalDbFile,
          evalSessionCleanup: "archive",
          systemOne: {
            enabled: true,
            executionMode: "cascade",
            endpoint: s1Endpoint,
            model: "gemini-decision-1",
            timeoutMs: 2000,
          },
        }),
        "utf8",
      );

      await adapter.handlePermissionAsked({
        id: "perm-cas-2",
        sessionID: "ses-cas-coding",
        action: "bash",
        resources: ["rm -rf /tmp/bar"],
        metadata: { directory: tempDir, command: "rm -rf /tmp/bar" },
      });

      expect(removedS2).toEqual(["ses_s2_cas_1"]);
      expect(archivedS2).toEqual(["ses_s2_cas_2"]);
    } finally {
      await adapter.dispose();
    }

    const store = new AutoGateEvalStore(evalDbFile, { readonly: true });
    try {
      const e1 = store.getEvaluation("perm-cas-1");
      expect(e1).not.toBeNull();
      expect(e1?.verdict).toBe("BLOCK");
      expect(e1?.cascadeWinner).toBe("system2");
      expect(e1?.cascade?.escalationReason).toBe("low_allow_prob");
      expect(e1?.s2Aborted).toBe(false);
      expect(e1?.s2SessionId).toBe("ses_s2_cas_1");
      expect(e1?.modelId).toBe("claude-haiku-4-5");
      expect(e1?.modelProvider).toBe("anthropic");
      expect(e1?.promptTokens).toBe(500);
      expect(e1?.outputTokens).toBe(70);
      expect(e1?.reasoningTokens).toBe(30);
      expect(e1?.cost).toBeCloseTo(0.0012, 8);
      expect(e1?.thinking).toBe("Dangerous unrequested deletion.");

      const e2 = store.getEvaluation("perm-cas-2");
      expect(e2?.s2SessionId).toBe("ses_s2_cas_2");
      expect(store.getS2Session("ses_s2_cas_2")?.status).toBe("completed");
    } finally {
      store.close();
    }
  });

  it("persists classifier UNSURE intact before requestReview() across terminal permission.replied and Ntfy overrides, and clears post-verdict interrupt errors", async () => {
    const ntfyTopic = "autogate-test-unsure-preserve";
    const publishedIds: string[] = [];
    const ntfyServer = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      fetch: async (req) => {
        const url = new URL(req.url);
        if (req.method === "POST" && url.pathname === `/${ntfyTopic}`) {
          await req.text();
          const seqId = req.headers.get("x-sequence-id");
          if (seqId) publishedIds.push(seqId);
          return Response.json({ id: seqId ?? "ok" });
        }
        if (url.pathname.endsWith("/sse")) {
          return new Response("", {
            headers: { "Content-Type": "text/event-stream" },
          });
        }
        return new Response("ok");
      },
    });

    try {
      fs.writeFileSync(
        configPath,
        JSON.stringify({
          autoMode: true,
          reviewFallbackMode: "ntfy",
          ntfyServer: `http://127.0.0.1:${ntfyServer.port}`,
          ntfyTopic,
          notifyOnVerdict: false,
          opencode: { evalDbFile },
        }),
        "utf8",
      );

      const { recordEvaluationVerdict } = await import("../src/evaluator.js");
      let s2Seq = 0;

      const adapter = new OpenCodeHarnessAdapter({
        directory: tempDir,
        client: {
          agent: { list: async () => ({ data: [{ id: "auto-gate-eval" }] }) },
          session: {
            create: async () => ({ data: { id: `ses_unsure_${++s2Seq}` } }),
            get: async ({ sessionID }) => ({
              data: {
                id: sessionID,
                title: sessionID === "ses-unsure-coding" ? "Coding" : "[auto-gate-eval] bash",
                outcome: "succeeded",
              },
            }),
            context: async ({ sessionID }) =>
              sessionID === "ses-unsure-coding"
                ? [{ type: "user", text: "Deploy release" }]
                : [
                    { type: "user", text: "Evaluate deploy" },
                    {
                      type: "assistant",
                      error: { message: "Step interrupted" },
                      content: [],
                    },
                  ],
            prompt: async ({ sessionID }) => {
              recordEvaluationVerdict(sessionID, {
                verdict: "UNSURE",
                risk_level: "HIGH",
                user_authorization: "LOW",
                reason: "Needs human approval for deploy",
              });
              return { data: { parts: [] } };
            },
            remove: async () => ({}),
          },
          permission: { reply: async () => ({}) },
        },
        permission: { reply: async () => ({}) },
      });

      await adapter.start();
      try {
        // 1. Terminal permission.replied aborts requestReview() -> UNSURE row must still exist
        const p1 = adapter.handlePermissionAsked({
          id: "perm-unsure-term",
          sessionID: "ses-unsure-coding",
          action: "bash",
          resources: ["npm publish"],
          metadata: { directory: tempDir, command: "npm publish" },
        });
        const waitPub1 = Date.now();
        while (!publishedIds.includes("perm-unsure-term") && Date.now() - waitPub1 < 2000) {
          await new Promise((r) => setTimeout(r, 10));
        }
        await adapter.handlePermissionReplied({ requestID: "perm-unsure-term", reply: "once" });
        await p1;

        // 2. Ntfy human override (reply: "once" -> ALLOW) must NOT overwrite classifier UNSURE row
        const p2 = adapter.handlePermissionAsked({
          id: "perm-unsure-ntfy",
          sessionID: "ses-unsure-coding",
          action: "bash",
          resources: ["terraform apply"],
          metadata: { directory: tempDir, command: "terraform apply" },
        });
        const waitPub2 = Date.now();
        while (!publishedIds.includes("perm-unsure-ntfy") && Date.now() - waitPub2 < 2000) {
          await new Promise((r) => setTimeout(r, 10));
        }
        await new Promise((r) => setTimeout(r, 60));
        adapter.getEngine().resolveReviewResponse({
          req_id: "perm-unsure-ntfy",
          reply: "once",
          source: "ntfy",
        });
        await p2;
      } finally {
        await adapter.dispose();
      }

      const store = new AutoGateEvalStore(evalDbFile, { readonly: true });
      try {
        const termRow = store.getEvaluation("perm-unsure-term");
        expect(termRow).not.toBeNull();
        expect(termRow?.verdict).toBe("UNSURE");
        expect(termRow?.riskLevel).toBe("HIGH");
        expect(termRow?.userAuthorization).toBe("LOW");
        expect(termRow?.reasoning).toBe("Needs human approval for deploy");
        expect(termRow?.error).toBeNull();
        expect(termRow?.hasS2Session).toBe(true);

        const ntfyRow = store.getEvaluation("perm-unsure-ntfy");
        expect(ntfyRow).not.toBeNull();
        expect(ntfyRow?.verdict).toBe("UNSURE");
        expect(ntfyRow?.riskLevel).toBe("HIGH");
        expect(ntfyRow?.reasoning).toBe("Needs human approval for deploy");
        expect(ntfyRow?.durationMs).toBeLessThan(60);
        expect(ntfyRow?.error).toBeNull();
      } finally {
        store.close();
      }
    } finally {
      ntfyServer.stop(true);
    }
  });

  it("handles context_drifted (S2 #1 abort -> S2 #2 ALLOW) without UNSURE corruption and emits no phantom evaluation row on mid-S2 session.archived", async () => {
    const s1Endpoint = "http://127.0.0.1:49993/v1/systemone";
    fs.writeFileSync(
      configPath,
      JSON.stringify({
        autoMode: true,
        reviewFallbackMode: "native",
        evalDbFile,
        evalSessionCleanup: "export-and-delete",
        systemOne: {
          enabled: true,
          executionMode: "race",
          endpoint: s1Endpoint,
          model: "gemini-decision-1",
          timeoutMs: 2000,
        },
      }),
      "utf8",
    );

    const { recordEvaluationVerdict } = await import("../src/evaluator.js");
    const replies: Array<{ requestID: string; decision: string }> = [];
    let s2Count = 0;
    let triggerDrift: (() => void) | undefined;
    let firstS2PromptStarted!: () => void;
    const firstS2PromptPromise = new Promise<void>((r) => {
      firstS2PromptStarted = r;
    });

    globalThis.fetch = (async (input: string | URL | Request) => {
      if (String(input) === s1Endpoint) {
        await firstS2PromptPromise;
        triggerDrift?.();
        return new Response(
          JSON.stringify({
            answers: {
              verdict: { probabilities: { ALLOW: 0.99, BLOCK: 0.01 } },
              in_scope: { noul: 0.96 },
              injection_risk: { noul: 0.01 },
            },
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
      }
      throw new Error(`Unexpected fetch URL: ${String(input)}`);
    }) as typeof fetch;

    const adapter = new OpenCodeHarnessAdapter({
      directory: tempDir,
      client: {
        agent: { list: async () => ({ data: [{ id: "auto-gate-eval" }] }) },
        session: {
          create: async () => ({ data: { id: `ses_drift_s2_${++s2Count}` } }),
          get: async ({ sessionID }) => ({
            data: {
              id: sessionID,
              title: sessionID.startsWith("ses_drift_s2_") ? "[auto-gate-eval] bash" : "Coding",
              outcome: "succeeded",
            },
          }),
          context: async ({ sessionID }) =>
            sessionID.startsWith("ses_drift_s2_")
              ? [{ type: "user", text: "Eval" }]
              : [{ type: "user", text: "Initial prompt" }],
          interrupt: async () => ({}),
          prompt: async ({ sessionID }) => {
            if (sessionID === "ses_drift_s2_1") {
              firstS2PromptStarted();
              await new Promise((r) => setTimeout(r, 120));
              return { data: { parts: [] } };
            }
            if (sessionID === "ses_drift_s2_2") {
              recordEvaluationVerdict(sessionID, {
                verdict: "ALLOW",
                risk_level: "LOW",
                user_authorization: "HIGH",
                reason: "Allowed after drift re-eval",
              });
              return { data: { parts: [] } };
            }
            // Test 2 (mid-S2 session.archived) waits to be aborted
            firstS2PromptStarted();
            await new Promise((r) => setTimeout(r, 120));
            return { data: { parts: [] } };
          },
          remove: async () => ({}),
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
    });

    await adapter.start();
    try {
      // 1. context_drifted: S2 #1 aborts, S2 #2 returns ALLOW
      triggerDrift = () => {
        adapter.getEngine().setUserPrompt("ses-drift-coding", "Drifted prompt");
      };
      await adapter.handlePermissionAsked({
        id: "perm-drift-1",
        sessionID: "ses-drift-coding",
        action: "bash",
        resources: ["git status"],
        metadata: { directory: tempDir, command: "git status" },
      });
      await adapter.dispose();

      const store1 = new AutoGateEvalStore(evalDbFile, { readonly: true });
      try {
        const driftRow = store1.getEvaluation("perm-drift-1");
        expect(driftRow).not.toBeNull();
        expect(driftRow?.verdict).toBe("ALLOW");
        expect(driftRow?.riskLevel).toBe("LOW");
        expect(driftRow?.reasoning).toBe("Allowed after drift re-eval");
        expect(driftRow?.s2SessionId).toBe("ses_drift_s2_2");
      } finally {
        store1.close();
      }
    } finally {
      await adapter.dispose();
    }

    // 2. Mid-S2 session.archived cancellation must NOT insert a phantom UNSURE row in evaluations
    const adapter2 = new OpenCodeHarnessAdapter(
      {
        directory: tempDir,
        client: {
          agent: { list: async () => ({ data: [{ id: "auto-gate-eval" }] }) },
          session: {
            create: async () => ({ data: { id: "ses_cancel_s2" } }),
            get: async ({ sessionID }) => ({ data: { id: sessionID, title: "S" } }),
            context: async () => [{ type: "user", text: "Prompt" }],
            interrupt: async () => ({}),
            prompt: async () => {
              await new Promise((r) => setTimeout(r, 80));
              return { data: { parts: [] } };
            },
            remove: async () => ({}),
          },
          permission: { reply: async () => ({}) },
        },
        permission: { reply: async () => ({}) },
      },
      {
        evalDbFile,
        systemOne: { enabled: false },
      },
    );
    await adapter2.start();
    try {
      const pCancel = adapter2.handlePermissionAsked({
        id: "perm-cancel-mid-s2",
        sessionID: "ses-cancel-coding",
        action: "bash",
        resources: ["ls"],
        metadata: { directory: tempDir, command: "ls" },
      });
      await new Promise((r) => setTimeout(r, 20));
      adapter2.cleanupSession("ses-cancel-coding");
      await pCancel;
    } finally {
      await adapter2.dispose();
    }

    const store2 = new AutoGateEvalStore(evalDbFile, { readonly: true });
    try {
      expect(store2.getEvaluation("perm-cancel-mid-s2")).toBeNull();
      expect(store2.getS2Session("ses_cancel_s2")?.status).toBe("aborted");
    } finally {
      store2.close();
    }
  });
});
