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
  isEventForWorkspace,
  OpenCodeHarnessAdapter,
  plugin,
} from "../src/index.js";

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
