import { afterEach, beforeEach, describe, it, expect } from "bun:test";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import type { PluginInput } from "@opencode-ai/plugin";
import { AutoGateEvalStore } from "@autogate/core";
import { AutoGatePlugin, OpenCodeV1HarnessAdapter, isEventForWorkspace } from "../src/index.js";

describe("@autogate/opencode1 runtime agent injection & workspace filter", () => {
  let tempDir: string;
  const origEnv = { ...process.env };
  const origFetch = globalThis.fetch;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "autogate-v1-index-"));
    process.env.XDG_CONFIG_HOME = tempDir;
    process.env.AUTOGATE_EVAL_DB = path.join(tempDir, "evals.db");
  });

  afterEach(() => {
    process.env = { ...origEnv };
    globalThis.fetch = origFetch;
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  });

  it("matches workspace correctly", () => {
    expect(isEventForWorkspace({}, undefined)).toBe(true);
    expect(
      isEventForWorkspace({ location: { directory: "/home/user/project" } }, "/home/user/project"),
    ).toBe(true);
    expect(
      isEventForWorkspace({ location: { directory: "/other/dir" } }, "/home/user/project"),
    ).toBe(false);
  });

  it("registers auto-gate-eval via config() hook in OpenCode v1 server plugin", async () => {
    const hooks = await AutoGatePlugin(
      { directory: "/tmp/test-ws-v1", client: {} } as unknown as PluginInput,
      {
        classifierModel: "google/gemini-3.5-flash-lite",
        ntfyServer: "http://127.0.0.1:59999",
      },
    );

    const hookMap = hooks as Record<string, unknown>;
    try {
      const configData: { agent?: Record<string, Record<string, unknown>> } = {};
      const configHook = hookMap.config as
        | ((cfg: Record<string, unknown>) => Promise<void>)
        | undefined;
      if (configHook) {
        await configHook(configData);
      }
      const evalAgent = configData.agent?.["auto-gate-eval"];
      expect(evalAgent).toBeDefined();
      expect(evalAgent?.mode).toBe("subagent");
      expect(evalAgent?.hidden).toBe(true);
      expect(typeof evalAgent?.prompt).toBe("string");
    } finally {
      const disposeHook = hookMap.dispose as (() => Promise<void>) | undefined;
      if (typeof disposeHook === "function") await disposeHook();
    }
  });

  it("persists cascade evaluations from handlePermissionAsked to AutoGateEvalStore", async () => {
    const dbPath = path.join(tempDir, "cascade-v1.db");
    const replied: Array<Record<string, unknown>> = [];

    globalThis.fetch = (async () =>
      new Response(
        JSON.stringify({
          answers: {
            verdict: { probabilities: { ALLOW: 0.98, BLOCK: 0.02 } },
            in_scope: { noul: 0.95 },
            injection_risk: { noul: 0.01 },
          },
        }),
        { status: 200 },
      )) as typeof fetch;

    const mockClient = {
      session: {
        get: async () => ({ data: { id: "ses-v1-cascade", title: "Root" } }),
        messages: async () => ({
          data: [{ role: "user", parts: [{ type: "text", text: "Check git status" }] }],
        }),
      },
      permission: {
        reply: async (opts: Record<string, unknown>) => {
          replied.push(opts);
          return { response: { ok: true } };
        },
      },
    };

    const adapter = new OpenCodeV1HarnessAdapter(
      { directory: tempDir, client: mockClient } as unknown as PluginInput,
      {
        evalDbFile: dbPath,
        notifyOnVerdict: false,
        reviewFallbackMode: "native",
        systemOne: {
          enabled: true,
          executionMode: "cascade",
          endpoint: "http://127.0.0.1:4006/v1/systemone",
          model: "gemini-decision-1",
          timeoutMs: 2000,
        },
      },
    );

    try {
      await adapter.handlePermissionAsked({
        id: "perm-v1-1",
        sessionID: "ses-v1-cascade",
        action: "bash",
        metadata: { command: "git status", directory: tempDir },
      });

      expect(replied).toHaveLength(1);

      const store = new AutoGateEvalStore(dbPath, { readonly: true });
      try {
        const records = store.queryEvaluations();
        expect(records).toHaveLength(1);
        const rec = records[0]!;
        expect(rec.sourceFormat).toBe("opencode1");
        expect(rec.sessionId).toBe("ses-v1-cascade");
        expect(rec.actionId).toBe("perm-v1-1");
        expect(rec.toolName).toBe("bash");
        expect(rec.commandString).toBe("git status");
        expect(rec.verdict).toBe("ALLOW");
        expect(rec.cascadeWinner).toBe("system1");
      } finally {
        store.close();
      }
    } finally {
      await adapter.dispose();
    }
  });
});
