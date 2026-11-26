import { describe, it, expect, beforeEach, afterEach, spyOn } from "bun:test";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { AutoGateEvalStore, loadConfig } from "@autogate/core";
import {
  classifyRequest,
  archiveEvaluationSession,
  extractVerdictFromSession,
  recordEvaluationVerdict,
  OpenCodeV1SessionEvaluator,
  type OpenCodeV1SessionClient,
} from "../src/evaluator.js";

describe("@autogate/opencode1 evaluator OpenCode v1 support", () => {
  let tempDir: string;
  const origEnv = { ...process.env };

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "autogate-eval-v1-test-"));
    process.env.XDG_CONFIG_HOME = tempDir;
    process.env.AUTOGATE_EVAL_DB = path.join(tempDir, "evals.db");
  });

  afterEach(() => {
    process.env = { ...origEnv };
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  });

  describe("archiveEvaluationSession", () => {
    it("archives session using client.session.update and registers in openchamber1 archive if file exists", async () => {
      const oc1Dir = path.join(tempDir, ".config", "openchamber1");
      fs.mkdirSync(oc1Dir, { recursive: true });
      const archiveFile = path.join(oc1Dir, "sessions-archive.json");
      fs.writeFileSync(archiveFile, JSON.stringify({ existing_id: 12345 }));

      process.env.HOME = tempDir;
      const homedirSpy = spyOn(os, "homedir").mockReturnValue(tempDir);

      const updateCalls: Array<{
        path: { id?: string; sessionID?: string };
        body: { title?: string; time?: { archived?: number } };
      }> = [];
      const mockClient = {
        session: {
          update: async (opts: {
            path: { id?: string; sessionID?: string };
            body: { title?: string; time?: { archived?: number } };
          }) => {
            updateCalls.push(opts);
            return { ok: true };
          },
        },
      } as unknown as OpenCodeV1SessionClient;

      try {
        await archiveEvaluationSession(mockClient, "ses_test_123", "bash", "ALLOW");

        expect(updateCalls.length).toBe(1);
        expect(updateCalls[0]?.path).toEqual({ id: "ses_test_123", sessionID: "ses_test_123" });
        expect(updateCalls[0]?.body.title).toBe("[auto-gate-eval] bash -> ALLOW");

        const written = JSON.parse(fs.readFileSync(archiveFile, "utf8")) as Record<string, number>;
        expect(written.existing_id).toBe(12345);
        expect(typeof written.ses_test_123).toBe("number");
      } finally {
        homedirSpy.mockRestore();
      }
    });
  });

  describe("extractVerdictFromSession", () => {
    it("queries messages with path id/sessionID and limit: 50", async () => {
      const messageCalls: unknown[] = [];
      const mockClient = {
        session: {
          messages: async (opts: unknown) => {
            messageCalls.push(opts);
            return {
              data: [
                {
                  parts: [
                    {
                      type: "tool",
                      tool: "classify_result",
                      state: {
                        input: {
                          verdict: "ALLOW",
                          risk_level: "LOW",
                          user_authorization: "LOW",
                          reason: "Safe check",
                        },
                      },
                    },
                  ],
                },
              ],
            };
          },
        },
      } as unknown as OpenCodeV1SessionClient;

      const result = await extractVerdictFromSession(mockClient, "ses_789");
      expect(result).not.toBeNull();
      expect(result?.verdict).toBe("ALLOW");
      expect(messageCalls.length).toBe(1);
      expect(messageCalls[0]).toEqual({
        path: { id: "ses_789", sessionID: "ses_789" },
        query: { limit: 50 },
      });
    });
  });

  describe("classifyRequest session creation", () => {
    it("uses v1 directory schema and parts array", async () => {
      let createOpts: Record<string, unknown> | undefined;
      let promptOpts: Record<string, unknown> | undefined;
      const mockClient = {
        app: { agents: async () => ({ data: [{ name: "auto-gate-eval" }] }) },
        session: {
          create: async (opts: Record<string, unknown>) => {
            createOpts = opts;
            return { data: { id: "ses_v1_created" } };
          },
          update: async () => ({}),
          prompt: async (opts: { path: { id?: string } }) => {
            promptOpts = opts as unknown as Record<string, unknown>;
            if (opts.path.id) {
              recordEvaluationVerdict(opts.path.id, {
                verdict: "ALLOW",
                risk_level: "LOW",
                user_authorization: "LOW",
                reason: "OK",
              });
            }
            return { data: { parts: [] } };
          },
        },
      } as unknown as OpenCodeV1SessionClient;

      const res = await classifyRequest({
        client: mockClient,
        actionName: "bash",
        actionArgs: { command: "ls" },
      });

      expect(res.verdict).toBe("ALLOW");
      expect(createOpts?.directory).toBeDefined();
      const body = promptOpts?.body as { parts?: unknown[] } | undefined;
      expect(Array.isArray(body?.parts)).toBe(true);
    });

    it("aborts ephemeral v1 session and skips reprompts when signal aborts", async () => {
      const controller = new AbortController();
      let abortedSessionID: string | undefined;
      let promptCalls = 0;

      const mockClient = {
        app: { agents: async () => ({ data: [{ name: "auto-gate-eval" }] }) },
        session: {
          create: async () => ({ data: { id: "ses_v1_abort" } }),
          update: async () => ({}),
          abort: async (opts: { path: { id?: string } }) => {
            abortedSessionID = opts.path.id;
            return {};
          },
          prompt: async () => {
            promptCalls++;
            await new Promise((r) => setTimeout(r, 80));
            return { data: { parts: [] } };
          },
        },
      } as unknown as OpenCodeV1SessionClient;

      setTimeout(() => controller.abort("system1-won-race"), 10);

      const res = await classifyRequest({
        client: mockClient,
        actionName: "bash",
        actionArgs: { command: "git status" },
        signal: controller.signal,
      });

      expect(res.verdict).toBe("UNSURE");
      expect(res.reason).toContain("aborted");
      expect(abortedSessionID).toBe("ses_v1_abort");
      await new Promise((r) => setTimeout(r, 100));
      expect(promptCalls).toBe(1);
    });

    it("OpenCodeV1SessionEvaluator normalizes rawArgs glob patterns with metadata.command for prober", async () => {
      const scriptsDir = path.join(tempDir, "scripts");
      fs.mkdirSync(scriptsDir, { recursive: true });
      fs.writeFileSync(path.join(scriptsDir, "deploy.py"), "print('v1_deploy_ok')\n");

      const capturedPrompts: string[] = [];
      const mockClient = {
        app: { agents: async () => ({ data: [{ name: "auto-gate-eval" }] }) },
        session: {
          create: async () => ({ data: { id: "ses_v1_wiring" } }),
          update: async () => ({}),
          prompt: async (opts: {
            path: { id?: string };
            body: { parts: Array<{ type: string; text: string }> };
          }) => {
            capturedPrompts.push(opts.body.parts[0]?.text ?? "");
            if (opts.path.id) {
              recordEvaluationVerdict(opts.path.id, {
                verdict: "ALLOW",
                risk_level: "LOW",
                user_authorization: "HIGH",
                reason: "OK",
              });
            }
            return { data: { parts: [] } };
          },
        },
      } as unknown as OpenCodeV1SessionClient;

      const evaluator = new OpenCodeV1SessionEvaluator(mockClient);
      const res = await evaluator.evaluate({
        id: "act-v1-wire",
        harness: "opencode",
        sessionID: "ses-orig",
        toolName: "bash",
        commandString: "python3 scripts/deploy.py",
        patterns: ["python3 *"],
        rawArgs: ["python3 *"],
        workspaceRoot: tempDir,
        userPrompt: "Deploy",
        metadata: { command: "python3 scripts/deploy.py", directory: tempDir },
      });

      expect(res.verdict).toBe("ALLOW");
      expect(capturedPrompts[0]).toContain("Target Script Inspected");
      expect(capturedPrompts[0]).toContain("print('v1_deploy_ok')");
    });

    it("records opencode1 evaluation decisions into AutoGateEvalStore when evalDbFile is configured", async () => {
      const dbPath = path.join(tempDir, "custom-opencode1.db");
      const mockClient = {
        app: { agents: async () => ({ data: [{ name: "auto-gate-eval" }] }) },
        session: {
          create: async () => ({ data: { id: "ses_s2_v1_record" } }),
          update: async () => ({}),
          prompt: async (opts: { path: { id?: string } }) => {
            if (opts.path.id) {
              recordEvaluationVerdict(opts.path.id, {
                verdict: "BLOCK",
                risk_level: "HIGH",
                user_authorization: "NONE",
                reason: "Blocked unauthorized write",
              });
            }
            return { data: { parts: [] } };
          },
        },
      } as unknown as OpenCodeV1SessionClient;

      const config = loadConfig({
        evalDbFile: dbPath,
        classifierModel: "google/gemini-3.5-flash-lite",
        systemOne: { enabled: false },
      });
      const evaluator = new OpenCodeV1SessionEvaluator(mockClient, config);
      const res = await evaluator.evaluate({
        id: "act-v1-db",
        harness: "opencode",
        sessionID: "ses-target-v1",
        toolName: "edit",
        targetPath: "/etc/hosts",
        workspaceRoot: tempDir,
        userPrompt: "Check readme",
      });

      expect(res.verdict).toBe("BLOCK");

      const store = new AutoGateEvalStore(dbPath, { readonly: true });
      try {
        const records = store.queryEvaluations();
        expect(records).toHaveLength(1);
        const rec = records[0]!;
        expect(rec.sourceFormat).toBe("opencode1");
        expect(rec.sessionId).toBe("ses-target-v1");
        expect(rec.s2SessionId).toBe("ses_s2_v1_record");
        expect(rec.actionId).toBe("act-v1-db");
        expect(rec.toolName).toBe("edit");
        expect(rec.targetPath).toBe("/etc/hosts");
        expect(rec.verdict).toBe("BLOCK");
        expect(rec.riskLevel).toBe("HIGH");
        expect(rec.userAuthorization).toBe("NONE");
        expect(rec.reasoning).toBe("Blocked unauthorized write");
        expect(rec.modelProvider).toBe("google");
        expect(rec.modelId).toBe("gemini-3.5-flash-lite");
      } finally {
        store.close();
      }
    });
  });
});
