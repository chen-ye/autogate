import { describe, it, expect, beforeEach, afterEach, spyOn } from "bun:test";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { loadConfig, type AutoGateConfig } from "@autogate/core";
import {
  classifyRequest,
  archiveEvaluationSession,
  extractVerdictFromSession,
  recordEvaluationVerdict,
  OpenCodeSessionEvaluator,
  type OpenCodeSessionClient,
} from "../src/evaluator.js";

describe("@autogate/opencode evaluator OpenCode v2 support", () => {
  let tempDir: string;
  const origEnv = { ...process.env };

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "autogate-eval-test-"));
  });

  afterEach(() => {
    process.env = { ...origEnv };
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  });

  describe("archiveEvaluationSession", () => {
    it("archives session using client.session.update and registers in openchamber archive if file exists", async () => {
      const ocDir = path.join(tempDir, ".config", "openchamber");
      fs.mkdirSync(ocDir, { recursive: true });
      const archiveFile = path.join(ocDir, "sessions-archive.json");
      fs.writeFileSync(archiveFile, JSON.stringify({ existing_id: 12345 }));

      process.env.HOME = tempDir;
      const homedirSpy = spyOn(os, "homedir").mockReturnValue(tempDir);

      const updateCalls: Array<{ sessionID: string; title?: string; archived?: boolean }> = [];
      const mockClient = {
        session: {
          update: async (opts: { sessionID: string; title?: string; archived?: boolean }) => {
            updateCalls.push(opts);
            return { ok: true };
          },
        },
      } as unknown as OpenCodeSessionClient;

      try {
        await archiveEvaluationSession(mockClient, "ses_test_123", "bash", "ALLOW");

        expect(updateCalls.length).toBe(1);
        expect(updateCalls[0]).toEqual({
          sessionID: "ses_test_123",
          title: "[auto-gate-eval] bash -> ALLOW",
          archived: true,
        });

        const written = JSON.parse(fs.readFileSync(archiveFile, "utf8")) as Record<string, number>;
        expect(written.existing_id).toBe(12345);
        expect(typeof written.ses_test_123).toBe("number");
      } finally {
        homedirSpy.mockRestore();
      }
    });

    it("does not fail or write if openchamber archive does not exist", async () => {
      const homedirSpy = spyOn(os, "homedir").mockReturnValue(tempDir);
      const updateCalls: Array<{ sessionID: string; title?: string; archived?: boolean }> = [];
      const mockClient = {
        session: {
          update: async (opts: { sessionID: string; title?: string; archived?: boolean }) => {
            updateCalls.push(opts);
            return { ok: true };
          },
        },
      } as unknown as OpenCodeSessionClient;

      try {
        await archiveEvaluationSession(mockClient, "ses_test_456", "bash", "BLOCK");
        expect(updateCalls.length).toBe(1);
        expect(updateCalls[0]).toEqual({
          sessionID: "ses_test_456",
          title: "[auto-gate-eval] bash -> BLOCK",
          archived: true,
        });
      } finally {
        homedirSpy.mockRestore();
      }
    });

    it("falls back to title-only update when client.session.update rejects archived", async () => {
      const homedirSpy = spyOn(os, "homedir").mockReturnValue(tempDir);
      const updateCalls: Array<{ sessionID: string; title?: string; archived?: boolean }> = [];
      const mockClient = {
        session: {
          update: async (opts: { sessionID: string; title?: string; archived?: boolean }) => {
            updateCalls.push(opts);
            if ("archived" in opts) {
              throw new Error("Unknown field archived");
            }
            return { ok: true };
          },
        },
      } as unknown as OpenCodeSessionClient;

      try {
        await archiveEvaluationSession(mockClient, "ses_test_20x", "bash", "ALLOW");
        expect(updateCalls).toEqual([
          { sessionID: "ses_test_20x", title: "[auto-gate-eval] bash -> ALLOW", archived: true },
          { sessionID: "ses_test_20x", title: "[auto-gate-eval] bash -> ALLOW" },
        ]);
      } finally {
        homedirSpy.mockRestore();
      }
    });

    it("uses explicit serverUrl PATCH fallback only when serverUrl is configured and time.archived is absent", async () => {
      const homedirSpy = spyOn(os, "homedir").mockReturnValue(tempDir);
      const origFetch = globalThis.fetch;
      const patchCalls: Array<{ url: string; method?: string; body?: string }> = [];

      globalThis.fetch = (async (url: string | URL | Request, init?: RequestInit) => {
        patchCalls.push({
          url: String(url),
          method: init?.method,
          body: typeof init?.body === "string" ? init.body : undefined,
        });
        return { ok: true, status: 204 } as Response;
      }) as typeof fetch;

      try {
        const strippedClient = {
          session: {
            update: async () => undefined,
            get: async () => ({ id: "ses_strip_1", title: "[auto-gate-eval] bash -> ALLOW" }),
          },
        } as unknown as OpenCodeSessionClient;

        // Without explicit serverUrl, no HTTP call is made (hermetic unit tests)
        await archiveEvaluationSession(strippedClient, "ses_strip_1", "bash", "ALLOW");
        expect(patchCalls.length).toBe(0);

        // With explicit serverUrl and missing time.archived, sends PATCH /api/session/:id
        // omitting title because client.session.update already succeeded
        await archiveEvaluationSession(strippedClient, "ses_strip_1", "bash", "ALLOW", {
          serverUrl: "http://127.0.0.1:9998",
        });
        expect(patchCalls).toEqual([
          {
            url: "http://127.0.0.1:9998/api/session/ses_strip_1",
            method: "PATCH",
            body: JSON.stringify({
              archived: true,
            }),
          },
        ]);

        // With explicit serverUrl and no session.get method, still sends PATCH fallback
        const noGetClient = {
          session: {
            update: async () => undefined,
          },
        } as unknown as OpenCodeSessionClient;
        await archiveEvaluationSession(noGetClient, "ses_noget_1", "bash", "ALLOW", {
          serverUrl: "http://127.0.0.1:9998",
        });
        expect(patchCalls.length).toBe(2);
        expect(patchCalls[1]).toEqual({
          url: "http://127.0.0.1:9998/api/session/ses_noget_1",
          method: "PATCH",
          body: JSON.stringify({
            archived: true,
          }),
        });

        // When session.get already reports time.archived, skips redundant PATCH
        const archivedClient = {
          session: {
            update: async () => undefined,
            get: async () => ({
              id: "ses_done_1",
              time: { created: 100, updated: 200, archived: 300 },
            }),
          },
        } as unknown as OpenCodeSessionClient;
        await archiveEvaluationSession(archivedClient, "ses_done_1", "bash", "ALLOW", {
          serverUrl: "http://127.0.0.1:9998",
        });
        expect(patchCalls.length).toBe(2);

        // Two-arg OpenCodeSessionEvaluator(client, loadConfig()) must not leak PATCH to default :4096
        const twoArgClient = {
          agent: { list: async () => ({ data: [{ id: "auto-gate-eval" }] }) },
          session: {
            create: async () => ({ data: { id: "ses_two_arg_1" } }),
            update: async () => undefined,
            get: async () => ({ id: "ses_two_arg_1" }),
            prompt: async (opts: { sessionID: string }) => {
              recordEvaluationVerdict(opts.sessionID, { verdict: "ALLOW", reason: "OK" });
              return { data: { parts: [] } };
            },
          },
        } as unknown as OpenCodeSessionClient;
        const twoArgEvaluator = new OpenCodeSessionEvaluator(twoArgClient, loadConfig({}));
        await twoArgEvaluator.evaluate({
          id: "act-two-arg",
          harness: "opencode",
          sessionID: "ses-parent",
          toolName: "bash",
          commandString: "ls",
          workspaceRoot: tempDir,
          userPrompt: "list files",
        });
        expect(patchCalls.length).toBe(2);
      } finally {
        globalThis.fetch = origFetch;
        homedirSpy.mockRestore();
      }
    });
  });

  describe("extractVerdictFromSession", () => {
    it("queries session.context({ sessionID }) and extracts classify_result verdict", async () => {
      const contextCalls: Array<{ sessionID: string }> = [];
      const mockClient = {
        session: {
          context: async (opts: { sessionID: string }) => {
            contextCalls.push(opts);
            return [
              {
                type: "assistant",
                content: [
                  {
                    type: "tool",
                    name: "classify_result",
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
            ];
          },
        },
      } as unknown as OpenCodeSessionClient;

      const result = await extractVerdictFromSession(mockClient, "ses_789");
      expect(result).not.toBeNull();
      expect(result?.verdict).toBe("ALLOW");
      expect(contextCalls.length).toBe(1);
      expect(contextCalls[0]).toEqual({
        sessionID: "ses_789",
      });
    });
  });

  describe("classifyRequest session creation", () => {
    it("uses v2 location schema and top-level prompt input", async () => {
      let createOpts: Record<string, unknown> | undefined;
      let promptOpts: Record<string, unknown> | undefined;
      const mockClient = {
        agent: { list: async () => ({ data: [{ id: "auto-gate-eval" }] }) },
        session: {
          create: async (opts: Record<string, unknown>) => {
            createOpts = opts;
            return { data: { id: "ses_v2_created" } };
          },
          update: async () => ({}),
          prompt: async (opts: { sessionID: string; text: string }) => {
            promptOpts = opts;
            recordEvaluationVerdict(opts.sessionID, {
              verdict: "ALLOW",
              risk_level: "LOW",
              user_authorization: "LOW",
              reason: "OK",
            });
            return { data: { parts: [] } };
          },
        },
      } as unknown as OpenCodeSessionClient;

      const res = await classifyRequest({
        client: mockClient,
        actionName: "shell",
        actionArgs: { command: "ls" },
      });

      expect(res.verdict).toBe("ALLOW");
      const loc = createOpts?.location as { directory?: string } | undefined;
      expect(loc).toBeDefined();
      expect(typeof loc?.directory).toBe("string");
      expect(promptOpts?.sessionID).toBe("ses_v2_created");
      expect(typeof promptOpts?.text).toBe("string");
    });

    it("falls back to direct HTTP API if client.session.create fails entirely", async () => {
      const origFetch = globalThis.fetch;
      const fetchedUrls: string[] = [];
      const fetchedBodies: Array<Record<string, unknown>> = [];

      globalThis.fetch = (async (url: string | URL | Request, init?: RequestInit) => {
        fetchedUrls.push(String(url));
        if (typeof init?.body === "string") {
          fetchedBodies.push(JSON.parse(init.body) as Record<string, unknown>);
        }
        return {
          ok: true,
          json: async () => ({ data: { id: "ses_http_api_123" } }),
        } as Response;
      }) as typeof fetch;

      const mockClient = {
        agent: { list: async () => ({ data: [] }) },
        session: {
          create: async () => {
            throw new Error("Client session create completely broken");
          },
          update: async () => ({}),
          prompt: async (opts: { sessionID: string }) => {
            recordEvaluationVerdict(opts.sessionID, {
              verdict: "ALLOW",
              reason: "Direct HTTP OK",
            });
            return { data: { parts: [] } };
          },
        },
      } as unknown as OpenCodeSessionClient;

      try {
        const res = await classifyRequest({
          client: mockClient,
          actionName: "shell",
          actionArgs: { command: "pwd" },
          config: {
            serverUrl: "http://127.0.0.1:9999",
          } as unknown as AutoGateConfig,
        });

        expect(res.verdict).toBe("ALLOW");
        expect(fetchedUrls.length).toBeGreaterThan(0);
        expect(fetchedUrls[0]).toBe("http://127.0.0.1:9999/api/session");
        expect(fetchedBodies[0]?.location).toBeDefined();
      } finally {
        globalThis.fetch = origFetch;
      }
    });

    it("interrupts ephemeral session and skips reprompts when signal aborts", async () => {
      const controller = new AbortController();
      let interruptedSessionID: string | undefined;
      let promptCalls = 0;

      const mockClient = {
        agent: { list: async () => ({ data: [{ id: "auto-gate-eval" }] }) },
        session: {
          create: async () => ({ data: { id: "ses_v2_abort" } }),
          update: async () => ({}),
          interrupt: async (opts: { sessionID: string; resume?: boolean }) => {
            interruptedSessionID = opts.sessionID;
            return {};
          },
          prompt: async () => {
            promptCalls++;
            await new Promise((r) => setTimeout(r, 80));
            return { data: { parts: [] } };
          },
        },
      } as unknown as OpenCodeSessionClient;

      setTimeout(() => controller.abort("system1-won-race"), 10);

      const res = await classifyRequest({
        client: mockClient,
        actionName: "bash",
        actionArgs: { command: "git status" },
        signal: controller.signal,
      });

      expect(res.verdict).toBe("UNSURE");
      expect(res.reason).toContain("aborted");
      expect(interruptedSessionID).toBe("ses_v2_abort");
      await new Promise((r) => setTimeout(r, 100));
      expect(promptCalls).toBe(1);
    });

    it("OpenCodeSessionEvaluator normalizes rawArgs glob patterns with metadata.command for prober", async () => {
      const scriptsDir = path.join(tempDir, "scripts");
      fs.mkdirSync(scriptsDir, { recursive: true });
      fs.writeFileSync(path.join(scriptsDir, "deploy.py"), "print('v2_deploy_ok')\n");

      const capturedPrompts: string[] = [];
      const mockClient = {
        agent: { list: async () => ({ data: [{ id: "auto-gate-eval" }] }) },
        session: {
          create: async () => ({ data: { id: "ses_v2_wiring" } }),
          update: async () => ({}),
          prompt: async (opts: { sessionID: string; text: string }) => {
            capturedPrompts.push(opts.text);
            recordEvaluationVerdict(opts.sessionID, {
              verdict: "ALLOW",
              risk_level: "LOW",
              user_authorization: "HIGH",
              reason: "OK",
            });
            return { data: { parts: [] } };
          },
        },
      } as unknown as OpenCodeSessionClient;

      const evaluator = new OpenCodeSessionEvaluator(mockClient);
      const res = await evaluator.evaluate({
        id: "act-v2-wire",
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
      expect(capturedPrompts[0]).toContain("print('v2_deploy_ok')");
    });
  });
});
