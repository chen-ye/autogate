import { describe, it, expect, beforeEach, afterEach, spyOn } from "bun:test";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import {
  AutoGateEvalStore,
  PASSIVE_EVALUATOR_DIRECTIVE,
  loadConfig,
  type AutoGateConfig,
} from "@autogate/core";
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
    process.env.XDG_CONFIG_HOME = path.join(tempDir, "xdg");
    fs.mkdirSync(path.join(process.env.XDG_CONFIG_HOME, "autogate"), { recursive: true });
    delete process.env.AUTOGATE_CONFIG;
    delete process.env.AUTOGATE_EVAL_DB;
    delete process.env.AUTOGATE_EVAL_SESSION_CLEANUP;
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

  describe("S2 archiving, evals.db persistence, and cleanup modes", () => {
    it("exports S2 session with zstd compression, prompt_templates dedup, metrics metadata, and deletes via session.remove", async () => {
      const evalDbFile = path.join(tempDir, "evals.db");
      const removedSessions: string[] = [];
      const updatedSessions: Array<{ sessionID: string; title?: string; archived?: boolean }> = [];
      let seq = 0;

      const mockClient = {
        agent: { list: async () => ({ data: [{ id: "auto-gate-eval" }] }) },
        session: {
          create: async () => {
            seq++;
            return { data: { id: `ses_s2_full_${seq}` } };
          },
          get: async ({ sessionID }: { sessionID: string }) => ({
            data: {
              id: sessionID,
              agent: "auto-gate-eval",
              model: { providerID: "google", id: "gemini-3.5-flash-lite" },
              tokens: {
                input: 420,
                output: 55,
                reasoning: 25,
                cache: { read: 110, write: 12 },
              },
              cost: 0.00041,
              outcome: "succeeded",
              location: { directory: "/tmp/opencode-auto-gate/sandbox" },
              time: { created: 1700000000100, updated: 1700000000600 },
            },
          }),
          context: async ({ sessionID }: { sessionID: string }) => [
            {
              type: "user",
              text: `Evaluate command for ${sessionID}`,
            },
            {
              type: "assistant",
              agent: "auto-gate-eval",
              model: { providerID: "google", id: "gemini-3.5-flash-lite" },
              content: [
                { type: "reasoning", text: "Command lists local files safely." },
                {
                  type: "tool",
                  id: "tc_1",
                  name: "classify_result",
                  state: {
                    status: "completed",
                    input: {
                      verdict: "ALLOW",
                      risk_level: "LOW",
                      user_authorization: "HIGH",
                      reason: "Safe read-only workspace check",
                    },
                  },
                },
              ],
            },
          ],
          prompt: async (opts: { sessionID: string; text: string }) => {
            recordEvaluationVerdict(opts.sessionID, {
              verdict: "ALLOW",
              risk_level: "LOW",
              user_authorization: "HIGH",
              reason: "Safe read-only workspace check",
            });
            return { data: { parts: [] } };
          },
          remove: async ({ sessionID }: { sessionID: string }) => {
            removedSessions.push(sessionID);
          },
          update: async (opts: { sessionID: string; title?: string; archived?: boolean }) => {
            updatedSessions.push(opts);
          },
        },
      } as unknown as OpenCodeSessionClient;

      const config = loadConfig({
        evalDbFile,
        evalSessionCleanup: "export-and-delete",
        classifierModel: "google/gemini-3.5-flash-lite",
      });

      const res1 = await classifyRequest({
        client: mockClient,
        config,
        evalDbFile,
        targetSessionId: "ses_coding_1",
        actionId: "act_1",
        toolName: "bash",
        commandString: "git status",
        workspaceRoot: tempDir,
        userPrompt: "Check git status",
      });

      const res2 = await classifyRequest({
        client: mockClient,
        config,
        evalDbFile,
        targetSessionId: "ses_coding_1",
        actionId: "act_2",
        toolName: "bash",
        commandString: "git diff",
        workspaceRoot: tempDir,
        userPrompt: "Check git diff",
      });

      expect(res1.verdict).toBe("ALLOW");
      expect(res1.metadata?.s2SessionId).toBe("ses_s2_full_1");
      expect(res1.metadata?.modelId).toBe("gemini-3.5-flash-lite");
      expect(res1.metadata?.modelProvider).toBe("google");
      expect(res1.metadata?.promptTokens).toBe(420);
      expect(res1.metadata?.outputTokens).toBe(55);
      expect(res1.metadata?.reasoningTokens).toBe(25);
      expect(res1.metadata?.cost).toBeCloseTo(0.00041, 8);
      expect(res1.metadata?.thinking).toBe("Command lists local files safely.");

      expect(removedSessions).toEqual(["ses_s2_full_1", "ses_s2_full_2"]);
      expect(updatedSessions).toEqual([]);
      expect(fs.existsSync(path.join(tempDir, "evals.jsonl"))).toBe(false);

      const store = new AutoGateEvalStore(evalDbFile, { readonly: true });
      try {
        const stats = store.getStats();
        expect(stats.total).toBe(2);
        expect(stats.s2SessionCount).toBe(2);
        expect(stats.promptTemplateCount).toBe(1);

        const detail = store.getEvaluationDetail("ses_s2_full_1");
        expect(detail).not.toBeNull();
        expect(detail?.evaluation.sessionId).toBe("ses_coding_1");
        expect(detail?.evaluation.actionId).toBe("act_1");
        expect(detail?.evaluation.s2SessionId).toBe("ses_s2_full_1");
        expect(detail?.evaluation.modelId).toBe("gemini-3.5-flash-lite");
        expect(detail?.evaluation.modelProvider).toBe("google");
        expect(detail?.evaluation.promptTokens).toBe(420);
        expect(detail?.evaluation.outputTokens).toBe(55);
        expect(detail?.evaluation.reasoningTokens).toBe(25);
        expect(detail?.evaluation.thinking).toBe("Command lists local files safely.");
        expect(detail?.s2Session?.status).toBe("completed");
        expect(detail?.s2Session?.cacheReadTokens).toBe(110);
        expect(detail?.s2Session?.cacheWriteTokens).toBe(12);
        expect(detail?.s2Session?.messageCount).toBe(2);
        expect(detail?.promptTemplate?.systemPrompt).toContain(PASSIVE_EVALUATOR_DIRECTIVE);

        const payload = detail?.s2Session?.payload as Record<string, unknown>;
        expect(typeof payload.capturedUserPrompt).toBe("string");
        expect(payload.capturedUserPrompt).toContain("git status");
        expect(Array.isArray(payload.messages)).toBe(true);
      } finally {
        store.close();
      }
    });

    it("archives partial, aborted, timeout, and error S2 sessions and bounds hung session.get/context fetches", async () => {
      const evalDbFile = path.join(tempDir, "partial-evals.db");

      // 1. Aborted mid-flight with hung session.get / session.context (tests bounded 1500ms capture)
      const abortController = new AbortController();
      const abortClient = {
        agent: { list: async () => ({ data: [{ id: "auto-gate-eval" }] }) },
        session: {
          create: async () => ({ data: { id: "ses_s2_hung_abort" } }),
          get: () => new Promise(() => {}),
          context: () => new Promise(() => {}),
          interrupt: async () => ({}),
          prompt: async () => {
            await new Promise((r) => setTimeout(r, 80));
            return { data: { reasoning: "Partial in-memory thought", parts: [] } };
          },
          remove: async () => {},
        },
      } as unknown as OpenCodeSessionClient;

      setTimeout(() => abortController.abort("system1-won-race"), 10);
      const t0 = Date.now();
      const abortRes = await classifyRequest({
        client: abortClient,
        evalDbFile,
        targetSessionId: "ses_target_abort",
        actionId: "act_abort",
        toolName: "bash",
        commandString: "ls -la",
        userPrompt: "List workspace",
        workspaceRoot: tempDir,
        signal: abortController.signal,
      });
      const abortElapsed = Date.now() - t0;
      expect(abortRes.verdict).toBe("UNSURE");
      expect(abortRes.metadata?.s2SessionId).toBe("ses_s2_hung_abort");
      expect(abortElapsed).toBeLessThan(3000);

      // 2. Timeout
      const timeoutClient = {
        agent: { list: async () => ({ data: [{ id: "auto-gate-eval" }] }) },
        session: {
          create: async () => ({ data: { id: "ses_s2_timeout" } }),
          interrupt: async () => ({}),
          prompt: async () => {
            await new Promise((r) => setTimeout(r, 200));
            return { data: { parts: [] } };
          },
          remove: async () => {},
        },
      } as unknown as OpenCodeSessionClient;

      const timeoutRes = await classifyRequest({
        client: timeoutClient,
        evalDbFile,
        targetSessionId: "ses_target_timeout",
        actionId: "act_timeout",
        toolName: "bash",
        commandString: "sleep 10",
        workspaceRoot: tempDir,
        config: loadConfig({ evalDbFile, classifierTimeout: 30 }),
      });
      expect(timeoutRes.verdict).toBe("UNSURE");
      expect(timeoutRes.reason).toContain("timed out");
      expect(timeoutRes.metadata?.s2SessionId).toBe("ses_s2_timeout");

      // 3. Retries exhausted -> partial
      const partialClient = {
        agent: { list: async () => ({ data: [{ id: "auto-gate-eval" }] }) },
        session: {
          create: async () => ({ data: { id: "ses_s2_partial" } }),
          prompt: async () => ({
            data: {
              reasoning: "Did not call tool",
              parts: [{ type: "text", text: "I am unsure what to do." }],
            },
          }),
          remove: async () => {},
        },
      } as unknown as OpenCodeSessionClient;

      const partialRes = await classifyRequest({
        client: partialClient,
        evalDbFile,
        targetSessionId: "ses_target_partial",
        actionId: "act_partial",
        toolName: "bash",
        commandString: "echo hi",
        workspaceRoot: tempDir,
      });
      expect(partialRes.verdict).toBe("UNSURE");
      expect(partialRes.metadata?.thinking).toBe("Did not call tool");

      // 4. Prompt throws error -> error
      const errorClient = {
        agent: { list: async () => ({ data: [{ id: "auto-gate-eval" }] }) },
        session: {
          create: async () => ({ data: { id: "ses_s2_error" } }),
          prompt: async () => {
            throw new Error("Upstream provider 503");
          },
          remove: async () => {},
        },
      } as unknown as OpenCodeSessionClient;

      const errorRes = await classifyRequest({
        client: errorClient,
        evalDbFile,
        targetSessionId: "ses_target_error",
        actionId: "act_error",
        toolName: "bash",
        commandString: "echo err",
        workspaceRoot: tempDir,
      });
      expect(errorRes.verdict).toBe("UNSURE");
      expect(errorRes.reason).toContain("Upstream provider 503");

      const store = new AutoGateEvalStore(evalDbFile, { readonly: true });
      try {
        expect(store.getS2Session("ses_s2_hung_abort")?.status).toBe("aborted");
        expect(store.getS2Session("ses_s2_timeout")?.status).toBe("timeout");
        expect(store.getS2Session("ses_s2_partial")?.status).toBe("partial");
        expect(store.getS2Session("ses_s2_error")?.status).toBe("error");

        const abortedDetail = store.getS2Session("ses_s2_hung_abort");
        const abortedPayload = abortedDetail?.payload as Record<string, unknown>;
        expect(abortedPayload.capturedUserPrompt).toContain("ls -la");
        expect(abortedPayload.status).toBe("aborted");
      } finally {
        store.close();
      }
    });

    it("respects evalSessionCleanup === 'archive', live getter, and falls back to archive when DB export or session.remove fails", async () => {
      const evalDbFile = path.join(tempDir, "cleanup-evals.db");
      const removedSessions: string[] = [];
      const archivedSessions: string[] = [];
      let seq = 0;

      const makeClient = (options?: { failRemove?: boolean }) =>
        ({
          agent: { list: async () => ({ data: [{ id: "auto-gate-eval" }] }) },
          session: {
            create: async () => ({ data: { id: `ses_clean_${++seq}` } }),
            prompt: async (opts: { sessionID: string }) => {
              recordEvaluationVerdict(opts.sessionID, {
                verdict: "ALLOW",
                risk_level: "LOW",
                user_authorization: "HIGH",
                reason: "OK",
              });
              return { data: { parts: [] } };
            },
            remove: async ({ sessionID }: { sessionID: string }) => {
              if (options?.failRemove) {
                throw new Error("remove failed");
              }
              removedSessions.push(sessionID);
            },
            update: async ({ sessionID }: { sessionID: string }) => {
              archivedSessions.push(sessionID);
            },
          },
        }) as unknown as OpenCodeSessionClient;

      // 1. Live getter switches from export-and-delete -> archive
      let currentMode: "export-and-delete" | "archive" = "export-and-delete";
      const evaluator = new OpenCodeSessionEvaluator(makeClient(), loadConfig({ evalDbFile }), {
        evalDbFile,
        getEvalSessionCleanup: () => currentMode,
      });

      await evaluator.evaluate({
        id: "act_c1",
        harness: "opencode",
        sessionID: "ses_parent",
        toolName: "bash",
        commandString: "pwd",
        workspaceRoot: tempDir,
        userPrompt: "pwd",
      });
      expect(removedSessions).toEqual(["ses_clean_1"]);
      expect(archivedSessions).toEqual([]);

      currentMode = "archive";
      await evaluator.evaluate({
        id: "act_c2",
        harness: "opencode",
        sessionID: "ses_parent",
        toolName: "bash",
        commandString: "ls",
        workspaceRoot: tempDir,
        userPrompt: "ls",
      });
      expect(removedSessions).toEqual(["ses_clean_1"]);
      expect(archivedSessions).toEqual(["ses_clean_2"]);

      // 2. Fallback to archive when DB export fails (unwritable path = existing directory)
      const originalWarn = console.warn;
      console.warn = () => {};
      try {
        await classifyRequest({
          client: makeClient(),
          evalDbFile: tempDir,
          evalSessionCleanup: "export-and-delete",
          actionName: "bash",
          actionArgs: { command: "ls" },
          workspaceRoot: tempDir,
        });
      } finally {
        console.warn = originalWarn;
      }
      expect(removedSessions).toEqual(["ses_clean_1"]);
      expect(archivedSessions).toEqual(["ses_clean_2", "ses_clean_3"]);

      // 3. Fallback to archive when session.remove rejects
      await classifyRequest({
        client: makeClient({ failRemove: true }),
        evalDbFile,
        evalSessionCleanup: "export-and-delete",
        actionName: "bash",
        actionArgs: { command: "ls" },
        workspaceRoot: tempDir,
      });
      expect(removedSessions).toEqual(["ses_clean_1"]);
      expect(archivedSessions).toEqual(["ses_clean_2", "ses_clean_3", "ses_clean_4"]);
    });

    it("does not leak session/message .id as modelId and keeps messageCount synced with sanitized payload", async () => {
      const evalDbFile = path.join(tempDir, "model-and-count.db");
      const { systemPrompt } = await import("@autogate/core").then((m) =>
        m.resolveEvalPromptBundle("auto-gate-eval", "google/gemini-3.5-flash-lite"),
      );

      const client = {
        agent: { list: async () => ({ data: [{ id: "auto-gate-eval" }] }) },
        session: {
          create: async () => ({ data: { id: "ses_s2_id_leak_guard" } }),
          prompt: async (opts: { sessionID: string }) => {
            recordEvaluationVerdict(opts.sessionID, {
              verdict: "ALLOW",
              risk_level: "LOW",
              user_authorization: "HIGH",
              reason: "Checked cleanly",
            });
            return { data: { parts: [] } };
          },
          get: async () => ({
            data: {
              id: "ses_s2_id_leak_guard",
              title: "[auto-gate-eval] bash",
              agent: "auto-gate-eval",
            },
          }),
          context: async () => ({
            data: [
              { id: "msg_sys", type: "system", text: systemPrompt },
              {
                id: "msg_user",
                type: "user",
                content: [{ type: "text", text: `${systemPrompt}\n\nProposed Action: ls` }],
              },
              {
                id: "msg_asst",
                info: {
                  id: "msg_asst",
                  role: "assistant",
                  modelID: "gemini-3.5-flash-lite",
                  providerID: "google",
                },
                parts: [{ type: "text", text: "Done" }],
              },
            ],
          }),
          remove: async () => {},
        },
      } as unknown as OpenCodeSessionClient;

      const res = await classifyRequest({
        client,
        evalDbFile,
        targetSessionId: "ses_parent_id_guard",
        actionId: "act_id_guard",
        toolName: "bash",
        commandString: "ls",
        workspaceRoot: tempDir,
        model: "google/gemini-3.5-flash-lite",
      });

      expect(res.metadata?.modelId).toBe("gemini-3.5-flash-lite");
      expect(res.metadata?.modelProvider).toBe("google");

      const store = new AutoGateEvalStore(evalDbFile, { readonly: true });
      try {
        const s2 = store.getS2Session("ses_s2_id_leak_guard");
        expect(s2?.modelId).toBe("gemini-3.5-flash-lite");
        expect(s2?.modelProvider).toBe("google");
        const payload = s2?.payload as { messages?: unknown[] };
        expect(payload.messages).toHaveLength(2);
        expect(s2?.messageCount).toBe(2);
      } finally {
        store.close();
      }
    });
  });
});
