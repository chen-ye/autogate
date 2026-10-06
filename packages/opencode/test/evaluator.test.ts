import { describe, it, expect, beforeEach, afterEach, spyOn } from "bun:test";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import {
  classifyRequest,
  archiveEvaluationSession,
  extractVerdictFromSession,
  recordEvaluationVerdict,
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
    it("archives session using client.session.update and registers in openchamber2 archive if file exists", async () => {
      const oc2Dir = path.join(tempDir, ".config", "openchamber2");
      fs.mkdirSync(oc2Dir, { recursive: true });
      const archiveFile = path.join(oc2Dir, "sessions-archive.json");
      fs.writeFileSync(archiveFile, JSON.stringify({ existing_id: 12345 }));

      process.env.HOME = tempDir;
      const homedirSpy = spyOn(os, "homedir").mockReturnValue(tempDir);

      let updateCalls: any[] = [];
      const mockClient = {
        session: {
          update: async (opts: any) => {
            updateCalls.push(opts);
            return { ok: true };
          },
        },
      };

      try {
        await archiveEvaluationSession(mockClient, "ses_test_123", "bash", "ALLOW");

        expect(updateCalls.length).toBe(1);
        expect(updateCalls[0].path).toEqual({ id: "ses_test_123", sessionID: "ses_test_123" });
        expect(updateCalls[0].body.title).toBe("[auto-gate-eval] bash -> ALLOW");

        const written = JSON.parse(fs.readFileSync(archiveFile, "utf8"));
        expect(written.existing_id).toBe(12345);
        expect(typeof written.ses_test_123).toBe("number");
      } finally {
        homedirSpy.mockRestore();
      }
    });

    it("does not fail or write if openchamber2 archive does not exist", async () => {
      const homedirSpy = spyOn(os, "homedir").mockReturnValue(tempDir);
      let updateCalls: any[] = [];
      const mockClient = {
        session: {
          update: async (opts: any) => {
            updateCalls.push(opts);
            return { ok: true };
          },
        },
      };

      try {
        await archiveEvaluationSession(mockClient, "ses_test_456", "bash", "BLOCK");
        expect(updateCalls.length).toBe(1);
      } finally {
        homedirSpy.mockRestore();
      }
    });
  });

  describe("extractVerdictFromSession", () => {
    it("queries messages with path id/sessionID and limit: 50", async () => {
      let messageCalls: any[] = [];
      const mockClient = {
        session: {
          messages: async (opts: any) => {
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
      };

      const result = await extractVerdictFromSession(mockClient, "ses_789");
      expect(result).not.toBeNull();
      expect(result?.verdict).toBe("ALLOW");
      expect(messageCalls.length).toBe(1);
      expect(messageCalls[0]).toEqual({
        path: { id: "ses_789", sessionID: "ses_789" },
        query: { limit: 50 },
      });
    });

    it("falls back to flat sessionID if path invocation fails", async () => {
      let callCount = 0;
      let lastOpts: any;
      const mockClient = {
        session: {
          messages: async (opts: any) => {
            callCount++;
            lastOpts = opts;
            if (opts.path) {
              throw new Error("v1 server path rejected");
            }
            return {
              data: [
                {
                  parts: [
                    {
                      type: "tool",
                      tool: "classify_result",
                      input: {
                        verdict: "BLOCK",
                        reason: "Denied",
                      },
                    },
                  ],
                },
              ],
            };
          },
        },
      };

      const result = await extractVerdictFromSession(mockClient, "ses_fallback");
      expect(result?.verdict).toBe("BLOCK");
      expect(callCount).toBe(2);
      expect(lastOpts).toEqual({
        sessionID: "ses_fallback",
        query: { limit: 50 },
      });
    });
  });

  describe("classifyRequest session creation", () => {
    it("uses v2 location schema when supported", async () => {
      let createOpts: any;
      const mockClient = {
        app: { agents: async () => ({ data: [{ name: "auto-gate-eval" }] }) },
        session: {
          create: async (opts: any) => {
            createOpts = opts;
            return { data: { id: "ses_v2_created" } };
          },
          update: async () => ({}),
          prompt: async (opts: any) => {
            recordEvaluationVerdict(opts.sessionID, {
              verdict: "ALLOW",
              risk_level: "LOW",
              user_authorization: "LOW",
              reason: "OK",
            });
            return { data: { parts: [] } };
          },
        },
      };

      const res = await classifyRequest({
        client: mockClient,
        actionName: "bash",
        actionArgs: { command: "ls" },
      });

      expect(res.verdict).toBe("ALLOW");
      expect(createOpts.location).toBeDefined();
      expect(typeof createOpts.location.directory).toBe("string");
      expect(createOpts.body.location).toBeDefined();
    });

    it("falls back to v1 directory schema if v2 schema fails", async () => {
      let attempts: any[] = [];
      const mockClient = {
        app: { agents: async () => ({ data: [] }) },
        session: {
          create: async (opts: any) => {
            attempts.push(opts);
            if (opts.location) {
              throw new Error("Schema error: unknown key location");
            }
            return { data: { id: "ses_v1_fallback" } };
          },
          update: async () => ({}),
          prompt: async (opts: any) => {
            recordEvaluationVerdict(opts.sessionID, {
              verdict: "BLOCK",
              risk_level: "HIGH",
              user_authorization: "NONE",
              reason: "Unsafe",
            });
            return { data: { parts: [] } };
          },
        },
      };

      const res = await classifyRequest({
        client: mockClient,
        actionName: "bash",
        actionArgs: { command: "rm -rf /" },
      });

      expect(res.verdict).toBe("BLOCK");
      expect(attempts.length).toBe(2);
      expect(attempts[1].directory).toBeDefined();
    });

    it("falls back to direct HTTP API if client.session.create fails entirely", async () => {
      const origFetch = globalThis.fetch;
      let fetchedUrls: string[] = [];
      let fetchedBodies: any[] = [];

      globalThis.fetch = (async (url: any, init: any) => {
        fetchedUrls.push(String(url));
        if (init?.body) {
          fetchedBodies.push(JSON.parse(init.body));
        }
        return {
          ok: true,
          json: async () => ({ data: { id: "ses_http_api_123" } }),
        };
      }) as any;

      const mockClient = {
        app: { agents: async () => ({ data: [] }) },
        session: {
          create: async () => {
            throw new Error("Client session create completely broken");
          },
          update: async () => ({}),
          prompt: async (opts: any) => {
            recordEvaluationVerdict(opts.sessionID, {
              verdict: "ALLOW",
              reason: "Direct HTTP OK",
            });
            return { data: { parts: [] } };
          },
        },
      };

      try {
        const res = await classifyRequest({
          client: mockClient,
          actionName: "bash",
          actionArgs: { command: "pwd" },
          config: {
            serverUrl: "http://127.0.0.1:9999",
          } as any,
        });

        expect(res.verdict).toBe("ALLOW");
        expect(fetchedUrls.length).toBeGreaterThan(0);
        expect(fetchedUrls[0]).toBe("http://127.0.0.1:9999/api/session");
        expect(fetchedBodies[0].location).toBeDefined();
      } finally {
        globalThis.fetch = origFetch;
      }
    });
  });
});
