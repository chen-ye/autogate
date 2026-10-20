import { describe, it, expect, beforeEach, afterEach, spyOn } from "bun:test";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import type { AutoGateConfig } from "@autogate/core";
import {
  classifyRequest,
  archiveEvaluationSession,
  extractVerdictFromSession,
  recordEvaluationVerdict,
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

      const updateCalls: Array<{ sessionID: string; title?: string }> = [];
      const mockClient = {
        session: {
          update: async (opts: { sessionID: string; title?: string }) => {
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
      const updateCalls: Array<{ sessionID: string; title?: string }> = [];
      const mockClient = {
        session: {
          update: async (opts: { sessionID: string; title?: string }) => {
            updateCalls.push(opts);
            return { ok: true };
          },
        },
      } as unknown as OpenCodeSessionClient;

      try {
        await archiveEvaluationSession(mockClient, "ses_test_456", "bash", "BLOCK");
        expect(updateCalls.length).toBe(1);
      } finally {
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
  });
});
