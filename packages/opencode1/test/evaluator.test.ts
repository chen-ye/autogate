import { describe, it, expect, beforeEach, afterEach, spyOn } from "bun:test";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import {
  classifyRequest,
  archiveEvaluationSession,
  extractVerdictFromSession,
  recordEvaluationVerdict,
  type OpenCodeV1SessionClient,
} from "../src/evaluator.js";

describe("@autogate/opencode1 evaluator OpenCode v1 support", () => {
  let tempDir: string;
  const origEnv = { ...process.env };

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "autogate-eval-v1-test-"));
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
  });
});
