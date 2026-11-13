import { describe, it } from "node:test";
import assert from "node:assert";
import {
  PaseoNativeEvaluator,
  DEFAULT_EVAL_CWD,
  ensureEvaluationDirectory,
} from "../server/evaluator.js";
import { PaseoHarnessAdapter } from "../server/adapter.js";
import {
  CLASSIFIER_JSON_SCHEMA,
  type GateAction,
  type ClassifierResult,
  type GateEvaluator,
} from "@autogate/core";

// --- Mock Helpers ---

function createMockAction(overrides?: Partial<GateAction>): GateAction {
  return {
    id: "action-test-1",
    harness: "paseo",
    sessionID: "session-target-42",
    toolName: "bash",
    commandString: "git status",
    workspaceRoot: "/home/user/project",
    userPrompt: "Check git status",
    ...overrides,
  };
}

class MockServer {
  public listeners = new Map<string, ((event: any, context?: any) => Promise<void> | void)[]>();
  public unregisterCalls: string[] = [];

  on(eventName: string, listener: (event: any, context?: any) => Promise<void> | void) {
    let list = this.listeners.get(eventName);
    if (!list) {
      list = [];
      this.listeners.set(eventName, list);
    }
    list.push(listener);

    return () => {
      this.unregisterCalls.push(eventName);
      const current = this.listeners.get(eventName);
      if (current) {
        this.listeners.set(
          eventName,
          current.filter((fn) => fn !== listener),
        );
      }
    };
  }

  async emit(eventName: string, event: any, context?: any) {
    const list = this.listeners.get(eventName);
    if (list) {
      for (const listener of [...list]) {
        await listener(event, context);
      }
    }
  }
}

class MockAgent {
  public responses: any[] = [];
  public timelineItems: any[] = [];
  public timelineAppendError: Error | null = null;

  constructor(public id: string = "agent-1") {}

  async respondToPermission(data: any) {
    this.responses.push(data);
  }

  timeline = {
    append: async (item: any) => {
      if (this.timelineAppendError) {
        throw this.timelineAppendError;
      }
      this.timelineItems.push(item);
    },
  };
}

class MockFallbackEvaluator implements GateEvaluator {
  readonly name = "mock-fallback-evaluator";
  public evaluatedActions: GateAction[] = [];
  public evaluateResult: ClassifierResult = {
    verdict: "ALLOW",
    risk_level: "LOW",
    reason: "Resolved by fallback evaluator",
  };

  async evaluate(action: GateAction): Promise<ClassifierResult> {
    this.evaluatedActions.push(action);
    return this.evaluateResult;
  }
}

describe("PaseoNativeEvaluator", () => {
  describe("1. Strict Isolation Invariants", () => {
    it("enforces strict isolation: parent is undefined, callerAgentId is undefined, and toolPolicy is empty", async () => {
      let capturedOptions: any = null;
      const mockAgent = {
        id: "eval-agent-iso",
        waitForFinish: async () => ({
          status: "idle",
          lastMessage: JSON.stringify({
            verdict: "ALLOW",
            risk_level: "LOW",
            user_authorization: "HIGH",
            reason: "Safe read-only command",
          }),
        }),
      };

      const mockPaseo = {
        agents: {
          create: async (options: any) => {
            capturedOptions = options;
            return mockAgent;
          },
        },
      };

      const evaluator = new PaseoNativeEvaluator(mockPaseo);
      const action = createMockAction({
        sessionID: "sess-prod-99",
        toolName: "bash",
        commandString: "ls -la",
      });

      const result = await evaluator.evaluate(action);
      assert.strictEqual(result.verdict, "ALLOW");

      assert.ok(capturedOptions !== null, "createOptions was captured");

      // Strict Invariant 1: parent MUST be undefined
      assert.strictEqual(capturedOptions.parent, undefined);

      // Strict Invariant 2: callerAgentId MUST be undefined
      assert.strictEqual(capturedOptions.callerAgentId, undefined);
      assert.strictEqual("callerAgentId" in capturedOptions, false);

      // Strict Invariant 3: internal: true, modeId: "ask", and no toolPolicy
      assert.strictEqual(capturedOptions.config?.internal, true);
      assert.strictEqual(capturedOptions.config?.modeId, "ask");
      assert.strictEqual(capturedOptions.config?.toolPolicy, undefined);
      // Strict Invariant 4: cwd defaults to /tmp/autogate-eval
      assert.strictEqual(capturedOptions.cwd, DEFAULT_EVAL_CWD);

      // Strict Invariant 5: autoArchive MUST be true
      assert.strictEqual(capturedOptions.autoArchive, true);

      // Strict Invariant 6: notifyOnFinish MUST be false
      assert.strictEqual(capturedOptions.notifyOnFinish, false);

      // Strict Invariant 7: labels['autogate.role'] MUST be 'evaluator'
      assert.strictEqual(capturedOptions.labels?.["autogate.role"], "evaluator");
      assert.strictEqual(capturedOptions.labels?.["autogate.targetAgentId"], "sess-prod-99");

      // Schema and prompt invariants
      assert.deepStrictEqual(capturedOptions.outputSchema, CLASSIFIER_JSON_SCHEMA);
      assert.ok(capturedOptions.title.startsWith("[auto-gate-eval]"));
    });

    it("respects custom configured sandbox directory for cwd", async () => {
      let capturedOptions: any = null;
      const customDir = ensureEvaluationDirectory("/tmp/custom-autogate-eval-test");

      const mockPaseo = {
        agents: {
          create: async (options: any) => {
            capturedOptions = options;
            return {
              id: "eval-agent-cwd",
              waitForFinish: async () => ({
                status: "idle",
                lastMessage: JSON.stringify({
                  verdict: "ALLOW",
                  reason: "ok",
                }),
              }),
            };
          },
        },
      };

      const evaluator = new PaseoNativeEvaluator(mockPaseo, { cwd: customDir });
      await evaluator.evaluate(createMockAction());

      assert.strictEqual(capturedOptions.cwd, customDir);
    });

    it("uses action.sessionId when sessionID is not present for targetAgentId label", async () => {
      let capturedOptions: any = null;
      const mockPaseo = {
        agents: {
          create: async (options: any) => {
            capturedOptions = options;
            return {
              id: "eval-agent-sess",
              waitForFinish: async () => ({
                status: "idle",
                lastMessage: JSON.stringify({ verdict: "ALLOW", reason: "ok" }),
              }),
            };
          },
        },
      };

      const evaluator = new PaseoNativeEvaluator(mockPaseo);
      const action = {
        id: "act-1",
        harness: "paseo",
        sessionId: "session-from-lower-d",
        toolName: "bash",
        workspaceRoot: "/tmp",
        userPrompt: "test",
      } as any;

      await evaluator.evaluate(action);
      assert.strictEqual(
        capturedOptions.labels?.["autogate.targetAgentId"],
        "session-from-lower-d",
      );
    });

    it("locks evaluator agents to modeId 'ask' and omits toolPolicy so Paseo never throws ToolPolicyUnsupportedError", async () => {
      let capturedOptions: any = null;
      const mockPaseo = {
        agents: {
          create: async (options: any) => {
            capturedOptions = options;
            return {
              id: "eval-agent-mode",
              waitForFinish: async () => ({
                status: "idle",
                lastMessage: JSON.stringify({ verdict: "ALLOW", reason: "ok" }),
              }),
            };
          },
        },
      };

      const evaluator = new PaseoNativeEvaluator(mockPaseo);
      await evaluator.evaluate(createMockAction());

      assert.ok(capturedOptions !== null);
      assert.strictEqual(capturedOptions.config?.modeId, "ask");
      assert.strictEqual(capturedOptions.config?.toolPolicy, undefined);
      assert.strictEqual(capturedOptions.config?.internal, true);
    });
  });

  describe("2. Provider Fallback Resolution", () => {
    it("uses explicit provider from evaluator options", async () => {
      let capturedOptions: any = null;
      const mockPaseo = {
        agents: {
          create: async (options: any) => {
            capturedOptions = options;
            return {
              id: "eval-1",
              waitForFinish: async () => ({
                status: "idle",
                lastMessage: JSON.stringify({ verdict: "ALLOW", reason: "ok" }),
              }),
            };
          },
        },
      };

      const evaluator = new PaseoNativeEvaluator(mockPaseo, {
        provider: "claude-3-7-sonnet",
      });
      await evaluator.evaluate(createMockAction());

      assert.strictEqual(capturedOptions.config?.provider, "claude-3-7-sonnet");
    });

    it("uses explicit evaluatorProvider alias from evaluator options", async () => {
      let capturedOptions: any = null;
      const mockPaseo = {
        agents: {
          create: async (options: any) => {
            capturedOptions = options;
            return {
              id: "eval-2",
              waitForFinish: async () => ({
                status: "idle",
                lastMessage: JSON.stringify({ verdict: "ALLOW", reason: "ok" }),
              }),
            };
          },
        },
      };

      const evaluator = new PaseoNativeEvaluator(mockPaseo, {
        evaluatorProvider: "antigravity",
      });
      await evaluator.evaluate(createMockAction());

      assert.strictEqual(capturedOptions.config?.provider, "antigravity");
    });

    it("uses evaluatorProvider from options.config.paseo.evaluatorProvider", async () => {
      let capturedOptions: any = null;
      const mockPaseo = {
        agents: {
          create: async (options: any) => {
            capturedOptions = options;
            return {
              id: "eval-3",
              waitForFinish: async () => ({
                status: "idle",
                lastMessage: JSON.stringify({ verdict: "ALLOW", reason: "ok" }),
              }),
            };
          },
        },
      };

      const evaluator = new PaseoNativeEvaluator(mockPaseo, {
        config: {
          autoMode: true,
          ntfyTopic: "test",
          ntfyServer: "https://ntfy.sh",
          classifierModel: "test",
          paseo: { evaluatorProvider: "custom-proxy" },
        },
      });
      await evaluator.evaluate(createMockAction());

      assert.strictEqual(capturedOptions.config?.provider, "custom-proxy");
    });

    it("prefers runtimeOptions provider override if specified", async () => {
      let capturedOptions: any = null;
      const mockPaseo = {
        agents: {
          create: async (options: any) => {
            capturedOptions = options;
            return {
              id: "eval-4",
              waitForFinish: async () => ({
                status: "idle",
                lastMessage: JSON.stringify({ verdict: "ALLOW", reason: "ok" }),
              }),
            };
          },
        },
      };

      const evaluator = new PaseoNativeEvaluator(mockPaseo, {
        provider: "default-provider",
      });
      await evaluator.evaluate(createMockAction(), {
        provider: "runtime-override-provider",
      });

      assert.strictEqual(capturedOptions.config?.provider, "runtime-override-provider");
    });

    it("prefers runtimeOptions evaluatorProvider alias if specified", async () => {
      let capturedOptions: any = null;
      const mockPaseo = {
        agents: {
          create: async (options: any) => {
            capturedOptions = options;
            return {
              id: "eval-4b",
              waitForFinish: async () => ({
                status: "idle",
                lastMessage: JSON.stringify({ verdict: "ALLOW", reason: "ok" }),
              }),
            };
          },
        },
      };

      const evaluator = new PaseoNativeEvaluator(mockPaseo, {
        evaluatorProvider: "default-provider",
      });
      await evaluator.evaluate(createMockAction(), {
        evaluatorProvider: "runtime-alias-override",
      });

      assert.strictEqual(capturedOptions.config?.provider, "runtime-alias-override");
    });

    it("resolves provider from paseo.metadataGeneration.providers[0] string", async () => {
      let capturedOptions: any = null;
      const mockPaseo = {
        metadataGeneration: {
          providers: ["meta-gemini-pro"],
        },
        agents: {
          create: async (options: any) => {
            capturedOptions = options;
            return {
              id: "eval-5",
              waitForFinish: async () => ({
                status: "idle",
                lastMessage: JSON.stringify({ verdict: "ALLOW", reason: "ok" }),
              }),
            };
          },
        },
      };

      const evaluator = new PaseoNativeEvaluator(mockPaseo);
      await evaluator.evaluate(createMockAction());

      assert.strictEqual(capturedOptions.config?.provider, "meta-gemini-pro");
    });

    it("resolves provider from paseo.metadataGeneration.providers[0] object with provider / id / name", async () => {
      let capturedOptions: any = null;
      const mockPaseo1 = {
        metadataGeneration: {
          providers: [{ provider: "obj-provider-val" }],
        },
        agents: {
          create: async (options: any) => {
            capturedOptions = options;
            return {
              id: "eval-6a",
              waitForFinish: async () => ({
                status: "idle",
                lastMessage: JSON.stringify({ verdict: "ALLOW", reason: "ok" }),
              }),
            };
          },
        },
      };

      const evaluator1 = new PaseoNativeEvaluator(mockPaseo1);
      await evaluator1.evaluate(createMockAction());
      assert.strictEqual(capturedOptions.config?.provider, "obj-provider-val");

      const mockPaseo2 = {
        metadataGeneration: {
          providers: [{ id: "obj-id-val" }],
        },
        agents: {
          create: async (options: any) => {
            capturedOptions = options;
            return {
              id: "eval-6b",
              waitForFinish: async () => ({
                status: "idle",
                lastMessage: JSON.stringify({ verdict: "ALLOW", reason: "ok" }),
              }),
            };
          },
        },
      };

      const evaluator2 = new PaseoNativeEvaluator(mockPaseo2);
      await evaluator2.evaluate(createMockAction());
      assert.strictEqual(capturedOptions.config?.provider, "obj-id-val");
    });

    it("preserves model from paseo.metadataGeneration.providers[0] (e.g. provider 'omp' and model 'litellm/gemini/gemini-flash-lite-latest')", async () => {
      let capturedOptions: any = null;
      const mockPaseo = {
        metadataGeneration: {
          providers: [
            {
              provider: "omp",
              model: "litellm/gemini/gemini-flash-lite-latest",
            },
          ],
        },
        agents: {
          create: async (options: any) => {
            capturedOptions = options;
            return {
              id: "eval-model-preserve",
              waitForFinish: async () => ({
                status: "idle",
                lastMessage: JSON.stringify({ verdict: "ALLOW", reason: "ok" }),
              }),
            };
          },
        },
      };

      const evaluator = new PaseoNativeEvaluator(mockPaseo);
      await evaluator.evaluate(createMockAction());

      assert.strictEqual(
        capturedOptions.config?.provider,
        "omp/litellm/gemini/gemini-flash-lite-latest",
      );
    });

    it("resolves provider from paseo.daemonConfig.metadataGeneration.providers[0]", async () => {
      let capturedOptions: any = null;
      const mockPaseo = {
        daemonConfig: {
          metadataGeneration: {
            providers: ["daemon-cfg-provider"],
          },
        },
        agents: {
          create: async (options: any) => {
            capturedOptions = options;
            return {
              id: "eval-7",
              waitForFinish: async () => ({
                status: "idle",
                lastMessage: JSON.stringify({ verdict: "ALLOW", reason: "ok" }),
              }),
            };
          },
        },
      };

      const evaluator = new PaseoNativeEvaluator(mockPaseo);
      await evaluator.evaluate(createMockAction());

      assert.strictEqual(capturedOptions.config?.provider, "daemon-cfg-provider");
    });

    it("resolves provider from async paseo.config.get()", async () => {
      let capturedOptions: any = null;
      const mockPaseo = {
        config: {
          get: async () => ({
            config: {
              metadataGeneration: {
                providers: [{ provider: "async-cfg-provider" }],
              },
            },
          }),
        },
        agents: {
          create: async (options: any) => {
            capturedOptions = options;
            return {
              id: "eval-8",
              waitForFinish: async () => ({
                status: "idle",
                lastMessage: JSON.stringify({ verdict: "ALLOW", reason: "ok" }),
              }),
            };
          },
        },
      };

      const evaluator = new PaseoNativeEvaluator(mockPaseo);
      await evaluator.evaluate(createMockAction());

      assert.strictEqual(capturedOptions.config?.provider, "async-cfg-provider");
    });

    it("preserves model from async paseo.config.get() metadataGeneration.providers[0]", async () => {
      let capturedOptions: any = null;
      const mockPaseo = {
        config: {
          get: async () => ({
            config: {
              metadataGeneration: {
                providers: [
                  {
                    provider: "omp",
                    model: "litellm/gemini/gemini-flash-lite-latest",
                  },
                ],
              },
            },
          }),
        },
        agents: {
          create: async (options: any) => {
            capturedOptions = options;
            return {
              id: "eval-async-model-preserve",
              waitForFinish: async () => ({
                status: "idle",
                lastMessage: JSON.stringify({ verdict: "ALLOW", reason: "ok" }),
              }),
            };
          },
        },
      };

      const evaluator = new PaseoNativeEvaluator(mockPaseo);
      await evaluator.evaluate(createMockAction());

      assert.strictEqual(
        capturedOptions.config?.provider,
        "omp/litellm/gemini/gemini-flash-lite-latest",
      );
    });

    it("defaults to 'omp' when no provider or metadata is specified", async () => {
      let capturedOptions: any = null;
      const mockPaseo = {
        agents: {
          create: async (options: any) => {
            capturedOptions = options;
            return {
              id: "eval-9",
              waitForFinish: async () => ({
                status: "idle",
                lastMessage: JSON.stringify({ verdict: "ALLOW", reason: "ok" }),
              }),
            };
          },
        },
      };

      const evaluator = new PaseoNativeEvaluator(mockPaseo);
      await evaluator.evaluate(createMockAction());

      assert.strictEqual(capturedOptions.config?.provider, "omp");
    });
  });

  describe("3. Structured Output Parsing", () => {
    it("parses lastMessage containing structured JSON for ALLOW with full fields and evalAgentId", async () => {
      const mockAgent = {
        id: "eval-agent-allow",
        waitForFinish: async () => ({
          status: "idle",
          lastMessage: JSON.stringify({
            verdict: "ALLOW",
            risk_level: "LOW",
            user_authorization: "HIGH",
            reason: "Safe read-only operation",
          }),
        }),
      };

      const mockPaseo = {
        agents: {
          create: async () => mockAgent,
        },
      };

      const evaluator = new PaseoNativeEvaluator(mockPaseo);
      const result = await evaluator.evaluate(createMockAction());

      assert.strictEqual(result.verdict, "ALLOW");
      assert.strictEqual(result.risk_level, "LOW");
      assert.strictEqual(result.user_authorization, "HIGH");
      assert.strictEqual(result.reason, "Safe read-only operation");
      assert.deepStrictEqual((result as any).metadata, { evalAgentId: "eval-agent-allow" });
    });

    it("parses lastMessage containing structured JSON for BLOCK", async () => {
      const mockAgent = {
        id: "eval-agent-block",
        waitForFinish: async () => ({
          status: "idle",
          lastMessage: JSON.stringify({
            verdict: "BLOCK",
            risk_level: "CRITICAL",
            user_authorization: "NONE",
            reason: "Destructive disk format",
          }),
        }),
      };

      const mockPaseo = {
        agents: {
          create: async () => mockAgent,
        },
      };

      const evaluator = new PaseoNativeEvaluator(mockPaseo);
      const result = await evaluator.evaluate(
        createMockAction({ commandString: "mkfs.ext4 /dev/sda" }),
      );

      assert.strictEqual(result.verdict, "BLOCK");
      assert.strictEqual(result.risk_level, "CRITICAL");
      assert.strictEqual(result.user_authorization, "NONE");
      assert.strictEqual(result.reason, "Destructive disk format");
      assert.deepStrictEqual((result as any).metadata, { evalAgentId: "eval-agent-block" });
    });

    it("parses lastMessage containing structured JSON for UNSURE", async () => {
      const mockAgent = {
        id: "eval-agent-unsure",
        waitForFinish: async () => ({
          status: "idle",
          lastMessage: JSON.stringify({
            verdict: "UNSURE",
            risk_level: "MEDIUM",
            user_authorization: "LOW",
            reason: "Ambiguous deploy script execution",
          }),
        }),
      };

      const mockPaseo = {
        agents: {
          create: async () => mockAgent,
        },
      };

      const evaluator = new PaseoNativeEvaluator(mockPaseo);
      const result = await evaluator.evaluate(createMockAction());

      assert.strictEqual(result.verdict, "UNSURE");
      assert.strictEqual(result.risk_level, "MEDIUM");
      assert.strictEqual(result.user_authorization, "LOW");
      assert.strictEqual(result.reason, "Ambiguous deploy script execution");
      assert.deepStrictEqual((result as any).metadata, { evalAgentId: "eval-agent-unsure" });
    });

    it("parses markdown code-fenced JSON in lastMessage", async () => {
      const mockAgent = {
        id: "eval-agent-fence",
        waitForFinish: async () => ({
          status: "idle",
          lastMessage:
            'Here is the evaluation result:\n```json\n{\n  "verdict": "ALLOW",\n  "risk_level": "LOW",\n  "user_authorization": "HIGH",\n  "reason": "Fenced code json response"\n}\n```',
        }),
      };

      const mockPaseo = {
        agents: {
          create: async () => mockAgent,
        },
      };

      const evaluator = new PaseoNativeEvaluator(mockPaseo);
      const result = await evaluator.evaluate(createMockAction());

      assert.strictEqual(result.verdict, "ALLOW");
      assert.strictEqual(result.risk_level, "LOW");
      assert.strictEqual(result.reason, "Fenced code json response");
    });

    it("handles candidate text in diverse finishResult shapes (lastMessage.text, lastMessage.content, final.lastMessage, root text)", async () => {
      // 1. lastMessage.text
      const p1 = {
        agents: {
          create: async () => ({
            id: "agent-text",
            waitForFinish: async () => ({
              lastMessage: {
                text: JSON.stringify({ verdict: "ALLOW", reason: "from lastMessage.text" }),
              },
            }),
          }),
        },
      };
      const r1 = await new PaseoNativeEvaluator(p1).evaluate(createMockAction());
      assert.strictEqual(r1.verdict, "ALLOW");
      assert.strictEqual(r1.reason, "from lastMessage.text");

      // 2. lastMessage.content
      const p2 = {
        agents: {
          create: async () => ({
            id: "agent-content",
            waitForFinish: async () => ({
              lastMessage: {
                content: JSON.stringify({ verdict: "BLOCK", reason: "from lastMessage.content" }),
              },
            }),
          }),
        },
      };
      const r2 = await new PaseoNativeEvaluator(p2).evaluate(createMockAction());
      assert.strictEqual(r2.verdict, "BLOCK");
      assert.strictEqual(r2.reason, "from lastMessage.content");

      // 3. final.lastMessage
      const p3 = {
        agents: {
          create: async () => ({
            id: "agent-final",
            waitForFinish: async () => ({
              final: {
                lastMessage: JSON.stringify({ verdict: "ALLOW", reason: "from final.lastMessage" }),
              },
            }),
          }),
        },
      };
      const r3 = await new PaseoNativeEvaluator(p3).evaluate(createMockAction());
      assert.strictEqual(r3.verdict, "ALLOW");
      assert.strictEqual(r3.reason, "from final.lastMessage");

      // 4. root text
      const p4 = {
        agents: {
          create: async () => ({
            id: "agent-root-text",
            waitForFinish: async () => ({
              text: JSON.stringify({ verdict: "UNSURE", reason: "from root.text" }),
            }),
          }),
        },
      };
      const r4 = await new PaseoNativeEvaluator(p4).evaluate(createMockAction());
      assert.strictEqual(r4.verdict, "UNSURE");
      assert.strictEqual(r4.reason, "from root.text");
    });
  });

  describe("4. Error and Timeout Handling", () => {
    it("returns UNSURE when waitForFinish returns { status: 'timeout' }", async () => {
      const mockPaseo = {
        agents: {
          create: async () => ({
            id: "eval-timeout-1",
            waitForFinish: async () => ({
              status: "timeout",
            }),
          }),
        },
      };

      const evaluator = new PaseoNativeEvaluator(mockPaseo, { classifierTimeout: 2000 });
      const result = await evaluator.evaluate(createMockAction());

      assert.strictEqual(result.verdict, "UNSURE");
      assert.ok(result.reason?.includes("timed out"));
      assert.deepStrictEqual((result as any).metadata, { evalAgentId: "eval-timeout-1" });
    });

    it("returns UNSURE when waitForFinish promise exceeds classifierTimeout", async () => {
      const mockPaseo = {
        agents: {
          create: async () => ({
            id: "eval-timeout-hang",
            waitForFinish: async () =>
              new Promise((resolve) => {
                // Hang longer than timeoutMs
                setTimeout(() => resolve({ status: "idle", lastMessage: "{}" }), 500);
              }),
          }),
        },
      };

      const evaluator = new PaseoNativeEvaluator(mockPaseo, { classifierTimeout: 20 });
      const result = await evaluator.evaluate(createMockAction());

      assert.strictEqual(result.verdict, "UNSURE");
      assert.ok(result.reason?.includes("timed out"));
      assert.deepStrictEqual((result as any).metadata, { evalAgentId: "eval-timeout-hang" });
    });

    it("returns UNSURE immediately when action.signal is already aborted", async () => {
      const mockPaseo = {
        agents: {
          create: async () => ({
            id: "eval-pre-aborted",
            waitForFinish: async () => ({
              status: "idle",
              lastMessage: JSON.stringify({ verdict: "ALLOW", reason: "ok" }),
            }),
          }),
        },
      };

      const controller = new AbortController();
      controller.abort(new Error("Pre-aborted request"));

      const evaluator = new PaseoNativeEvaluator(mockPaseo);
      const action = createMockAction({ signal: controller.signal });
      const result = await evaluator.evaluate(action);

      assert.strictEqual(result.verdict, "UNSURE");
      assert.ok(result.reason?.includes("aborted") || result.reason?.includes("Pre-aborted"));
    });

    it("handles action.signal aborted in-flight during waitForFinish", async () => {
      const controller = new AbortController();
      const mockPaseo = {
        agents: {
          create: async () => ({
            id: "eval-inflight-abort",
            waitForFinish: async () => {
              // Trigger abort during execution
              setTimeout(() => {
                controller.abort(new Error("Aborted in-flight"));
              }, 10);
              return new Promise((resolve) => {
                setTimeout(
                  () =>
                    resolve({
                      status: "idle",
                      lastMessage: JSON.stringify({ verdict: "ALLOW", reason: "ok" }),
                    }),
                  200,
                );
              });
            },
          }),
        },
      };

      const evaluator = new PaseoNativeEvaluator(mockPaseo);
      const action = createMockAction({ signal: controller.signal });
      const result = await evaluator.evaluate(action);

      assert.strictEqual(result.verdict, "UNSURE");
      assert.ok(result.reason?.includes("aborted") || result.reason?.includes("Aborted in-flight"));
    });

    it("returns UNSURE when waitForFinish returns { status: 'error' } without lastMessage", async () => {
      const mockPaseo = {
        agents: {
          create: async () => ({
            id: "eval-agent-err",
            waitForFinish: async () => ({
              status: "error",
              error: "Inference engine out of memory",
            }),
          }),
        },
      };

      const evaluator = new PaseoNativeEvaluator(mockPaseo);
      const result = await evaluator.evaluate(createMockAction());

      assert.strictEqual(result.verdict, "UNSURE");
      assert.ok(result.reason?.includes("Inference engine out of memory"));
      assert.deepStrictEqual((result as any).metadata, { evalAgentId: "eval-agent-err" });
    });

    it("delegates to fallbackEvaluator if paseo.agents.create throws", async () => {
      const fallback = new MockFallbackEvaluator();
      fallback.evaluateResult = {
        verdict: "BLOCK",
        risk_level: "HIGH",
        reason: "Blocked by fallback evaluator",
      };

      const mockPaseo = {
        agents: {
          create: async () => {
            throw new Error("Paseo daemon agent creation failed");
          },
        },
      };

      const evaluator = new PaseoNativeEvaluator(mockPaseo, {
        fallbackEvaluator: fallback,
      });

      const action = createMockAction();
      const result = await evaluator.evaluate(action);

      assert.strictEqual(result.verdict, "BLOCK");
      assert.strictEqual(result.reason, "Blocked by fallback evaluator");
      assert.strictEqual(fallback.evaluatedActions.length, 1);
    });

    it("returns UNSURE when paseo.agents.create throws and no fallbackEvaluator is provided", async () => {
      const mockPaseo = {
        agents: {
          create: async () => {
            throw new Error("Paseo daemon agent creation failed");
          },
        },
      };

      const evaluator = new PaseoNativeEvaluator(mockPaseo);
      const result = await evaluator.evaluate(createMockAction());

      assert.strictEqual(result.verdict, "UNSURE");
      assert.ok(result.reason?.includes("Failed to create evaluation agent"));
    });

    it("delegates to fallbackEvaluator if paseo.agents or create is missing", async () => {
      const fallback = new MockFallbackEvaluator();
      fallback.evaluateResult = {
        verdict: "ALLOW",
        reason: "Allowed by fallback on missing SDK",
      };

      const mockPaseo = {}; // No agents property

      const evaluator = new PaseoNativeEvaluator(mockPaseo, {
        fallbackEvaluator: fallback,
      });

      const result = await evaluator.evaluate(createMockAction());
      assert.strictEqual(result.verdict, "ALLOW");
      assert.strictEqual(result.reason, "Allowed by fallback on missing SDK");
    });

    it("returns UNSURE when paseo.agents is missing and no fallbackEvaluator is provided", async () => {
      const mockPaseo = {}; // No agents property
      const evaluator = new PaseoNativeEvaluator(mockPaseo);

      const result = await evaluator.evaluate(createMockAction());
      assert.strictEqual(result.verdict, "UNSURE");
      assert.ok(result.reason?.includes("agents.create is not available"));
    });

    it("delegates to fallbackEvaluator if evaluation agent is missing waitForFinish", async () => {
      const fallback = new MockFallbackEvaluator();
      fallback.evaluateResult = {
        verdict: "UNSURE",
        reason: "Fallback evaluated for invalid agent",
      };

      const mockPaseo = {
        agents: {
          create: async () => ({ id: "no-wait-method" }),
        },
      };

      const evaluator = new PaseoNativeEvaluator(mockPaseo, {
        fallbackEvaluator: fallback,
      });

      const result = await evaluator.evaluate(createMockAction());
      assert.strictEqual(result.verdict, "UNSURE");
      assert.strictEqual(result.reason, "Fallback evaluated for invalid agent");
    });

    it("returns UNSURE when evaluation agent is missing waitForFinish and no fallbackEvaluator is provided", async () => {
      const mockPaseo = {
        agents: {
          create: async () => ({ id: "no-wait-method-2" }),
        },
      };

      const evaluator = new PaseoNativeEvaluator(mockPaseo);
      const result = await evaluator.evaluate(createMockAction());

      assert.strictEqual(result.verdict, "UNSURE");
      assert.ok(result.reason?.includes("missing waitForFinish"));
      assert.deepStrictEqual((result as any).metadata, { evalAgentId: "no-wait-method-2" });
    });

    it("resolves dynamic paseo source passed as function () => paseo or object { getPaseo: () => paseo }", async () => {
      const mockPaseo = {
        agents: {
          create: async () => ({
            id: "dynamic-agent",
            waitForFinish: async () => ({
              status: "idle",
              lastMessage: JSON.stringify({ verdict: "ALLOW", reason: "from dynamic" }),
            }),
          }),
        },
      };

      // Function source
      const evaluator1 = new PaseoNativeEvaluator(() => mockPaseo);
      const res1 = await evaluator1.evaluate(createMockAction());
      assert.strictEqual(res1.verdict, "ALLOW");

      // Object with getPaseo()
      const evaluator2 = new PaseoNativeEvaluator({ getPaseo: async () => mockPaseo });
      const res2 = await evaluator2.evaluate(createMockAction());
      assert.strictEqual(res2.verdict, "ALLOW");
    });
  });

  describe("5. Adapter Timeline Badges Integration", () => {
    it("PaseoHarnessAdapter invokes agent.timeline.append with plugin autogate-eval card", async () => {
      const server = new MockServer();
      const targetAgent = new MockAgent("agent-timeline-target");

      const mockPaseoClient = {
        agents: {
          create: async () => ({
            id: "eval-badge-agent",
            waitForFinish: async () => ({
              status: "idle",
              lastMessage: JSON.stringify({
                verdict: "ALLOW",
                risk_level: "LOW",
                user_authorization: "HIGH",
                reason: "Safe git status command",
              }),
            }),
          }),
          ref: (id: string) => (id === "agent-timeline-target" ? targetAgent : null),
        },
      };

      const adapter = new PaseoHarnessAdapter(server, {
        paseo: mockPaseoClient,
      });

      const event = {
        agent: targetAgent,
        request: {
          id: "req-badge-1",
          name: "bash",
          input: { command: "git status" },
        },
      };

      await server.emit("agent.permission_requested", event);

      // Verify permission response was delivered
      assert.strictEqual(targetAgent.responses.length, 1);
      assert.strictEqual(targetAgent.responses[0].requestId, "req-badge-1");
      assert.strictEqual(targetAgent.responses[0].response.behavior, "allow");

      // Verify timeline item was appended
      assert.strictEqual(targetAgent.timelineItems.length, 1);
      const timelineItem = targetAgent.timelineItems[0];

      assert.strictEqual(timelineItem.type, "plugin");
      assert.strictEqual(timelineItem.id, "autogate-eval-req-badge-1");
      assert.strictEqual(timelineItem.kind, "autogate-eval");
      assert.strictEqual(timelineItem.version, 1);
      assert.strictEqual(timelineItem.data.verdict, "ALLOW");
      assert.strictEqual(timelineItem.data.risk_level, "LOW");
      assert.strictEqual(timelineItem.data.reason, "Safe git status command");
      assert.strictEqual(timelineItem.data.command, "git status");
      assert.strictEqual(timelineItem.data.toolName, "bash");

      await adapter.dispose();
    });

    it("timelineBadges: false suppresses timeline append in PaseoHarnessAdapter", async () => {
      const server = new MockServer();
      const targetAgent = new MockAgent("agent-timeline-suppressed");

      const mockPaseoClient = {
        agents: {
          create: async () => ({
            id: "eval-badge-suppressed",
            waitForFinish: async () => ({
              status: "idle",
              lastMessage: JSON.stringify({
                verdict: "ALLOW",
                risk_level: "LOW",
                reason: "Safe command",
              }),
            }),
          }),
          ref: (id: string) => (id === "agent-timeline-suppressed" ? targetAgent : null),
        },
      };

      const adapter = new PaseoHarnessAdapter(server, {
        paseo: {
          ...mockPaseoClient,
          timelineBadges: false,
        },
      });

      const event = {
        agent: targetAgent,
        request: {
          id: "req-badge-suppressed",
          name: "bash",
          input: { command: "git status" },
        },
      };

      await server.emit("agent.permission_requested", event);

      // Verify permission response was still delivered
      assert.strictEqual(targetAgent.responses.length, 1);
      assert.strictEqual(targetAgent.responses[0].response.behavior, "allow");

      // Verify timeline item was NOT appended
      assert.strictEqual(targetAgent.timelineItems.length, 0);

      await adapter.dispose();
    });

    it("timeline append failure does not disrupt permission resolution", async () => {
      const server = new MockServer();
      const targetAgent = new MockAgent("agent-timeline-err");
      targetAgent.timelineAppendError = new Error("Timeline DB connection lost");

      const mockPaseoClient = {
        agents: {
          create: async () => ({
            id: "eval-badge-err",
            waitForFinish: async () => ({
              status: "idle",
              lastMessage: JSON.stringify({
                verdict: "ALLOW",
                risk_level: "LOW",
                reason: "Safe command",
              }),
            }),
          }),
          ref: (id: string) => (id === "agent-timeline-err" ? targetAgent : null),
        },
      };

      const adapter = new PaseoHarnessAdapter(server, {
        paseo: mockPaseoClient,
      });

      const event = {
        agent: targetAgent,
        request: {
          id: "req-badge-err",
          name: "bash",
          input: { command: "git status" },
        },
      };

      // Emitting should not throw
      await assert.doesNotReject(async () => {
        await server.emit("agent.permission_requested", event);
      });

      // Permission response must still be delivered despite timeline error
      assert.strictEqual(targetAgent.responses.length, 1);
      assert.strictEqual(targetAgent.responses[0].response.behavior, "allow");

      await adapter.dispose();
    });

    it("invokes evalAgent.abort() on action.signal abort and surfaces cascade trace in timeline badge", async () => {
      let agentAborted = false;
      const controller = new AbortController();

      const mockPaseo = {
        agents: {
          create: async () => ({
            id: "eval-abort-hook",
            abort: async () => {
              agentAborted = true;
            },
            waitForFinish: async () =>
              new Promise((resolve) => {
                setTimeout(() => resolve({ status: "idle", lastMessage: "{}" }), 500);
              }),
          }),
        },
      };

      const evaluator = new PaseoNativeEvaluator(mockPaseo);
      setTimeout(() => controller.abort("system1-won-race"), 10);

      const res = await evaluator.evaluate(createMockAction({ signal: controller.signal }));
      assert.strictEqual(res.verdict, "UNSURE");
      assert.strictEqual(agentAborted, true);

      // Verify CascadeTrace is surfaced in Paseo timeline badge
      const server = new MockServer();
      const targetAgent = new MockAgent("agent-cascade-badge");
      const origFetch = globalThis.fetch;
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

      try {
        const adapter = new PaseoHarnessAdapter(server, {
          paseo: {
            agents: {
              create: async () => ({
                id: "slow-s2",
                waitForFinish: async () =>
                  new Promise((resolve) => {
                    setTimeout(
                      () =>
                        resolve({
                          status: "idle",
                          lastMessage: JSON.stringify({ verdict: "ALLOW", reason: "s2" }),
                        }),
                      200,
                    );
                  }),
              }),
              ref: (id: string) => (id === "agent-cascade-badge" ? targetAgent : null),
            },
          },
          systemOne: {
            enabled: true,
            executionMode: "race",
            endpoint: "http://127.0.0.1:4006/v1/systemone",
            model: "gemini-decision-1",
            timeoutMs: 2000,
          },
        });

        await server.emit("agent.permission_requested", {
          agent: targetAgent,
          request: { id: "req-cascade-badge", name: "bash", input: { command: "git status" } },
        });

        assert.strictEqual(targetAgent.timelineItems.length, 1);
        assert.strictEqual(targetAgent.timelineItems[0].data.cascade?.winner, "system1");
        assert.strictEqual(targetAgent.timelineItems[0].data.cascade?.mode, "race");
        assert.strictEqual(targetAgent.timelineItems[0].data.cascade?.s2Aborted, true);

        await adapter.dispose();
      } finally {
        globalThis.fetch = origFetch;
      }
    });
  });
});
