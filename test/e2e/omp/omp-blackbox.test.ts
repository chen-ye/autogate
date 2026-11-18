import { describe, it, expect, beforeEach, afterEach, spyOn } from "bun:test";
import { MockInferenceProvider } from "../opencode/mock-provider";
import { DirectApiEvaluator } from "@autogate/core";
import {
  AuthStorage,
  createAgentSession,
  ModelRegistry,
  SessionManager,
  Settings,
  SqliteAuthCredentialStore,
} from "@oh-my-pi/pi-coding-agent";
import { Database } from "bun:sqlite";
import autoGateOmpExtension, { OmpHarnessAdapter } from "../../../packages/omp/src/index.ts";
import { verdictStore } from "../../../packages/omp/src/hook.ts";
import { NtfyAdapter } from "@autogate/core";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import * as os from "node:os";

const hasLiveNtfy = Boolean(process.env.NTFY_SERVER && process.env.NTFY_TOKEN);

describe("True Black-box OMP E2E Test Suite", () => {
  let mockProvider: MockInferenceProvider;
  let activeAdapters: OmpHarnessAdapter[] = [];
  let savedEnv: Record<string, string | undefined> = {};

  const trackedExtension = (pi: any, options?: Record<string, unknown>) => {
    const res = autoGateOmpExtension(pi, options);
    activeAdapters.push(res.adapter);
    return res;
  };
  let sandboxDir: string;
  let authStorage: AuthStorage;
  let modelRegistry: ModelRegistry;

  beforeEach(async () => {
    savedEnv = {
      NTFY_SERVER: process.env.NTFY_SERVER,
      NTFY_TOPIC: process.env.NTFY_TOPIC,
      NTFY_TOKEN: process.env.NTFY_TOKEN,
      OPENCODE_AUTO_MODE: process.env.OPENCODE_AUTO_MODE,
    };
    mockProvider = new MockInferenceProvider(0);
    sandboxDir = await fs.mkdtemp(path.join(os.tmpdir(), "omp-blackbox-test-"));
    authStorage = new AuthStorage(new SqliteAuthCredentialStore(new Database(":memory:")));
    authStorage.setRuntimeApiKey("mock-provider", "test-key");
    modelRegistry = new ModelRegistry(authStorage);

    modelRegistry.registerProvider("mock-provider", {
      baseUrl: `${mockProvider.url}/v1`,
      apiKey: "test-key",
      api: "openai-completions",
      models: [
        {
          id: "mock-model",
          name: "Mock Model",
          reasoning: false,
          input: ["text"],
          cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
          contextWindow: 128000,
          maxTokens: 8192,
        },
      ],
    });

    process.env.NTFY_SERVER = process.env.NTFY_SERVER || "https://ntfy.sh";
    process.env.NTFY_TOPIC = process.env.NTFY_TOPIC || "autogate-test-omp";
    process.env.NTFY_TOKEN = process.env.NTFY_TOKEN || "test-token";
    process.env.OPENCODE_AUTO_MODE = "true";
  });

  afterEach(async () => {
    authStorage.close();
    await mockProvider.stop();
    for (const adapter of activeAdapters) {
      await adapter.dispose();
    }
    activeAdapters = [];
    for (const [key, val] of Object.entries(savedEnv)) {
      if (val === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = val;
      }
    }
    try {
      await fs.rm(sandboxDir, { recursive: true, force: true });
    } catch {}
  });

  it("Test 1 (Black-box ALLOW): Safe command execution via real createAgentSession loop", async () => {
    mockProvider.pushResponse({
      toolCall: {
        name: "bash",
        input: { command: "echo 'pure blackbox allow'" },
      },
    });
    mockProvider.pushResponse({
      text: JSON.stringify({
        verdict: "ALLOW",
        reason: "Safe operation",
        risk_level: "LOW",
        user_authorization: "HIGH",
      }),
    });
    mockProvider.pushResponse({
      text: "Done",
    });

    const settings = Settings.isolated({
      "tools.approvalMode": "yolo",
    });
    settings.setModelRole("default", "mock-provider/mock-model");

    const evaluator = new DirectApiEvaluator({
      apiKey: "test-key",
      model: "mock-model",
      baseUrl: mockProvider.url,
      fetchImpl: globalThis.fetch,
    });

    const { session } = await createAgentSession({
      cwd: sandboxDir,
      agentDir: sandboxDir,
      authStorage,
      modelRegistry,
      sessionManager: SessionManager.inMemory(),
      settings,
      disableExtensionDiscovery: true,
      extensions: [(pi) => trackedExtension(pi, { evaluator })],
      toolNames: ["bash"],
      skills: [],
      contextFiles: [],
      promptTemplates: [],
      slashCommands: [],
      enableMCP: false,
      enableLsp: false,
      rules: [],
      workspaceTree: {
        rootPath: sandboxDir,
        rendered: "",
        truncated: false,
        totalLines: 0,
        agentsMdFiles: [],
      },
      skipPythonPreflight: true,
    });

    try {
      await session.prompt("Run safe command");
      const branch = session.sessionManager.getBranch();
      const hasToolResult = branch.some((m: any) => {
        const isRes =
          m.role === "toolResult" ||
          m.type === "toolResult" ||
          m.message?.role === "toolResult" ||
          (m.content &&
            Array.isArray(m.content) &&
            m.content.some((c: any) => c.type === "toolResult"));
        const str = JSON.stringify(m);
        return (
          isRes &&
          str.includes("pure blackbox allow") &&
          (m.isError === false || m.details?.isError === false || !m.isError)
        );
      });
      expect(hasToolResult).toBe(true);
    } finally {
      await session.dispose();
    }
  }, 30000);

  it("Test 2 (Black-box BLOCK): Unsafe command execution rejected with SAFE_TRANSFORM_REJECT and git stash", async () => {
    mockProvider.pushResponse({
      toolCall: {
        name: "bash",
        input: { command: "git checkout -- ." },
      },
    });
    mockProvider.pushResponse({
      text: JSON.stringify({
        verdict: "BLOCK",
        reason: "Working tree discard protection",
        risk_level: "HIGH",
        user_authorization: "LOW",
      }),
    });
    mockProvider.pushResponse({
      text: "Done",
    });

    const settings = Settings.isolated({
      "tools.approvalMode": "write",
    });
    settings.setModelRole("default", "mock-provider/mock-model");

    const evaluator = new DirectApiEvaluator({
      apiKey: "test-key",
      model: "mock-model",
      baseUrl: mockProvider.url,
      fetchImpl: globalThis.fetch,
    });

    const { session } = await createAgentSession({
      cwd: sandboxDir,
      agentDir: sandboxDir,
      authStorage,
      modelRegistry,
      sessionManager: SessionManager.inMemory(),
      settings,
      disableExtensionDiscovery: true,
      extensions: [(pi) => trackedExtension(pi, { evaluator })],
      toolNames: ["bash"],
      skills: [],
      contextFiles: [],
      promptTemplates: [],
      slashCommands: [],
      enableMCP: false,
      enableLsp: false,
      rules: [],
      workspaceTree: {
        rootPath: sandboxDir,
        rendered: "",
        truncated: false,
        totalLines: 0,
        agentsMdFiles: [],
      },
      skipPythonPreflight: true,
    });

    try {
      await session.prompt("Discard working tree");
      const branch = session.sessionManager.getBranch();
      const hasBlockedResult = branch.some((m: any) => {
        const isRes =
          m.role === "toolResult" ||
          m.type === "toolResult" ||
          m.message?.role === "toolResult" ||
          (m.content &&
            Array.isArray(m.content) &&
            m.content.some((c: any) => c.type === "toolResult"));
        const str = JSON.stringify(m);
        return isRes && str.includes("SAFE_TRANSFORM_REJECT") && str.includes("git stash");
      });
      expect(hasBlockedResult).toBe(true);
    } finally {
      await session.dispose();
    }
  }, 30000);

  it.skipIf(!hasLiveNtfy)(
    "Test 3 (Black-box Live ntfy Mobile Approval): Tests live ntfy roundtrip on fixed topic autogate-test-omp",
    async () => {
      const topic = process.env.NTFY_TOPIC || "autogate-test-omp";
      const token = process.env.NTFY_TOKEN;
      const server = process.env.NTFY_SERVER;
      if (!server || !token) {
        console.log("[SKIP] NTFY_SERVER/NTFY_TOKEN not set");
        return;
      }
      const ntfyAdapter = new NtfyAdapter({
        server,
        topic,
        token,
      });

      const reqId = "req-bb-roundtrip-" + Date.now();
      let receivedReply: any = null;
      let unsubscribe: (() => void) | undefined;

      const checkRateLimit = (resOrErr: any, text?: string) => {
        const status = resOrErr?.status;
        const str = String(resOrErr?.message || resOrErr || text || "").toLowerCase();
        if (
          status === 429 ||
          status === 403 ||
          str.includes("429") ||
          str.includes("403") ||
          str.includes("quota") ||
          str.includes("rate limit") ||
          str.includes("rate-limit") ||
          str.includes("limit") ||
          str.includes("forbidden")
        ) {
          console.log("[SKIP] ntfy rate limited or forbidden (status:", status, ")");
          return true;
        }
        return false;
      };

      try {
        unsubscribe = await ntfyAdapter.listen(async (resp) => {
          if (resp.req_id === reqId) {
            receivedReply = resp;
          }
        });

        await ntfyAdapter.publish({
          id: reqId,
          harness: "omp",
          sessionID: "ses-bb-3",
          toolName: "bash",
          commandString: "npm test",
          workspaceRoot: sandboxDir,
          userPrompt: "run tests",
          title: "[REVIEW] bash",
          message: "Target: npm test\nReason: Blackbox live roundtrip test",
          priority: "high",
          tags: ["lock", "robot"],
          actions: [
            { id: "appr", label: "Approve", reply: "once" },
            { id: "deny", label: "Deny", reply: "reject" },
          ],
        });

        await new Promise((r) => setTimeout(r, 2000));

        const getRes = await fetch(`${server}/${topic}/json?poll=1`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        const getTxt = await getRes.text().catch(() => "");
        if (checkRateLimit(getRes, getTxt)) return;
        expect(getRes.ok).toBe(true);
        expect(getTxt).toContain(reqId);

        const replyRes = await fetch(`${server}/${topic}-response`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${token}`,
          },
          body: JSON.stringify({ req_id: reqId, reply: "once" }),
        });
        const replyTxt = await replyRes.text().catch(() => "");
        if (checkRateLimit(replyRes, replyTxt)) return;
        expect(replyRes.ok).toBe(true);

        for (let i = 0; i < 20; i++) {
          if (receivedReply) break;
          await new Promise((r) => setTimeout(r, 500));
        }

        expect(receivedReply).toBeDefined();
        expect(receivedReply.req_id).toBe(reqId);
      } catch (err: any) {
        if (checkRateLimit(err)) return;
        throw err;
      } finally {
        if (unsubscribe) {
          unsubscribe();
        }
      }
    },
    30000,
  );

  it("Test 4 (Black-box Native Fallback Mode): UNSURE verdict with native fallback mode records UNSURE / prompt policy without ntfy notification", async () => {
    mockProvider.pushResponse({
      toolCall: {
        name: "bash",
        input: { command: "custom_unsure_command" },
      },
    });
    mockProvider.pushResponse({
      text: JSON.stringify({
        verdict: "UNSURE",
        reason: "Requires human review",
        risk_level: "MEDIUM",
        user_authorization: "LOW",
      }),
    });
    mockProvider.pushResponse({
      text: "Done",
    });

    const settings = Settings.isolated({
      "tools.approvalMode": "write",
    });
    settings.setModelRole("default", "mock-provider/mock-model");

    const evaluator = new DirectApiEvaluator({
      apiKey: "test-key",
      model: "mock-model",
      baseUrl: mockProvider.url,
      fetchImpl: globalThis.fetch,
    });

    const { session } = await createAgentSession({
      cwd: sandboxDir,
      agentDir: sandboxDir,
      authStorage,
      modelRegistry,
      sessionManager: SessionManager.inMemory(),
      settings,
      disableExtensionDiscovery: true,
      extensions: [
        (pi) => {
          trackedExtension(pi, { evaluator, reviewFallbackMode: "native" });
        },
      ],
      toolNames: ["bash"],
      skills: [],
      contextFiles: [],
      promptTemplates: [],
      slashCommands: [],
      enableMCP: false,
      enableLsp: false,
      rules: [],
      workspaceTree: {
        rootPath: sandboxDir,
        rendered: "",
        truncated: false,
        totalLines: 0,
        agentsMdFiles: [],
      },
      skipPythonPreflight: true,
    });

    const publishSpy = spyOn(NtfyAdapter.prototype, "publish");

    try {
      await session.prompt("Run unsure command");
      expect(publishSpy).not.toHaveBeenCalled();

      const record = verdictStore.get("custom_unsure_command");
      expect(record?.verdict).toBe("UNSURE");
      expect(record?.policy).toBe("prompt");

      const branch = session.sessionManager.getBranch();
      const hasToolResult = branch.some((m: any) => {
        const str = JSON.stringify(m);
        return str.includes("custom_unsure_command");
      });
      expect(hasToolResult).toBe(true);
    } finally {
      publishSpy.mockRestore();
      await session.dispose();
    }
  }, 30000);

  it("Test 5 (True Production Evaluator): Safe bash command execution with real OmpNativeEvaluator (no evaluator override)", async () => {
    mockProvider.pushResponse({
      toolCall: {
        name: "bash",
        input: { command: "echo 'production evaluator allow'" },
      },
    });
    mockProvider.pushResponse({
      toolCall: {
        name: "classify_result",
        input: {
          verdict: "ALLOW",
          risk_level: "LOW",
          user_authorization: "HIGH",
          reason: "Production evaluator safe check",
        },
      },
    });
    mockProvider.pushResponse({
      text: "Finished successfully",
    });

    const settings = Settings.isolated({
      "tools.approvalMode": "yolo",
    });
    settings.setModelRole("default", "mock-provider/mock-model");
    settings.setModelRole("smol", "mock-provider/mock-model");

    const { session } = await createAgentSession({
      cwd: sandboxDir,
      agentDir: sandboxDir,
      authStorage,
      modelRegistry,
      sessionManager: SessionManager.inMemory(),
      settings,
      disableExtensionDiscovery: true,
      extensions: [trackedExtension],
      toolNames: ["bash"],
      skills: [],
      contextFiles: [],
      promptTemplates: [],
      slashCommands: [],
      enableMCP: false,
      enableLsp: false,
      rules: [],
      workspaceTree: {
        rootPath: sandboxDir,
        rendered: "",
        truncated: false,
        totalLines: 0,
        agentsMdFiles: [],
      },
      skipPythonPreflight: true,
    });

    try {
      await session.prompt("Run command with real evaluator");
      const branch = session.sessionManager.getBranch();
      const hasToolResult = branch.some((m: any) => {
        const isRes =
          m.role === "toolResult" ||
          m.type === "toolResult" ||
          m.message?.role === "toolResult" ||
          (m.content &&
            Array.isArray(m.content) &&
            m.content.some((c: any) => c.type === "toolResult"));
        const str = JSON.stringify(m);
        return (
          isRes &&
          str.includes("production evaluator allow") &&
          (m.isError === false || m.details?.isError === false || !m.isError)
        );
      });
      expect(hasToolResult).toBe(true);

      const requests = mockProvider.getRequests();
      expect(requests.length).toBeGreaterThan(1);
    } finally {
      await session.dispose();
    }
  }, 30000);

  it("Test 6 (True Production Evaluator BLOCK): Blocked bash command execution with real OmpNativeEvaluator", async () => {
    mockProvider.pushResponse({
      toolCall: {
        name: "bash",
        input: { command: "rm -rf /" },
      },
    });
    mockProvider.pushResponse({
      toolCall: {
        name: "classify_result",
        input: {
          verdict: "BLOCK",
          risk_level: "CRITICAL",
          user_authorization: "NONE",
          reason: "Dangerous root deletion command",
        },
      },
    });
    mockProvider.pushResponse({
      text: "Blocked successfully",
    });

    const settings = Settings.isolated({
      "tools.approvalMode": "write",
    });
    settings.setModelRole("default", "mock-provider/mock-model");
    settings.setModelRole("smol", "mock-provider/mock-model");

    const { session } = await createAgentSession({
      cwd: sandboxDir,
      agentDir: sandboxDir,
      authStorage,
      modelRegistry,
      sessionManager: SessionManager.inMemory(),
      settings,
      disableExtensionDiscovery: true,
      extensions: [trackedExtension],
      toolNames: ["bash"],
      skills: [],
      contextFiles: [],
      promptTemplates: [],
      slashCommands: [],
      enableMCP: false,
      enableLsp: false,
      rules: [],
      workspaceTree: {
        rootPath: sandboxDir,
        rendered: "",
        truncated: false,
        totalLines: 0,
        agentsMdFiles: [],
      },
      skipPythonPreflight: true,
    });

    try {
      await session.prompt("Run dangerous command");
      const branch = session.sessionManager.getBranch();
      const hasBlockedResult = branch.some((m: any) => {
        const isRes =
          m.role === "toolResult" ||
          m.type === "toolResult" ||
          m.message?.role === "toolResult" ||
          (m.content &&
            Array.isArray(m.content) &&
            m.content.some((c: any) => c.type === "toolResult"));
        const str = JSON.stringify(m);
        return (
          isRes &&
          (str.includes("BLOCK") ||
            str.includes("Dangerous root deletion command") ||
            str.includes("SAFE_TRANSFORM_REJECT"))
        );
      });
      expect(hasBlockedResult).toBe(true);
    } finally {
      await session.dispose();
    }
  }, 30000);

  it("Test 7 (Multi-Tool Session Fast-Paths): Agent session executes read skill://, todo, and bash, verifying fast-paths vs evaluation", async () => {
    mockProvider.pushResponse({
      toolCall: {
        name: "read",
        input: { path: "skill://customize-omo" },
      },
    });
    mockProvider.pushResponse({
      toolCall: {
        name: "todo",
        input: { action: "list" },
      },
    });
    mockProvider.pushResponse({
      toolCall: {
        name: "bash",
        input: { command: "echo 'multi-tool test'" },
      },
    });
    mockProvider.pushResponse({
      toolCall: {
        name: "classify_result",
        input: {
          verdict: "ALLOW",
          risk_level: "LOW",
          user_authorization: "HIGH",
          reason: "Safe echo",
        },
      },
    });
    mockProvider.pushResponse({
      text: "All tools executed successfully",
    });

    const settings = Settings.isolated({
      "tools.approvalMode": "yolo",
    });
    settings.setModelRole("default", "mock-provider/mock-model");
    settings.setModelRole("smol", "mock-provider/mock-model");

    const { session } = await createAgentSession({
      cwd: sandboxDir,
      agentDir: sandboxDir,
      authStorage,
      modelRegistry,
      sessionManager: SessionManager.inMemory(),
      settings,
      disableExtensionDiscovery: true,
      extensions: [trackedExtension],
      toolNames: ["bash", "read", "todo"],
      skills: [],
      contextFiles: [],
      promptTemplates: [],
      slashCommands: [],
      enableMCP: false,
      enableLsp: false,
      rules: [],
      workspaceTree: {
        rootPath: sandboxDir,
        rendered: "",
        truncated: false,
        totalLines: 0,
        agentsMdFiles: [],
      },
      skipPythonPreflight: true,
    });

    try {
      await session.prompt("Run multi-tool workflow");

      const branch = session.sessionManager.getBranch();
      const hasReadResult = branch.some((m: any) => {
        const str = JSON.stringify(m);
        return str.includes("skill://customize-omo");
      });
      const hasTodoResult = branch.some((m: any) => {
        const str = JSON.stringify(m);
        return str.includes("list") || str.includes("todo");
      });
      const hasBashResult = branch.some((m: any) => {
        const str = JSON.stringify(m);
        return str.includes("multi-tool test");
      });

      expect(hasReadResult).toBe(true);
      expect(hasTodoResult).toBe(true);
      expect(hasBashResult).toBe(true);

      const requests = mockProvider.getRequests();
      const evalRequests = requests.filter((r: any) => {
        const str = JSON.stringify(r.body);
        return str.includes("classify_result") || str.includes("security classification");
      });
      expect(evalRequests.length).toBe(1);
    } finally {
      await session.dispose();
    }
  }, 30000);
});
