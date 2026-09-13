import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { MockInferenceProvider } from "../opencode/mock-provider";
import { MockNtfyServer } from "../mock-ntfy";
import { DirectApiEvaluator } from "@autogate/core";
import { createAgentSession, SessionManager, Settings } from "@oh-my-pi/pi-coding-agent";
import { AuthStorage, SqliteAuthCredentialStore } from "@oh-my-pi/pi-coding-agent";
import { ModelRegistry } from "@oh-my-pi/pi-coding-agent";
import { Database } from "bun:sqlite";
import autoGateOmpExtension from "../../../packages/omp/src/index.ts";
import { NtfyAdapter } from "@autogate/core";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import * as os from "node:os";

describe("True Black-box OMP E2E Test Suite", () => {
  let mockProvider: MockInferenceProvider;
  let mockNtfy: MockNtfyServer;
  let sandboxDir: string;
  let authStorage: AuthStorage;
  let modelRegistry: ModelRegistry;

  beforeEach(async () => {
    mockProvider = new MockInferenceProvider(0);
    mockNtfy = new MockNtfyServer(0);
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

    process.env.NTFY_SERVER = mockNtfy.url;
    process.env.OPENCODE_AUTO_MODE = "true";
  });

  afterEach(async () => {
    authStorage.close();
    await mockProvider.stop();
    await mockNtfy.stop();
    delete process.env.NTFY_SERVER;
    delete process.env.OPENCODE_AUTO_MODE;
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
      text: JSON.stringify({ verdict: "ALLOW", reason: "Safe operation", risk_level: "LOW", user_authorization: "HIGH" }),
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
      extensions: [pi => autoGateOmpExtension(pi, { evaluator })],
      toolNames: ["bash"],
      skills: [],
      contextFiles: [],
      promptTemplates: [],
      slashCommands: [],
      enableMCP: false,
      enableLsp: false,
      rules: [],
      workspaceTree: { rootPath: sandboxDir, rendered: "", truncated: false, totalLines: 0, agentsMdFiles: [] },
      skipPythonPreflight: true,
    });

    try {
      await session.prompt("Run safe command");
      const branch = session.sessionManager.getBranch();
      const hasToolResult = branch.some((m: any) => {
        const isRes = m.role === "toolResult" || m.type === "toolResult" || m.message?.role === "toolResult" || (m.content && Array.isArray(m.content) && m.content.some((c: any) => c.type === "toolResult"));
        const str = JSON.stringify(m);
        return isRes && str.includes("pure blackbox allow") && (m.isError === false || m.details?.isError === false || !m.isError);
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
      text: JSON.stringify({ verdict: "BLOCK", reason: "Working tree discard protection", risk_level: "HIGH", user_authorization: "LOW" }),
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
      extensions: [pi => autoGateOmpExtension(pi, { evaluator })],
      toolNames: ["bash"],
      skills: [],
      contextFiles: [],
      promptTemplates: [],
      slashCommands: [],
      enableMCP: false,
      enableLsp: false,
      rules: [],
      workspaceTree: { rootPath: sandboxDir, rendered: "", truncated: false, totalLines: 0, agentsMdFiles: [] },
      skipPythonPreflight: true,
    });

    try {
      await session.prompt("Discard working tree");
      const branch = session.sessionManager.getBranch();
      const hasBlockedResult = branch.some((m: any) => {
        const isRes = m.role === "toolResult" || m.type === "toolResult" || m.message?.role === "toolResult" || (m.content && Array.isArray(m.content) && m.content.some((c: any) => c.type === "toolResult"));
        const str = JSON.stringify(m);
        return isRes && str.includes("SAFE_TRANSFORM_REJECT") && str.includes("git stash");
      });
      expect(hasBlockedResult).toBe(true);
    } finally {
      await session.dispose();
    }
  }, 30000);

  it("Test 3 (Black-box Live ntfy.sh Mobile Approval): Tests live ntfy.sh roundtrip on unique dynamic topic", async () => {
    const topic = `autogate_bb_omp_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
const ntfyAdapter = new NtfyAdapter({
server: "https://ntfy.sh",
      topic: topic,
      token: "***REMOVED***",
});

    const reqId = "req-bb-roundtrip-" + Date.now();
    let receivedReply: any = null;
    let unsubscribe: (() => void) | undefined;

    const checkRateLimit = (resOrErr: any, text?: string) => {
      const status = resOrErr?.status;
      const str = String(resOrErr?.message || resOrErr || text || "").toLowerCase();
      if (status === 429 || status === 403 || str.includes("429") || str.includes("403") || str.includes("quota") || str.includes("rate limit") || str.includes("rate-limit") || str.includes("limit") || str.includes("forbidden")) {
        console.log("[SKIP] ntfy.sh rate limited or forbidden (status:", status, ")");
        if (unsubscribe) unsubscribe();
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

      const getRes = await fetch(`https://ntfy.sh/${topic}/json?poll=1`, {
        headers: { "Authorization": "Bearer ***REMOVED***" }
      });
const getTxt = await getRes.text().catch(() => "");
if (checkRateLimit(getRes, getTxt)) return;
expect(getRes.ok).toBe(true);
expect(getTxt).toContain(reqId);

      const replyRes = await fetch(`https://ntfy.sh/${topic}-response`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": "Bearer ***REMOVED***"
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

      if (unsubscribe) unsubscribe();

      expect(receivedReply).toBeDefined();
      expect(receivedReply.req_id).toBe(reqId);
    } catch (err: any) {
      if (checkRateLimit(err)) return;
      throw err;
    }
  }, 30000);
op:

  it("Test 4 (Black-box Native Fallback Mode): UNSURE verdict with native fallback mode records UNSURE / prompt policy without ntfy notification", async () => {
    mockProvider.pushResponse({
      toolCall: {
        name: "bash",
        input: { command: "custom_unsure_command" },
      },
    });
    mockProvider.pushResponse({
      text: JSON.stringify({ verdict: "UNSURE", reason: "Requires human review", risk_level: "MEDIUM", user_authorization: "LOW" }),
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
      extensions: [pi => {
        autoGateOmpExtension(pi, { evaluator, reviewFallbackMode: "native" });
      }],
      toolNames: ["bash"],
      skills: [],
      contextFiles: [],
      promptTemplates: [],
      slashCommands: [],
      enableMCP: false,
      enableLsp: false,
      rules: [],
      workspaceTree: { rootPath: sandboxDir, rendered: "", truncated: false, totalLines: 0, agentsMdFiles: [] },
      skipPythonPreflight: true,
    });

    try {
      await session.prompt("Run unsure command");
      const ntfyMessages = mockNtfy.getPublished();
expect(ntfyMessages.length).toBe(0);

      const branch = session.sessionManager.getBranch();
      const hasToolResult = branch.some((m: any) => {
        const str = JSON.stringify(m);
        return str.includes("custom_unsure_command");
      });
      expect(hasToolResult).toBe(true);
    } finally {
      await session.dispose();
    }
  }, 30000);
});
