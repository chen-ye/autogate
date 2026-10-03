import { describe, it, expect, afterEach } from "bun:test";
import * as fs from "fs";
import * as path from "path";
import { createRealPaseoHarness, RealPaseoHarness } from "./real-harness";

describe("RealPaseoHarness", () => {
  let harness: RealPaseoHarness | undefined;

  afterEach(async () => {
    if (harness) {
      await harness.dispose();
      harness = undefined;
    }
  });

  it("starts real Paseo daemon, binds port 0, client connects via WebSocket, and cleans up completely without orphan processes", async () => {
    harness = await createRealPaseoHarness({
      ntfyTopic: "autogate-test-paseo",
    });

    // 1. Verify MockInferenceProvider is initialized on port 0
    expect(harness.mockProvider).toBeDefined();
    expect(harness.mockProvider.port).toBeGreaterThan(0);
    expect(harness.mockProvider.url).toContain("http://127.0.0.1:");

    // 2. Verify ephemeral sandbox setup
    expect(fs.existsSync(harness.scratchDir)).toBe(true);
    expect(fs.existsSync(harness.workspaceDir)).toBe(true);
    expect(fs.existsSync(path.join(harness.workspaceDir, ".git"))).toBe(true);

    // 3. Verify pre-seeded config.json
    const configPath = path.join(harness.scratchDir, "config.json");
    expect(fs.existsSync(configPath)).toBe(true);
    const config = JSON.parse(fs.readFileSync(configPath, "utf-8"));

    expect(config.pluginsEnabled).toBe(true);
    expect(config.plugins?.autogate?.enabled).toBe(true);
    expect(config.plugins?.autogate?.source).toBe("directory");
    expect(config.plugins?.autogate?.path).toBe(path.resolve(process.cwd(), "packages/paseo"));

    expect(config.features?.voiceMode?.enabled).toBe(false);
    expect(config.features?.dictation?.enabled).toBe(false);

    expect(config.agents?.providers?.omp?.env?.OPENAI_BASE_URL).toBe(
      `${harness.mockProvider.url}/v1`,
    );
    expect(config.agents?.providers?.omp?.env?.OPENAI_API_KEY).toBe("test-key");
    expect(config.agents?.providers?.omp?.env?.PI_CONFIG_DIR).toBe(
      path.join(harness.scratchDir, "omp-config"),
    );
    expect(config.agents?.providers?.omp?.env?.PI_CODING_AGENT_DIR).toBe(
      path.join(harness.scratchDir, "omp-agent"),
    );

    // 4. Verify dynamic port binding and WebSocket URL
    expect(harness.port).toBeGreaterThan(0);
    expect(harness.listenHost).toMatch(/^127\.0\.0\.1:\d+$/);
    expect(harness.listenUrl).toBe(`ws://${harness.listenHost}/ws`);

    // 5. Verify @getpaseo/client connection
    expect(harness.client).toBeDefined();
    const connState = harness.client.getConnectionState();
    expect(connState.status).toBe("connected");

    // 6. Execute real RPC request over WebSocket client
    const workspaceList = await harness.client.workspaces.list();
    expect(workspaceList).toBeDefined();
    expect(Array.isArray(workspaceList.entries)).toBe(true);

    // 7. Verify supervisor and worker processes exist
    const supervisorPid = harness.supervisorPid;
    expect(supervisorPid).toBeDefined();
    expect(typeof supervisorPid).toBe("number");
    expect(supervisorPid!).toBeGreaterThan(0);
    expect(harness.isProcessRunning(supervisorPid!)).toBe(true);

    const workerPid = harness.findWorkerPid();
    if (workerPid) {
      expect(harness.isProcessRunning(workerPid)).toBe(true);
    }

    // 8. Clean disposal
    const scratchDir = harness.scratchDir;
    const workspaceDir = harness.workspaceDir;
    const boundPort = harness.port;

    await harness.dispose();

    // Verify scratch directory removed
    expect(fs.existsSync(scratchDir)).toBe(false);
    expect(fs.existsSync(workspaceDir)).toBe(false);

    // Verify process termination
    expect(harness.isProcessRunning(supervisorPid!)).toBe(false);
    if (workerPid) {
      expect(harness.isProcessRunning(workerPid)).toBe(false);
    }

    // Verify port released
    expect(harness.findPortPid(boundPort)).toBeUndefined();

    harness = undefined;
  }, 30000);

  it("configures ntfy topic autogate-test-paseo, server, and token by default", async () => {
    const defaultHarness = new RealPaseoHarness();
    try {
      expect(defaultHarness.ntfyServer).toBe("https://ntfy.sh");
      expect(defaultHarness.ntfyTopic).toBe("autogate-test-paseo");
      expect(defaultHarness.ntfyToken).toBe("***REMOVED***");
    } finally {
      await defaultHarness.dispose();
    }

    const customHarness = new RealPaseoHarness({
      ntfyServer: "https://custom.ntfy",
      ntfyTopic: "custom-topic",
      ntfyToken: "custom-token",
    });
    try {
      expect(customHarness.ntfyServer).toBe("https://custom.ntfy");
      expect(customHarness.ntfyTopic).toBe("custom-topic");
      expect(customHarness.ntfyToken).toBe("custom-token");
    } finally {
      await customHarness.dispose();
    }
  });

  it("tracks active harnesses in static registry and removes them upon disposal", async () => {
    harness = await createRealPaseoHarness();
    expect(RealPaseoHarness.activeHarnesses.has(harness)).toBe(true);

    await harness.dispose();
    expect(RealPaseoHarness.activeHarnesses.has(harness)).toBe(false);
    harness = undefined;
  }, 20000);

  it("dispose() is idempotent, completely cleans up temporary directories, and terminates server processes", async () => {
    harness = await createRealPaseoHarness();
    const scratchDir = harness.scratchDir;
    const workspaceDir = harness.workspaceDir;
    const supervisorPid = harness.supervisorPid;
    const port = harness.port;

    expect(fs.existsSync(scratchDir)).toBe(true);
    expect(fs.existsSync(workspaceDir)).toBe(true);
    expect(supervisorPid).toBeDefined();
    expect(harness.isProcessRunning(supervisorPid!)).toBe(true);

    // First dispose
    await harness.dispose();

    // Verify cleanup
    expect(fs.existsSync(scratchDir)).toBe(false);
    expect(fs.existsSync(workspaceDir)).toBe(false);
    expect(harness.isProcessRunning(supervisorPid!)).toBe(false);
    expect(harness.findPortPid(port)).toBeUndefined();
    expect(RealPaseoHarness.activeHarnesses.has(harness)).toBe(false);

    // Verify subsequent dispose calls are idempotent
    await expect(harness.dispose()).resolves.toBeUndefined();
    await expect(harness.dispose()).resolves.toBeUndefined();
    expect(() => harness!.disposeSync()).not.toThrow();

    harness = undefined;
  }, 20000);

  it("disposeSync() synchronously performs teardown, terminates server processes, and cleans up temp directories", async () => {
    harness = await createRealPaseoHarness();
    const scratchDir = harness.scratchDir;
    const workspaceDir = harness.workspaceDir;
    const supervisorPid = harness.supervisorPid;
    const port = harness.port;

    expect(fs.existsSync(scratchDir)).toBe(true);
    expect(fs.existsSync(workspaceDir)).toBe(true);
    expect(RealPaseoHarness.activeHarnesses.has(harness)).toBe(true);

    // Synchronous disposal
    harness.disposeSync();

    expect(RealPaseoHarness.activeHarnesses.has(harness)).toBe(false);
    expect(fs.existsSync(scratchDir)).toBe(false);
    expect(fs.existsSync(workspaceDir)).toBe(false);
    if (supervisorPid) {
      expect(harness.isProcessRunning(supervisorPid)).toBe(false);
    }
    expect(harness.findPortPid(port)).toBeUndefined();

    // Subsequent async dispose
    await expect(harness.dispose()).resolves.toBeUndefined();
    harness = undefined;
  }, 20000);

  it("sends notification to autogate-test-paseo topic on ntfy.sh", async () => {
    harness = new RealPaseoHarness({
      ntfyTopic: "autogate-test-paseo",
    });

    try {
      const res = await fetch(`${harness.ntfyServer}/${harness.ntfyTopic}`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${harness.ntfyToken}`,
          Title: "RealPaseoHarness Initialized",
        },
        body: "Paseo blackbox harness test verified topic delivery",
      });

      if (res.status === 429) {
        console.log("[SKIP] ntfy.sh 429 quota reached");
        return;
      }

      expect(res.ok).toBe(true);
    } finally {
      await harness.dispose();
      harness = undefined;
    }
  });
});
