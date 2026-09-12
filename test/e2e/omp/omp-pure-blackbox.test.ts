import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { MockInferenceProvider } from "../opencode/mock-provider";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import * as os from "node:os";

describe("OMP Pure Black-box E2E Test Suite", () => {
  let mockProvider: MockInferenceProvider;
  let sandboxDir: string;

  beforeEach(async () => {
    mockProvider = new MockInferenceProvider(0);
    sandboxDir = await fs.mkdtemp(path.join(os.tmpdir(), "omp-bb-test-"));
  });

  afterEach(async () => {
    await mockProvider.stop();
    try {
      await fs.rm(sandboxDir, { recursive: true, force: true });
    } catch {}
  });

  it.skip("Test 1 (Black-box ALLOW): Executes safe bash command via mock-provider tool call", async () => {
    mockProvider.pushResponse({
      toolCall: {
        name: "bash",
        input: { command: "echo 'blackbox-allow-live'" },
      },
    });
    mockProvider.pushResponse({ text: "Done" });

    const configContent = `
providers:
  mock-provider:
    baseUrl: "${mockProvider.url}/v1"
    apiKey: "test-key"
    api: "openai-completions"
    discovery:
      type: "litellm"

models:
  - id: "mock-model"
    provider: "mock-provider"

extensions:
  - "./packages/omp/src/index.ts"

tools:
  approvalMode: "write"
`;
    const configPath = path.join(sandboxDir, "test-omp-config.yml");
    await fs.writeFile(configPath, configContent, "utf-8");

    const modelsContent = `
providers:
  mock-provider:
    baseUrl: "${mockProvider.url}/v1"
    apiKey: "test-key"
    api: "openai-completions"
    discovery:
      type: "litellm"

models:
  - id: "mock-model"
    provider: "mock-provider"
`;
    const modelsPath = path.join(sandboxDir, "models.yml");
    await fs.writeFile(modelsPath, modelsContent, "utf-8");

    const proc = Bun.spawn([
      "omp",
      "-p",
      "--no-session",
      "--config",
      configPath,
      "--model",
      "mock-provider/mock-model",
      "--auto-approve",
      "Run safe check",
    ], {
      cwd: sandboxDir,
      env: {
        ...process.env,
        OPENCODE_AUTO_MODE: "true",
        PI_CODING_AGENT_DIR: sandboxDir,
      },
      stdout: "pipe",
      stderr: "pipe",
    });

    const exitCode = await proc.exited;
    const stdout = await new Response(proc.stdout).text();
    const stderr = await new Response(proc.stderr).text();

    console.log("[TEST 1] exitCode:", exitCode);
    console.log("[TEST 1] stdout:", stdout);
    console.log("[TEST 1] stderr:", stderr);
    console.log("[TEST 1] requests received by mockProvider:", mockProvider.getRequests().map(r => ({ url: r.url, method: r.method })));

    expect(exitCode).toBe(0);
  }, 30000);
});
