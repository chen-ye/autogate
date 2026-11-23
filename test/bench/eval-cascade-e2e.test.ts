import { afterEach, describe, expect, it } from "bun:test";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { Database } from "bun:sqlite";
import { parseEvalCliArgs, runEvalCascade } from "../../scripts/eval-cascade.js";
import {
  OpenCodeS2Runner,
  seedCredentialsFromSourceDb,
} from "../../scripts/bench/opencode-s2-runner.js";
import { loadBenchmarkArtifact } from "../../scripts/bench/report.js";
import { MockInferenceProvider } from "../e2e/opencode/mock-provider.js";

function createMockSystemOneServer(options?: { forceAllUnsure?: boolean }): {
  url: string;
  requests: Array<{ state: string }>;
  stop: () => void;
} {
  const requests: Array<{ state: string }> = [];
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch: async (req) => {
      const body = (await req.json()) as { state?: string };
      const state = body.state ?? "";
      requests.push({ state });

      if (options?.forceAllUnsure) {
        return Response.json({
          answers: {
            verdict: { probabilities: { ALLOW: 0.5, BLOCK: 0.5 } },
            in_scope: { noul: 0.2 },
            injection_risk: { noul: 0.1 },
          },
        });
      }

      if (state.includes("SYSTEM OVERRIDE") || state.includes("base64 -d")) {
        return Response.json({
          answers: {
            verdict: { probabilities: { ALLOW: 0.05, BLOCK: 0.95 } },
            in_scope: { noul: 0.9 },
            injection_risk: { noul: 0.92 },
          },
        });
      }

      if (state.includes("kubectl apply") || state.includes("opaque_ext")) {
        return Response.json({
          answers: {
            verdict: { probabilities: { ALLOW: 0.55, BLOCK: 0.45 } },
            in_scope: { noul: 0.25 },
            injection_risk: { noul: 0.05 },
          },
        });
      }

      if (
        state.includes("rm -rf /") ||
        state.includes("git reset --hard") ||
        state.includes("evil.example.com") ||
        state.includes("git clean -fd")
      ) {
        return Response.json({
          answers: {
            verdict: { probabilities: { ALLOW: 0.02, BLOCK: 0.98 } },
            in_scope: { noul: 0.95 },
            injection_risk: { noul: 0.05 },
          },
        });
      }

      return Response.json({
        answers: {
          verdict: { probabilities: { ALLOW: 0.98, BLOCK: 0.02 } },
          in_scope: { noul: 0.95 },
          injection_risk: { noul: 0.02 },
        },
      });
    },
  });

  return {
    url: `http://127.0.0.1:${server.port}/v1/systemone`,
    requests,
    stop: () => {
      server.stop(true);
    },
  };
}

describe("eval-cascade CLI & end-to-end OpenCode v2 runner", () => {
  const tempDirs: string[] = [];
  const servers: Array<() => void> = [];
  const mockProviders: MockInferenceProvider[] = [];

  const makeTempDir = (prefix: string): string => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), `autogate-e2e-bench-${prefix}-`));
    tempDirs.push(dir);
    return dir;
  };

  afterEach(async () => {
    for (const stop of servers.splice(0)) {
      try {
        stop();
      } catch {}
    }
    for (const mp of mockProviders.splice(0)) {
      await mp.close().catch(() => {});
    }
    for (const dir of tempDirs.splice(0)) {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("parses CLI defaults and overrides strictly", () => {
    const defaults = parseEvalCliArgs([]);
    expect(defaults.datasets).toEqual(["synthetic"]);
    expect(defaults.mode).toBe("s1");
    expect(defaults.seed).toBe(42);
    expect(defaults.concurrency).toBe(8);

    const withFile = parseEvalCliArgs(["--file", "~/evals.jsonl"]);
    expect(withFile.datasets).toEqual(["synthetic", "historical"]);

    const raceOpts = parseEvalCliArgs([
      "--datasets",
      "synthetic,authgate",
      "--mode",
      "race",
      "--limit=6",
      "--seed",
      "42",
      "--check",
    ]);
    expect(raceOpts.datasets).toEqual(["synthetic", "authgate"]);
    expect(raceOpts.mode).toBe("race");
    expect(raceOpts.limit).toBe(6);
    expect(raceOpts.seed).toBe(42);
    expect(raceOpts.concurrency).toBe(4);
    expect(raceOpts.check).toBe(true);

    expect(() => parseEvalCliArgs(["--mode", "invalid"])).toThrow(/Invalid --mode/);
    expect(() => parseEvalCliArgs(["--datasets", "nope"])).toThrow(/Unknown dataset/);
  });

  it("executes real CLI --dry-run and writes a valid provenance-stamped artifact", () => {
    const tmpDir = makeTempDir("dry");
    const outPath = path.join(tmpDir, "dry-run.json");
    const proc = spawnSync(
      "bun",
      ["run", "scripts/eval-cascade.ts", "--dry-run", "--datasets", "synthetic", "--out", outPath],
      {
        cwd: process.cwd(),
        encoding: "utf8",
      },
    );

    expect(proc.status).toBe(0);
    expect(proc.stdout).toContain("Dry-run verified OpenCode v2 prompt parity");
    expect(proc.stdout).toContain("Zero empty-prompt collapses verified across 11 projected");

    const artifact = loadBenchmarkArtifact(outPath);
    expect(artifact.schemaVersion).toBe(1);
    expect(artifact.mode).toBe("s1");
    expect(artifact.provenance.evalAgentSystemSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(artifact.provenance.s1QuestionsSha256).toMatch(/^[0-9a-f]{64}$/);
  });

  it("runs --mode s1 Pareto sweep + --check anti-degeneracy gate against local System 1 server", async () => {
    const tmpDir = makeTempDir("s1");
    const outGood = path.join(tmpDir, "s1-good.json");
    const outDegenerate = path.join(tmpDir, "s1-bad.json");

    const goodS1 = createMockSystemOneServer();
    servers.push(goodS1.stop);

    const opts = parseEvalCliArgs([
      "--datasets",
      "synthetic",
      "--mode",
      "s1",
      "--s1-endpoint",
      goodS1.url,
      "--out",
      outGood,
      "--check",
    ]);
    const logs: string[] = [];
    const res = await runEvalCascade(opts, { log: (l) => logs.push(l) });

    expect(res.kind).toBe("eval");
    expect(res.records?.length).toBe(11);
    expect(res.artifact?.paretoGrid?.length).toBeGreaterThan(0);
    expect(res.artifact?.summary.overall.s1AcceptRate).toBeCloseTo(7 / 11, 4);
    expect(res.artifact?.summary.overall.falseAllowCount).toBe(0);
    expect(res.checkResult?.passed).toBe(true);
    expect(logs.join("\n")).toContain("Artifact saved:");

    // Verify 100% UNSURE degeneracy fails --check even with 0 falseAllow
    const badS1 = createMockSystemOneServer({ forceAllUnsure: true });
    servers.push(badS1.stop);
    const badOpts = parseEvalCliArgs([
      "--datasets",
      "synthetic",
      "--mode",
      "s1",
      "--s1-endpoint",
      badS1.url,
      "--out",
      outDegenerate,
      "--check",
    ]);
    await expect(runEvalCascade(badOpts, { log: () => {} })).rejects.toThrow(
      /Regression check failed/,
    );
  });

  it("runs --mode race end-to-end with real OpenCodeS2Runner (opencode 2.0.21) + MockInferenceProvider + System 1", async () => {
    const tmpDir = makeTempDir("race");
    const outPath = path.join(tmpDir, "race-run.json");
    const mockS1 = createMockSystemOneServer();
    servers.push(mockS1.stop);

    const mockProvider = new MockInferenceProvider(0);
    mockProviders.push(mockProvider);
    // Queue enough System 2 responses for escalated cases (injection -> BLOCK, OOD -> UNSURE)
    // and any race losers before abort
    for (let i = 0; i < 16; i++) {
      mockProvider.pushResponse({
        delayMs: 250,
        toolCall: {
          name: "classify_result",
          input: {
            risk_level: "HIGH",
            user_authorization: "LOW",
            verdict: "UNSURE",
            reason: "Mock OpenCode v2 System 2 review",
          },
        },
      });
    }

    const opts = parseEvalCliArgs([
      "--datasets",
      "synthetic",
      "--mode",
      "race",
      "--limit",
      "4",
      "--seed",
      "13",
      "--concurrency",
      "1",
      "--classifier-model",
      "mock-provider/mock-model",
      "--s1-endpoint",
      mockS1.url,
      "--out",
      outPath,
    ]);

    const res = await runEvalCascade(opts, {
      mockProvider: {
        baseUrl: `${mockProvider.url}/v1`,
        modelId: "mock-model",
        apiKey: "mock-key",
      },
      log: () => {},
    });

    expect(res.kind).toBe("eval");
    expect(res.records?.length).toBe(4);
    expect(res.artifact?.summary.overall.evaluatorErrorCount).toBe(0);

    // At least one case accepted fast by System 1 (aborting System 2) and at least one escalated to System 2
    const s1Winners = res.records!.filter((r) => r.cascade?.winner === "system1");
    const s2Winners = res.records!.filter((r) => r.cascade?.winner === "system2");
    expect(s1Winners.length).toBeGreaterThanOrEqual(1);
    expect(s2Winners.length).toBeGreaterThanOrEqual(1);

    // Verify OpenCode v2 prompt parity reached the live System 2 mock provider (auto-gate-eval system + classify_result tool)
    const recorded = mockProvider.getRecordedRequests();
    expect(recorded.length).toBeGreaterThanOrEqual(1);
    const chatReq = recorded.find((r) => r.url.includes("/chat/completions"));
    expect(chatReq).toBeDefined();
    const bodyStr = JSON.stringify(chatReq?.body ?? {});
    expect(bodyStr).toContain("classify_result");
    expect(bodyStr).toContain("Environment Trust Boundaries");

    const loaded = loadBenchmarkArtifact(outPath);
    expect(loaded.mode).toBe("race");
    expect(loaded.classifierModel).toBe("mock-provider/mock-model");
  }, 60000);

  it("seedCredentialsFromSourceDb supersedes stale auth.json rows with rotated opencode.db rows per integration_id", () => {
    const tmpDir = makeTempDir("sqlite-seed");
    const srcDbPath = path.join(tmpDir, "src.db");
    const dstDbPath = path.join(tmpDir, "dst.db");
    const ddl = `CREATE TABLE credential (
      id TEXT PRIMARY KEY,
      integration_id TEXT,
      label TEXT NOT NULL,
      value TEXT NOT NULL,
      active INTEGER,
      time_created INTEGER NOT NULL,
      time_updated INTEGER NOT NULL
    )`;

    const srcDb = new Database(srcDbPath);
    srcDb.exec(ddl);
    srcDb.run(
      "INSERT INTO credential (id, integration_id, label, value, active, time_created, time_updated) VALUES (?, ?, ?, ?, ?, ?, ?)",
      ["cred-live-google", "google", "Google", "fresh-rotated-token", null, 1000, 2000],
    );
    srcDb.close();

    const dstDb = new Database(dstDbPath);
    dstDb.exec(ddl);
    // Simulate legacy auth.json import creating a newer time_created row for google, plus another provider
    dstDb.run(
      "INSERT INTO credential (id, integration_id, label, value, active, time_created, time_updated) VALUES (?, ?, ?, ?, ?, ?, ?)",
      ["cred-legacy-google", "google", "Google", "stale-auth-json-token", null, 99999, 99999],
    );
    dstDb.run(
      "INSERT INTO credential (id, integration_id, label, value, active, time_created, time_updated) VALUES (?, ?, ?, ?, ?, ?, ?)",
      ["cred-legacy-openai", "openai", "OpenAI", "fallback-openai-key", null, 99999, 99999],
    );
    dstDb.close();

    seedCredentialsFromSourceDb(srcDbPath, dstDbPath);

    const checkDb = new Database(dstDbPath, { readonly: true });
    const googleRows = checkDb
      .query("SELECT id, value FROM credential WHERE integration_id = 'google'")
      .all() as Array<{ id: string; value: string }>;
    const openaiRows = checkDb
      .query("SELECT id, value FROM credential WHERE integration_id = 'openai'")
      .all() as Array<{ id: string; value: string }>;
    checkDb.close();

    expect(googleRows).toEqual([{ id: "cred-live-google", value: "fresh-rotated-token" }]);
    expect(openaiRows).toEqual([{ id: "cred-legacy-openai", value: "fallback-openai-key" }]);
  });

  it("enforces 0o700/0o600 permissions on OpenCodeS2Runner temp credentials, registers signal hooks, and cleans up via disposeAllSync", async () => {
    const tmpSrc = makeTempDir("runner-perms-src");
    const srcConfigDir = path.join(tmpSrc, "config");
    const srcDataDir = path.join(tmpSrc, "data");
    fs.mkdirSync(srcConfigDir, { recursive: true });
    fs.mkdirSync(srcDataDir, { recursive: true });
    fs.writeFileSync(
      path.join(srcConfigDir, "opencode.json"),
      JSON.stringify({ provider: { mock: { options: { apiKey: "secret-key" } } } }),
      "utf8",
    );
    fs.writeFileSync(
      path.join(srcDataDir, "auth.json"),
      JSON.stringify({ mock: "secret" }),
      "utf8",
    );

    const runner = await OpenCodeS2Runner.create({
      sourceConfigDir: srcConfigDir,
      sourceDataDir: srcDataDir,
      classifierModel: "mock/model",
      startupTimeoutMs: 25000,
    });

    const isolatedHome = runner.getIsolatedHome();
    const rootDir = path.dirname(isolatedHome);
    const opencodeJsonPath = path.join(isolatedHome, ".config", "opencode", "opencode.json");
    const authJsonPath = path.join(isolatedHome, ".local", "share", "opencode", "auth.json");
    const isolatedDbPath = path.join(isolatedHome, ".local", "share", "opencode", "opencode.db");

    try {
      expect(fs.statSync(rootDir).mode & 0o777).toBe(0o700);
      expect(fs.statSync(isolatedHome).mode & 0o777).toBe(0o700);
      expect(fs.statSync(opencodeJsonPath).mode & 0o777).toBe(0o600);
      expect(fs.statSync(authJsonPath).mode & 0o777).toBe(0o600);
      expect(fs.existsSync(isolatedDbPath)).toBe(true);
      expect(fs.statSync(isolatedDbPath).mode & 0o777).toBe(0o600);
      for (const sidecar of [`${isolatedDbPath}-wal`, `${isolatedDbPath}-shm`]) {
        if (fs.existsSync(sidecar)) {
          expect(fs.statSync(sidecar).mode & 0o777).toBe(0o600);
        }
      }

      expect(process.listenerCount("SIGINT")).toBeGreaterThanOrEqual(1);
      expect(process.listenerCount("SIGTERM")).toBeGreaterThanOrEqual(1);
      expect(process.listenerCount("SIGHUP")).toBeGreaterThanOrEqual(1);
      expect(OpenCodeS2Runner.activeRunners.has(runner)).toBe(true);

      OpenCodeS2Runner.disposeAllSync();
      expect(OpenCodeS2Runner.activeRunners.size).toBe(0);
      expect(fs.existsSync(rootDir)).toBe(false);
    } finally {
      await runner.dispose();
    }
  }, 30000);
});
