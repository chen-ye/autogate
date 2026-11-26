import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import {
  loadConfig,
  loadFileConfig,
  resolveConfigFilePath,
  resolveConfigDir,
  resolveRuntimeDir,
  resolveControlFilePath,
  resolveEvalDbFile,
  resolveEvalSessionCleanup,
  parseEvalSessionCleanupMode,
} from "../src/config";
import { NtfyAdapter } from "../src/remote/ntfy";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";

describe("config resolution", () => {
  const originalEnv = { ...process.env };
  const originalHomedir = os.homedir;
  let tempFiles: string[] = [];
  let tempDirs: string[] = [];

  beforeEach(() => {
    delete process.env.NTFY_TOPIC;
    process.env.NTFY_SERVER = "";
    delete process.env.AUTOGATE_CONFIG;
    delete process.env.AUTOGATE_NTFY_TOPIC;
    delete process.env.OPENCODE_NTFY_TOPIC;
    delete process.env.AUTOGATE_EVAL_DB;
    delete process.env.AUTOGATE_EVAL_SESSION_CLEANUP;
    const emptyConfigDir = path.join(os.tmpdir(), `empty-xdg-config-${Date.now()}`);
    tempDirs.push(emptyConfigDir);
    process.env.XDG_CONFIG_HOME = emptyConfigDir;
  });

  afterEach(() => {
    process.env = { ...originalEnv };
    os.homedir = originalHomedir;
    for (const f of tempFiles) {
      try {
        if (fs.existsSync(f)) {
          fs.unlinkSync(f);
        }
      } catch {}
    }
    tempFiles = [];
    for (const d of tempDirs) {
      try {
        if (fs.existsSync(d)) {
          fs.rmSync(d, { recursive: true, force: true });
        }
      } catch {}
    }
    tempDirs = [];
  });

  it("1. Default configuration: loadConfig() returns standard defaults", () => {
    process.env.NTFY_SERVER = "https://ntfy.sh";
    const config = loadConfig();
    expect(config.ntfyTopic).toBeUndefined();
    expect(config.ntfyServer).toBe("https://ntfy.sh");
    expect(config.autoMode).toBe(true);
    expect(config.reviewFallbackMode).toBe("ntfy");
  });

  it("2. File-based config loading: loads values from custom configFile", () => {
    const tmpFile = path.join(os.tmpdir(), `autogate-test-${Date.now()}.json`);
    tempFiles.push(tmpFile);

    const fileData = {
      ntfyTopic: "custom-file-topic",
      ntfyServer: "https://custom.ntfy.sh",
      autoMode: false,
    };
    fs.writeFileSync(tmpFile, JSON.stringify(fileData), "utf8");

    const config = loadConfig({ configFile: tmpFile });
    expect(config.ntfyTopic).toBe("custom-file-topic");
    expect(config.ntfyServer).toBe("https://custom.ntfy.sh");
    expect(config.autoMode).toBe(false);
  });

  it("3. Environment variable precedence: process.env overrides fileConfig", () => {
    const tmpFile = path.join(os.tmpdir(), `autogate-test-${Date.now()}.json`);
    tempFiles.push(tmpFile);

    const fileData = {
      ntfyTopic: "file-topic",
    };
    fs.writeFileSync(tmpFile, JSON.stringify(fileData), "utf8");

    process.env.NTFY_TOPIC = "env-topic";

    const config = loadConfig({ configFile: tmpFile });
    expect(config.ntfyTopic).toBe("env-topic");
  });

  it("4. Programmatic options precedence: options overrides env and fileConfig", () => {
    const tmpFile = path.join(os.tmpdir(), `autogate-test-${Date.now()}.json`);
    tempFiles.push(tmpFile);

    const fileData = {
      ntfyTopic: "file-topic",
    };
    fs.writeFileSync(tmpFile, JSON.stringify(fileData), "utf8");

    process.env.NTFY_TOPIC = "env-topic";

    const config = loadConfig({ configFile: tmpFile, ntfyTopic: "options-topic" });
    expect(config.ntfyTopic).toBe("options-topic");
  });

  it("5. Malformed JSON handling: invalid JSON logs warning and returns defaults", () => {
    const tmpFile = path.join(os.tmpdir(), `autogate-test-${Date.now()}.json`);
    tempFiles.push(tmpFile);

    fs.writeFileSync(tmpFile, "{ invalid json ...", "utf8");

    const originalWarn = console.warn;
    let warned = false;
    console.warn = () => {
      warned = true;
    };

    try {
      const config = loadConfig({ configFile: tmpFile });
      expect(config.ntfyTopic).toBeUndefined();
      expect(config.autoMode).toBe(true);
      expect(warned).toBe(true);
    } finally {
      console.warn = originalWarn;
    }
  });

  it("6. Fallback mode: reviewFallbackMode: native in file config is loaded", () => {
    const tmpFile = path.join(os.tmpdir(), `autogate-test-${Date.now()}.json`);
    tempFiles.push(tmpFile);

    const fileData = {
      reviewFallbackMode: "native",
    };
    fs.writeFileSync(tmpFile, JSON.stringify(fileData), "utf8");

    const config = loadConfig({ configFile: tmpFile });
    expect(config.reviewFallbackMode).toBe("native");
  });

  it("7. Eval db file default: loadConfig() returns <configDir>/evals.db when no option is provided", () => {
    const config = loadConfig();
    expect(config.evalDbFile).toBe(path.join(resolveConfigDir(), "evals.db"));
    expect(resolveEvalDbFile()).toBe(path.join(resolveConfigDir(), "evals.db"));
    expect(config.evalSessionCleanup).toBe("export-and-delete");
  });

  it("8. Eval db file & cleanup precedence: options > env > fileConfig > default", () => {
    const tmpFile = path.join(os.tmpdir(), `autogate-eval-db-${Date.now()}.json`);
    tempFiles.push(tmpFile);
    fs.writeFileSync(
      tmpFile,
      JSON.stringify({
        evalDbFile: "~/from-file.db",
        evalSessionCleanup: "archive",
      }),
      "utf8",
    );

    const fromFile = loadConfig({ configFile: tmpFile });
    expect(fromFile.evalDbFile).toBe(path.join(os.homedir(), "from-file.db"));
    expect(resolveEvalDbFile({ configFile: tmpFile })).toBe(
      path.join(os.homedir(), "from-file.db"),
    );
    expect(fromFile.evalSessionCleanup).toBe("archive");

    process.env.AUTOGATE_EVAL_DB = "/tmp/from-env.db";
    process.env.AUTOGATE_EVAL_SESSION_CLEANUP = "export-and-delete";
    const fromEnv = loadConfig({ configFile: tmpFile });
    expect(fromEnv.evalDbFile).toBe(path.resolve("/tmp/from-env.db"));
    expect(resolveEvalDbFile({ configFile: tmpFile })).toBe(path.resolve("/tmp/from-env.db"));
    expect(fromEnv.evalSessionCleanup).toBe("export-and-delete");

    const fromOpt = loadConfig({
      configFile: tmpFile,
      evalDbFile: "/tmp/custom.db",
      evalSessionCleanup: "archive",
    });
    expect(fromOpt.evalDbFile).toBe(path.resolve("/tmp/custom.db"));
    expect(resolveEvalDbFile({ configFile: tmpFile, evalDbFile: "/tmp/custom.db" })).toBe(
      path.resolve("/tmp/custom.db"),
    );
    expect(fromOpt.evalSessionCleanup).toBe("archive");

    expect(resolveEvalDbFile({ evalDbFile: ":memory:" })).toBe(":memory:");
  });

  it("9. ~/.config/autogate/config.json is loaded when present", () => {
    const fakeHome = path.join(os.tmpdir(), `autogate-home-${Date.now()}`);
    tempDirs.push(fakeHome);
    const configDir = path.join(fakeHome, ".config", "autogate");
    fs.mkdirSync(configDir, { recursive: true });
    const configFile = path.join(configDir, "config.json");
    fs.writeFileSync(configFile, JSON.stringify({ ntfyTopic: "xdg-fallback-topic" }), "utf8");

    os.homedir = () => fakeHome;
    delete process.env.XDG_CONFIG_HOME;

    const fileConfig = loadFileConfig();
    expect(fileConfig.ntfyTopic).toBe("xdg-fallback-topic");

    const config = loadConfig();
    expect(config.ntfyTopic).toBe("xdg-fallback-topic");
  });

  it("10. $XDG_CONFIG_HOME/autogate/config.json is honored before ~/.config/autogate/config.json", () => {
    const fakeHome = path.join(os.tmpdir(), `autogate-home-${Date.now()}`);
    tempDirs.push(fakeHome);
    const homeConfigDir = path.join(fakeHome, ".config", "autogate");
    fs.mkdirSync(homeConfigDir, { recursive: true });
    fs.writeFileSync(
      path.join(homeConfigDir, "config.json"),
      JSON.stringify({ ntfyTopic: "home-topic" }),
      "utf8",
    );

    const fakeXdg = path.join(os.tmpdir(), `autogate-xdg-${Date.now()}`);
    tempDirs.push(fakeXdg);
    const xdgConfigDir = path.join(fakeXdg, "autogate");
    fs.mkdirSync(xdgConfigDir, { recursive: true });
    fs.writeFileSync(
      path.join(xdgConfigDir, "config.json"),
      JSON.stringify({ ntfyTopic: "xdg-topic" }),
      "utf8",
    );

    os.homedir = () => fakeHome;
    process.env.XDG_CONFIG_HOME = fakeXdg;

    const fileConfig = loadFileConfig();
    expect(fileConfig.ntfyTopic).toBe("xdg-topic");

    const config = loadConfig();
    expect(config.ntfyTopic).toBe("xdg-topic");
  });

  it("11. .autogate.json in cwd is NOT loaded", () => {
    const cwdFile = path.resolve(process.cwd(), ".autogate.json");
    tempFiles.push(cwdFile);
    fs.writeFileSync(cwdFile, JSON.stringify({ ntfyTopic: "cwd-topic" }), "utf8");

    const fakeHome = path.join(os.tmpdir(), `autogate-empty-home-${Date.now()}`);
    tempDirs.push(fakeHome);
    os.homedir = () => fakeHome;
    delete process.env.XDG_CONFIG_HOME;

    const fileConfig = loadFileConfig();
    expect(fileConfig.ntfyTopic).toBeUndefined();

    const config = loadConfig();
    expect(config.ntfyTopic).toBeUndefined();
  });

  it("12. options.omp deeply merges with fileConfig.omp", () => {
    const tmpFile = path.join(os.tmpdir(), `autogate-test-${Date.now()}.json`);
    tempFiles.push(tmpFile);

    const fileData = {
      omp: {
        reviewFallbackMode: "native",
        evalDbFile: "/tmp/from-file.db",
      },
    };
    fs.writeFileSync(tmpFile, JSON.stringify(fileData), "utf8");

    const config = loadConfig({
      configFile: tmpFile,
      omp: {
        evalDbFile: "/tmp/from-options.db",
      },
    });

    expect(config.omp).toEqual({
      reviewFallbackMode: "native",
      evalDbFile: "/tmp/from-options.db",
    });
  });

  it("13. options.opencode deeply merges with fileConfig.opencode", () => {
    const tmpFile = path.join(os.tmpdir(), `autogate-test-${Date.now()}.json`);
    tempFiles.push(tmpFile);

    const fileData = {
      opencode: {
        serverUrl: "http://file-server:4096",
      },
    };
    fs.writeFileSync(tmpFile, JSON.stringify(fileData), "utf8");

    const config = loadConfig({
      configFile: tmpFile,
      opencode: {
        serverUrl: "http://options-server:4096",
      },
    });

    expect(config.opencode).toEqual({
      serverUrl: "http://options-server:4096",
    });
  });

  it("14. ~/.omp/autogate.json is NOT loaded by loadFileConfig", () => {
    const fakeHome = path.join(os.tmpdir(), `autogate-omp-home-${Date.now()}`);
    tempDirs.push(fakeHome);
    const ompDir = path.join(fakeHome, ".omp");
    fs.mkdirSync(ompDir, { recursive: true });
    fs.writeFileSync(
      path.join(ompDir, "autogate.json"),
      JSON.stringify({ ntfyTopic: "omp-topic" }),
      "utf8",
    );

    os.homedir = () => fakeHome;
    delete process.env.XDG_CONFIG_HOME;

    const fileConfig = loadFileConfig();
    expect(fileConfig.ntfyTopic).toBeUndefined();

    const config = loadConfig();
    expect(config.ntfyTopic).toBeUndefined();
  });

  it("15. ntfyVerbosity defaults to 'normal'", () => {
    const config = loadConfig();
    expect(config.ntfyVerbosity).toBe("normal");
  });

  it("16. ntfyVerbosity resolves to 'verbose' from env and options", () => {
    const optConfig = loadConfig({ ntfyVerbosity: "verbose" });
    expect(optConfig.ntfyVerbosity).toBe("verbose");

    process.env.AUTOGATE_NTFY_VERBOSITY = "verbose";
    const envConfig = loadConfig();
    expect(envConfig.ntfyVerbosity).toBe("verbose");
    delete process.env.AUTOGATE_NTFY_VERBOSITY;

    process.env.NTFY_VERBOSITY = "verbose";
    const envConfig2 = loadConfig();
    expect(envConfig2.ntfyVerbosity).toBe("verbose");
    delete process.env.NTFY_VERBOSITY;
  });

  it("17. systemOne config defaults, file loading, and env overrides", () => {
    const def = loadConfig();
    expect(def.systemOne?.enabled).toBe(false);
    expect(def.systemOne?.executionMode).toBe("race");
    expect(def.systemOne?.endpoint).toBe("http://127.0.0.1:4006/v1/systemone");
    expect(def.systemOne?.model).toBe("gemini-decision-1");
    expect(def.systemOne?.timeoutMs).toBe(4000);
    expect(def.systemOne?.thresholds).toEqual({
      allowMinProb: 0.92,
      blockMinProb: 0.85,
      minOddsRatio: 4.0,
      minInScopeNoul: 0.7,
      maxInjectionNoul: 0.5,
    });

    const tmpFile = path.join(os.tmpdir(), `autogate-s1-cfg-${Date.now()}.json`);
    tempFiles.push(tmpFile);
    fs.writeFileSync(
      tmpFile,
      JSON.stringify({
        systemOne: {
          enabled: true,
          executionMode: "cascade",
          timeoutMs: 2500,
          thresholds: { allowMinProb: 0.95 },
        },
      }),
      "utf8",
    );

    const fromFile = loadConfig({ configFile: tmpFile });
    expect(fromFile.systemOne?.enabled).toBe(true);
    expect(fromFile.systemOne?.executionMode).toBe("cascade");
    expect(fromFile.systemOne?.timeoutMs).toBe(2500);
    expect(fromFile.systemOne?.thresholds.allowMinProb).toBe(0.95);
    expect(fromFile.systemOne?.thresholds.blockMinProb).toBe(0.85);

    process.env.AUTOGATE_SYSTEM_ONE_ENABLED = "false";
    process.env.AUTOGATE_SYSTEM_ONE_MODE = "race";
    const envOverride = loadConfig({ configFile: tmpFile });
    expect(envOverride.systemOne?.enabled).toBe(false);
    expect(envOverride.systemOne?.executionMode).toBe("race");
  });

  it("18. resolveConfigFilePath, resolveConfigDir, resolveRuntimeDir, and resolveControlFilePath follow candidate precedence", () => {
    const fakeHome = path.join(os.tmpdir(), `autogate-paths-home-${Date.now()}`);
    tempDirs.push(fakeHome);
    os.homedir = () => fakeHome;
    delete process.env.XDG_CONFIG_HOME;
    delete process.env.AUTOGATE_CONFIG;

    // Default ~/.config/autogate
    expect(resolveConfigFilePath()).toBe(path.join(fakeHome, ".config", "autogate", "config.json"));
    expect(resolveConfigDir()).toBe(path.join(fakeHome, ".config", "autogate"));
    expect(resolveRuntimeDir()).toBe(path.join(fakeHome, ".config", "autogate", "runtime"));
    expect(resolveControlFilePath()).toBe(
      path.join(fakeHome, ".config", "autogate", "control.json"),
    );

    // XDG_CONFIG_HOME
    const xdgDir = path.join(os.tmpdir(), `autogate-paths-xdg-${Date.now()}`);
    tempDirs.push(xdgDir);
    process.env.XDG_CONFIG_HOME = xdgDir;
    expect(resolveConfigFilePath()).toBe(path.join(xdgDir, "autogate", "config.json"));
    expect(resolveConfigDir()).toBe(path.join(xdgDir, "autogate"));
    expect(resolveRuntimeDir()).toBe(path.join(xdgDir, "autogate", "runtime"));
    expect(resolveControlFilePath()).toBe(path.join(xdgDir, "autogate", "control.json"));

    // AUTOGATE_CONFIG env
    const customEnvCfg = path.join(os.tmpdir(), `autogate-paths-env-${Date.now()}`, "custom.json");
    process.env.AUTOGATE_CONFIG = customEnvCfg;
    expect(resolveConfigFilePath()).toBe(path.resolve(customEnvCfg));
    expect(resolveConfigDir()).toBe(path.dirname(path.resolve(customEnvCfg)));
    expect(resolveRuntimeDir()).toBe(
      path.join(path.dirname(path.resolve(customEnvCfg)), "runtime"),
    );
    expect(resolveControlFilePath()).toBe(
      path.join(path.dirname(path.resolve(customEnvCfg)), "control.json"),
    );

    // options.configFile takes precedence over env
    const optCfg = path.join(os.tmpdir(), `autogate-paths-opt-${Date.now()}`, "opt.json");
    expect(resolveConfigFilePath({ configFile: optCfg })).toBe(path.resolve(optCfg));
    expect(resolveConfigDir({ configFile: optCfg })).toBe(path.dirname(path.resolve(optCfg)));
    expect(resolveEvalDbFile({ configFile: optCfg })).toBe(
      path.join(path.dirname(path.resolve(optCfg)), "evals.db"),
    );
  });

  it("19. parseEvalSessionCleanupMode normalizes valid modes and falls back safely", () => {
    expect(parseEvalSessionCleanupMode("export-and-delete")).toBe("export-and-delete");
    expect(parseEvalSessionCleanupMode("  ARCHIVE  ")).toBe("archive");
    expect(parseEvalSessionCleanupMode("Export-And-Delete")).toBe("export-and-delete");
    expect(parseEvalSessionCleanupMode("invalid-mode")).toBe("export-and-delete");
    expect(parseEvalSessionCleanupMode(undefined, "archive")).toBe("archive");
    expect(parseEvalSessionCleanupMode(123, "archive")).toBe("archive");
  });

  it("20. NtfyAdapter throws when constructed without an explicit topic", () => {
    expect(() => new NtfyAdapter({ server: "https://ntfy.example.com" })).toThrow();
    expect(() => new NtfyAdapter({ topic: "   " })).toThrow();

    const ok = new NtfyAdapter({
      server: "https://ntfy.example.com",
      topic: "custom-entropy-topic",
    });
    expect(ok.topic).toBe("custom-entropy-topic");
  });

  it("resolves harness-specific evalDbFile and evalSessionCleanup with precedence options.<harness> > options > env > file.<harness> > file > default", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "autogate-harness-cfg-"));
    tempDirs.push(dir);
    const cfgPath = path.join(dir, "config.json");
    fs.writeFileSync(
      cfgPath,
      JSON.stringify({
        evalDbFile: path.join(dir, "file-top.db"),
        evalSessionCleanup: "archive",
        opencode: {
          evalDbFile: path.join(dir, "file-oc.db"),
          evalSessionCleanup: "export-and-delete",
        },
        omp: {
          evalDbFile: path.join(dir, "file-omp.db"),
        },
      }),
      "utf8",
    );
    process.env.AUTOGATE_CONFIG = cfgPath;
    delete process.env.AUTOGATE_EVAL_DB;
    delete process.env.AUTOGATE_EVAL_SESSION_CLEANUP;

    // file.<harness> beats file top-level
    const cfgOcFile = loadConfig({}, "opencode");
    expect(cfgOcFile.evalDbFile).toBe(path.join(dir, "file-oc.db"));
    expect(cfgOcFile.evalSessionCleanup).toBe("export-and-delete");

    const cfgOmpFile = loadConfig({}, "omp");
    expect(cfgOmpFile.evalDbFile).toBe(path.join(dir, "file-omp.db"));
    expect(cfgOmpFile.evalSessionCleanup).toBe("archive");

    // env beats file.<harness>
    process.env.AUTOGATE_EVAL_DB = path.join(dir, "env.db");
    process.env.AUTOGATE_EVAL_SESSION_CLEANUP = "archive";
    const cfgEnv = loadConfig({}, "opencode");
    expect(cfgEnv.evalDbFile).toBe(path.join(dir, "env.db"));
    expect(cfgEnv.evalSessionCleanup).toBe("archive");

    // options top-level beats env, options.<harness> beats options top-level
    const cfgOpt = loadConfig({ evalDbFile: path.join(dir, "opt.db") }, "opencode");
    expect(cfgOpt.evalDbFile).toBe(path.join(dir, "opt.db"));

    const cfgHarnessOpt = loadConfig(
      {
        evalDbFile: path.join(dir, "opt.db"),
        opencode: {
          evalDbFile: path.join(dir, "opt-oc.db"),
          evalSessionCleanup: "export-and-delete",
        },
      },
      "opencode",
    );
    expect(cfgHarnessOpt.evalDbFile).toBe(path.join(dir, "opt-oc.db"));
    expect(cfgHarnessOpt.evalSessionCleanup).toBe("export-and-delete");
    expect(resolveEvalSessionCleanup({ evalSessionCleanup: "archive" }, "opencode")).toBe(
      "archive",
    );
  });
});
