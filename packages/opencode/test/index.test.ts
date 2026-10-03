import { describe, it, expect, beforeEach, afterEach, spyOn } from "bun:test";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { resolveServerPassword, isEventForWorkspace } from "../src/index.js";

describe("@autogate/opencode resolveServerPassword", () => {
  const origEnv = { ...process.env };
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "autogate-opencode-test-"));
    delete process.env.OPENCODE_CONFIG_DIR;
    delete process.env.OPENCODE_SERVER_PASSWORD;
    delete process.env.OPENCODE_PASSWORD;
    delete process.env.XDG_CONFIG_HOME;
  });

  afterEach(() => {
    process.env = { ...origEnv };
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  });

  it("prioritizes OPENCODE_SERVER_PASSWORD over service.json", () => {
    process.env.OPENCODE_CONFIG_DIR = tempDir;
    fs.writeFileSync(
      path.join(tempDir, "service.json"),
      JSON.stringify({ password: "service-json-password" }),
    );
    process.env.OPENCODE_SERVER_PASSWORD = "env-server-password";

    expect(resolveServerPassword()).toBe("env-server-password");
  });

  it("prioritizes OPENCODE_PASSWORD over service.json when OPENCODE_SERVER_PASSWORD is unset", () => {
    process.env.OPENCODE_CONFIG_DIR = tempDir;
    fs.writeFileSync(
      path.join(tempDir, "service.json"),
      JSON.stringify({ password: "service-json-password" }),
    );
    process.env.OPENCODE_PASSWORD = "env-password";

    expect(resolveServerPassword()).toBe("env-password");
  });

  it("resolves password from service.json in OPENCODE_CONFIG_DIR when env vars are unset", () => {
    process.env.OPENCODE_CONFIG_DIR = tempDir;
    fs.writeFileSync(
      path.join(tempDir, "service.json"),
      JSON.stringify({ password: "  config-dir-pw-123  " }),
    );

    expect(resolveServerPassword()).toBe("config-dir-pw-123");
  });

  it("resolves password from service.json in explicitly passed configDir", () => {
    fs.writeFileSync(
      path.join(tempDir, "service.json"),
      JSON.stringify({ password: "explicit-config-dir-pw" }),
    );

    expect(resolveServerPassword(tempDir)).toBe("explicit-config-dir-pw");
  });

  it("resolves password from service.json in default config dir when env vars and OPENCODE_CONFIG_DIR are unset", () => {
    const defaultDir = path.join(tempDir, ".config", "opencode");
    fs.mkdirSync(defaultDir, { recursive: true });
    fs.writeFileSync(
      path.join(defaultDir, "service.json"),
      JSON.stringify({ password: "default-config-pw" }),
    );

    const homedirSpy = spyOn(os, "homedir").mockReturnValue(tempDir);
    try {
      expect(resolveServerPassword()).toBe("default-config-pw");
    } finally {
      homedirSpy.mockRestore();
    }
  });

  it("resolves password from service.json in XDG_CONFIG_HOME when env vars and OPENCODE_CONFIG_DIR are unset", () => {
    const xdgDir = path.join(tempDir, "xdg-config");
    const opencodeDir = path.join(xdgDir, "opencode");
    fs.mkdirSync(opencodeDir, { recursive: true });
    fs.writeFileSync(
      path.join(opencodeDir, "service.json"),
      JSON.stringify({ password: "xdg-password" }),
    );
    process.env.XDG_CONFIG_HOME = xdgDir;

    expect(resolveServerPassword()).toBe("xdg-password");
  });

  it("returns empty string when no env var and no service.json exists", () => {
    const homedirSpy = spyOn(os, "homedir").mockReturnValue(tempDir);
    try {
      expect(resolveServerPassword()).toBe("");
    } finally {
      homedirSpy.mockRestore();
    }
  });

  it("returns empty string when service.json has empty or invalid password", () => {
    process.env.OPENCODE_CONFIG_DIR = tempDir;
    fs.writeFileSync(path.join(tempDir, "service.json"), JSON.stringify({ password: "   " }));

    expect(resolveServerPassword()).toBe("");
  });
});

describe("@autogate/opencode isEventForWorkspace", () => {
  it("matches workspace correctly", () => {
    expect(isEventForWorkspace({}, undefined)).toBe(true);
    expect(
      isEventForWorkspace({ location: { directory: "/home/user/project" } }, "/home/user/project"),
    ).toBe(true);
    expect(
      isEventForWorkspace({ location: { directory: "/other/dir" } }, "/home/user/project"),
    ).toBe(false);
  });
});
