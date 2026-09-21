import { describe, it, expect, beforeEach, afterEach } from "bun:test"
import { loadConfig, loadFileConfig } from "../src/config"
import fs from "node:fs"
import path from "node:path"
import os from "node:os"

describe("config resolution", () => {
  const originalEnv = { ...process.env }
  const originalHomedir = os.homedir
  let tempFiles: string[] = []
  let tempDirs: string[] = []

  beforeEach(() => {
    delete process.env.NTFY_TOPIC
    process.env.NTFY_SERVER = ""
    delete process.env.AUTOGATE_CONFIG
    delete process.env.AUTOGATE_NTFY_TOPIC
    const emptyConfigDir = path.join(os.tmpdir(), `empty-xdg-config-${Date.now()}`)
    tempDirs.push(emptyConfigDir)
    process.env.XDG_CONFIG_HOME = emptyConfigDir
  })

  afterEach(() => {
    process.env = { ...originalEnv }
    os.homedir = originalHomedir
    for (const f of tempFiles) {
      try {
        if (fs.existsSync(f)) {
          fs.unlinkSync(f)
        }
      } catch {}
    }
    tempFiles = []
    for (const d of tempDirs) {
      try {
        if (fs.existsSync(d)) {
          fs.rmSync(d, { recursive: true, force: true })
        }
      } catch {}
    }
    tempDirs = []
  })

  it("1. Default configuration: loadConfig() returns standard defaults", () => {
    process.env.NTFY_SERVER = "https://ntfy.sh"
    const config = loadConfig()
    expect(config.ntfyTopic).toBe("autogate")
    expect(config.ntfyServer).toBe("https://ntfy.sh")
    expect(config.autoMode).toBe(true)
    expect(config.reviewFallbackMode).toBe("ntfy")
  })

  it("2. File-based config loading: loads values from custom configFile", () => {
    const tmpFile = path.join(os.tmpdir(), `autogate-test-${Date.now()}.json`)
    tempFiles.push(tmpFile)

    const fileData = {
      ntfyTopic: "custom-file-topic",
      ntfyServer: "https://custom.ntfy.sh",
      autoMode: false,
    }
    fs.writeFileSync(tmpFile, JSON.stringify(fileData), "utf8")

    const config = loadConfig({ configFile: tmpFile })
    expect(config.ntfyTopic).toBe("custom-file-topic")
    expect(config.ntfyServer).toBe("https://custom.ntfy.sh")
    expect(config.autoMode).toBe(false)
  })

  it("3. Environment variable precedence: process.env overrides fileConfig", () => {
    const tmpFile = path.join(os.tmpdir(), `autogate-test-${Date.now()}.json`)
    tempFiles.push(tmpFile)

    const fileData = {
      ntfyTopic: "file-topic",
    }
    fs.writeFileSync(tmpFile, JSON.stringify(fileData), "utf8")

    process.env.NTFY_TOPIC = "env-topic"

    const config = loadConfig({ configFile: tmpFile })
    expect(config.ntfyTopic).toBe("env-topic")
  })

  it("4. Programmatic options precedence: options overrides env and fileConfig", () => {
    const tmpFile = path.join(os.tmpdir(), `autogate-test-${Date.now()}.json`)
    tempFiles.push(tmpFile)

    const fileData = {
      ntfyTopic: "file-topic",
    }
    fs.writeFileSync(tmpFile, JSON.stringify(fileData), "utf8")

    process.env.NTFY_TOPIC = "env-topic"

    const config = loadConfig({ configFile: tmpFile, ntfyTopic: "options-topic" })
    expect(config.ntfyTopic).toBe("options-topic")
  })

  it("5. Malformed JSON handling: invalid JSON logs warning and returns defaults", () => {
    const tmpFile = path.join(os.tmpdir(), `autogate-test-${Date.now()}.json`)
    tempFiles.push(tmpFile)

    fs.writeFileSync(tmpFile, "{ invalid json ...", "utf8")

    const originalWarn = console.warn
    let warned = false
    console.warn = () => {
      warned = true
    }

    try {
      const config = loadConfig({ configFile: tmpFile })
      expect(config.ntfyTopic).toBe("autogate")
      expect(config.autoMode).toBe(true)
      expect(warned).toBe(true)
    } finally {
      console.warn = originalWarn
    }
  })

  it("6. Fallback mode: reviewFallbackMode: native in file config is loaded", () => {
    const tmpFile = path.join(os.tmpdir(), `autogate-test-${Date.now()}.json`)
    tempFiles.push(tmpFile)

    const fileData = {
      reviewFallbackMode: "native",
    }
    fs.writeFileSync(tmpFile, JSON.stringify(fileData), "utf8")

    const config = loadConfig({ configFile: tmpFile })
    expect(config.reviewFallbackMode).toBe("native")
  })

  it("7. Eval log file default: loadConfig() returns ~/.omp/logs/autogate-evals.jsonl when no option is provided", () => {
    const config = loadConfig()
    expect(config.evalLogFile).toBe(path.join(os.homedir(), ".omp", "logs", "autogate-evals.jsonl"))
  })

  it("8. Eval log file custom: loadConfig({ evalLogFile: \"/tmp/custom.jsonl\" }) returns resolved custom path", () => {
    const config = loadConfig({ evalLogFile: "/tmp/custom.jsonl" })
    expect(config.evalLogFile).toBe(path.resolve("/tmp/custom.jsonl"))
  })

  it("9. ~/.config/autogate/config.json is loaded when present", () => {
    const fakeHome = path.join(os.tmpdir(), `autogate-home-${Date.now()}`)
    tempDirs.push(fakeHome)
    const configDir = path.join(fakeHome, ".config", "autogate")
    fs.mkdirSync(configDir, { recursive: true })
    const configFile = path.join(configDir, "config.json")
    fs.writeFileSync(configFile, JSON.stringify({ ntfyTopic: "xdg-fallback-topic" }), "utf8")

    os.homedir = () => fakeHome
    delete process.env.XDG_CONFIG_HOME

    const fileConfig = loadFileConfig()
    expect(fileConfig.ntfyTopic).toBe("xdg-fallback-topic")

    const config = loadConfig()
    expect(config.ntfyTopic).toBe("xdg-fallback-topic")
  })

  it("10. $XDG_CONFIG_HOME/autogate/config.json is honored before ~/.config/autogate/config.json", () => {
    const fakeHome = path.join(os.tmpdir(), `autogate-home-${Date.now()}`)
    tempDirs.push(fakeHome)
    const homeConfigDir = path.join(fakeHome, ".config", "autogate")
    fs.mkdirSync(homeConfigDir, { recursive: true })
    fs.writeFileSync(path.join(homeConfigDir, "config.json"), JSON.stringify({ ntfyTopic: "home-topic" }), "utf8")

    const fakeXdg = path.join(os.tmpdir(), `autogate-xdg-${Date.now()}`)
    tempDirs.push(fakeXdg)
    const xdgConfigDir = path.join(fakeXdg, "autogate")
    fs.mkdirSync(xdgConfigDir, { recursive: true })
    fs.writeFileSync(path.join(xdgConfigDir, "config.json"), JSON.stringify({ ntfyTopic: "xdg-topic" }), "utf8")

    os.homedir = () => fakeHome
    process.env.XDG_CONFIG_HOME = fakeXdg

    const fileConfig = loadFileConfig()
    expect(fileConfig.ntfyTopic).toBe("xdg-topic")

    const config = loadConfig()
    expect(config.ntfyTopic).toBe("xdg-topic")
  })

  it("11. .autogate.json in cwd is NOT loaded", () => {
    const cwdFile = path.resolve(process.cwd(), ".autogate.json")
    tempFiles.push(cwdFile)
    fs.writeFileSync(cwdFile, JSON.stringify({ ntfyTopic: "cwd-topic" }), "utf8")

    const fakeHome = path.join(os.tmpdir(), `autogate-empty-home-${Date.now()}`)
    tempDirs.push(fakeHome)
    os.homedir = () => fakeHome
    delete process.env.XDG_CONFIG_HOME

    const fileConfig = loadFileConfig()
    expect(fileConfig.ntfyTopic).toBeUndefined()

    const config = loadConfig()
    expect(config.ntfyTopic).toBe("autogate")
  })

  it("12. options.omp deeply merges with fileConfig.omp", () => {
    const tmpFile = path.join(os.tmpdir(), `autogate-test-${Date.now()}.json`)
    tempFiles.push(tmpFile)

    const fileData = {
      omp: {
        reviewFallbackMode: "native",
        evalLogFile: "/tmp/from-file.jsonl",
      },
    }
    fs.writeFileSync(tmpFile, JSON.stringify(fileData), "utf8")

    const config = loadConfig({
      configFile: tmpFile,
      omp: {
        evalLogFile: "/tmp/from-options.jsonl",
      },
    })

    expect(config.omp).toEqual({
      reviewFallbackMode: "native",
      evalLogFile: "/tmp/from-options.jsonl",
    })
  })

  it("13. options.opencode deeply merges with fileConfig.opencode", () => {
    const tmpFile = path.join(os.tmpdir(), `autogate-test-${Date.now()}.json`)
    tempFiles.push(tmpFile)

    const fileData = {
      opencode: {
        serverUrl: "http://file-server:4096",
      },
    }
    fs.writeFileSync(tmpFile, JSON.stringify(fileData), "utf8")

    const config = loadConfig({
      configFile: tmpFile,
      opencode: {
        serverUrl: "http://options-server:4096",
      },
    })

    expect(config.opencode).toEqual({
      serverUrl: "http://options-server:4096",
    })
  })

  it("14. ~/.omp/autogate.json is NOT loaded by loadFileConfig", () => {
    const fakeHome = path.join(os.tmpdir(), `autogate-omp-home-${Date.now()}`)
    tempDirs.push(fakeHome)
    const ompDir = path.join(fakeHome, ".omp")
    fs.mkdirSync(ompDir, { recursive: true })
    fs.writeFileSync(path.join(ompDir, "autogate.json"), JSON.stringify({ ntfyTopic: "omp-topic" }), "utf8")

    os.homedir = () => fakeHome
    delete process.env.XDG_CONFIG_HOME

    const fileConfig = loadFileConfig()
    expect(fileConfig.ntfyTopic).toBeUndefined()

    const config = loadConfig()
    expect(config.ntfyTopic).toBe("autogate")
  })
})
