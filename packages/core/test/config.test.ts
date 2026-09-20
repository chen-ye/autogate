import { describe, it, expect, beforeEach, afterEach } from "bun:test"
import { loadConfig, loadFileConfig } from "../src/config"
import fs from "node:fs"
import path from "node:path"
import os from "node:os"

describe("config resolution", () => {
  const originalEnv = { ...process.env }
  let tempFiles: string[] = []

  beforeEach(() => {
    delete process.env.NTFY_TOPIC
    process.env.NTFY_SERVER = ""
    delete process.env.AUTOGATE_CONFIG
    delete process.env.AUTOGATE_NTFY_TOPIC
  })

  afterEach(() => {
    process.env = { ...originalEnv }
    for (const f of tempFiles) {
      try {
        if (fs.existsSync(f)) {
          fs.unlinkSync(f)
        }
      } catch {}
    }
    tempFiles = []
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
})
