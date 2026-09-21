import type { AutoGateConfig, EnvironmentConfig, OmpHarnessConfig, OpenCodeHarnessConfig, PaseoHarnessConfig, ReviewFallbackMode } from "./types"
import fs from "node:fs"
import path from "node:path"
import os from "node:os"


function expandPath(p: string): string {
  if (typeof p !== "string") return p
  if (p.startsWith("~/")) {
    return path.join(os.homedir(), p.slice(2))
  }
  if (p === "~") {
    return os.homedir()
  }
  return p
}

export function loadFileConfig(options?: Record<string, unknown>): Record<string, unknown> {
  const env = process.env
  const customConfigPath = (options?.configFile ?? options?.AUTOGATE_CONFIG ?? env.AUTOGATE_CONFIG) as string | undefined

  const candidates: string[] = []
  if (typeof customConfigPath === "string" && customConfigPath.trim().length > 0) {
    candidates.push(path.resolve(expandPath(customConfigPath.trim())))
  }

  const xdgConfigHome = env.XDG_CONFIG_HOME?.trim()
  if (xdgConfigHome) {
    candidates.push(path.resolve(expandPath(path.join(xdgConfigHome, "autogate", "config.json"))))
  } else {
    const fallbackConfigPath = path.join(os.homedir(), ".config", "autogate", "config.json")
    if (!candidates.includes(fallbackConfigPath)) {
      candidates.push(fallbackConfigPath)
    }
  }
  for (const candidate of candidates) {
    try {
      if (fs.existsSync(candidate)) {
        const content = fs.readFileSync(candidate, "utf8")
        const parsed = JSON.parse(content)
        if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
          return parsed as Record<string, unknown>
        }
      }
    } catch (err) {
      console.warn(`[AutoGate] Failed to parse config file at ${candidate}:`, err)
      return {}
    }
  }

  return {}
}

export function loadConfig(options?: Record<string, unknown>): AutoGateConfig {
  const env = process.env
  const fileConfig = loadFileConfig(options)

  const rawAutoMode = options?.autoMode ?? options?.AUTOGATE_AUTO_MODE ?? env.AUTOGATE_AUTO_MODE ?? options?.OPENCODE_AUTO_MODE ?? env.OPENCODE_AUTO_MODE ?? fileConfig.autoMode
  let autoMode = true
  if (typeof rawAutoMode === "boolean") {
    autoMode = rawAutoMode
  } else if (typeof rawAutoMode === "string") {
    const lower = rawAutoMode.toLowerCase().trim()
    if (lower === "false" || lower === "0" || lower === "off") {
      autoMode = false
    } else if (lower === "true" || lower === "1" || lower === "on") {
      autoMode = true
    }
  }

  const rawNotifyOnVerdict = options?.notifyOnVerdict ?? options?.NOTIFY_ON_VERDICT ?? env.AUTOGATE_NOTIFY_ON_VERDICT ?? fileConfig.notifyOnVerdict
  let notifyOnVerdict = true
  if (typeof rawNotifyOnVerdict === "boolean") {
    notifyOnVerdict = rawNotifyOnVerdict
  } else if (typeof rawNotifyOnVerdict === "string") {
    const lower = rawNotifyOnVerdict.toLowerCase().trim()
    if (lower === "false" || lower === "0" || lower === "off") {
      notifyOnVerdict = false
    } else if (lower === "true" || lower === "1" || lower === "on") {
      notifyOnVerdict = true
    }
  }

  const rawTopic = options?.ntfyTopic ?? options?.AUTOGATE_NTFY_TOPIC ?? env.AUTOGATE_NTFY_TOPIC ?? options?.NTFY_TOPIC ?? env.NTFY_TOPIC ?? env.OPENCODE_NTFY_TOPIC ?? fileConfig.ntfyTopic
  const ntfyTopic = typeof rawTopic === "string" && rawTopic.trim().length > 0 ? rawTopic.trim() : "autogate"

  const rawServer = options?.ntfyServer ?? options?.NTFY_SERVER ?? (env.NTFY_SERVER && env.NTFY_SERVER.trim().length > 0 ? env.NTFY_SERVER : undefined) ?? fileConfig.ntfyServer
  let ntfyServer = "https://ntfy.sh"
  if (typeof rawServer === "string" && rawServer.trim().length > 0) {
    try {
      const parsed = new URL(rawServer.trim())
      ntfyServer = parsed.toString().replace(/\/$/, "")
    } catch {
      ntfyServer = "https://ntfy.sh"
    }
  }

  const rawServerUrl = options?.serverUrl ?? options?.SERVER_URL ?? env.SERVER_URL ?? fileConfig.serverUrl
  const serverUrl = typeof rawServerUrl === "string" && rawServerUrl.trim().length > 0 ? rawServerUrl.trim() : "http://localhost:4096"

  const rawToken = options?.ntfyToken ?? options?.NTFY_TOKEN ?? env.NTFY_TOKEN ?? env.AUTOGATE_NTFY_TOKEN ?? fileConfig.ntfyToken
  const ntfyToken = typeof rawToken === "string" && rawToken.trim().length > 0 ? rawToken.trim() : undefined

  const rawFallback = options?.reviewFallbackMode ?? options?.fallbackMode ?? options?.AUTOGATE_FALLBACK ?? env.AUTOGATE_FALLBACK ?? fileConfig.reviewFallbackMode ?? fileConfig.fallbackMode
  let reviewFallbackMode: ReviewFallbackMode = "ntfy"
  if (typeof rawFallback === "string") {
    const lower = rawFallback.toLowerCase().trim()
    if (lower === "native" || lower === "terminal" || lower === "desk") {
      reviewFallbackMode = "native"
    } else if (lower === "ntfy" || lower === "mobile" || lower === "remote") {
      reviewFallbackMode = "ntfy"
    }
  }

  const rawModel = options?.classifierModel ?? options?.CLASSIFIER_MODEL ?? env.CLASSIFIER_MODEL ?? fileConfig.classifierModel
  const classifierModel = typeof rawModel === "string" && rawModel.trim().length > 0 ? rawModel.trim() : "google/gemini-3.5-flash-lite"

  const rawEvalLogFile = options?.evalLogFile ?? env.AUTOGATE_EVAL_LOG ?? fileConfig.evalLogFile
  const evalLogFile = typeof rawEvalLogFile === "string" && rawEvalLogFile.trim().length > 0
    ? path.resolve(expandPath(rawEvalLogFile.trim()))
    : path.join(os.homedir(), ".omp", "logs", "autogate-evals.jsonl")
  const rawThreshold = options?.consecutiveBlockThreshold ?? options?.CONSECUTIVE_BLOCK_THRESHOLD ?? env.CONSECUTIVE_BLOCK_THRESHOLD ?? fileConfig.consecutiveBlockThreshold
  let consecutiveBlockThreshold = 3
  if (typeof rawThreshold === "number" && !isNaN(rawThreshold)) {
    consecutiveBlockThreshold = rawThreshold
  } else if (typeof rawThreshold === "string" && !isNaN(Number(rawThreshold))) {
    consecutiveBlockThreshold = Number(rawThreshold)
  }

  const rawTimeout = options?.classifierTimeout ?? options?.CLASSIFIER_TIMEOUT ?? env.CLASSIFIER_TIMEOUT ?? fileConfig.classifierTimeout
  let classifierTimeout = 45000
  if (typeof rawTimeout === "number" && !isNaN(rawTimeout) && rawTimeout > 0) {
    classifierTimeout = rawTimeout
  } else if (typeof rawTimeout === "string" && !isNaN(Number(rawTimeout)) && Number(rawTimeout) > 0) {
    classifierTimeout = Number(rawTimeout)
  }

  const envTrustedDomains = env.AUTOGATE_TRUSTED_DOMAINS
    ? env.AUTOGATE_TRUSTED_DOMAINS.split(",").map((s: string) => s.trim()).filter(Boolean)
    : undefined
  const envTrustedRemotes = env.AUTOGATE_TRUSTED_REMOTES
    ? env.AUTOGATE_TRUSTED_REMOTES.split(",").map((s: string) => s.trim()).filter(Boolean)
    : undefined
  const envTrustedPaths = env.AUTOGATE_TRUSTED_PATHS
    ? env.AUTOGATE_TRUSTED_PATHS.split(",").map((s: string) => s.trim()).filter(Boolean)
    : undefined

  const optEnv = (options?.environment as EnvironmentConfig | undefined) ?? {}
  const fileEnv = (fileConfig.environment as EnvironmentConfig | undefined) ?? {}

  const environment: EnvironmentConfig = {
    trustedDomains: optEnv.trustedDomains ?? envTrustedDomains ?? fileEnv.trustedDomains ?? (fileConfig.trustedDomains as string[] | undefined) ?? ["*.example.com"],
    trustedGitRemotes: optEnv.trustedGitRemotes ?? envTrustedRemotes ?? fileEnv.trustedGitRemotes ?? (fileConfig.trustedGitRemotes as string[] | undefined) ?? ["origin"],
    trustedPaths: optEnv.trustedPaths ?? envTrustedPaths ?? fileEnv.trustedPaths ?? (fileConfig.trustedPaths as string[] | undefined) ?? ["~/Projects"],
  }

  return {
    autoMode,
    ntfyTopic,
    ntfyServer,
    ntfyToken,
    classifierModel,
    classifierTimeout,
    consecutiveBlockThreshold,
    notifyOnVerdict,
    environment,
    serverUrl,
    reviewFallbackMode,
    evalLogFile,
    omp: { ...((fileConfig.omp as Record<string, unknown>) || {}), ...((options?.omp as Record<string, unknown>) || {}) },
    opencode: { ...((fileConfig.opencode as Record<string, unknown>) || {}), ...((options?.opencode as Record<string, unknown>) || {}) },
    paseo: { ...((fileConfig.paseo as Record<string, unknown>) || {}), ...((options?.paseo as Record<string, unknown>) || {}) },
  }
}
