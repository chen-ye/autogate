import type { EnvironmentConfig, ReviewFallbackMode } from "./types"

export interface AutoGateConfig {
  autoMode: boolean
  ntfyTopic: string
  ntfyServer: string
  ntfyToken?: string
  classifierModel: string
  classifierTimeout?: number
  consecutiveBlockThreshold?: number
  notifyOnVerdict?: boolean
  environment?: EnvironmentConfig
  serverUrl?: string
  reviewFallbackMode?: ReviewFallbackMode
}

export function loadConfig(options?: Record<string, unknown>): AutoGateConfig {
  const env = process.env

  const rawAutoMode = options?.autoMode ?? options?.AUTOGATE_AUTO_MODE ?? env.AUTOGATE_AUTO_MODE ?? options?.OPENCODE_AUTO_MODE ?? env.OPENCODE_AUTO_MODE
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

  const rawNotifyOnVerdict = options?.notifyOnVerdict ?? options?.NOTIFY_ON_VERDICT ?? env.AUTOGATE_NOTIFY_ON_VERDICT
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

  const rawTopic = options?.ntfyTopic ?? options?.AUTOGATE_NTFY_TOPIC ?? env.AUTOGATE_NTFY_TOPIC ?? options?.NTFY_TOPIC ?? env.NTFY_TOPIC ?? env.OPENCODE_NTFY_TOPIC
  const ntfyTopic = typeof rawTopic === "string" && rawTopic.trim().length > 0 ? rawTopic.trim() : "autogate"

  const rawServer = options?.ntfyServer ?? options?.NTFY_SERVER ?? env.NTFY_SERVER
  let ntfyServer = "https://ntfy.sh"
  if (typeof rawServer === "string" && rawServer.trim().length > 0) {
    try {
      const parsed = new URL(rawServer.trim())
      ntfyServer = parsed.toString().replace(/\/$/, "")
    } catch {
      ntfyServer = "https://ntfy.sh"
    }
  }

  const rawServerUrl = options?.serverUrl ?? options?.SERVER_URL ?? env.SERVER_URL
  const serverUrl = typeof rawServerUrl === "string" && rawServerUrl.trim().length > 0 ? rawServerUrl.trim() : "http://localhost:4096"

  const rawToken = options?.ntfyToken ?? options?.NTFY_TOKEN ?? env.NTFY_TOKEN
  const ntfyToken = typeof rawToken === "string" && rawToken.trim().length > 0 ? rawToken.trim() : undefined

  const rawFallback = options?.reviewFallbackMode ?? options?.fallbackMode ?? options?.AUTOGATE_FALLBACK ?? env.AUTOGATE_FALLBACK
  let reviewFallbackMode: ReviewFallbackMode = "ntfy"
  if (typeof rawFallback === "string") {
    const lower = rawFallback.toLowerCase().trim()
    if (lower === "native" || lower === "terminal" || lower === "desk") {
      reviewFallbackMode = "native"
    } else if (lower === "ntfy" || lower === "mobile" || lower === "remote") {
      reviewFallbackMode = "ntfy"
    }
  }
  const rawModel = options?.classifierModel ?? options?.CLASSIFIER_MODEL ?? env.CLASSIFIER_MODEL
  const classifierModel = typeof rawModel === "string" && rawModel.trim().length > 0 ? rawModel.trim() : "google/gemini-2.5-flash-lite"

  const rawThreshold = options?.consecutiveBlockThreshold ?? options?.CONSECUTIVE_BLOCK_THRESHOLD ?? env.CONSECUTIVE_BLOCK_THRESHOLD
  let consecutiveBlockThreshold = 3
  if (typeof rawThreshold === "number" && !isNaN(rawThreshold)) {
    consecutiveBlockThreshold = rawThreshold
  } else if (typeof rawThreshold === "string" && !isNaN(Number(rawThreshold))) {
    consecutiveBlockThreshold = Number(rawThreshold)
  }

  const rawTimeout = options?.classifierTimeout ?? options?.CLASSIFIER_TIMEOUT ?? env.CLASSIFIER_TIMEOUT
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

  const environment: EnvironmentConfig = {
    trustedDomains: optEnv.trustedDomains ?? envTrustedDomains ?? ["*.example.com"],
    trustedGitRemotes: optEnv.trustedGitRemotes ?? envTrustedRemotes ?? ["origin"],
    trustedPaths: optEnv.trustedPaths ?? envTrustedPaths ?? ["~/Projects"],
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
}
}
