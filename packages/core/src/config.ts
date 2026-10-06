import type {
  AutoGateConfig,
  EnvironmentConfig,
  NtfyVerbosity,
  OmpHarnessConfig,
  OpenCodeHarnessConfig,
  PaseoHarnessConfig,
  ReviewFallbackMode,
} from "./types";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";

function expandPath(p: string): string {
  if (typeof p !== "string") return p;
  if (p.startsWith("~/")) {
    return path.join(os.homedir(), p.slice(2));
  }
  if (p === "~") {
    return os.homedir();
  }
  return p;
}

export function isRecord(val: unknown): val is Record<string, unknown> {
  return typeof val === "object" && val !== null && !Array.isArray(val);
}

export function isStringArray(val: unknown): val is string[] {
  return Array.isArray(val) && val.every((item) => typeof item === "string");
}

export function parseEnvironmentConfig(val: unknown): EnvironmentConfig | undefined {
  if (!isRecord(val)) return undefined;
  return {
    trustedDomains: isStringArray(val.trustedDomains) ? val.trustedDomains : undefined,
    trustedGitRemotes: isStringArray(val.trustedGitRemotes) ? val.trustedGitRemotes : undefined,
    trustedPaths: isStringArray(val.trustedPaths) ? val.trustedPaths : undefined,
  };
}

function parseHarnessRecord(val: unknown): Record<string, unknown> {
  return isRecord(val) ? val : {};
}

export function loadFileConfig(options?: Record<string, unknown>): Record<string, unknown> {
  const env = process.env;
  const customConfigPath =
    typeof options?.configFile === "string"
      ? options.configFile
      : typeof options?.AUTOGATE_CONFIG === "string"
        ? options.AUTOGATE_CONFIG
        : typeof env.AUTOGATE_CONFIG === "string"
          ? env.AUTOGATE_CONFIG
          : undefined;

  const candidates: string[] = [];
  if (customConfigPath && customConfigPath.trim().length > 0) {
    candidates.push(path.resolve(expandPath(customConfigPath.trim())));
  }

  const xdgConfigHome = env.XDG_CONFIG_HOME?.trim();
  if (xdgConfigHome) {
    candidates.push(path.resolve(expandPath(path.join(xdgConfigHome, "autogate", "config.json"))));
  } else {
    const fallbackConfigPath = path.join(os.homedir(), ".config", "autogate", "config.json");
    if (!candidates.includes(fallbackConfigPath)) {
      candidates.push(fallbackConfigPath);
    }
  }
  for (const candidate of candidates) {
    try {
      if (fs.existsSync(candidate)) {
        const content = fs.readFileSync(candidate, "utf8");
        const parsed: unknown = JSON.parse(content);
        if (isRecord(parsed)) {
          return parsed;
        }
      }
    } catch (err) {
      console.warn(`[AutoGate] Failed to parse config file at ${candidate}:`, err);
      return {};
    }
  }

  return {};
}

export function loadConfig(options?: Record<string, unknown>): AutoGateConfig {
  const env = process.env;
  const fileConfig = loadFileConfig(options);

  const rawAutoMode =
    options?.autoMode ??
    options?.AUTOGATE_AUTO_MODE ??
    env.AUTOGATE_AUTO_MODE ??
    options?.OPENCODE_AUTO_MODE ??
    env.OPENCODE_AUTO_MODE ??
    fileConfig.autoMode;
  let autoMode = true;
  if (typeof rawAutoMode === "boolean") {
    autoMode = rawAutoMode;
  } else if (typeof rawAutoMode === "string") {
    const lower = rawAutoMode.toLowerCase().trim();
    if (lower === "false" || lower === "0" || lower === "off") {
      autoMode = false;
    } else if (lower === "true" || lower === "1" || lower === "on") {
      autoMode = true;
    }
  }

  const rawNotifyOnVerdict =
    options?.notifyOnVerdict ??
    options?.NOTIFY_ON_VERDICT ??
    env.AUTOGATE_NOTIFY_ON_VERDICT ??
    fileConfig.notifyOnVerdict;
  let notifyOnVerdict = true;
  if (typeof rawNotifyOnVerdict === "boolean") {
    notifyOnVerdict = rawNotifyOnVerdict;
  } else if (typeof rawNotifyOnVerdict === "string") {
    const lower = rawNotifyOnVerdict.toLowerCase().trim();
    if (lower === "false" || lower === "0" || lower === "off") {
      notifyOnVerdict = false;
    } else if (lower === "true" || lower === "1" || lower === "on") {
      notifyOnVerdict = true;
    }
  }

  const rawTopic =
    options?.ntfyTopic ??
    options?.AUTOGATE_NTFY_TOPIC ??
    env.AUTOGATE_NTFY_TOPIC ??
    options?.NTFY_TOPIC ??
    env.NTFY_TOPIC ??
    env.OPENCODE_NTFY_TOPIC ??
    fileConfig.ntfyTopic;
  const ntfyTopic =
    typeof rawTopic === "string" && rawTopic.trim().length > 0 ? rawTopic.trim() : "autogate";

  const rawServer =
    options?.ntfyServer ??
    options?.NTFY_SERVER ??
    (env.NTFY_SERVER && env.NTFY_SERVER.trim().length > 0 ? env.NTFY_SERVER : undefined) ??
    fileConfig.ntfyServer;
  let ntfyServer = "https://ntfy.sh";
  if (typeof rawServer === "string" && rawServer.trim().length > 0) {
    try {
      const parsed = new URL(rawServer.trim());
      ntfyServer = parsed.toString().replace(/\/$/, "");
    } catch {
      ntfyServer = "https://ntfy.sh";
    }
  }

  const defaultPort =
    process.env.OPENCODE_PORT ||
    (process.env.OPENCODE_CONFIG_DIR?.includes("opencode2") ? "4097" : undefined) ||
    "4096";
  const rawServerUrl =
    options?.serverUrl ??
    options?.SERVER_URL ??
    env.SERVER_URL ??
    fileConfig.serverUrl ??
    process.env.OPENCODE_SERVER_URL;
  const serverUrl =
    typeof rawServerUrl === "string" && rawServerUrl.trim().length > 0
      ? rawServerUrl.trim()
      : `http://localhost:${defaultPort}`;

  const rawToken =
    options?.ntfyToken ??
    options?.NTFY_TOKEN ??
    env.NTFY_TOKEN ??
    env.AUTOGATE_NTFY_TOKEN ??
    fileConfig.ntfyToken;
  const ntfyToken =
    typeof rawToken === "string" && rawToken.trim().length > 0 ? rawToken.trim() : undefined;

  const rawVerbosity =
    options?.ntfyVerbosity ??
    options?.AUTOGATE_NTFY_VERBOSITY ??
    env.AUTOGATE_NTFY_VERBOSITY ??
    options?.NTFY_VERBOSITY ??
    env.NTFY_VERBOSITY ??
    fileConfig.ntfyVerbosity;
  const ntfyVerbosity: NtfyVerbosity =
    typeof rawVerbosity === "string" && rawVerbosity.toLowerCase().trim() === "verbose"
      ? "verbose"
      : "normal";

  const rawFallback =
    options?.reviewFallbackMode ??
    options?.fallbackMode ??
    options?.AUTOGATE_FALLBACK ??
    env.AUTOGATE_FALLBACK ??
    fileConfig.reviewFallbackMode ??
    fileConfig.fallbackMode;
  let reviewFallbackMode: ReviewFallbackMode = "ntfy";
  if (typeof rawFallback === "string") {
    const lower = rawFallback.toLowerCase().trim();
    if (lower === "native" || lower === "terminal" || lower === "desk") {
      reviewFallbackMode = "native";
    } else if (lower === "ntfy" || lower === "mobile" || lower === "remote") {
      reviewFallbackMode = "ntfy";
    }
  }

  const rawModel =
    options?.classifierModel ??
    options?.CLASSIFIER_MODEL ??
    env.CLASSIFIER_MODEL ??
    fileConfig.classifierModel;
  const classifierModel =
    typeof rawModel === "string" && rawModel.trim().length > 0
      ? rawModel.trim()
      : "google/gemini-3.5-flash-lite";

  const rawEvalLogFile = options?.evalLogFile ?? env.AUTOGATE_EVAL_LOG ?? fileConfig.evalLogFile;
  const evalLogFile =
    typeof rawEvalLogFile === "string" && rawEvalLogFile.trim().length > 0
      ? path.resolve(expandPath(rawEvalLogFile.trim()))
      : path.join(os.homedir(), ".omp", "logs", "autogate-evals.jsonl");
  const rawThreshold =
    options?.consecutiveBlockThreshold ??
    options?.CONSECUTIVE_BLOCK_THRESHOLD ??
    env.CONSECUTIVE_BLOCK_THRESHOLD ??
    fileConfig.consecutiveBlockThreshold;
  let consecutiveBlockThreshold = 3;
  if (typeof rawThreshold === "number" && !isNaN(rawThreshold)) {
    consecutiveBlockThreshold = rawThreshold;
  } else if (typeof rawThreshold === "string" && !isNaN(Number(rawThreshold))) {
    consecutiveBlockThreshold = Number(rawThreshold);
  }

  const rawTimeout =
    options?.classifierTimeout ??
    options?.CLASSIFIER_TIMEOUT ??
    env.CLASSIFIER_TIMEOUT ??
    fileConfig.classifierTimeout;
  let classifierTimeout = 45000;
  if (typeof rawTimeout === "number" && !isNaN(rawTimeout) && rawTimeout > 0) {
    classifierTimeout = rawTimeout;
  } else if (
    typeof rawTimeout === "string" &&
    !isNaN(Number(rawTimeout)) &&
    Number(rawTimeout) > 0
  ) {
    classifierTimeout = Number(rawTimeout);
  }

  const envTrustedDomains = env.AUTOGATE_TRUSTED_DOMAINS
    ? env.AUTOGATE_TRUSTED_DOMAINS.split(",")
        .map((s: string) => s.trim())
        .filter(Boolean)
    : undefined;
  const envTrustedRemotes = env.AUTOGATE_TRUSTED_REMOTES
    ? env.AUTOGATE_TRUSTED_REMOTES.split(",")
        .map((s: string) => s.trim())
        .filter(Boolean)
    : undefined;
  const envTrustedPaths = env.AUTOGATE_TRUSTED_PATHS
    ? env.AUTOGATE_TRUSTED_PATHS.split(",")
        .map((s: string) => s.trim())
        .filter(Boolean)
    : undefined;

  const optEnv = parseEnvironmentConfig(options?.environment) ?? {};
  const fileEnv = parseEnvironmentConfig(fileConfig.environment) ?? {};

  const fileTrustedDomains = isStringArray(fileConfig.trustedDomains)
    ? fileConfig.trustedDomains
    : undefined;
  const fileTrustedRemotes = isStringArray(fileConfig.trustedGitRemotes)
    ? fileConfig.trustedGitRemotes
    : undefined;
  const fileTrustedPaths = isStringArray(fileConfig.trustedPaths)
    ? fileConfig.trustedPaths
    : undefined;

  const environment: EnvironmentConfig = {
    trustedDomains: optEnv.trustedDomains ??
      envTrustedDomains ??
      fileEnv.trustedDomains ??
      fileTrustedDomains ?? ["*.example.com"],
    trustedGitRemotes: optEnv.trustedGitRemotes ??
      envTrustedRemotes ??
      fileEnv.trustedGitRemotes ??
      fileTrustedRemotes ?? ["origin"],
    trustedPaths: optEnv.trustedPaths ??
      envTrustedPaths ??
      fileEnv.trustedPaths ??
      fileTrustedPaths ?? ["~/Projects"],
  };

  return {
    autoMode,
    ntfyTopic,
    ntfyServer,
    ntfyToken,
    ntfyVerbosity,
    classifierModel,
    classifierTimeout,
    consecutiveBlockThreshold,
    notifyOnVerdict,
    environment,
    serverUrl,
    reviewFallbackMode,
    evalLogFile,
    omp: {
      ...parseHarnessRecord(fileConfig.omp),
      ...parseHarnessRecord(options?.omp),
    },
    opencode: {
      ...parseHarnessRecord(fileConfig.opencode),
      ...parseHarnessRecord(options?.opencode),
    },
    paseo: {
      ...parseHarnessRecord(fileConfig.paseo),
      ...parseHarnessRecord(options?.paseo),
    },
  } satisfies AutoGateConfig;
}
