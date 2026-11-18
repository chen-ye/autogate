import type {
  AutoGateConfig,
  EnvironmentConfig,
  NtfyVerbosity,
  ReviewFallbackMode,
  SystemOneConfig,
  SystemOneExecutionMode,
  SystemOneThresholds,
} from "./types";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { getDefaultClassifierModel } from "./agent";

export const DEFAULT_SYSTEM_ONE_ENDPOINT = "http://127.0.0.1:4006/v1/systemone";
export const DEFAULT_SYSTEM_ONE_MODEL = "gemini-decision-1";
export const DEFAULT_SYSTEM_ONE_TIMEOUT_MS = 4000;
export const DEFAULT_SYSTEM_ONE_THRESHOLDS: SystemOneThresholds = {
  allowMinProb: 0.92,
  blockMinProb: 0.85,
  minOddsRatio: 4.0,
  minInScopeNoul: 0.7,
  maxInjectionNoul: 0.5,
};

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

function parseFiniteUnitNumber(val: unknown, fallback: number): number {
  if (typeof val === "number" && Number.isFinite(val) && val >= 0 && val <= 1) {
    return val;
  }
  return fallback;
}

function parsePositiveNumber(val: unknown, fallback: number): number {
  if (typeof val === "number" && Number.isFinite(val) && val > 0) {
    return val;
  }
  if (typeof val === "string" && val.trim().length > 0) {
    const num = Number(val);
    if (Number.isFinite(num) && num > 0) {
      return num;
    }
  }
  return fallback;
}

function parseBooleanValue(val: unknown): boolean | undefined {
  if (typeof val === "boolean") return val;
  if (typeof val === "string") {
    const lower = val.toLowerCase().trim();
    if (lower === "true" || lower === "1" || lower === "on") return true;
    if (lower === "false" || lower === "0" || lower === "off") return false;
  }
  return undefined;
}

export function parseSystemOneConfig(
  fileVal: unknown,
  optVal: unknown,
  env: NodeJS.ProcessEnv = process.env,
): SystemOneConfig {
  const fileObj = isRecord(fileVal) ? fileVal : {};
  const optObj = isRecord(optVal) ? optVal : {};

  const optEnabled = parseBooleanValue(optObj.enabled);
  const envEnabled = parseBooleanValue(env.AUTOGATE_SYSTEM_ONE_ENABLED);
  const fileEnabled = parseBooleanValue(fileObj.enabled);
  const enabled = optEnabled ?? envEnabled ?? fileEnabled ?? false;

  const rawMode = optObj.executionMode ?? env.AUTOGATE_SYSTEM_ONE_MODE ?? fileObj.executionMode;
  const executionMode: SystemOneExecutionMode =
    rawMode === "cascade" || rawMode === "race" ? rawMode : "race";

  const rawEndpoint = optObj.endpoint ?? env.AUTOGATE_SYSTEM_ONE_ENDPOINT ?? fileObj.endpoint;
  const endpoint =
    typeof rawEndpoint === "string" && rawEndpoint.trim().length > 0
      ? rawEndpoint.trim()
      : DEFAULT_SYSTEM_ONE_ENDPOINT;

  const rawModel = optObj.model ?? env.AUTOGATE_SYSTEM_ONE_MODEL ?? fileObj.model;
  const model =
    typeof rawModel === "string" && rawModel.trim().length > 0
      ? rawModel.trim()
      : DEFAULT_SYSTEM_ONE_MODEL;

  const rawApiKey = optObj.apiKey ?? env.AUTOGATE_SYSTEM_ONE_API_KEY ?? fileObj.apiKey;
  const apiKey =
    typeof rawApiKey === "string" && rawApiKey.trim().length > 0 ? rawApiKey.trim() : undefined;

  const timeoutMs = parsePositiveNumber(
    optObj.timeoutMs ?? env.AUTOGATE_SYSTEM_ONE_TIMEOUT_MS ?? fileObj.timeoutMs,
    DEFAULT_SYSTEM_ONE_TIMEOUT_MS,
  );

  const fileThresh = isRecord(fileObj.thresholds) ? fileObj.thresholds : {};
  const optThresh = isRecord(optObj.thresholds) ? optObj.thresholds : {};

  const thresholds: SystemOneThresholds = {
    allowMinProb: parseFiniteUnitNumber(
      optThresh.allowMinProb ?? fileThresh.allowMinProb,
      DEFAULT_SYSTEM_ONE_THRESHOLDS.allowMinProb,
    ),
    blockMinProb: parseFiniteUnitNumber(
      optThresh.blockMinProb ?? fileThresh.blockMinProb,
      DEFAULT_SYSTEM_ONE_THRESHOLDS.blockMinProb,
    ),
    minOddsRatio: parsePositiveNumber(
      optThresh.minOddsRatio ?? fileThresh.minOddsRatio,
      DEFAULT_SYSTEM_ONE_THRESHOLDS.minOddsRatio,
    ),
    minInScopeNoul: parseFiniteUnitNumber(
      optThresh.minInScopeNoul ?? fileThresh.minInScopeNoul,
      DEFAULT_SYSTEM_ONE_THRESHOLDS.minInScopeNoul,
    ),
    maxInjectionNoul: parseFiniteUnitNumber(
      optThresh.maxInjectionNoul ?? fileThresh.maxInjectionNoul,
      DEFAULT_SYSTEM_ONE_THRESHOLDS.maxInjectionNoul,
    ),
  };

  return {
    enabled,
    executionMode,
    endpoint,
    model,
    ...(apiKey !== undefined ? { apiKey } : {}),
    timeoutMs,
    thresholds,
  };
}

function getConfigFileCandidates(options?: Record<string, unknown>): string[] {
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
    const xdgConfigPath = path.resolve(
      expandPath(path.join(xdgConfigHome, "autogate", "config.json")),
    );
    if (!candidates.includes(xdgConfigPath)) {
      candidates.push(xdgConfigPath);
    }
  } else {
    const fallbackConfigPath = path.join(os.homedir(), ".config", "autogate", "config.json");
    if (!candidates.includes(fallbackConfigPath)) {
      candidates.push(fallbackConfigPath);
    }
  }

  return candidates;
}

export function resolveConfigFilePath(options?: Record<string, unknown>): string {
  const candidates = getConfigFileCandidates(options);
  return candidates[0] ?? path.join(os.homedir(), ".config", "autogate", "config.json");
}

export function resolveConfigDir(options?: Record<string, unknown>): string {
  return path.dirname(resolveConfigFilePath(options));
}

export function resolveRuntimeDir(options?: Record<string, unknown>): string {
  return path.join(resolveConfigDir(options), "runtime");
}

export function resolveControlFilePath(options?: Record<string, unknown>): string {
  return path.join(resolveConfigDir(options), "control.json");
}

export function loadFileConfig(options?: Record<string, unknown>): Record<string, unknown> {
  const candidates = getConfigFileCandidates(options);
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
    (process.env.OPENCODE_CONFIG_DIR?.includes("opencode1") ||
    process.env.OPENCODE_CONFIG_DIR?.includes("opencode2")
      ? "4097"
      : undefined) ||
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
      : getDefaultClassifierModel();

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
    trustedDomains:
      optEnv.trustedDomains ??
      envTrustedDomains ??
      fileEnv.trustedDomains ??
      fileTrustedDomains ??
      [],
    trustedGitRemotes: optEnv.trustedGitRemotes ??
      envTrustedRemotes ??
      fileEnv.trustedGitRemotes ??
      fileTrustedRemotes ?? ["origin"],
    trustedPaths: optEnv.trustedPaths ??
      envTrustedPaths ??
      fileEnv.trustedPaths ??
      fileTrustedPaths ?? ["~/Projects"],
  };

  const parsedSystemOne = parseSystemOneConfig(fileConfig.systemOne, options?.systemOne, env);
  const systemOne: SystemOneConfig =
    options?.evaluator !== undefined && options?.systemOne === undefined
      ? { ...parsedSystemOne, enabled: false }
      : parsedSystemOne;

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
    systemOne,
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
