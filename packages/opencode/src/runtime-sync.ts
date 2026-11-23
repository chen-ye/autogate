import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import {
  AutoGateCoreEngine,
  isRecord,
  loadConfig,
  resolveConfigFilePath,
  resolveControlFilePath,
  resolveRuntimeDir,
  type AutoGateConfig,
} from "@autogate/core";

export interface InFlightEvaluation {
  id: string;
  sessionID: string;
  toolName: string;
  commandString?: string;
  stage: "evaluating" | "awaiting-review";
  startedAt: number;
}

export interface RuntimeVerdictSummary {
  timestamp: number;
  sessionID: string;
  toolName: string;
  commandString?: string;
  verdict: "ALLOW" | "BLOCK" | "UNSURE";
  riskLevel?: string;
  durationMs: number;
  reason: string;
  cached?: boolean;
  source?: string;
}

export interface OpenCodeRuntimeState {
  version: 1;
  pid: number;
  workspaceRoot: string;
  startedAt: number;
  updatedAt: number;
  autoMode: boolean;
  reviewFallbackMode: "ntfy" | "native";
  remoteReviewEnabled: boolean;
  consecutiveBlocks: number;
  consecutiveBlockThreshold: number;
  classifierModel: string;
  systemOneEnabled: boolean;
  systemOneMode?: string;
  evalLogFile: string;
  inFlight: InFlightEvaluation[];
  lastVerdict?: RuntimeVerdictSummary;
}

export interface OpenCodeRuntimeSyncOptions {
  engine: AutoGateCoreEngine;
  config: AutoGateConfig;
  workspaceRoot: string;
  options?: Record<string, unknown>;
  pid?: number;
}

function isErrnoException(err: unknown): err is NodeJS.ErrnoException {
  return typeof err === "object" && err !== null && "code" in err;
}

export class OpenCodeRuntimeSync {
  private readonly engine: AutoGateCoreEngine;
  private readonly config: AutoGateConfig;
  private readonly workspaceRoot: string;
  private readonly options?: Record<string, unknown>;
  private readonly pid: number;
  private readonly startedAt: number;
  private readonly configFilePath: string;
  private readonly controlFilePath: string;
  private readonly runtimeDir: string;
  private readonly stateFilePath: string;

  private started = false;
  private disposed = false;
  private lastConfigRaw: string | null = null;
  private lastControlRaw: string | null = null;
  private lastHandledResetAt = 0;

  private inFlight = new Map<string, InFlightEvaluation>();
  private lastVerdict?: RuntimeVerdictSummary;

  private configWatchListener?: (curr: fs.Stats, prev: fs.Stats) => void;
  private controlWatchListener?: (curr: fs.Stats, prev: fs.Stats) => void;

  constructor(opts: OpenCodeRuntimeSyncOptions) {
    this.engine = opts.engine;
    this.config = opts.config;
    this.workspaceRoot = opts.workspaceRoot;
    this.options = opts.options;
    this.pid = opts.pid ?? process.pid;
    this.startedAt = Date.now();

    this.configFilePath = resolveConfigFilePath(this.options);
    this.controlFilePath = resolveControlFilePath(this.options);
    this.runtimeDir = resolveRuntimeDir(this.options);

    const instanceHash = crypto
      .createHash("sha256")
      .update(`${this.pid}:${this.workspaceRoot}`)
      .digest("hex")
      .slice(0, 16);
    this.stateFilePath = path.join(this.runtimeDir, `opencode-${instanceHash}.json`);
  }

  public getStateFilePath(): string {
    return this.stateFilePath;
  }

  public start(): void {
    if (this.started && !this.disposed) {
      return;
    }
    this.disposed = false;
    this.started = true;

    this.lastConfigRaw = this.readFileText(this.configFilePath);
    this.lastControlRaw = this.readFileText(this.controlFilePath);
    this.lastHandledResetAt = this.readInitialResetTimestamp(this.lastControlRaw);

    this.configWatchListener = () => {
      if (!this.disposed) {
        this.syncControlAndConfig();
      }
    };
    this.controlWatchListener = () => {
      if (!this.disposed) {
        this.syncControlAndConfig();
      }
    };

    fs.watchFile(
      this.configFilePath,
      { persistent: false, interval: 1000 },
      this.configWatchListener,
    );
    fs.watchFile(
      this.controlFilePath,
      { persistent: false, interval: 1000 },
      this.controlWatchListener,
    );

    this.engine.setOnStateChange(() => {
      if (!this.disposed && this.syncInFlightStages()) {
        this.flush();
      }
    });

    this.flush();
  }

  public syncControlAndConfig(): void {
    if (this.disposed) {
      return;
    }

    let dirty = false;

    const configRaw = this.readFileText(this.configFilePath);
    if (configRaw !== this.lastConfigRaw) {
      this.lastConfigRaw = configRaw;
      if (this.applyConfigFileChanges()) {
        dirty = true;
      }
    }

    const controlRaw = this.readFileText(this.controlFilePath);
    if (controlRaw !== this.lastControlRaw) {
      this.lastControlRaw = controlRaw;
      if (controlRaw !== null && this.applyControlFileChanges(controlRaw)) {
        dirty = true;
      }
    }

    if (dirty) {
      this.flush();
    }
  }

  public beginEvaluation(entry: Omit<InFlightEvaluation, "stage">): void {
    if (this.disposed) {
      return;
    }
    const reviewIds = new Set(this.engine.getInFlightRequests().map((r) => r.id));
    this.inFlight.set(entry.id, {
      ...entry,
      stage: reviewIds.has(entry.id) ? "awaiting-review" : "evaluating",
    });
    this.flush();
  }

  public completeEvaluation(id: string, summary?: RuntimeVerdictSummary): void {
    if (this.disposed) {
      return;
    }
    const removed = this.inFlight.delete(id);
    if (summary) {
      this.lastVerdict = summary;
    }
    if (removed || summary) {
      this.flush();
    }
  }

  public markPermissionReplied(requestID?: string): void {
    if (this.disposed || !requestID) {
      return;
    }
    if (this.inFlight.delete(requestID)) {
      this.flush();
    }
  }

  public cleanupSession(sessionID: string): void {
    if (this.disposed || !sessionID) {
      return;
    }
    let changed = false;
    for (const [id, entry] of this.inFlight.entries()) {
      if (entry.sessionID === sessionID) {
        this.inFlight.delete(id);
        changed = true;
      }
    }
    if (changed) {
      this.flush();
    }
  }

  public flush(): void {
    if (this.disposed) {
      return;
    }

    this.syncInFlightStages();

    const state: OpenCodeRuntimeState = {
      version: 1,
      pid: this.pid,
      workspaceRoot: this.workspaceRoot,
      startedAt: this.startedAt,
      updatedAt: Date.now(),
      autoMode: this.engine.isEnabled(),
      reviewFallbackMode: this.engine.getFallbackMode(),
      remoteReviewEnabled: this.engine.isRemoteReviewEnabled(),
      consecutiveBlocks: this.engine.getConsecutiveBlocks(),
      consecutiveBlockThreshold: this.engine.getConsecutiveBlockThreshold(),
      classifierModel: this.config.classifierModel,
      systemOneEnabled: Boolean(this.config.systemOne?.enabled),
      ...(this.config.systemOne?.executionMode
        ? { systemOneMode: this.config.systemOne.executionMode }
        : {}),
      evalLogFile: this.config.evalLogFile ?? "",
      inFlight: Array.from(this.inFlight.values(), (item) => ({ ...item })),
      ...(this.lastVerdict ? { lastVerdict: { ...this.lastVerdict } } : {}),
    };

    const tmpPath = `${this.stateFilePath}.tmp.${process.pid}.${Math.random().toString(36).slice(2, 8)}`;
    try {
      fs.mkdirSync(this.runtimeDir, { recursive: true });
      fs.writeFileSync(tmpPath, JSON.stringify(state, null, 2) + "\n", "utf8");
      fs.renameSync(tmpPath, this.stateFilePath);
    } catch (err) {
      try {
        fs.rmSync(tmpPath, { force: true });
      } catch (cleanupErr) {
        console.warn(
          `[AutoGate] Failed to clean up temp runtime state file ${tmpPath}:`,
          cleanupErr,
        );
      }
      console.warn(`[AutoGate] Failed to write runtime state file (${this.stateFilePath}):`, err);
    }
  }

  public dispose(): void {
    if (this.disposed) {
      return;
    }
    this.disposed = true;
    this.started = false;
    this.engine.setOnStateChange(undefined);
    this.inFlight.clear();

    if (this.configWatchListener) {
      fs.unwatchFile(this.configFilePath, this.configWatchListener);
      this.configWatchListener = undefined;
    }
    if (this.controlWatchListener) {
      fs.unwatchFile(this.controlFilePath, this.controlWatchListener);
      this.controlWatchListener = undefined;
    }

    try {
      fs.rmSync(this.stateFilePath, { force: true });
    } catch (err) {
      console.warn(
        `[AutoGate] Failed to remove runtime state file on dispose (${this.stateFilePath}):`,
        err,
      );
    }
  }

  private syncInFlightStages(): boolean {
    if (this.inFlight.size === 0) {
      return false;
    }
    const reviewIds = new Set(this.engine.getInFlightRequests().map((r) => r.id));
    let changed = false;
    for (const [id, entry] of this.inFlight.entries()) {
      if (reviewIds.has(id) && entry.stage !== "awaiting-review") {
        entry.stage = "awaiting-review";
        changed = true;
      }
    }
    return changed;
  }

  private readFileText(filePath: string): string | null {
    try {
      return fs.readFileSync(filePath, "utf8");
    } catch (err: unknown) {
      if (isErrnoException(err) && err.code === "ENOENT") {
        return null;
      }
      console.warn(`[AutoGate] Failed to read ${filePath}:`, err);
      return null;
    }
  }

  private readInitialResetTimestamp(raw: string | null): number {
    if (raw === null) {
      return 0;
    }
    try {
      const parsed: unknown = JSON.parse(raw);
      if (
        isRecord(parsed) &&
        typeof parsed.resetCircuitBreakerAt === "number" &&
        Number.isFinite(parsed.resetCircuitBreakerAt)
      ) {
        return parsed.resetCircuitBreakerAt;
      }
    } catch (err) {
      console.warn(
        `[AutoGate] Failed to parse initial control file (${this.controlFilePath}):`,
        err,
      );
    }
    return 0;
  }

  private applyConfigFileChanges(): boolean {
    const reloaded = loadConfig(this.options);
    let updated = false;

    if (
      this.engine.isEnabled() !== reloaded.autoMode ||
      this.config.autoMode !== reloaded.autoMode
    ) {
      this.engine.setEnabled(reloaded.autoMode);
      this.config.autoMode = reloaded.autoMode;
      updated = true;
    }

    const nextFallback = reloaded.ntfyTopic ? (reloaded.reviewFallbackMode ?? "ntfy") : "native";
    const hasExplicitRemote = typeof this.options?.remoteReviewEnabled === "boolean";
    if (
      !hasExplicitRemote &&
      (this.engine.getFallbackMode() !== nextFallback ||
        this.config.reviewFallbackMode !== nextFallback)
    ) {
      this.engine.setFallbackMode(nextFallback);
      this.config.reviewFallbackMode = nextFallback;
      updated = true;
    }

    return updated;
  }

  private applyControlFileChanges(raw: string): boolean {
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch (err) {
      console.warn(
        `[AutoGate] Failed to parse control file during live sync (${this.controlFilePath}):`,
        err,
      );
      return false;
    }
    if (!isRecord(parsed)) {
      return false;
    }

    const resetTs = parsed.resetCircuitBreakerAt;
    if (
      typeof resetTs === "number" &&
      Number.isFinite(resetTs) &&
      resetTs > this.lastHandledResetAt
    ) {
      this.lastHandledResetAt = resetTs;
      this.engine.resetConsecutiveBlocks();
      return true;
    }

    return false;
  }
}
