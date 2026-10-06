import type {
  AutoGateConfig,
  NotifierAdapter,
  ReviewRequest,
  ReviewResponse,
  GateAction,
  GateDecision,
  GateEvaluator,
  ClassifierResult,
  ReviewFallbackMode,
  RiskLevel,
  UserAuthorization,
  PermissionEventData,
} from "./types";
import { sanitizeUserPrompt } from "./classifier";
import { formatNotificationTitle, formatNotificationBody } from "./formatters";

export const sharedRecentlyRejected = new Map<string, { timestamp: number; reason: string }>();
export const sharedExplicitEscalations = new Map<
  string,
  { timestamp: number; action: string; reason: string }
>();

export function sweepExpiredState(now = Date.now()): void {
  for (const [k, v] of sharedRecentlyRejected.entries()) {
    if (now - v.timestamp > 60000) sharedRecentlyRejected.delete(k);
  }
  for (const [k, v] of sharedExplicitEscalations.entries()) {
    if (now - v.timestamp > 60000) sharedExplicitEscalations.delete(k);
  }
}

export function recordEscalationIntent(sessionID: string, action: string, reason: string): void {
  sweepExpiredState();
  sharedExplicitEscalations.set(sessionID, {
    timestamp: Date.now(),
    action: action.trim(),
    reason: reason.trim(),
  });
}

function getRequestPermission(request: PermissionEventData | GateAction): string {
  if ("toolName" in request && typeof request.toolName === "string" && request.toolName) {
    return request.toolName;
  }
  if ("permission" in request && typeof request.permission === "string" && request.permission) {
    return request.permission;
  }
  if ("action" in request && typeof request.action === "string" && request.action) {
    return request.action;
  }
  return "";
}

function getRequestCommandString(
  request: PermissionEventData | GateAction,
  overrideCmd?: string,
): string {
  if (typeof overrideCmd === "string" && overrideCmd.trim().length > 0) {
    return overrideCmd.trim();
  }
  if (typeof request.commandString === "string" && request.commandString.trim().length > 0) {
    return request.commandString.trim();
  }
  const meta = request.metadata;
  if (meta && typeof meta === "object") {
    if (typeof meta.command === "string" && meta.command.trim().length > 0) {
      return meta.command.trim();
    }
    if (typeof meta.cmd === "string" && meta.cmd.trim().length > 0) {
      return meta.cmd.trim();
    }
    if (Array.isArray(meta.patterns) && meta.patterns.length > 0) {
      return meta.patterns.filter((p): p is string => typeof p === "string").join(" ");
    }
  }
  if ("resources" in request && Array.isArray(request.resources) && request.resources.length > 0) {
    return request.resources.filter((r): r is string => typeof r === "string").join(" ");
  }
  if ("patterns" in request && Array.isArray(request.patterns) && request.patterns.length > 0) {
    return request.patterns.filter((p): p is string => typeof p === "string").join(" ");
  }
  if ("rawArgs" in request && Array.isArray(request.rawArgs) && request.rawArgs.length > 0) {
    return request.rawArgs.filter((a): a is string => typeof a === "string").join(" ");
  }
  if (typeof request.targetPath === "string") {
    return request.targetPath.trim();
  }
  return "";
}

function getRequestSessionID(request: PermissionEventData | GateAction): string {
  return typeof request.sessionID === "string" ? request.sessionID : "";
}

function getRequestPatterns(request: PermissionEventData | GateAction): string {
  if ("patterns" in request && Array.isArray(request.patterns) && request.patterns.length > 0) {
    return request.patterns.map(String).join(",");
  }
  return getRequestCommandString(request);
}

export function getActionKey(request: PermissionEventData | GateAction): string {
  const perm = getRequestPermission(request);
  const patterns = getRequestPatterns(request);
  const sessionID = getRequestSessionID(request);
  return `${sessionID}:${perm}:${patterns}`;
}

function matchesAction(
  entryAction: string,
  request: PermissionEventData | GateAction,
  commandString: string,
): boolean {
  const normEntry = entryAction
    .trim()
    .replace(/^["']|["']$/g, "")
    .toLowerCase();
  if (!normEntry) return false;

  const normCmd = commandString.trim().toLowerCase();
  if (normCmd) {
    if (normCmd === normEntry || normCmd.includes(normEntry) || normEntry.includes(normCmd)) {
      return true;
    }
  }

  if ("patterns" in request && Array.isArray(request.patterns)) {
    for (const pat of request.patterns) {
      const normPat = String(pat)
        .trim()
        .replace(/^["']|["']$/g, "")
        .toLowerCase();
      if (normPat) {
        if (normPat === normEntry || normPat.includes(normEntry) || normEntry.includes(normPat)) {
          return true;
        }
      }
    }
  }

  const meta = request.metadata;
  const filepath =
    (typeof meta?.filepath === "string" ? meta.filepath : "") ||
    (typeof meta?.path === "string" ? meta.path : "") ||
    (typeof meta?.file === "string" ? meta.file : "");

  if (filepath) {
    const normFp = filepath
      .trim()
      .replace(/^["']|["']$/g, "")
      .toLowerCase();
    if (normFp === normEntry || normFp.includes(normEntry) || normEntry.includes(normFp)) {
      return true;
    }
  }

  return false;
}

export function checkAndConsumeEscalation(
  request: PermissionEventData | GateAction,
  parentSessionID?: string,
): string | null {
  sweepExpiredState();

  const perm = getRequestPermission(request);
  const commandString = getRequestCommandString(request);

  const isBash = perm === "bash" || perm === "shell:run" || perm === "shell";
  if (isBash && commandString.includes("AUTOGATE_ESCALATE=1")) {
    return "Escalated via AUTOGATE_ESCALATE=1 environment variable";
  }

  const sessionID = getRequestSessionID(request);
  const sessionCandidates = [sessionID, parentSessionID].filter(
    (s): s is string => typeof s === "string" && s.length > 0,
  );
  for (const sid of sessionCandidates) {
    const entry = sharedExplicitEscalations.get(sid);
    if (entry) {
      if (Date.now() - entry.timestamp > 60000) {
        sharedExplicitEscalations.delete(sid);
      } else if (matchesAction(entry.action, request, commandString)) {
        sharedExplicitEscalations.delete(sid);
        return entry.reason || "Manual review requested via escalate_permission tool";
      }
    }
  }

  const actionKey = getActionKey(request);
  const rejectedEntry = sharedRecentlyRejected.get(actionKey);
  if (rejectedEntry) {
    if (Date.now() - rejectedEntry.timestamp < 60000) {
      sharedRecentlyRejected.delete(actionKey);
      return rejectedEntry.reason
        ? `Re-attempted action within 60s after push-back: ${rejectedEntry.reason}`
        : "Re-attempted action within 60s of automated rejection";
    } else {
      sharedRecentlyRejected.delete(actionKey);
    }
  }

  if (parentSessionID && parentSessionID !== sessionID) {
    const parentPatterns =
      "patterns" in request && Array.isArray(request.patterns)
        ? request.patterns.map(String).join(",")
        : commandString;
    const parentActionKey = `${parentSessionID}:${perm}:${parentPatterns}`;
    const parentRejected = sharedRecentlyRejected.get(parentActionKey);
    if (parentRejected) {
      if (Date.now() - parentRejected.timestamp < 60000) {
        sharedRecentlyRejected.delete(parentActionKey);
        return parentRejected.reason
          ? `Re-attempted action within 60s after push-back: ${parentRejected.reason}`
          : "Re-attempted action within 60s of automated rejection";
      } else {
        sharedRecentlyRejected.delete(parentActionKey);
      }
    }
  }

  return null;
}

export function isTransformableAction(
  request: PermissionEventData | GateAction,
  commandString?: string,
): boolean {
  const cmd = getRequestCommandString(request, commandString);

  if (!cmd) return false;

  if (
    /^rm\s+(-[a-zA-Z]*r[a-zA-Z]*\s+)?\/(\s|$)/.test(cmd) ||
    cmd === "rm -rf /" ||
    cmd === "rm -rf /*"
  ) {
    return false;
  }

  const hasRm = cmd.includes("rm ") || /^rm(\s+|$)/i.test(cmd);
  const hasGitRestore = cmd.includes("git restore") && !cmd.includes("stash");
  const hasGitCheckout = cmd.includes("git checkout") && !cmd.includes("stash");

  return hasRm || hasGitRestore || hasGitCheckout;
}

export class DefaultGateEvaluator implements GateEvaluator {
  readonly name = "default-classifier";
  constructor(private config?: AutoGateConfig) {}
  async evaluate(action: GateAction): Promise<ClassifierResult> {
    return { verdict: "UNSURE", reason: "No evaluator configured on engine" };
  }
}

function createDummyAdapter(): NotifierAdapter {
  return {
    name: "dummy",
    async publish() {},
    async listen() {
      return () => {};
    },
    async updateStatus() {},
  };
}

export interface AutoGateEngineOptions {
  config: AutoGateConfig;
  adapter?: NotifierAdapter;
  evaluator?: GateEvaluator;
  workspaceRoot?: string;
  remoteReviewEnabled?: boolean;
}

export class AutoGateCoreEngine {
  private config: AutoGateConfig;
  private remoteAdapter: NotifierAdapter;
  private evaluator: GateEvaluator;
  private enabled: boolean;
  private userPrompt: string = "";
  private userPrompts = new Map<string, string>();
  private sessionParentCache = new Map<string, string>();
  private consecutiveBlocks: number = 0;
  private consecutiveBlockThreshold: number;
  private inFlightRequests = new Map<
    string,
    {
      resolve: (decision: GateDecision) => void;
      reject: (err: Error) => void;
      abort: AbortController;
      sessionID?: string;
      directory?: string;
      message?: string;
    }
  >();
  private turnDecisionCache = new Map<string, Set<string>>();
  private workspaceRoot?: string;
  private stopRemoteListen?: () => void;
  private reviewFallbackMode: ReviewFallbackMode = "ntfy";
  private remoteReviewEnabled: boolean = true;

  constructor(
    optionsOrConfig?: AutoGateEngineOptions | AutoGateConfig,
    remoteAdapter?: NotifierAdapter,
    evaluator?: GateEvaluator,
  ) {
    let remoteReviewOption: boolean | undefined;
    if (
      optionsOrConfig &&
      typeof optionsOrConfig === "object" &&
      !Array.isArray(optionsOrConfig) &&
      ("config" in optionsOrConfig ||
        "evaluator" in optionsOrConfig ||
        "adapter" in optionsOrConfig ||
        "remoteReviewEnabled" in optionsOrConfig)
    ) {
      const opts = optionsOrConfig as AutoGateEngineOptions;
      this.config = opts.config;
      this.remoteAdapter = opts.adapter ?? createDummyAdapter();
      this.evaluator = opts.evaluator ?? new DefaultGateEvaluator(opts.config);
      this.workspaceRoot = opts.workspaceRoot ?? this.config.environment?.trustedPaths?.[0];
      remoteReviewOption = opts.remoteReviewEnabled;
    } else {
      this.config = (optionsOrConfig as AutoGateConfig) || { autoMode: false };
      this.remoteAdapter = remoteAdapter ?? createDummyAdapter();
      this.evaluator = evaluator ?? new DefaultGateEvaluator(this.config);
    }
    this.workspaceRoot = this.workspaceRoot || this.config.environment?.trustedPaths?.[0];
    this.enabled = this.config.autoMode;
    this.consecutiveBlockThreshold = this.config.consecutiveBlockThreshold ?? 3;
    this.reviewFallbackMode = this.config.reviewFallbackMode ?? "ntfy";
    if (remoteReviewOption !== undefined) {
      this.remoteReviewEnabled = remoteReviewOption;
      this.reviewFallbackMode = remoteReviewOption ? "ntfy" : "native";
    } else if (this.config?.reviewFallbackMode === "native") {
      this.remoteReviewEnabled = false;
      this.reviewFallbackMode = "native";
    } else {
      this.remoteReviewEnabled = true;
    }
  }

  public isRemoteReviewEnabled(): boolean {
    return this.remoteReviewEnabled;
  }

  public setRemoteReviewEnabled(enabled: boolean): void {
    this.remoteReviewEnabled = enabled;
    this.reviewFallbackMode = enabled ? "ntfy" : "native";
  }

  public getFallbackMode(): ReviewFallbackMode {
    return this.reviewFallbackMode;
  }

  public setFallbackMode(mode: ReviewFallbackMode): void {
    this.reviewFallbackMode = mode;
    if (mode === "native") {
      this.setRemoteReviewEnabled(false);
    } else {
      this.setRemoteReviewEnabled(true);
    }
  }

  public setUserPrompt(prompt: string): void;
  public setUserPrompt(sessionID: string, prompt: string): void;
  public setUserPrompt(promptOrSession: string, promptText?: string): void {
    const text = typeof promptText === "string" ? promptText : promptOrSession;
    const isSlashCommand = /<auto-slash-command[^>]*>/i.test(text);
    if (
      text.includes("## Environment Trust Boundaries:") ||
      text.includes("## Context:") ||
      text.includes("### Conversation Transcript") ||
      text.startsWith("[auto-gate-eval]") ||
      text.includes("[SYSTEM DIRECTIVE:") ||
      text.includes("[restore checkpointed") ||
      (text.includes("<!-- OMO_INTERNAL") && !isSlashCommand)
    ) {
      return;
    }
    const sanitizedText = sanitizeUserPrompt(text);
    if (typeof promptText === "string") {
      this.userPrompts.set(promptOrSession, sanitizedText);
      if (!this.userPrompt) {
        this.userPrompt = sanitizedText;
      }
    } else {
      this.userPrompt = sanitizedText;
    }
  }

  public setSessionParent(sessionID: string, parentID: string): void {
    this.sessionParentCache.set(sessionID, parentID);
  }

  public getUserPrompt(sessionID?: string): string {
    if (sessionID && this.userPrompts.has(sessionID)) {
      return this.userPrompts.get(sessionID)!;
    }
    if (sessionID && this.sessionParentCache.has(sessionID)) {
      let curr: string | undefined = sessionID;
      const visited = new Set<string>([sessionID]);
      while (curr && this.sessionParentCache.has(curr)) {
        const parentID: string | undefined = this.sessionParentCache.get(curr);
        if (!parentID || visited.has(parentID)) break;
        visited.add(parentID);
        if (this.userPrompts.has(parentID)) {
          return this.userPrompts.get(parentID)!;
        }
        curr = parentID;
      }
    }
    if (sessionID) {
      return "";
    }
    return this.userPrompt;
  }

  public setEnabled(enabled: boolean): void {
    this.enabled = enabled;
  }

  public isEnabled(): boolean {
    return this.enabled;
  }

  public getConsecutiveBlocks(): number {
    return this.consecutiveBlocks;
  }

  public resetConsecutiveBlocks(): void {
    this.consecutiveBlocks = 0;
  }

  public clearTurnCache(sessionID: string): void {
    this.turnDecisionCache.delete(sessionID);
  }

  public checkAndConsumeEscalation(request: PermissionEventData | GateAction): string | null {
    const parentSessionID = request.sessionID
      ? this.sessionParentCache.get(request.sessionID)
      : undefined;
    return checkAndConsumeEscalation(request, parentSessionID);
  }

  public recordEscalationIntent(sessionID: string, action: string, reason: string): void {
    recordEscalationIntent(sessionID, action, reason);
  }

  public async start(): Promise<(() => void) | undefined> {
    if (this.stopRemoteListen) {
      this.stopRemoteListen();
    }
    this.stopRemoteListen = await this.remoteAdapter.listen(async (resp) => {
      this.resolveReviewResponse(resp);
    });
    return this.stopRemoteListen;
  }

  public async stop(): Promise<void> {
    if (this.stopRemoteListen) {
      this.stopRemoteListen();
      this.stopRemoteListen = undefined;
    }
    for (const entry of this.inFlightRequests.values()) {
      entry.abort.abort();
    }
    this.inFlightRequests.clear();
    this.turnDecisionCache.clear();
    sharedRecentlyRejected.clear();
    sharedExplicitEscalations.clear();
  }

  public async evaluate(action: GateAction): Promise<GateDecision> {
    if (action.signal?.aborted) {
      return {
        verdict: "BLOCK",
        reason: "Action evaluation aborted by signal",
      };
    }
    // 1. Checks disabled state -> requests review if disabled.
    if (!this.isEnabled()) {
      if (!this.remoteReviewEnabled) {
        return { verdict: "UNSURE", reason: "AutoMode is disabled (local harness fallback)" };
      }
      return this.requestReview(action, "AutoMode is disabled", false, undefined, undefined);
    }

    // 2. Checks circuit breaker (`consecutiveBlocks >= threshold`) -> requests review.
    const threshold = this.consecutiveBlockThreshold;
    if (this.consecutiveBlocks >= threshold) {
      const reason = `Circuit breaker tripped: consecutive blocks (${this.consecutiveBlocks}) reached threshold (${threshold}).`;
      if (!this.remoteReviewEnabled) {
        return { verdict: "UNSURE", reason };
      }
      return this.requestReview(action, reason, true);
    }

    // 3. Checks explicit escalation (`checkAndConsumeEscalation`) -> requests review.
    const parentSessionID = action.sessionID
      ? this.sessionParentCache.get(action.sessionID)
      : undefined;
    const escalationReason = checkAndConsumeEscalation(action, parentSessionID);
    if (escalationReason) {
      if (!this.remoteReviewEnabled) {
        return { verdict: "UNSURE", reason: escalationReason };
      }
      return this.requestReview(action, escalationReason, false, undefined, undefined);
    }

    // 4. Checks turn decision cache -> returns cached ALLOW if found.
    const sid = action.sessionID || "";
    const commandString =
      action.commandString ||
      (typeof action.metadata?.command === "string" ? action.metadata.command : "") ||
      (Array.isArray(action.metadata?.patterns)
        ? action.metadata.patterns.filter((p): p is string => typeof p === "string").join(" ")
        : "") ||
      (Array.isArray(action.rawArgs)
        ? action.rawArgs.filter((a): a is string => typeof a === "string").join(" ")
        : "");
    const actionKey = `${action.toolName}:${commandString || action.targetPath || JSON.stringify(action.rawArgs || "")}`;

    if (this.turnDecisionCache.get(sid)?.has(actionKey)) {
      return {
        verdict: "ALLOW",
        reason: "Cached turn decision",
        cached: true,
      };
    }

    // Resolve prompts if not already populated on action
    if (!action.userPrompt) {
      const fallbackPrompt =
        (action.sessionID ? this.userPrompts.get(action.sessionID) : undefined) ||
        this.userPrompt ||
        "";
      action.userPrompt = sanitizeUserPrompt(fallbackPrompt);
    }

    // 5. Calls `this.evaluator.evaluate(action)`.
    let verdictResult: ClassifierResult;
    try {
      verdictResult = await this.evaluator.evaluate(action);
    } catch (err) {
      verdictResult = { verdict: "UNSURE", reason: `Classifier error: ${err}` };
    }

    // 6. Handle verdict with compile-time exhaustiveness checking.
    switch (verdictResult.verdict) {
      case "ALLOW": {
        let sessionCache = this.turnDecisionCache.get(sid);
        if (!sessionCache) {
          sessionCache = new Set();
          this.turnDecisionCache.set(sid, sessionCache);
        }
        sessionCache.add(actionKey);
        this.resetConsecutiveBlocks();
        if (this.config.notifyOnVerdict !== false) {
          this.sendInformationalNotification(
            action,
            "ALLOW",
            verdictResult.reason,
            verdictResult.risk_level,
            verdictResult.user_authorization,
          ).catch(() => {});
        }
        return {
          verdict: "ALLOW",
          riskLevel: verdictResult.risk_level,
          userAuthorization: verdictResult.user_authorization,
          reason: verdictResult.reason || "Allowed by AutoGate classifier policy",
          cached: false,
        };
      }
      case "BLOCK": {
        this.consecutiveBlocks++;
        const baseReason = verdictResult.reason || "Blocked by AutoGate classifier policy";
        const regActionKey = getActionKey(action);
        sweepExpiredState();

        let message = baseReason;
        if (isTransformableAction(action, commandString)) {
          message = `[SAFE_TRANSFORM_REJECT]: ${baseReason}. Safe alternative: use 'npx trash-cli' instead of permanent 'rm', or 'git stash' before checkout/restore. To insist on manual review, call 'escalate_permission' tool, use AUTOGATE_ESCALATE=1 (for shell), or re-issue the exact action within 60s.`;
        }

        sharedRecentlyRejected.set(regActionKey, {
          timestamp: Date.now(),
          reason: message,
        });

        if (this.config.notifyOnVerdict !== false) {
          this.sendInformationalNotification(
            action,
            "BLOCK",
            message,
            verdictResult.risk_level,
            verdictResult.user_authorization,
          ).catch(() => {});
        }

        return {
          verdict: "BLOCK",
          riskLevel: verdictResult.risk_level,
          userAuthorization: verdictResult.user_authorization,
          reason: message,
          safeTransformAlternative: isTransformableAction(action, commandString)
            ? message
            : undefined,
        };
      }
      case "UNSURE": {
        if (!this.remoteReviewEnabled) {
          return {
            verdict: "UNSURE",
            reason: verdictResult.reason || "Manual review required (local harness fallback)",
            riskLevel: verdictResult.risk_level,
            userAuthorization: verdictResult.user_authorization,
          };
        }
        return this.requestReview(
          action,
          verdictResult.reason,
          false,
          verdictResult.risk_level,
          verdictResult.user_authorization,
        );
      }
      default: {
        const _exhaustive: never = verdictResult;
        return _exhaustive;
      }
    }
  }

  public async requestReview(
    action: GateAction,
    reason?: string,
    isCircuitBreaker?: boolean,
    riskLevel?: RiskLevel,
    userAuth?: UserAuthorization,
  ): Promise<GateDecision> {
    if (action.signal?.aborted) {
      return {
        verdict: "BLOCK",
        reason: "Review request aborted by signal",
      };
    }

    if (!this.stopRemoteListen) {
      await this.start();
    }
    const messageBody = formatNotificationBody({
      target: action.commandString
        ? [action.commandString]
        : action.targetPath
          ? [action.targetPath]
          : action.rawArgs
            ? [String(action.rawArgs)]
            : action.toolName,
      reason,
      warning: isCircuitBreaker
        ? `Consecutive block threshold (${this.consecutiveBlocks} >= ${this.config.consecutiveBlockThreshold ?? 3}) reached.`
        : undefined,
      risk_level: riskLevel,
      user_authorization: userAuth,
      verbosity: this.config.ntfyVerbosity,
      toolName: action.toolName,
      workspaceRoot: action.workspaceRoot,
      sessionID: action.sessionID,
      rawArgs: action.rawArgs,
      userPrompt: action.userPrompt,
      subagentPrompt: action.subagentPrompt,
      reasoning: action.metadata?.reasoning as string | undefined,
      environment: action.environment || this.config.environment,
    });
    const payload: ReviewRequest = {
      id: action.id,
      title: formatNotificationTitle(
        isCircuitBreaker ? "CIRCUIT BREAKER" : "REVIEW",
        action.toolName,
      ),
      message: messageBody,
      priority: isCircuitBreaker ? "urgent" : "high",
      tags: isCircuitBreaker ? ["rotating_light", "warning", "lock"] : ["lock", "robot"],
      actions: [
        { id: "approve-once", label: "Approve", reply: "once" },
        { id: "approve-always", label: "Always Approve", reply: "always" },
        { id: "deny", label: "Deny", reply: "reject" },
      ],
    };

    const abortController = new AbortController();
    let timeoutTimer: NodeJS.Timeout | undefined = undefined;

    let onAbort: (() => void) | undefined = undefined;
    const decisionPromise = new Promise<GateDecision>((resolve, reject) => {
      this.inFlightRequests.set(action.id, {
        resolve,
        reject,
        abort: abortController,
        sessionID: action.sessionID,
        directory: action.workspaceRoot || this.workspaceRoot,
        message: messageBody,
      });

      if (action.signal) {
        onAbort = () => {
          if (timeoutTimer) clearTimeout(timeoutTimer);
          const entry = this.inFlightRequests.get(action.id);
          if (entry) {
            this.inFlightRequests.delete(action.id);
            entry.abort.abort();
          }
          resolve({
            verdict: "BLOCK",
            reason: "Review request aborted by signal",
          });
        };
        if (action.signal.aborted) {
          onAbort();
        } else {
          action.signal.addEventListener("abort", onAbort, { once: true });
        }
      }
    });

    decisionPromise
      .finally(() => {
        if (action.signal && onAbort) {
          action.signal.removeEventListener("abort", onAbort);
        }
      })
      .catch(() => {});

    try {
      await this.remoteAdapter.publish(payload, abortController.signal);
    } catch (err: unknown) {
      if (abortController.signal.aborted || (err instanceof Error && err.name === "AbortError")) {
        if (timeoutTimer) clearTimeout(timeoutTimer);
        this.inFlightRequests.delete(action.id);
        return {
          verdict: "BLOCK",
          reason: "Review request aborted",
        };
      }
      console.error("Failed to publish notification to remote adapter:", err);
    }

    const timeoutMs = this.config.reviewTimeout ?? 300000;
    const timeoutPromise = new Promise<GateDecision>((resolve) => {
      timeoutTimer = setTimeout(() => {
        const entry = this.inFlightRequests.get(action.id);
        if (entry) {
          this.inFlightRequests.delete(action.id);
          entry.abort.abort();
          resolve({
            verdict: "BLOCK",
            reason: `Review request timed out after ${Math.round(timeoutMs / 1000)} seconds`,
          });
        }
      }, timeoutMs);
    });

    const finalDecision = await Promise.race([decisionPromise, timeoutPromise]);
    if (timeoutTimer) clearTimeout(timeoutTimer);
    return finalDecision;
  }

  public resolveReviewResponse(resp: ReviewResponse): void {
    const reqID = resp.req_id ?? resp.id;
    if (!reqID) return;

    const entry = this.inFlightRequests.get(reqID);
    if (entry) {
      entry.abort.abort();
      this.inFlightRequests.delete(reqID);
      const preserveBody =
        this.config.ntfyVerbosity === "verbose" ? entry.message : undefined;
      this.remoteAdapter
        .updateStatus(
          reqID,
          `✅ Answered Remotely (${resp.reply})`,
          `Permission request was answered remotely via ${resp.source ?? "ntfy"}.`,
          preserveBody,
        )
        .catch(() => {});

      if (resp.reply === "once" || resp.reply === "always") {
        this.resetConsecutiveBlocks();
      }

      if (resp.reply === "reject") {
        entry.resolve({
          verdict: "BLOCK",
          reply: "reject",
          reason: `Answered remotely via reject`,
        });
      } else {
        entry.resolve({
          verdict: "ALLOW",
          reply: resp.reply,
          reason: `Answered remotely via ${resp.reply}`,
        });
      }
    }
  }

  public handlePermissionReplied(data: { requestID?: string; id?: string; reply?: string }): void {
    const reqID = data.requestID ?? data.id;
    if (!reqID) return;
    const entry = this.inFlightRequests.get(reqID);
    if (entry) {
      entry.abort.abort();
      this.inFlightRequests.delete(reqID);
      const preserveBody =
        this.config.ntfyVerbosity === "verbose" ? entry.message : undefined;
      this.remoteAdapter
        .updateStatus(
          reqID,
          "✅ Answered in Terminal",
          "Permission request was answered locally in the terminal.",
          preserveBody,
        )
        .catch(() => {});
    }
  }

  public async handleRemoteResponse(resp: ReviewResponse): Promise<void> {
    this.resolveReviewResponse(resp);
  }

  private async sendInformationalNotification(
    action: GateAction,
    verdict: "ALLOW" | "BLOCK",
    reason?: string,
    riskLevel?: RiskLevel,
    userAuth?: UserAuthorization,
  ): Promise<void> {
    const payload: ReviewRequest = {
      id: action.id,
      title: formatNotificationTitle(verdict, action.toolName),
      message: formatNotificationBody({
        target: action.commandString
          ? [action.commandString]
          : action.targetPath
            ? [action.targetPath]
            : action.rawArgs
              ? [String(action.rawArgs)]
              : action.toolName,
        reason,
        risk_level: riskLevel,
        user_authorization: userAuth,
        verbosity: this.config.ntfyVerbosity,
        toolName: action.toolName,
        workspaceRoot: action.workspaceRoot,
        sessionID: action.sessionID,
        rawArgs: action.rawArgs,
        userPrompt: action.userPrompt,
        subagentPrompt: action.subagentPrompt,
        reasoning: action.metadata?.reasoning as string | undefined,
        environment: action.environment || this.config.environment,
      }),
      priority: verdict === "ALLOW" ? "low" : "default",
      tags: verdict === "ALLOW" ? ["white_check_mark"] : ["octagonal_sign"],
      actions: undefined,
    };

    try {
      await this.remoteAdapter.publish(payload, AbortSignal.timeout(3000));
    } catch {
      // Silently swallow informational notification errors
    }
  }
}

export const AutoGateEngine = AutoGateCoreEngine;
