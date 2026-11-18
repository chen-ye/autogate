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
  CascadeTrace,
  ContextFingerprint,
} from "./types";
import { sanitizeUserPrompt } from "./classifier";
import { formatNotificationTitle, formatNotificationBody } from "./formatters";
import { CascadeEvaluator, computeContextFingerprint } from "./cascade";
import { SystemOneEvaluator, createConfiguredEvaluator } from "./system-one";

export interface ExplicitEscalationEntry {
  timestamp: number;
  action: string;
  reason: string;
}

export const sharedRecentlyRejected = new Map<string, { timestamp: number; reason: string }>();
export const sharedExplicitEscalations = new Map<string, ExplicitEscalationEntry[]>();

export function sweepExpiredState(now = Date.now()): void {
  for (const [k, v] of sharedRecentlyRejected.entries()) {
    if (now - v.timestamp > 60000) sharedRecentlyRejected.delete(k);
  }
  for (const [k, entries] of sharedExplicitEscalations.entries()) {
    const active = entries.filter((v) => now - v.timestamp <= 60000);
    if (active.length === 0) {
      sharedExplicitEscalations.delete(k);
    } else if (active.length !== entries.length) {
      sharedExplicitEscalations.set(k, active);
    }
  }
}

function normalizeEscalationText(value: string): string {
  let result = value.trim();
  while (
    result.length >= 2 &&
    ((result.startsWith('"') && result.endsWith('"')) ||
      (result.startsWith("'") && result.endsWith("'")))
  ) {
    result = result.slice(1, -1).trim();
  }
  return result.toLowerCase();
}

export function recordEscalationIntent(sessionID: string, action: string, reason: string): boolean {
  sweepExpiredState();
  const trimmedSessionID = sessionID.trim();
  const trimmedAction = action.trim();
  const trimmedReason = reason.trim();
  const normAction = normalizeEscalationText(trimmedAction);
  if (!trimmedSessionID || !normAction) {
    return false;
  }
  const existing = sharedExplicitEscalations.get(trimmedSessionID) ?? [];
  const filtered = existing.filter((entry) => normalizeEscalationText(entry.action) !== normAction);
  filtered.push({
    timestamp: Date.now(),
    action: trimmedAction,
    reason: trimmedReason,
  });
  sharedExplicitEscalations.set(trimmedSessionID, filtered);
  return true;
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

function hasShellCompoundOperators(value: string): boolean {
  return /[;&|`\r\n<>]|\$\(/.test(value);
}

function isSinglePathToken(value: string): boolean {
  if (
    value.length === 0 ||
    value === "/" ||
    value === "./" ||
    value === "../" ||
    value === "~/" ||
    /\s/.test(value) ||
    hasShellCompoundOperators(value)
  ) {
    return false;
  }
  return (
    value.startsWith("/") ||
    value.startsWith("./") ||
    value.startsWith("../") ||
    value.startsWith("~/")
  );
}

function buildEntryVariants(normEntry: string, toolName: string): string[] {
  const variants = [normEntry];
  const toolLower = toolName.trim().toLowerCase();
  if (toolLower) {
    for (const prefix of [`${toolLower} `, `${toolLower}: `]) {
      if (normEntry.startsWith(prefix)) {
        const stripped = normalizeEscalationText(normEntry.slice(prefix.length));
        if (stripped && !variants.includes(stripped)) {
          variants.push(stripped);
        }
      }
    }
  }
  return variants;
}

function matchesExactOrCommandPath(
  entryVariants: string[],
  candidate: unknown,
  allowCommandTokenMatch: boolean,
): boolean {
  if (typeof candidate !== "string") return false;
  const normCand = normalizeEscalationText(candidate);
  if (!normCand) return false;
  if (entryVariants.includes(normCand)) {
    return true;
  }
  if (allowCommandTokenMatch && !hasShellCompoundOperators(normCand)) {
    const tokens = normCand.split(/\s+/);
    if (entryVariants.some((ev) => isSinglePathToken(ev) && tokens.includes(ev))) {
      return true;
    }
  }
  return false;
}

function collectNonEmptyStringItems(val: unknown): string[] | undefined {
  if (!Array.isArray(val)) return undefined;
  const items = val.filter(
    (item): item is string => typeof item === "string" && normalizeEscalationText(item).length > 0,
  );
  return items.length > 0 ? items : undefined;
}

function listIsCovered(entryVariants: string[], items: string[]): boolean {
  const normJoined = normalizeEscalationText(items.join(" "));
  if (normJoined && entryVariants.includes(normJoined)) {
    return true;
  }
  return items.every((item) => matchesExactOrCommandPath(entryVariants, item, false));
}

function matchesAction(
  entryAction: string,
  request: PermissionEventData | GateAction,
  commandString: string,
): boolean {
  const normEntry = normalizeEscalationText(entryAction);
  if (!normEntry) return false;

  const entryVariants = buildEntryVariants(normEntry, getRequestPermission(request));
  const meta = request.metadata;

  // Exact full-command match takes precedence even when OpenCode splits a compound
  // command (e.g. "cd app && rm -rf dist") into per-subcommand patterns[].
  for (const fullCmd of [commandString, meta?.command, meta?.cmd]) {
    if (matchesExactOrCommandPath(entryVariants, fullCmd, false)) {
      return true;
    }
  }

  const patternsList =
    "patterns" in request ? collectNonEmptyStringItems(request.patterns) : undefined;
  const resourcesList =
    "resources" in request ? collectNonEmptyStringItems(request.resources) : undefined;
  const rawArgsList =
    "rawArgs" in request ? collectNonEmptyStringItems(request.rawArgs) : undefined;

  // Reject multi-resource requests unless every resource/pattern is covered by the escalation entry.
  for (const list of [patternsList, resourcesList, rawArgsList]) {
    if (list && list.length > 1 && !listIsCovered(entryVariants, list)) {
      return false;
    }
  }

  if (matchesExactOrCommandPath(entryVariants, commandString, true)) {
    return true;
  }

  if (
    "targetPath" in request &&
    matchesExactOrCommandPath(entryVariants, request.targetPath, false)
  ) {
    return true;
  }

  if (patternsList && listIsCovered(entryVariants, patternsList)) {
    return true;
  }

  if (resourcesList && listIsCovered(entryVariants, resourcesList)) {
    return true;
  }

  for (const field of [meta?.filepath, meta?.path, meta?.file]) {
    if (matchesExactOrCommandPath(entryVariants, field, false)) {
      return true;
    }
  }
  for (const field of [meta?.command, meta?.cmd]) {
    if (matchesExactOrCommandPath(entryVariants, field, true)) {
      return true;
    }
  }

  if ("rawArgs" in request && request.rawArgs !== undefined) {
    const rawArgs = request.rawArgs;
    if (typeof rawArgs === "string" && matchesExactOrCommandPath(entryVariants, rawArgs, true)) {
      return true;
    }
    if (rawArgsList && listIsCovered(entryVariants, rawArgsList)) {
      return true;
    }
    if (rawArgs && !Array.isArray(rawArgs) && typeof rawArgs === "object") {
      const rec = rawArgs as Record<string, unknown>;
      for (const field of [rec.filepath, rec.path, rec.file]) {
        if (matchesExactOrCommandPath(entryVariants, field, false)) {
          return true;
        }
      }
      for (const field of [rec.command, rec.cmd]) {
        if (matchesExactOrCommandPath(entryVariants, field, true)) {
          return true;
        }
      }
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

  const now = Date.now();
  const sessionID = getRequestSessionID(request);
  const sessionCandidates = Array.from(
    new Set(
      [sessionID, parentSessionID].filter(
        (s): s is string => typeof s === "string" && s.length > 0,
      ),
    ),
  );
  for (const sid of sessionCandidates) {
    const entries = sharedExplicitEscalations.get(sid);
    if (!entries || entries.length === 0) continue;

    const active = entries.filter((entry) => now - entry.timestamp <= 60000);
    const matchIdx = active.findIndex((entry) =>
      matchesAction(entry.action, request, commandString),
    );
    if (matchIdx !== -1) {
      const [matched] = active.splice(matchIdx, 1);
      if (active.length === 0) {
        sharedExplicitEscalations.delete(sid);
      } else {
        sharedExplicitEscalations.set(sid, active);
      }
      return matched.reason || "Manual review requested via escalate_permission tool";
    }
    if (active.length === 0) {
      sharedExplicitEscalations.delete(sid);
    } else if (active.length !== entries.length) {
      sharedExplicitEscalations.set(sid, active);
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

function resolveNotificationTarget(action: GateAction): string | string[] {
  if (action.commandString) {
    return [action.commandString];
  }
  if (action.targetPath) {
    return [action.targetPath];
  }
  if (Array.isArray(action.patterns) && action.patterns.length > 0) {
    return action.patterns;
  }
  if (action.rawArgs !== undefined) {
    if (Array.isArray(action.rawArgs)) {
      const items = action.rawArgs.filter(
        (v): v is string => typeof v === "string" && v.length > 0,
      );
      if (items.length > 0) return items;
    }
    return [String(action.rawArgs)];
  }
  return action.toolName;
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
  onStateChange?: () => void;
}

export class AutoGateCoreEngine {
  private config: AutoGateConfig;
  private remoteAdapter: NotifierAdapter;
  private hasRemoteAdapter: boolean;
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
  private onStateChange?: () => void;

  constructor(
    optionsOrConfig?: AutoGateEngineOptions | AutoGateConfig,
    remoteAdapter?: NotifierAdapter,
    evaluator?: GateEvaluator,
  ) {
    let remoteReviewOption: boolean | undefined;
    let baseEvaluator: GateEvaluator;
    if (
      optionsOrConfig &&
      typeof optionsOrConfig === "object" &&
      !Array.isArray(optionsOrConfig) &&
      ("config" in optionsOrConfig ||
        "evaluator" in optionsOrConfig ||
        "adapter" in optionsOrConfig ||
        "remoteReviewEnabled" in optionsOrConfig ||
        "onStateChange" in optionsOrConfig)
    ) {
      const opts = optionsOrConfig as AutoGateEngineOptions;
      this.config = opts.config;
      this.hasRemoteAdapter = Boolean(opts.adapter);
      this.remoteAdapter = opts.adapter ?? createDummyAdapter();
      baseEvaluator = opts.evaluator ?? new DefaultGateEvaluator(opts.config);
      this.workspaceRoot = opts.workspaceRoot ?? this.config.environment?.trustedPaths?.[0];
      remoteReviewOption = opts.remoteReviewEnabled;
      this.onStateChange = opts.onStateChange;
    } else {
      this.config = (optionsOrConfig as AutoGateConfig) || { autoMode: false };
      this.hasRemoteAdapter = Boolean(remoteAdapter);
      this.remoteAdapter = remoteAdapter ?? createDummyAdapter();
      baseEvaluator = evaluator ?? new DefaultGateEvaluator(this.config);
    }
    this.evaluator =
      this.config.systemOne?.enabled &&
      !(baseEvaluator instanceof CascadeEvaluator) &&
      !(baseEvaluator instanceof SystemOneEvaluator)
        ? createConfiguredEvaluator(this.config, baseEvaluator, {
            getContextFingerprint: (act) => this.computeActionFingerprint(act),
            refreshAction: (act) => this.refreshActionContext(act),
          })
        : baseEvaluator;
    this.workspaceRoot = this.workspaceRoot || this.config.environment?.trustedPaths?.[0];
    this.enabled = this.config.autoMode;
    this.consecutiveBlockThreshold = this.config.consecutiveBlockThreshold ?? 3;
    this.reviewFallbackMode = this.config.reviewFallbackMode ?? "ntfy";
    if (remoteReviewOption !== undefined) {
      this.remoteReviewEnabled = remoteReviewOption;
      this.reviewFallbackMode = remoteReviewOption ? "ntfy" : "native";
    } else if (!this.hasRemoteAdapter || this.config?.reviewFallbackMode === "native") {
      this.remoteReviewEnabled = false;
      this.reviewFallbackMode = "native";
    } else {
      this.remoteReviewEnabled = true;
    }
  }

  public setOnStateChange(cb?: () => void): void {
    this.onStateChange = cb;
  }

  private computeActionFingerprint(action: GateAction): ContextFingerprint {
    const latestSessionPrompt = this.getUserPrompt(action.sessionID || undefined);
    const promptMaterial = latestSessionPrompt
      ? `${action.userPrompt}\n::session::${latestSessionPrompt}`
      : action.userPrompt;
    return computeContextFingerprint(promptMaterial, action.environment);
  }

  private refreshActionContext(action: GateAction): GateAction {
    const latestPrompt = this.getUserPrompt(action.sessionID || undefined);
    return {
      ...action,
      userPrompt: latestPrompt || action.userPrompt,
    };
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

  public getConsecutiveBlockThreshold(): number {
    return this.consecutiveBlockThreshold;
  }

  public getInFlightRequests(): Array<{ id: string; sessionID?: string; directory?: string }> {
    return Array.from(this.inFlightRequests.entries(), ([id, entry]) => ({
      id,
      ...(entry.sessionID !== undefined ? { sessionID: entry.sessionID } : {}),
      ...(entry.directory !== undefined ? { directory: entry.directory } : {}),
    }));
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

  public recordEscalationIntent(sessionID: string, action: string, reason: string): boolean {
    return recordEscalationIntent(sessionID, action, reason);
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
    const patternsString =
      Array.isArray(action.patterns) && action.patterns.length > 0
        ? action.patterns.filter((p): p is string => typeof p === "string").join(" ")
        : Array.isArray(action.metadata?.patterns)
          ? action.metadata.patterns.filter((p): p is string => typeof p === "string").join(" ")
          : "";
    const commandString =
      action.commandString ||
      (typeof action.metadata?.command === "string" ? action.metadata.command : "") ||
      patternsString ||
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

    // Resolve prompts & environment if not already populated on action
    if (!action.userPrompt) {
      const fallbackPrompt =
        (action.sessionID ? this.userPrompts.get(action.sessionID) : undefined) ||
        this.userPrompt ||
        "";
      action.userPrompt = sanitizeUserPrompt(fallbackPrompt);
    }
    if (!action.environment && this.config.environment) {
      action.environment = this.config.environment;
    }

    // 5. Calls `this.evaluator.evaluate(action)`.
    let verdictResult: ClassifierResult;
    try {
      verdictResult = await this.evaluator.evaluate(action);
    } catch (err) {
      verdictResult = { verdict: "UNSURE", reason: `Classifier error: ${err}` };
    }

    if (action.signal?.aborted) {
      return {
        verdict: "BLOCK",
        reason: "Action evaluation aborted by signal",
      };
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
            verdictResult.cascade,
          ).catch(() => {});
        }
        return {
          verdict: "ALLOW",
          riskLevel: verdictResult.risk_level,
          userAuthorization: verdictResult.user_authorization,
          reason: verdictResult.reason || "Allowed by AutoGate classifier policy",
          cached: false,
          ...(verdictResult.cascade ? { cascade: verdictResult.cascade } : {}),
          ...(verdictResult.metadata ? { metadata: verdictResult.metadata } : {}),
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
            verdictResult.cascade,
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
          ...(verdictResult.cascade ? { cascade: verdictResult.cascade } : {}),
          ...(verdictResult.metadata ? { metadata: verdictResult.metadata } : {}),
        };
      }
      case "UNSURE": {
        if (!this.remoteReviewEnabled) {
          return {
            verdict: "UNSURE",
            reason: verdictResult.reason || "Manual review required (local harness fallback)",
            riskLevel: verdictResult.risk_level,
            userAuthorization: verdictResult.user_authorization,
            ...(verdictResult.cascade ? { cascade: verdictResult.cascade } : {}),
            ...(verdictResult.metadata ? { metadata: verdictResult.metadata } : {}),
          };
        }
        return this.requestReview(
          action,
          verdictResult.reason,
          false,
          verdictResult.risk_level,
          verdictResult.user_authorization,
          verdictResult.cascade,
          verdictResult.metadata,
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
    cascade?: CascadeTrace,
    metadata?: Record<string, unknown>,
  ): Promise<GateDecision> {
    if (action.signal?.aborted) {
      return {
        verdict: "BLOCK",
        reason: "Review request aborted by signal",
        ...(cascade ? { cascade } : {}),
        ...(metadata ? { metadata } : {}),
      };
    }

    if (!this.hasRemoteAdapter) {
      return {
        verdict: "UNSURE",
        reason: reason || "Manual review required (ntfy disabled: ntfyTopic not configured)",
        riskLevel,
        userAuthorization: userAuth,
        ...(cascade ? { cascade } : {}),
        ...(metadata ? { metadata } : {}),
      };
    }

    if (!this.stopRemoteListen) {
      await this.start();
    }
    const messageBody = formatNotificationBody({
      target: resolveNotificationTarget(action),
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
      cascade,
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
      this.onStateChange?.();

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
    if (!cascade && !metadata) {
      return finalDecision;
    }
    return {
      ...finalDecision,
      ...(cascade ? { cascade } : {}),
      ...(metadata ? { metadata } : {}),
    };
  }

  public resolveReviewResponse(resp: ReviewResponse): void {
    const reqID = resp.req_id ?? resp.id;
    if (!reqID) return;

    const entry = this.inFlightRequests.get(reqID);
    if (entry) {
      entry.abort.abort();
      this.inFlightRequests.delete(reqID);
      const preserveBody = this.config.ntfyVerbosity === "verbose" ? entry.message : undefined;
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
    if (data.reply === "once" || data.reply === "always") {
      this.resetConsecutiveBlocks();
    }
    const entry = this.inFlightRequests.get(reqID);
    if (entry) {
      entry.abort.abort();
      this.inFlightRequests.delete(reqID);
      const preserveBody = this.config.ntfyVerbosity === "verbose" ? entry.message : undefined;
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
    cascade?: CascadeTrace,
  ): Promise<void> {
    const payload: ReviewRequest = {
      id: action.id,
      title: formatNotificationTitle(verdict, action.toolName),
      message: formatNotificationBody({
        target: resolveNotificationTarget(action),
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
        cascade,
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
