export type ClassifierVerdict = "ALLOW" | "BLOCK" | "UNSURE";
export type ReviewFallbackMode = "native" | "ntfy";

export type RiskLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type UserAuthorization = "NONE" | "LOW" | "MEDIUM" | "HIGH";

export type SessionId = string & { readonly __brand: "SessionId" };
export type RequestId = string & { readonly __brand: "RequestId" };
export type ActionId = string & { readonly __brand: "ActionId" };
export type TopicName = string & { readonly __brand: "TopicName" };

export function parseSessionId(value: unknown, fallback: string = "default-session"): SessionId {
  if (typeof value !== "string" || value.trim().length === 0) {
    return fallback as SessionId;
  }
  return value.trim() as SessionId;
}

export function parseRequestId(value: unknown): RequestId {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new TypeError(`Invalid RequestId: expected non-empty string, got ${typeof value}`);
  }
  return value.trim() as RequestId;
}

export function parseActionId(value: unknown): ActionId {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new TypeError(`Invalid ActionId: expected non-empty string, got ${typeof value}`);
  }
  return value.trim() as ActionId;
}

export function parseTopicName(value: unknown): TopicName {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new TypeError(`Invalid TopicName: expected non-empty string, got ${typeof value}`);
  }
  return value.trim() as TopicName;
}

export type ClassifierResult =
  | {
      readonly verdict: "ALLOW";
      readonly reason: string;
      readonly risk_level?: RiskLevel;
      readonly user_authorization?: UserAuthorization;
    }
  | {
      readonly verdict: "BLOCK";
      readonly reason: string;
      readonly risk_level?: RiskLevel;
      readonly user_authorization?: UserAuthorization;
    }
  | {
      readonly verdict: "UNSURE";
      readonly reason: string;
      readonly risk_level?: RiskLevel;
      readonly user_authorization?: UserAuthorization;
    };

export const CLASSIFIER_JSON_SCHEMA = {
  type: "object",
  properties: {
    risk_level: {
      type: "string",
      enum: ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
    },
    user_authorization: {
      type: "string",
      enum: ["NONE", "LOW", "MEDIUM", "HIGH"],
    },
    verdict: {
      type: "string",
      enum: ["ALLOW", "BLOCK", "UNSURE"],
    },
    reason: {
      type: "string",
    },
  },
  required: ["risk_level", "user_authorization", "verdict", "reason"],
} as const;

export interface EnvironmentConfig {
  trustedDomains?: string[];
  trustedGitRemotes?: string[];
  trustedPaths?: string[];
}
export interface OmpHarnessConfig {
  reviewFallbackMode?: "native" | "ntfy";
  evalLogFile?: string;
}

export interface OpenCodeHarnessConfig {
  serverUrl?: string;
}

export interface PaseoHarnessConfig {
  timelineBadges?: boolean;
  notifyOnVerdict?: boolean;
  /**
   * Specifies the provider/model string (e.g. "omp", "antigravity") for native evaluation in Paseo.
   */
  evaluatorProvider?: string;
  /**
   * Forces using DirectApiEvaluator instead of Paseo agent creation.
   */
  useDirectApi?: boolean;
}

export interface AutoGateConfig {
  autoMode: boolean;
  ntfyTopic: string;
  ntfyServer: string;
  ntfyToken?: string;
  classifierModel: string;
  classifierTimeout?: number;
  consecutiveBlockThreshold?: number;
  notifyOnVerdict?: boolean;
  environment?: EnvironmentConfig;
  serverUrl?: string;
  /**
   * @deprecated Kept for backward compatibility. Use config.omp?.reviewFallbackMode or harness-level settings instead.
   */
  reviewFallbackMode?: ReviewFallbackMode;
  evalLogFile?: string;
  omp?: OmpHarnessConfig;
  opencode?: OpenCodeHarnessConfig;
  paseo?: PaseoHarnessConfig;
}

export interface BaseAdapter {
  readonly name: string;
  start?(): Promise<void> | void;
  dispose?(): Promise<void> | void;
}

export interface HarnessAdapter extends BaseAdapter {
  // Inbound bridge that translates host events to GateAction and enforces GateDecision
}

export interface GateAction {
  id: ActionId | string;
  harness: string;
  sessionID: SessionId | string;
  toolName: string;
  commandString?: string;
  targetPath?: string;
  rawArgs?: unknown;
  workspaceRoot: string;
  userPrompt: string;
  subagentPrompt?: string;
  environment?: EnvironmentConfig;
  metadata?: Record<string, unknown>;
  signal?: AbortSignal;
}

export function createGateAction(input: {
  id?: string;
  harness?: string;
  sessionID?: string;
  toolName: string;
  commandString?: string;
  targetPath?: string;
  rawArgs?: unknown;
  workspaceRoot?: string;
  userPrompt?: string;
  subagentPrompt?: string;
  environment?: EnvironmentConfig;
  metadata?: Record<string, unknown>;
  signal?: AbortSignal;
}): GateAction {
  return {
    id: parseActionId(input.id || Math.random().toString(36).slice(2)),
    harness: input.harness || "generic",
    sessionID: parseSessionId(input.sessionID || "default-session"),
    toolName: input.toolName,
    commandString: input.commandString,
    targetPath: input.targetPath,
    rawArgs: input.rawArgs,
    workspaceRoot: input.workspaceRoot || process.cwd(),
    userPrompt: input.userPrompt || "",
    subagentPrompt: input.subagentPrompt,
    environment: input.environment,
    metadata: input.metadata,
    signal: input.signal,
  };
}
export type GateDecision =
  | {
      readonly verdict: "ALLOW";
      readonly reason: string;
      readonly riskLevel?: RiskLevel;
      readonly userAuthorization?: UserAuthorization;
      readonly cached?: boolean;
      readonly reply?: "once" | "always";
      readonly safeTransformAlternative?: never;
    }
  | {
      readonly verdict: "BLOCK";
      readonly reason: string;
      readonly riskLevel?: RiskLevel;
      readonly userAuthorization?: UserAuthorization;
      readonly safeTransformAlternative?: string;
      readonly cached?: false;
      readonly reply?: "reject";
    }
  | {
      readonly verdict: "UNSURE";
      readonly reason: string;
      readonly riskLevel?: RiskLevel;
      readonly userAuthorization?: UserAuthorization;
      readonly reply?: "once" | "always" | "reject";
      readonly cached?: false;
      readonly safeTransformAlternative?: never;
    };

export interface ReviewAction {
  id: string;
  label: string;
  reply: "once" | "always" | "reject";
}

export interface ReviewRequest {
  id: string;
  title: string;
  message: string;
  priority?: string;
  tags?: string[];
  actions?: ReviewAction[];
}

export interface ReviewResponse {
  req_id: string;
  reply: "once" | "always" | "reject";
  source?: string;
}

export interface NotifierAdapter extends BaseAdapter {
  publish(request: ReviewRequest, signal?: AbortSignal): Promise<void>;
  listen(
    onResponse: (resp: ReviewResponse) => Promise<void>,
    signal?: AbortSignal,
  ): Promise<() => void>;
  updateStatus(requestId: string, status: string, details?: string): Promise<void>;
}

export interface GateEvaluator {
  readonly name: string;
  evaluate(action: GateAction, options?: Record<string, unknown>): Promise<ClassifierResult>;
}

export interface EngineOptions {
  config?: AutoGateConfig;
  adapter?: NotifierAdapter;
  evaluator?: GateEvaluator;
  workspaceRoot?: string;
  remoteReviewEnabled?: boolean;
}

// Backward compatibility aliases
export type NotificationPayload = ReviewRequest;
export type ApprovalResponse = ReviewResponse;
export type RemoteAdapter = NotifierAdapter;
export type NotificationAction = ReviewAction;
export interface PermissionEventData {
  [key: string]: any;
  permission?: string;
  toolName?: string;
  patterns?: unknown[];
  metadata?: Record<string, any>;
  commandString?: string;
  targetPath?: string;
  sessionID?: string;
}

export interface ClassifyInput {
  model?: string;
  request?: PermissionEventData;
  userPrompt?: string;
  subagentPrompt?: string;
  directory?: string;
  actionName?: string;
  actionArgs?: unknown;
  workspaceRoot?: string;
  environment?: EnvironmentConfig;
  config?: unknown;
}

export interface BuildClassifierPromptInput {
  request?: PermissionEventData;
  userPrompt?: string;
  subagentPrompt?: string;
  actionName?: string;
  actionArgs?: unknown;
  workspaceRoot?: string;
  directory?: string;
  environment?: EnvironmentConfig;
}
