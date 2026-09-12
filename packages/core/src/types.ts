export type ClassifierVerdict = "ALLOW" | "BLOCK" | "UNSURE"

export type RiskLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
export type UserAuthorization = "NONE" | "LOW" | "MEDIUM" | "HIGH"

export interface ClassifierResult {
  verdict: ClassifierVerdict
  risk_level?: RiskLevel
  user_authorization?: UserAuthorization
  reason?: string
}

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
} as const

export interface EnvironmentConfig {
  trustedDomains?: string[]
  trustedGitRemotes?: string[]
  trustedPaths?: string[]
}

export interface BaseAdapter {
  readonly name: string
  start?(): Promise<void> | void
  dispose?(): Promise<void> | void
}

export interface HarnessAdapter extends BaseAdapter {
  // Inbound bridge that translates host events to GateAction and enforces GateDecision
}

export interface GateAction {
  id: string
  harness: string
  sessionID: string
  toolName: string
  commandString?: string
  targetPath?: string
  rawArgs?: unknown
  workspaceRoot: string
  userPrompt: string
  subagentPrompt?: string
  environment?: EnvironmentConfig
  metadata?: Record<string, unknown>
}

export interface GateDecision {
verdict: ClassifierVerdict
riskLevel?: RiskLevel
userAuthorization?: UserAuthorization
reason: string
safeTransformAlternative?: string
  cached?: boolean
  reply?: "once" | "always" | "reject"
}

export interface ReviewAction {
  id: string
  label: string
  reply: "once" | "always" | "reject"
}

export interface ReviewRequest {
  id: string
  title: string
  message: string
  priority?: string
  tags?: string[]
  actions?: ReviewAction[]
}

export interface ReviewResponse {
  req_id: string
  reply: "once" | "always" | "reject"
  source?: string
}

export interface NotifierAdapter extends BaseAdapter {
  publish(request: ReviewRequest, signal?: AbortSignal): Promise<void>
  listen(onResponse: (resp: ReviewResponse) => Promise<void>, signal?: AbortSignal): Promise<() => void>
  updateStatus(requestId: string, status: string, details?: string): Promise<void>
}

export interface GateEvaluator {
  readonly name: string
  evaluate(action: GateAction, options?: Record<string, unknown>): Promise<ClassifierResult>
}

// Backward compatibility aliases
export type NotificationPayload = ReviewRequest
export type ApprovalResponse = ReviewResponse
export type RemoteAdapter = NotifierAdapter
export type NotificationAction = ReviewAction
export type PermissionEventData = any

export interface ClassifyInput {
  // deno-lint-ignore no-explicit-any
  client: any
  model?: string
  request?: PermissionEventData
  userPrompt?: string
  subagentPrompt?: string
  directory?: string
  actionName?: string
  actionArgs?: unknown
  workspaceRoot?: string
  environment?: EnvironmentConfig
  config?: any
}

export interface BuildClassifierPromptInput {
  request?: PermissionEventData
  userPrompt?: string
  subagentPrompt?: string
  actionName?: string
  actionArgs?: unknown
  workspaceRoot?: string
  directory?: string
  environment?: EnvironmentConfig
}
