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
export interface PermissionEventData {
  id: string
  sessionID: string
  permission: string
  patterns: string[]
  metadata: Record<string, unknown>
  always: string[]
  tool?: {
    messageID: string
    callID: string
  }
}

export interface NotificationAction {
  id: string
  label: string
  reply: "once" | "always" | "reject"
}

export interface NotificationPayload {
  id: string
  title: string
  message: string
  priority?: string
  tags?: string[]
  actions?: NotificationAction[]
}

export interface ApprovalResponse {
  req_id: string
  reply: "once" | "always" | "reject"
  source?: "ntfy" | "telegram" | "manual"
}

export interface RemoteAdapter {
  name: string
  publish(payload: NotificationPayload, signal?: AbortSignal): Promise<void>
  listen(onResponse: (resp: ApprovalResponse) => Promise<void>, signal?: AbortSignal): Promise<() => void>
  updateStatus(id: string, status: string, details?: string): Promise<void>
}
