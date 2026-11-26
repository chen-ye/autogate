import type { CascadeTrace, ClassifierVerdict, RiskLevel, UserAuthorization } from "../types.js";

export const DEFAULT_EVAL_STORE_BUSY_TIMEOUT_MS = 5000;
export const DEFAULT_EVAL_QUERY_LIMIT = 200;

export type EvalSourceFormat = "opencode" | "opencode1" | "omp" | (string & {});
export type EvalSourceOrigin = "live" | "jsonl-import" | "opencode-db-import" | (string & {});
export type S2SessionStatus =
  | "completed"
  | "aborted"
  | "partial"
  | "timeout"
  | "error"
  | (string & {});

export interface AutoGateEvalStoreOptions {
  dbPath?: string;
  readonly?: boolean;
  busyTimeoutMs?: number;
}

export interface PromptTemplateRecord {
  hash: string;
  systemPrompt: string;
  agentConfig: string | null;
  createdAt: number;
}

export interface RecordS2SessionInput {
  s2SessionId: string;
  targetSessionId?: string | null;
  title?: string | null;
  agent?: string | null;
  directory?: string | null;
  status?: S2SessionStatus;
  systemPrompt?: string | null;
  agentConfig?: string | Record<string, unknown> | null;
  templateHash?: string | null;
  modelId?: string | null;
  modelProvider?: string | null;
  promptTokens?: number | null;
  outputTokens?: number | null;
  reasoningTokens?: number | null;
  cacheReadTokens?: number | null;
  cacheWriteTokens?: number | null;
  cost?: number | null;
  messageCount?: number | null;
  createdAt?: number | null;
  updatedAt?: number | null;
  archivedAt?: number | null;
  payload: unknown;
}

export interface S2SessionSummary {
  s2SessionId: string;
  targetSessionId: string | null;
  title: string | null;
  agent: string | null;
  directory: string | null;
  status: string;
  templateHash: string | null;
  modelId: string | null;
  modelProvider: string | null;
  promptTokens: number | null;
  outputTokens: number | null;
  reasoningTokens: number | null;
  cacheReadTokens: number | null;
  cacheWriteTokens: number | null;
  cost: number | null;
  messageCount: number;
  createdAt: number | null;
  updatedAt: number | null;
  archivedAt: number | null;
  rawBytes: number;
  compressedBytes: number;
}

export interface S2SessionRecord extends S2SessionSummary {
  payload: unknown;
  payloadText: string;
}

export interface RecordEvaluationInput {
  id?: string;
  sourceFormat: EvalSourceFormat;
  timestamp?: number;
  sessionId: string;
  s2SessionId?: string | null;
  actionId?: string | null;
  toolName: string;
  commandString?: string | null;
  targetPath?: string | null;
  workspaceRoot?: string | null;
  userPrompt?: string | null;
  reasoning?: string | null;
  thinking?: string | null;
  verdict: ClassifierVerdict | string;
  riskLevel?: RiskLevel | string | null;
  userAuthorization?: UserAuthorization | string | null;
  durationMs?: number | null;
  modelId?: string | null;
  modelProvider?: string | null;
  promptTokens?: number | null;
  outputTokens?: number | null;
  reasoningTokens?: number | null;
  cost?: number | null;
  attempts?: number | null;
  error?: string | null;
  cascade?: CascadeTrace | null;
  cascadeJson?: string | null;
  cascadeWinner?: "system1" | "system2" | string | null;
  s2Aborted?: boolean | number | null;
  sourceOrigin?: EvalSourceOrigin;
}

export interface EvaluationRecord {
  id: string;
  sourceFormat: string;
  timestamp: number;
  sessionId: string;
  s2SessionId: string | null;
  actionId: string | null;
  toolName: string;
  commandString: string;
  targetPath: string | null;
  workspaceRoot: string | null;
  userPrompt: string;
  reasoning: string | null;
  thinking: string | null;
  verdict: ClassifierVerdict;
  riskLevel: RiskLevel | null;
  userAuthorization: UserAuthorization | null;
  durationMs: number;
  modelId: string | null;
  modelProvider: string | null;
  promptTokens: number | null;
  outputTokens: number | null;
  reasoningTokens: number | null;
  cost: number | null;
  attempts: number | null;
  error: string | null;
  cascade: CascadeTrace | null;
  cascadeJson: string | null;
  cascadeWinner: "system1" | "system2" | null;
  s2Aborted: boolean;
  sourceOrigin: string;
  hasS2Session: boolean;
}

export interface EvaluationQueryOptions {
  sessionId?: string;
  s2SessionId?: string;
  verdict?: ClassifierVerdict | string;
  sourceFormat?: string;
  sourceOrigin?: string;
  cascadeWinner?: "system1" | "system2" | string;
  toolName?: string;
  query?: string;
  search?: string;
  since?: number;
  until?: number;
  hasS2Session?: boolean;
  limit?: number;
  offset?: number;
  order?: "asc" | "desc";
}

export interface ListS2SessionsOptions {
  targetSessionId?: string;
  status?: string;
  limit?: number;
  offset?: number;
}

export interface EvaluationDetail {
  evaluation: EvaluationRecord;
  s2Session: S2SessionRecord | null;
  promptTemplate: PromptTemplateRecord | null;
}

export interface EvalStatsOptions {
  sessionId?: string;
  sourceFormat?: string;
  since?: number;
  until?: number;
}

export interface MergeCorrelatedEvaluationInput {
  sourceId: string;
  targetId: string;
  sessionId: string;
  verdict: ClassifierVerdict | string;
  riskLevel?: RiskLevel | string | null;
  userAuthorization?: UserAuthorization | string | null;
  reasoning?: string | null;
  userPrompt?: string;
  durationMs?: number | null;
  timestamp?: number | null;
  cascadeJson?: string | null;
  cascadeWinner?: "system1" | "system2" | string | null;
  s2Aborted?: boolean | number | null;
  s2SessionId?: string | null;
  createdAt?: number;
}

export interface LinkS2SessionInput {
  actionId: string;
  s2SessionId: string;
  targetSessionId?: string | null;
  status?: S2SessionStatus;
  timestamp?: number;
  toolName: string;
  commandString?: string | null;
  targetPath?: string | null;
  workspaceRoot?: string | null;
  userPrompt?: string | null;
  verdict: ClassifierVerdict | string;
  riskLevel?: RiskLevel | string | null;
  userAuthorization?: UserAuthorization | string | null;
  reasoning?: string | null;
  thinking?: string | null;
  durationMs?: number | null;
  modelId?: string | null;
  modelProvider?: string | null;
  promptTokens?: number | null;
  outputTokens?: number | null;
  reasoningTokens?: number | null;
  cost?: number | null;
  attempts?: number | null;
  error?: string | null;
  s2Aborted?: boolean;
}

export interface EvalStats {
  total: number;
  allow: number;
  block: number;
  unsure: number;
  avgLatencyMs: number;
  s1FastPathCount: number;
  s1FastPathPct: number;
  s2Count: number;
  s2AbortedCount: number;
  totalPromptTokens: number;
  totalOutputTokens: number;
  totalReasoningTokens: number;
  totalCost: number;
  s2SessionCount: number;
  promptTemplateCount: number;
  totalRawBytes: number;
  totalCompressedBytes: number;
}
