import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash, randomUUID } from "node:crypto";
import {
  DatabaseSync,
  type SQLInputValue,
  type SQLOutputValue,
  type StatementSync,
} from "node:sqlite";
import { zstdCompressSync, zstdDecompressSync } from "node:zlib";
import { isClassifierVerdict, isRiskLevel, isUserAuthorization } from "./classifier.js";
import { resolveEvalDbFile } from "./config.js";
import type { CascadeTrace, ClassifierVerdict, RiskLevel, UserAuthorization } from "./types.js";

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

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS prompt_templates (
  hash TEXT PRIMARY KEY,
  system_prompt TEXT NOT NULL,
  agent_config TEXT,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS s2_sessions (
  s2_session_id TEXT PRIMARY KEY,
  target_session_id TEXT,
  title TEXT,
  agent TEXT,
  directory TEXT,
  status TEXT NOT NULL,
  template_hash TEXT REFERENCES prompt_templates(hash),
  model_id TEXT,
  model_provider TEXT,
  prompt_tokens INTEGER,
  output_tokens INTEGER,
  reasoning_tokens INTEGER,
  cache_read_tokens INTEGER,
  cache_write_tokens INTEGER,
  cost REAL,
  message_count INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER,
  updated_at INTEGER,
  archived_at INTEGER,
  payload_zstd BLOB NOT NULL,
  raw_bytes INTEGER NOT NULL,
  compressed_bytes INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS evaluations (
  id TEXT PRIMARY KEY,
  source_format TEXT NOT NULL,
  timestamp INTEGER NOT NULL,
  session_id TEXT NOT NULL,
  s2_session_id TEXT UNIQUE,
  action_id TEXT,
  tool_name TEXT NOT NULL,
  command_string TEXT NOT NULL,
  target_path TEXT,
  workspace_root TEXT,
  user_prompt TEXT NOT NULL DEFAULT '',
  reasoning TEXT,
  thinking TEXT,
  verdict TEXT NOT NULL,
  risk_level TEXT,
  user_authorization TEXT,
  duration_ms INTEGER NOT NULL DEFAULT 0,
  model_id TEXT,
  model_provider TEXT,
  prompt_tokens INTEGER,
  output_tokens INTEGER,
  reasoning_tokens INTEGER,
  cost REAL,
  attempts INTEGER,
  error TEXT,
  cascade_json TEXT,
  cascade_winner TEXT,
  s2_aborted INTEGER NOT NULL DEFAULT 0,
  source_origin TEXT NOT NULL DEFAULT 'live'
);

CREATE TABLE IF NOT EXISTS deduped_eval_ids (
  id TEXT PRIMARY KEY,
  target_id TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_evaluations_timestamp ON evaluations(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_evaluations_session_timestamp ON evaluations(session_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_evaluations_verdict_timestamp ON evaluations(verdict, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_evaluations_action_id ON evaluations(action_id);
CREATE INDEX IF NOT EXISTS idx_s2_sessions_target_created ON s2_sessions(target_session_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_s2_sessions_created ON s2_sessions(created_at DESC);
`;

const UPSERT_EVALUATION_BY_ID_SQL = `
INSERT INTO evaluations (
  id, source_format, timestamp, session_id, s2_session_id,
  action_id, tool_name, command_string, target_path, workspace_root,
  user_prompt, reasoning, thinking, verdict, risk_level,
  user_authorization, duration_ms, model_id, model_provider,
  prompt_tokens, output_tokens, reasoning_tokens, cost, attempts,
  error, cascade_json, cascade_winner, s2_aborted, source_origin
) VALUES (
  ?, ?, ?, ?, ?,
  ?, ?, ?, ?, ?,
  ?, ?, ?, ?, ?,
  ?, ?, ?, ?,
  ?, ?, ?, ?, ?,
  ?, ?, ?, ?, ?
)
ON CONFLICT(id) DO UPDATE SET
  source_format = COALESCE(NULLIF(evaluations.source_format, ''), excluded.source_format),
  timestamp = CASE
    WHEN evaluations.source_origin = 'opencode-db-import' AND excluded.source_origin != 'opencode-db-import' AND excluded.timestamp > 0 THEN excluded.timestamp
    WHEN evaluations.timestamp > 0 THEN evaluations.timestamp
    ELSE excluded.timestamp
  END,
  session_id = CASE
    WHEN evaluations.source_origin = 'opencode-db-import' AND excluded.source_origin != 'opencode-db-import' AND excluded.session_id != '' THEN excluded.session_id
    ELSE COALESCE(NULLIF(evaluations.session_id, ''), excluded.session_id)
  END,
  s2_session_id = COALESCE(NULLIF(evaluations.s2_session_id, ''), excluded.s2_session_id),
  action_id = COALESCE(NULLIF(evaluations.action_id, ''), excluded.action_id),
  tool_name = CASE
    WHEN evaluations.source_origin = 'opencode-db-import' AND excluded.source_origin != 'opencode-db-import' AND excluded.tool_name != '' THEN excluded.tool_name
    ELSE COALESCE(NULLIF(evaluations.tool_name, ''), excluded.tool_name)
  END,
  command_string = CASE
    WHEN evaluations.source_origin = 'opencode-db-import' AND excluded.source_origin != 'opencode-db-import' AND excluded.command_string != '' THEN excluded.command_string
    ELSE COALESCE(NULLIF(evaluations.command_string, ''), excluded.command_string)
  END,
  target_path = COALESCE(NULLIF(evaluations.target_path, ''), excluded.target_path),
  workspace_root = CASE
    WHEN evaluations.source_origin = 'opencode-db-import' AND excluded.source_origin != 'opencode-db-import' AND NULLIF(excluded.workspace_root, '') IS NOT NULL THEN excluded.workspace_root
    ELSE COALESCE(NULLIF(evaluations.workspace_root, ''), excluded.workspace_root)
  END,
  user_prompt = CASE
    WHEN evaluations.source_origin = 'opencode-db-import' AND excluded.source_origin != 'opencode-db-import' AND excluded.user_prompt != '' THEN excluded.user_prompt
    WHEN evaluations.user_prompt != '' THEN evaluations.user_prompt
    ELSE excluded.user_prompt
  END,
  reasoning = CASE
    WHEN evaluations.source_origin = 'opencode-db-import' AND excluded.source_origin != 'opencode-db-import' AND NULLIF(excluded.reasoning, '') IS NOT NULL THEN excluded.reasoning
    ELSE COALESCE(NULLIF(evaluations.reasoning, ''), excluded.reasoning)
  END,
  thinking = COALESCE(NULLIF(evaluations.thinking, ''), excluded.thinking),
  verdict = CASE
    WHEN evaluations.source_origin = 'opencode-db-import' AND excluded.source_origin != 'opencode-db-import' THEN excluded.verdict
    ELSE COALESCE(NULLIF(evaluations.verdict, ''), excluded.verdict)
  END,
  risk_level = CASE
    WHEN evaluations.source_origin = 'opencode-db-import' AND excluded.source_origin != 'opencode-db-import' AND NULLIF(excluded.risk_level, '') IS NOT NULL THEN excluded.risk_level
    ELSE COALESCE(NULLIF(evaluations.risk_level, ''), excluded.risk_level)
  END,
  user_authorization = CASE
    WHEN evaluations.source_origin = 'opencode-db-import' AND excluded.source_origin != 'opencode-db-import' AND NULLIF(excluded.user_authorization, '') IS NOT NULL THEN excluded.user_authorization
    ELSE COALESCE(NULLIF(evaluations.user_authorization, ''), excluded.user_authorization)
  END,
  duration_ms = CASE
    WHEN evaluations.source_origin = 'opencode-db-import' AND excluded.source_origin != 'opencode-db-import' AND excluded.duration_ms > 0 THEN excluded.duration_ms
    WHEN evaluations.duration_ms > 0 THEN evaluations.duration_ms
    ELSE excluded.duration_ms
  END,
  model_id = COALESCE(NULLIF(evaluations.model_id, ''), excluded.model_id),
  model_provider = COALESCE(NULLIF(evaluations.model_provider, ''), excluded.model_provider),
  prompt_tokens = COALESCE(evaluations.prompt_tokens, excluded.prompt_tokens),
  output_tokens = COALESCE(evaluations.output_tokens, excluded.output_tokens),
  reasoning_tokens = COALESCE(evaluations.reasoning_tokens, excluded.reasoning_tokens),
  cost = COALESCE(evaluations.cost, excluded.cost),
  attempts = COALESCE(evaluations.attempts, excluded.attempts),
  error = COALESCE(NULLIF(evaluations.error, ''), excluded.error),
  cascade_json = COALESCE(NULLIF(evaluations.cascade_json, ''), excluded.cascade_json),
  cascade_winner = COALESCE(NULLIF(evaluations.cascade_winner, ''), excluded.cascade_winner),
  s2_aborted = CASE
    WHEN evaluations.source_origin = 'opencode-db-import' AND excluded.source_origin != 'opencode-db-import' THEN excluded.s2_aborted
    ELSE MAX(evaluations.s2_aborted, excluded.s2_aborted)
  END,
  source_origin = CASE
    WHEN evaluations.source_origin = 'opencode-db-import' AND excluded.source_origin != 'opencode-db-import' THEN excluded.source_origin
    ELSE COALESCE(NULLIF(evaluations.source_origin, ''), excluded.source_origin)
  END
RETURNING *
`;

const UPSERT_S2_SESSION_SQL = `
INSERT INTO s2_sessions (
  s2_session_id, target_session_id, title, agent, directory,
  status, template_hash, model_id, model_provider,
  prompt_tokens, output_tokens, reasoning_tokens,
  cache_read_tokens, cache_write_tokens, cost,
  message_count, created_at, updated_at, archived_at,
  payload_zstd, raw_bytes, compressed_bytes
) VALUES (
  ?, ?, ?, ?, ?,
  ?, ?, ?, ?,
  ?, ?, ?,
  ?, ?, ?,
  ?, ?, ?, ?,
  ?, ?, ?
)
ON CONFLICT(s2_session_id) DO UPDATE SET
  target_session_id = COALESCE(excluded.target_session_id, s2_sessions.target_session_id),
  title = COALESCE(excluded.title, s2_sessions.title),
  agent = COALESCE(excluded.agent, s2_sessions.agent),
  directory = COALESCE(excluded.directory, s2_sessions.directory),
  status = CASE
    WHEN s2_sessions.message_count > 0 AND excluded.message_count <= 0 THEN s2_sessions.status
    ELSE excluded.status
  END,
  template_hash = COALESCE(excluded.template_hash, s2_sessions.template_hash),
  model_id = COALESCE(excluded.model_id, s2_sessions.model_id),
  model_provider = COALESCE(excluded.model_provider, s2_sessions.model_provider),
  prompt_tokens = COALESCE(excluded.prompt_tokens, s2_sessions.prompt_tokens),
  output_tokens = COALESCE(excluded.output_tokens, s2_sessions.output_tokens),
  reasoning_tokens = COALESCE(excluded.reasoning_tokens, s2_sessions.reasoning_tokens),
  cache_read_tokens = COALESCE(excluded.cache_read_tokens, s2_sessions.cache_read_tokens),
  cache_write_tokens = COALESCE(excluded.cache_write_tokens, s2_sessions.cache_write_tokens),
  cost = COALESCE(excluded.cost, s2_sessions.cost),
  message_count = CASE
    WHEN excluded.message_count > 0 THEN excluded.message_count
    ELSE s2_sessions.message_count
  END,
  created_at = COALESCE(s2_sessions.created_at, excluded.created_at),
  updated_at = COALESCE(excluded.updated_at, s2_sessions.updated_at),
  archived_at = COALESCE(excluded.archived_at, s2_sessions.archived_at),
  payload_zstd = CASE
    WHEN s2_sessions.message_count > 0 AND excluded.message_count <= 0 THEN s2_sessions.payload_zstd
    ELSE excluded.payload_zstd
  END,
  raw_bytes = CASE
    WHEN s2_sessions.message_count > 0 AND excluded.message_count <= 0 THEN s2_sessions.raw_bytes
    ELSE excluded.raw_bytes
  END,
  compressed_bytes = CASE
    WHEN s2_sessions.message_count > 0 AND excluded.message_count <= 0 THEN s2_sessions.compressed_bytes
    ELSE excluded.compressed_bytes
  END
RETURNING
  s2_session_id, target_session_id, title, agent, directory,
  status, template_hash, model_id, model_provider,
  prompt_tokens, output_tokens, reasoning_tokens,
  cache_read_tokens, cache_write_tokens, cost,
  message_count, created_at, updated_at, archived_at,
  raw_bytes, compressed_bytes
`;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function expandDbPath(inputPath: string): string {
  const trimmed = inputPath.trim();
  if (trimmed === ":memory:") return ":memory:";
  if (trimmed.startsWith("~/")) {
    return path.resolve(path.join(os.homedir(), trimmed.slice(2)));
  }
  if (trimmed === "~") {
    return path.resolve(os.homedir());
  }
  return path.resolve(trimmed);
}

function stableSerializeJson(value: unknown, seen: WeakSet<object> = new WeakSet()): string {
  if (value === null || value === undefined) return "null";
  if (typeof value === "bigint") return JSON.stringify(value.toString());
  if (typeof value === "function" || typeof value === "symbol") return "null";
  if (typeof value !== "object") return JSON.stringify(value) ?? "null";

  if (seen.has(value)) return '"[Circular]"';
  seen.add(value);
  try {
    if (Array.isArray(value)) {
      return `[${value.map((item) => stableSerializeJson(item, seen)).join(",")}]`;
    }
    const rec = value as Record<string, unknown>;
    const keys = Object.keys(rec)
      .filter((k) => {
        const t = typeof rec[k];
        return t !== "undefined" && t !== "function" && t !== "symbol";
      })
      .sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${stableSerializeJson(rec[k], seen)}`).join(",")}}`;
  } finally {
    seen.delete(value);
  }
}

function normalizeAgentConfig(
  agentConfig?: string | Record<string, unknown> | null,
): string | null {
  if (agentConfig === undefined || agentConfig === null) {
    return null;
  }
  if (typeof agentConfig === "string") {
    return agentConfig;
  }
  return stableSerializeJson(agentConfig);
}

export function computePromptTemplateHash(
  systemPrompt: string,
  agentConfig?: string | Record<string, unknown> | null,
): string {
  const normalizedConfig = normalizeAgentConfig(agentConfig);
  const hash = createHash("sha256");
  hash.update(systemPrompt);
  if (normalizedConfig !== null) {
    hash.update("\0");
    hash.update(normalizedConfig);
  }
  return hash.digest("hex");
}

function nonEmptyStringOrNull(val: unknown): string | null {
  if (typeof val !== "string") return null;
  const trimmed = val.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function stringOrEmpty(val: unknown): string {
  return typeof val === "string" ? val : "";
}

function finiteNumberOrNull(val: unknown): number | null {
  if (typeof val === "number" && Number.isFinite(val)) return val;
  if (typeof val === "bigint") return Number(val);
  return null;
}

function finiteIntOrNull(val: unknown): number | null {
  const num = finiteNumberOrNull(val);
  return num !== null ? Math.trunc(num) : null;
}

function asBytes(val: unknown): Uint8Array | null {
  if (val instanceof Uint8Array) return val;
  return null;
}

function normalizeStoredVerdict(val: unknown): ClassifierVerdict {
  if (typeof val === "string") {
    const upper = val.trim().toUpperCase();
    if (isClassifierVerdict(upper)) return upper;
  }
  return "UNSURE";
}

function normalizeStoredRiskLevel(val: unknown): RiskLevel | null {
  if (typeof val === "string") {
    const upper = val.trim().toUpperCase();
    if (isRiskLevel(upper)) return upper;
  }
  return null;
}

function normalizeStoredUserAuthorization(val: unknown): UserAuthorization | null {
  if (typeof val === "string") {
    const upper = val.trim().toUpperCase();
    if (isUserAuthorization(upper)) return upper;
  }
  return null;
}

function normalizeCascadeWinner(val: unknown): "system1" | "system2" | null {
  if (val === "system1" || val === "system2") return val;
  return null;
}

function parseCascadeJson(raw: string | null): CascadeTrace | null {
  if (!raw) return null;
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!isRecord(parsed)) return null;
    if (
      (parsed.mode === "race" || parsed.mode === "cascade") &&
      (parsed.winner === "system1" || parsed.winner === "system2")
    ) {
      return parsed as unknown as CascadeTrace;
    }
    return null;
  } catch {
    return null;
  }
}

function compressPayloadZstd(payload: unknown): {
  payloadZstd: Buffer;
  rawBytes: number;
  compressedBytes: number;
  inferredMessageCount: number;
} {
  let rawBuf: Buffer;
  let inferredMessageCount = 0;

  if (typeof payload === "string") {
    rawBuf = Buffer.from(payload, "utf8");
  } else if (Buffer.isBuffer(payload)) {
    rawBuf = payload;
  } else if (payload instanceof Uint8Array) {
    rawBuf = Buffer.from(payload.buffer, payload.byteOffset, payload.byteLength);
  } else {
    if (isRecord(payload) && Array.isArray(payload.messages)) {
      inferredMessageCount = payload.messages.length;
    }
    const serialized = JSON.stringify(payload === undefined ? null : payload);
    rawBuf = Buffer.from(serialized ?? "null", "utf8");
  }

  const payloadZstd = zstdCompressSync(rawBuf);
  return {
    payloadZstd,
    rawBytes: rawBuf.byteLength,
    compressedBytes: payloadZstd.byteLength,
    inferredMessageCount,
  };
}

function decompressPayloadZstd(compressed: Uint8Array): { payload: unknown; payloadText: string } {
  const raw = zstdDecompressSync(compressed);
  const payloadText = raw.toString("utf8");
  try {
    const payload: unknown = JSON.parse(payloadText);
    return { payload, payloadText };
  } catch {
    return { payload: payloadText, payloadText };
  }
}

function isMissingTableError(err: unknown): boolean {
  const message = err instanceof Error ? err.message : String(err);
  return message.toLowerCase().includes("no such table");
}

function escapeSqlLikePattern(term: string): string {
  const escaped = term.replace(/\\/g, "\\\\").replace(/%/g, "\\%").replace(/_/g, "\\_");
  return `%${escaped}%`;
}

function rowToPromptTemplate(row: Record<string, SQLOutputValue>): PromptTemplateRecord {
  return {
    hash: String(row.hash ?? ""),
    systemPrompt: String(row.system_prompt ?? ""),
    agentConfig: typeof row.agent_config === "string" ? row.agent_config : null,
    createdAt: finiteIntOrNull(row.created_at) ?? 0,
  };
}

function rowToS2SessionSummary(row: Record<string, SQLOutputValue>): S2SessionSummary {
  return {
    s2SessionId: String(row.s2_session_id ?? ""),
    targetSessionId: nonEmptyStringOrNull(row.target_session_id),
    title: typeof row.title === "string" ? row.title : null,
    agent: nonEmptyStringOrNull(row.agent),
    directory: nonEmptyStringOrNull(row.directory),
    status: String(row.status ?? "completed"),
    templateHash: nonEmptyStringOrNull(row.template_hash),
    modelId: nonEmptyStringOrNull(row.model_id),
    modelProvider: nonEmptyStringOrNull(row.model_provider),
    promptTokens: finiteIntOrNull(row.prompt_tokens),
    outputTokens: finiteIntOrNull(row.output_tokens),
    reasoningTokens: finiteIntOrNull(row.reasoning_tokens),
    cacheReadTokens: finiteIntOrNull(row.cache_read_tokens),
    cacheWriteTokens: finiteIntOrNull(row.cache_write_tokens),
    cost: finiteNumberOrNull(row.cost),
    messageCount: finiteIntOrNull(row.message_count) ?? 0,
    createdAt: finiteIntOrNull(row.created_at),
    updatedAt: finiteIntOrNull(row.updated_at),
    archivedAt: finiteIntOrNull(row.archived_at),
    rawBytes: finiteIntOrNull(row.raw_bytes) ?? 0,
    compressedBytes: finiteIntOrNull(row.compressed_bytes) ?? 0,
  };
}

function rowToEvaluationRecord(
  row: Record<string, SQLOutputValue>,
  hasS2SessionOverride?: boolean,
): EvaluationRecord {
  const cascadeJson = nonEmptyStringOrNull(row.cascade_json);
  const hasS2FromJoin = finiteIntOrNull(row.has_s2_session);
  const hasS2Session =
    hasS2SessionOverride !== undefined ? hasS2SessionOverride : Boolean(hasS2FromJoin);

  return {
    id: String(row.id ?? ""),
    sourceFormat: String(row.source_format ?? "opencode"),
    timestamp: finiteIntOrNull(row.timestamp) ?? 0,
    sessionId: String(row.session_id ?? ""),
    s2SessionId: nonEmptyStringOrNull(row.s2_session_id),
    actionId: nonEmptyStringOrNull(row.action_id),
    toolName: String(row.tool_name ?? ""),
    commandString: stringOrEmpty(row.command_string),
    targetPath: nonEmptyStringOrNull(row.target_path),
    workspaceRoot: nonEmptyStringOrNull(row.workspace_root),
    userPrompt: stringOrEmpty(row.user_prompt),
    reasoning: typeof row.reasoning === "string" ? row.reasoning : null,
    thinking: typeof row.thinking === "string" ? row.thinking : null,
    verdict: normalizeStoredVerdict(row.verdict),
    riskLevel: normalizeStoredRiskLevel(row.risk_level),
    userAuthorization: normalizeStoredUserAuthorization(row.user_authorization),
    durationMs: Math.max(0, finiteIntOrNull(row.duration_ms) ?? 0),
    modelId: nonEmptyStringOrNull(row.model_id),
    modelProvider: nonEmptyStringOrNull(row.model_provider),
    promptTokens: finiteIntOrNull(row.prompt_tokens),
    outputTokens: finiteIntOrNull(row.output_tokens),
    reasoningTokens: finiteIntOrNull(row.reasoning_tokens),
    cost: finiteNumberOrNull(row.cost),
    attempts: finiteIntOrNull(row.attempts),
    error: typeof row.error === "string" ? row.error : null,
    cascade: parseCascadeJson(cascadeJson),
    cascadeJson,
    cascadeWinner: normalizeCascadeWinner(row.cascade_winner),
    s2Aborted: (finiteIntOrNull(row.s2_aborted) ?? 0) !== 0,
    sourceOrigin: nonEmptyStringOrNull(row.source_origin) ?? "live",
    hasS2Session,
  };
}

function emptyStats(): EvalStats {
  return {
    total: 0,
    allow: 0,
    block: 0,
    unsure: 0,
    avgLatencyMs: 0,
    s1FastPathCount: 0,
    s1FastPathPct: 0,
    s2Count: 0,
    s2AbortedCount: 0,
    totalPromptTokens: 0,
    totalOutputTokens: 0,
    totalReasoningTokens: 0,
    totalCost: 0,
    s2SessionCount: 0,
    promptTemplateCount: 0,
    totalRawBytes: 0,
    totalCompressedBytes: 0,
  };
}

export class AutoGateEvalStore implements Disposable {
  private readonly dbPath: string;
  private readonly readonlyMode: boolean;
  private readonly busyTimeoutMs: number;
  private db: DatabaseSync | null = null;
  private stmtCache = new Map<string, StatementSync>();
  private explicitlyClosed = false;
  private savepointCounter = 0;

  constructor(
    dbPathOrOptions?: string | AutoGateEvalStoreOptions,
    options?: Omit<AutoGateEvalStoreOptions, "dbPath">,
  ) {
    const opts: AutoGateEvalStoreOptions =
      typeof dbPathOrOptions === "string"
        ? { ...options, dbPath: dbPathOrOptions }
        : { ...dbPathOrOptions };

    const rawPath = nonEmptyStringOrNull(opts.dbPath) ?? resolveEvalDbFile();
    this.dbPath = expandDbPath(rawPath);
    this.readonlyMode = Boolean(opts.readonly);
    this.busyTimeoutMs =
      typeof opts.busyTimeoutMs === "number" &&
      Number.isFinite(opts.busyTimeoutMs) &&
      opts.busyTimeoutMs > 0
        ? Math.trunc(opts.busyTimeoutMs)
        : DEFAULT_EVAL_STORE_BUSY_TIMEOUT_MS;

    if (this.readonlyMode) {
      this.tryOpenReadonly();
    } else {
      this.openReadWrite();
    }
  }

  public getDbPath(): string {
    return this.dbPath;
  }

  public isReadonly(): boolean {
    return this.readonlyMode;
  }

  public isOpen(): boolean {
    return Boolean(this.db && this.db.isOpen);
  }

  public getBusyTimeoutMs(): number | null {
    if (!this.db || !this.db.isOpen) return null;
    const row = this.db.prepare("PRAGMA busy_timeout").get();
    return finiteIntOrNull(row?.timeout);
  }

  public getJournalMode(): string | null {
    if (!this.db || !this.db.isOpen) return null;
    const row = this.db.prepare("PRAGMA journal_mode").get();
    return typeof row?.journal_mode === "string" ? row.journal_mode : null;
  }

  public close(): void {
    this.explicitlyClosed = true;
    this.stmtCache.clear();
    if (this.db) {
      try {
        if (this.db.isOpen) {
          this.db.close();
        }
      } finally {
        this.db = null;
      }
    }
  }

  public [Symbol.dispose](): void {
    this.close();
  }

  private prepareStmt(db: DatabaseSync, sql: string): StatementSync {
    let stmt = this.stmtCache.get(sql);
    if (!stmt) {
      stmt = db.prepare(sql);
      this.stmtCache.set(sql, stmt);
    }
    return stmt;
  }

  private ensurePrivateFilePermissions(): void {
    if (this.dbPath === ":memory:") return;
    for (const file of [this.dbPath, `${this.dbPath}-wal`, `${this.dbPath}-shm`]) {
      try {
        if (fs.existsSync(file)) {
          fs.chmodSync(file, 0o600);
        }
      } catch {
        // Ignore chmod failures on platforms/filesystems without POSIX mode support
      }
    }
  }

  private openReadWrite(): DatabaseSync {
    if (this.explicitlyClosed) {
      throw new Error("AutoGateEvalStore is closed");
    }
    if (this.db && this.db.isOpen) {
      return this.db;
    }
    if (this.dbPath !== ":memory:") {
      const parentDir = path.dirname(this.dbPath);
      const parentExisted = fs.existsSync(parentDir);
      fs.mkdirSync(parentDir, { recursive: true, mode: 0o700 });
      if (!parentExisted) {
        try {
          fs.chmodSync(parentDir, 0o700);
        } catch {
          // Ignore chmod failures on platforms/filesystems without POSIX mode support
        }
      }
      fs.writeFileSync(this.dbPath, "", { mode: 0o600, flag: "a" });
      try {
        fs.chmodSync(this.dbPath, 0o600);
      } catch {
        // Ignore chmod failures on platforms/filesystems without POSIX mode support
      }
    }
    const db = new DatabaseSync(this.dbPath, { timeout: this.busyTimeoutMs });
    db.exec(`PRAGMA busy_timeout = ${this.busyTimeoutMs};`);
    db.exec("PRAGMA journal_mode = WAL;");
    db.exec("PRAGMA synchronous = NORMAL;");
    db.exec("PRAGMA foreign_keys = ON;");
    db.exec(SCHEMA_SQL);
    this.ensurePrivateFilePermissions();
    this.db = db;
    return db;
  }

  private tryOpenReadonly(): DatabaseSync | null {
    if (this.explicitlyClosed) {
      throw new Error("AutoGateEvalStore is closed");
    }
    if (this.db && this.db.isOpen) {
      return this.db;
    }
    if (this.dbPath !== ":memory:" && !fs.existsSync(this.dbPath)) {
      return null;
    }
    const db = new DatabaseSync(this.dbPath, {
      readOnly: true,
      timeout: this.busyTimeoutMs,
    });
    db.exec(`PRAGMA busy_timeout = ${this.busyTimeoutMs};`);
    this.db = db;
    return db;
  }

  private getWriteDb(): DatabaseSync {
    if (this.explicitlyClosed) {
      throw new Error("AutoGateEvalStore is closed");
    }
    if (this.readonlyMode) {
      throw new Error("AutoGateEvalStore is opened in readonly mode");
    }
    return this.openReadWrite();
  }

  private getReadDb(): DatabaseSync | null {
    if (this.explicitlyClosed) {
      throw new Error("AutoGateEvalStore is closed");
    }
    if (this.readonlyMode) {
      return this.tryOpenReadonly();
    }
    return this.openReadWrite();
  }

  private runRead<T>(fallback: T, fn: (db: DatabaseSync) => T): T {
    const db = this.getReadDb();
    if (!db) return fallback;
    try {
      return fn(db);
    } catch (err: unknown) {
      if (this.readonlyMode && isMissingTableError(err)) {
        return fallback;
      }
      throw err;
    }
  }

  public withTransaction<T>(fn: () => T): T {
    const db = this.getWriteDb();
    if (db.isTransaction) {
      const sp = `ag_sp_${++this.savepointCounter}`;
      db.exec(`SAVEPOINT ${sp}`);
      try {
        const result = fn();
        db.exec(`RELEASE SAVEPOINT ${sp}`);
        return result;
      } catch (err) {
        try {
          db.exec(`ROLLBACK TO SAVEPOINT ${sp}`);
          db.exec(`RELEASE SAVEPOINT ${sp}`);
        } catch {
          // Ignore rollback cleanup failure
        }
        throw err;
      }
    }

    db.exec("BEGIN IMMEDIATE");
    try {
      const result = fn();
      db.exec("COMMIT");
      return result;
    } catch (err) {
      try {
        if (db.isTransaction) {
          db.exec("ROLLBACK");
        }
      } catch {
        // Ignore rollback cleanup failure
      }
      throw err;
    }
  }

  public ensurePromptTemplate(
    systemPrompt: string,
    agentConfig?: string | Record<string, unknown> | null,
    createdAt: number = Date.now(),
  ): PromptTemplateRecord {
    const db = this.getWriteDb();
    const normalizedConfig = normalizeAgentConfig(agentConfig);
    const hash = computePromptTemplateHash(systemPrompt, normalizedConfig);
    const effectiveCreatedAt =
      typeof createdAt === "number" && Number.isFinite(createdAt)
        ? Math.trunc(createdAt)
        : Date.now();

    this.prepareStmt(
      db,
      `INSERT INTO prompt_templates (hash, system_prompt, agent_config, created_at)
       VALUES (?, ?, ?, ?)
       ON CONFLICT(hash) DO NOTHING`,
    ).run(hash, systemPrompt, normalizedConfig, effectiveCreatedAt);

    const row = this.prepareStmt(
      db,
      `SELECT hash, system_prompt, agent_config, created_at
       FROM prompt_templates
       WHERE hash = ?`,
    ).get(hash);

    if (!row) {
      return {
        hash,
        systemPrompt,
        agentConfig: normalizedConfig,
        createdAt: effectiveCreatedAt,
      };
    }

    return rowToPromptTemplate(row);
  }

  public getPromptTemplate(hash: string): PromptTemplateRecord | null {
    const cleanHash = nonEmptyStringOrNull(hash);
    if (!cleanHash) return null;
    return this.runRead<PromptTemplateRecord | null>(null, (db) => {
      const row = db
        .prepare(
          `SELECT hash, system_prompt, agent_config, created_at
           FROM prompt_templates
           WHERE hash = ?`,
        )
        .get(cleanHash);
      return row ? rowToPromptTemplate(row) : null;
    });
  }

  public recordS2Session(input: RecordS2SessionInput): S2SessionSummary {
    const s2SessionId = nonEmptyStringOrNull(input.s2SessionId);
    if (!s2SessionId) {
      throw new TypeError("recordS2Session requires a non-empty s2SessionId");
    }

    return this.withTransaction(() => {
      const db = this.getWriteDb();

      let templateHash = nonEmptyStringOrNull(input.templateHash);
      if (typeof input.systemPrompt === "string" && input.systemPrompt.length > 0) {
        const template = this.ensurePromptTemplate(
          input.systemPrompt,
          input.agentConfig,
          input.createdAt ?? Date.now(),
        );
        templateHash = template.hash;
      }

      const { payloadZstd, rawBytes, compressedBytes, inferredMessageCount } = compressPayloadZstd(
        input.payload,
      );

      const messageCount =
        typeof input.messageCount === "number" &&
        Number.isFinite(input.messageCount) &&
        input.messageCount >= 0
          ? Math.trunc(input.messageCount)
          : inferredMessageCount;

      const status = nonEmptyStringOrNull(input.status) ?? "completed";

      const row = this.prepareStmt(db, UPSERT_S2_SESSION_SQL).get(
        s2SessionId,
        nonEmptyStringOrNull(input.targetSessionId),
        nonEmptyStringOrNull(input.title),
        nonEmptyStringOrNull(input.agent),
        nonEmptyStringOrNull(input.directory),
        status,
        templateHash,
        nonEmptyStringOrNull(input.modelId),
        nonEmptyStringOrNull(input.modelProvider),
        finiteIntOrNull(input.promptTokens),
        finiteIntOrNull(input.outputTokens),
        finiteIntOrNull(input.reasoningTokens),
        finiteIntOrNull(input.cacheReadTokens),
        finiteIntOrNull(input.cacheWriteTokens),
        finiteNumberOrNull(input.cost),
        messageCount,
        finiteIntOrNull(input.createdAt),
        finiteIntOrNull(input.updatedAt),
        finiteIntOrNull(input.archivedAt),
        payloadZstd,
        rawBytes,
        compressedBytes,
      );

      if (!row) {
        throw new Error(`Failed to persist S2 session ${s2SessionId}`);
      }

      return rowToS2SessionSummary(row);
    });
  }

  public getS2SessionSummary(s2SessionId: string): S2SessionSummary | null {
    const cleanId = nonEmptyStringOrNull(s2SessionId);
    if (!cleanId) return null;
    return this.runRead<S2SessionSummary | null>(null, (db) => {
      const row = db
        .prepare(
          `SELECT
             s2_session_id, target_session_id, title, agent, directory,
             status, template_hash, model_id, model_provider,
             prompt_tokens, output_tokens, reasoning_tokens,
             cache_read_tokens, cache_write_tokens, cost,
             message_count, created_at, updated_at, archived_at,
             raw_bytes, compressed_bytes
           FROM s2_sessions
           WHERE s2_session_id = ?`,
        )
        .get(cleanId);
      return row ? rowToS2SessionSummary(row) : null;
    });
  }

  public getS2Session(s2SessionId: string): S2SessionRecord | null {
    const cleanId = nonEmptyStringOrNull(s2SessionId);
    if (!cleanId) return null;
    return this.runRead<S2SessionRecord | null>(null, (db) => {
      const row = db
        .prepare(
          `SELECT
             s2_session_id, target_session_id, title, agent, directory,
             status, template_hash, model_id, model_provider,
             prompt_tokens, output_tokens, reasoning_tokens,
             cache_read_tokens, cache_write_tokens, cost,
             message_count, created_at, updated_at, archived_at,
             payload_zstd, raw_bytes, compressed_bytes
           FROM s2_sessions
           WHERE s2_session_id = ?`,
        )
        .get(cleanId);
      if (!row) return null;
      const summary = rowToS2SessionSummary(row);
      const bytes = asBytes(row.payload_zstd);
      const { payload, payloadText } = bytes
        ? decompressPayloadZstd(bytes)
        : { payload: null, payloadText: "" };
      return {
        ...summary,
        payload,
        payloadText,
      };
    });
  }

  public listS2Sessions(options: ListS2SessionsOptions = {}): S2SessionSummary[] {
    if (options.limit !== undefined && options.limit <= 0) {
      return [];
    }
    return this.runRead<S2SessionSummary[]>([], (db) => {
      const clauses: string[] = [];
      const params: SQLInputValue[] = [];

      const targetSessionId = nonEmptyStringOrNull(options.targetSessionId);
      if (targetSessionId) {
        clauses.push("target_session_id = ?");
        params.push(targetSessionId);
      }

      const status = nonEmptyStringOrNull(options.status);
      if (status) {
        clauses.push("status = ?");
        params.push(status);
      }

      const whereSql = clauses.length > 0 ? `WHERE ${clauses.join(" AND ")}` : "";
      const limit =
        typeof options.limit === "number" && Number.isFinite(options.limit) && options.limit > 0
          ? Math.trunc(options.limit)
          : DEFAULT_EVAL_QUERY_LIMIT;
      const offset =
        typeof options.offset === "number" && Number.isFinite(options.offset) && options.offset >= 0
          ? Math.trunc(options.offset)
          : 0;

      params.push(limit, offset);

      const rows = db
        .prepare(
          `SELECT
             s2_session_id, target_session_id, title, agent, directory,
             status, template_hash, model_id, model_provider,
             prompt_tokens, output_tokens, reasoning_tokens,
             cache_read_tokens, cache_write_tokens, cost,
             message_count, created_at, updated_at, archived_at,
             raw_bytes, compressed_bytes
           FROM s2_sessions
           ${whereSql}
           ORDER BY COALESCE(created_at, updated_at, archived_at, 0) DESC, rowid DESC
           LIMIT ? OFFSET ?`,
        )
        .all(...params);

      return rows.map(rowToS2SessionSummary);
    });
  }

  private upsertEvaluationRow(db: DatabaseSync, input: RecordEvaluationInput): EvaluationRecord {
    const s2SessionId = nonEmptyStringOrNull(input.s2SessionId);
    const explicitId = nonEmptyStringOrNull(input.id);
    let id = explicitId ?? (s2SessionId ? `s2:${s2SessionId}` : randomUUID());

    const sourceFormat = nonEmptyStringOrNull(input.sourceFormat) ?? "opencode";
    let timestamp =
      typeof input.timestamp === "number" && Number.isFinite(input.timestamp)
        ? Math.trunc(input.timestamp)
        : Date.now();
    let sessionId = typeof input.sessionId === "string" ? input.sessionId.trim() : "";
    let actionId = nonEmptyStringOrNull(input.actionId);
    let toolName = nonEmptyStringOrNull(input.toolName) ?? "permission";
    let commandString = typeof input.commandString === "string" ? input.commandString : "";
    let targetPath = nonEmptyStringOrNull(input.targetPath);
    let workspaceRoot = nonEmptyStringOrNull(input.workspaceRoot);
    let userPrompt = typeof input.userPrompt === "string" ? input.userPrompt : "";
    let reasoning = nonEmptyStringOrNull(input.reasoning);
    let thinking = nonEmptyStringOrNull(input.thinking);

    const rawVerdict = typeof input.verdict === "string" ? input.verdict.trim().toUpperCase() : "";
    let verdict: ClassifierVerdict = isClassifierVerdict(rawVerdict) ? rawVerdict : "UNSURE";

    const rawRisk = typeof input.riskLevel === "string" ? input.riskLevel.trim().toUpperCase() : "";
    let riskLevel = isRiskLevel(rawRisk) ? rawRisk : null;

    const rawAuth =
      typeof input.userAuthorization === "string"
        ? input.userAuthorization.trim().toUpperCase()
        : "";
    let userAuthorization = isUserAuthorization(rawAuth) ? rawAuth : null;

    let durationMs =
      typeof input.durationMs === "number" &&
      Number.isFinite(input.durationMs) &&
      input.durationMs > 0
        ? Math.round(input.durationMs)
        : 0;

    let modelId = nonEmptyStringOrNull(input.modelId);
    let modelProvider = nonEmptyStringOrNull(input.modelProvider);
    let promptTokens = finiteIntOrNull(input.promptTokens);
    let outputTokens = finiteIntOrNull(input.outputTokens);
    let reasoningTokens = finiteIntOrNull(input.reasoningTokens);
    let cost = finiteNumberOrNull(input.cost);
    let attempts = finiteIntOrNull(input.attempts);
    let error = nonEmptyStringOrNull(input.error);

    let cascadeJson = nonEmptyStringOrNull(input.cascadeJson);
    let parsedCascade: CascadeTrace | null = null;
    if (input.cascade) {
      cascadeJson = JSON.stringify(input.cascade);
      parsedCascade = input.cascade;
    } else if (cascadeJson) {
      parsedCascade = parseCascadeJson(cascadeJson);
    }

    let cascadeWinner =
      nonEmptyStringOrNull(input.cascadeWinner) ??
      (parsedCascade?.winner === "system1" || parsedCascade?.winner === "system2"
        ? parsedCascade.winner
        : null);

    const s2AbortedBool =
      input.s2Aborted !== undefined && input.s2Aborted !== null
        ? Boolean(input.s2Aborted)
        : Boolean(parsedCascade?.s2Aborted);
    let s2Aborted = s2AbortedBool ? 1 : 0;

    let sourceOrigin = nonEmptyStringOrNull(input.sourceOrigin) ?? "live";

    const absorbRetiredRow = (retired: Record<string, SQLOutputValue>) => {
      const retiredOrigin = nonEmptyStringOrNull(retired.source_origin) ?? "live";
      const retiredIsAuthoritative = retiredOrigin !== "opencode-db-import";
      const currentIsFallback = sourceOrigin === "opencode-db-import";

      if (retiredIsAuthoritative && currentIsFallback) {
        const retiredVerdict = nonEmptyStringOrNull(retired.verdict)?.toUpperCase() ?? "";
        if (isClassifierVerdict(retiredVerdict)) verdict = retiredVerdict;
        const retiredRisk = nonEmptyStringOrNull(retired.risk_level)?.toUpperCase() ?? "";
        if (isRiskLevel(retiredRisk)) riskLevel = retiredRisk;
        const retiredAuth = nonEmptyStringOrNull(retired.user_authorization)?.toUpperCase() ?? "";
        if (isUserAuthorization(retiredAuth)) userAuthorization = retiredAuth;
        reasoning = nonEmptyStringOrNull(retired.reasoning) ?? reasoning;
        toolName = nonEmptyStringOrNull(retired.tool_name) ?? toolName;
        const retDur = finiteIntOrNull(retired.duration_ms);
        if (retDur && retDur > 0) durationMs = retDur;
        const retTs = finiteIntOrNull(retired.timestamp);
        if (retTs && retTs > 0) timestamp = retTs;
        sourceOrigin = retiredOrigin;
      }

      sessionId = sessionId || (nonEmptyStringOrNull(retired.session_id) ?? "");
      actionId = actionId ?? nonEmptyStringOrNull(retired.action_id);
      commandString =
        commandString || (typeof retired.command_string === "string" ? retired.command_string : "");
      targetPath = targetPath ?? nonEmptyStringOrNull(retired.target_path);
      workspaceRoot = workspaceRoot ?? nonEmptyStringOrNull(retired.workspace_root);
      userPrompt =
        userPrompt || (typeof retired.user_prompt === "string" ? retired.user_prompt : "");
      reasoning = reasoning ?? nonEmptyStringOrNull(retired.reasoning);
      thinking = thinking ?? nonEmptyStringOrNull(retired.thinking);
      riskLevel =
        riskLevel ??
        (isRiskLevel(String(retired.risk_level ?? ""))
          ? (String(retired.risk_level) as RiskLevel)
          : null);
      userAuthorization =
        userAuthorization ??
        (isUserAuthorization(String(retired.user_authorization ?? ""))
          ? (String(retired.user_authorization) as UserAuthorization)
          : null);
      modelId = modelId ?? nonEmptyStringOrNull(retired.model_id);
      modelProvider = modelProvider ?? nonEmptyStringOrNull(retired.model_provider);
      promptTokens = promptTokens ?? finiteIntOrNull(retired.prompt_tokens);
      outputTokens = outputTokens ?? finiteIntOrNull(retired.output_tokens);
      reasoningTokens = reasoningTokens ?? finiteIntOrNull(retired.reasoning_tokens);
      cost = cost ?? finiteNumberOrNull(retired.cost);
      attempts = attempts ?? finiteIntOrNull(retired.attempts);
      error = error ?? nonEmptyStringOrNull(retired.error);
      cascadeJson = cascadeJson ?? nonEmptyStringOrNull(retired.cascade_json);
      cascadeWinner = cascadeWinner ?? nonEmptyStringOrNull(retired.cascade_winner);
      if (
        Number(retired.s2_aborted ?? 0) > 0 &&
        !(retiredOrigin === "opencode-db-import" && !currentIsFallback)
      ) {
        s2Aborted = 1;
      }
    };

    const existingById = this.prepareStmt(db, "SELECT * FROM evaluations WHERE id = ? LIMIT 1").get(
      id,
    );
    const existingByS2 = s2SessionId
      ? this.prepareStmt(db, "SELECT * FROM evaluations WHERE s2_session_id = ? LIMIT 1").get(
          s2SessionId,
        )
      : undefined;

    if (existingById && existingByS2 && String(existingById.id) !== String(existingByS2.id)) {
      const byIdOrigin = nonEmptyStringOrNull(existingById.source_origin) ?? "live";
      const byS2Origin = nonEmptyStringOrNull(existingByS2.source_origin) ?? "live";
      const retireById = byIdOrigin === "opencode-db-import" && byS2Origin !== "opencode-db-import";
      const retired = retireById ? existingById : existingByS2;
      const canonicalId = retireById ? String(existingByS2.id) : String(existingById.id);
      const retiredId = String(retired.id);
      absorbRetiredRow(retired);
      this.recordDedupedEvalId(retiredId, canonicalId);
      this.prepareStmt(db, "DELETE FROM evaluations WHERE id = ?").run(retiredId);
      id = canonicalId;
    } else if (!existingById && existingByS2 && String(existingByS2.id) !== id) {
      const existingS2Id = String(existingByS2.id);
      const existingS2Origin = nonEmptyStringOrNull(existingByS2.source_origin) ?? "live";
      if (sourceOrigin !== "opencode-db-import" && existingS2Origin === "opencode-db-import") {
        absorbRetiredRow(existingByS2);
        this.recordDedupedEvalId(existingS2Id, id);
        this.prepareStmt(db, "DELETE FROM evaluations WHERE id = ?").run(existingS2Id);
      } else {
        id = existingS2Id;
      }
    }

    const row = this.prepareStmt(db, UPSERT_EVALUATION_BY_ID_SQL).get(
      id,
      sourceFormat,
      timestamp,
      sessionId,
      s2SessionId,
      actionId,
      toolName,
      commandString,
      targetPath,
      workspaceRoot,
      userPrompt,
      reasoning,
      thinking,
      verdict,
      riskLevel,
      userAuthorization,
      durationMs,
      modelId,
      modelProvider,
      promptTokens,
      outputTokens,
      reasoningTokens,
      cost,
      attempts,
      error,
      cascadeJson,
      cascadeWinner,
      s2Aborted,
      sourceOrigin,
    );

    if (!row) {
      throw new Error(`Failed to persist evaluation ${id}`);
    }

    const storedS2Id = nonEmptyStringOrNull(row.s2_session_id);
    let hasS2Session = false;
    if (storedS2Id) {
      const s2Check = this.prepareStmt(
        db,
        "SELECT 1 AS present FROM s2_sessions WHERE s2_session_id = ? LIMIT 1",
      ).get(storedS2Id);
      hasS2Session = Boolean(s2Check);
    }

    return rowToEvaluationRecord(row, hasS2Session);
  }

  public linkS2SessionToEvaluation(input: LinkS2SessionInput): EvaluationRecord | null {
    const actionId = nonEmptyStringOrNull(input.actionId);
    const s2SessionId = nonEmptyStringOrNull(input.s2SessionId);
    if (!actionId || !s2SessionId) {
      throw new TypeError("linkS2SessionToEvaluation requires non-empty actionId and s2SessionId");
    }

    return this.withTransaction(() => {
      const db = this.getWriteDb();
      const existing =
        this.prepareStmt(
          db,
          "SELECT * FROM evaluations WHERE action_id = ? ORDER BY timestamp DESC LIMIT 1",
        ).get(actionId) ??
        this.prepareStmt(db, "SELECT * FROM evaluations WHERE id = ? LIMIT 1").get(actionId);

      if (!existing) {
        return null;
      }

      const s2Aborted = input.s2Aborted ? 1 : 0;
      const existingId = String(existing.id);
      const existingWinner = nonEmptyStringOrNull(existing.cascade_winner);
      if (existingWinner === "system1") {
        // System 1 already won the race: link aborted S2 session reference without overwriting S1 metrics/error/verdict
        const row = this.prepareStmt(
          db,
          `UPDATE evaluations
           SET
             s2_session_id = COALESCE(NULLIF(s2_session_id, ''), ?),
             s2_aborted = MAX(s2_aborted, ?)
           WHERE id = ?
           RETURNING *`,
        ).get(s2SessionId, s2Aborted, existingId);
        if (!row) {
          throw new Error(`Failed to link S2 session to System 1 evaluation ${existingId}`);
        }
        return rowToEvaluationRecord(row, true);
      }

      const row = this.prepareStmt(
        db,
        `UPDATE evaluations
         SET
           s2_session_id = COALESCE(NULLIF(s2_session_id, ''), ?),
           s2_aborted = MAX(s2_aborted, ?),
           thinking = COALESCE(NULLIF(thinking, ''), ?),
           model_id = COALESCE(NULLIF(model_id, ''), ?),
           model_provider = COALESCE(NULLIF(model_provider, ''), ?),
           prompt_tokens = COALESCE(prompt_tokens, ?),
           output_tokens = COALESCE(output_tokens, ?),
           reasoning_tokens = COALESCE(reasoning_tokens, ?),
           cost = COALESCE(cost, ?),
           attempts = COALESCE(attempts, ?),
           error = COALESCE(NULLIF(error, ''), ?),
           reasoning = COALESCE(NULLIF(reasoning, ''), ?)
         WHERE id = ?
         RETURNING *`,
      ).get(
        s2SessionId,
        s2Aborted,
        nonEmptyStringOrNull(input.thinking),
        nonEmptyStringOrNull(input.modelId),
        nonEmptyStringOrNull(input.modelProvider),
        finiteIntOrNull(input.promptTokens),
        finiteIntOrNull(input.outputTokens),
        finiteIntOrNull(input.reasoningTokens),
        finiteNumberOrNull(input.cost),
        finiteIntOrNull(input.attempts),
        nonEmptyStringOrNull(input.error),
        nonEmptyStringOrNull(input.reasoning),
        existingId,
      );
      if (!row) {
        throw new Error(`Failed to link S2 session to evaluation ${existingId}`);
      }
      return rowToEvaluationRecord(row, true);
    });
  }

  public recordEvaluation(input: RecordEvaluationInput): EvaluationRecord {
    return this.withTransaction(() => {
      const db = this.getWriteDb();
      return this.upsertEvaluationRow(db, input);
    });
  }

  public recordEvaluations(inputs: readonly RecordEvaluationInput[]): EvaluationRecord[] {
    if (inputs.length === 0) return [];
    return this.withTransaction(() => {
      const db = this.getWriteDb();
      return inputs.map((item) => this.upsertEvaluationRow(db, item));
    });
  }

  public getEvaluation(idOrS2SessionId: string): EvaluationRecord | null {
    const cleanKey = nonEmptyStringOrNull(idOrS2SessionId);
    if (!cleanKey) return null;
    return this.runRead<EvaluationRecord | null>(null, (db) => {
      const row = db
        .prepare(
          `SELECT
             e.*,
             CASE WHEN s.s2_session_id IS NOT NULL THEN 1 ELSE 0 END AS has_s2_session
           FROM evaluations e
           LEFT JOIN s2_sessions s ON s.s2_session_id = e.s2_session_id
           WHERE e.id = ? OR e.s2_session_id = ?
           ORDER BY CASE WHEN e.id = ? THEN 0 ELSE 1 END
           LIMIT 1`,
        )
        .get(cleanKey, cleanKey, cleanKey);
      return row ? rowToEvaluationRecord(row) : null;
    });
  }

  public queryEvaluations(options: EvaluationQueryOptions = {}): EvaluationRecord[] {
    if (options.limit !== undefined && options.limit <= 0) {
      return [];
    }

    return this.runRead<EvaluationRecord[]>([], (db) => {
      const clauses: string[] = [];
      const params: SQLInputValue[] = [];

      const sessionId = nonEmptyStringOrNull(options.sessionId);
      if (sessionId) {
        clauses.push("e.session_id = ?");
        params.push(sessionId);
      }

      const s2SessionId = nonEmptyStringOrNull(options.s2SessionId);
      if (s2SessionId) {
        clauses.push("e.s2_session_id = ?");
        params.push(s2SessionId);
      }

      const verdict = nonEmptyStringOrNull(options.verdict);
      if (verdict) {
        clauses.push("e.verdict = ?");
        params.push(verdict.toUpperCase());
      }

      const sourceFormat = nonEmptyStringOrNull(options.sourceFormat);
      if (sourceFormat) {
        clauses.push("e.source_format = ?");
        params.push(sourceFormat);
      }

      const sourceOrigin = nonEmptyStringOrNull(options.sourceOrigin);
      if (sourceOrigin) {
        clauses.push("e.source_origin = ?");
        params.push(sourceOrigin);
      }

      const cascadeWinner = nonEmptyStringOrNull(options.cascadeWinner);
      if (cascadeWinner) {
        clauses.push("e.cascade_winner = ?");
        params.push(cascadeWinner);
      }

      const toolName = nonEmptyStringOrNull(options.toolName);
      if (toolName) {
        clauses.push("e.tool_name = ?");
        params.push(toolName);
      }

      if (typeof options.since === "number" && Number.isFinite(options.since)) {
        clauses.push("e.timestamp >= ?");
        params.push(Math.trunc(options.since));
      }

      if (typeof options.until === "number" && Number.isFinite(options.until)) {
        clauses.push("e.timestamp <= ?");
        params.push(Math.trunc(options.until));
      }

      if (options.hasS2Session === true) {
        clauses.push("s.s2_session_id IS NOT NULL");
      } else if (options.hasS2Session === false) {
        clauses.push("s.s2_session_id IS NULL");
      }

      const searchTerm = nonEmptyStringOrNull(options.query ?? options.search);
      if (searchTerm) {
        const pattern = escapeSqlLikePattern(searchTerm);
        clauses.push(
          `(
            LOWER(e.tool_name) LIKE LOWER(?) ESCAPE '\\'
            OR LOWER(e.command_string) LIKE LOWER(?) ESCAPE '\\'
            OR LOWER(COALESCE(e.target_path, '')) LIKE LOWER(?) ESCAPE '\\'
            OR LOWER(e.user_prompt) LIKE LOWER(?) ESCAPE '\\'
            OR LOWER(COALESCE(e.reasoning, '')) LIKE LOWER(?) ESCAPE '\\'
            OR LOWER(e.session_id) LIKE LOWER(?) ESCAPE '\\'
            OR LOWER(COALESCE(e.s2_session_id, '')) LIKE LOWER(?) ESCAPE '\\'
            OR LOWER(COALESCE(e.error, '')) LIKE LOWER(?) ESCAPE '\\'
          )`,
        );
        params.push(pattern, pattern, pattern, pattern, pattern, pattern, pattern, pattern);
      }

      const whereSql = clauses.length > 0 ? `WHERE ${clauses.join(" AND ")}` : "";
      const orderDir = options.order === "asc" ? "ASC" : "DESC";
      const limit =
        typeof options.limit === "number" && Number.isFinite(options.limit) && options.limit > 0
          ? Math.trunc(options.limit)
          : DEFAULT_EVAL_QUERY_LIMIT;
      const offset =
        typeof options.offset === "number" && Number.isFinite(options.offset) && options.offset >= 0
          ? Math.trunc(options.offset)
          : 0;

      params.push(limit, offset);

      const rows = db
        .prepare(
          `SELECT
             e.*,
             CASE WHEN s.s2_session_id IS NOT NULL THEN 1 ELSE 0 END AS has_s2_session
           FROM evaluations e
           LEFT JOIN s2_sessions s ON s.s2_session_id = e.s2_session_id
           ${whereSql}
           ORDER BY e.timestamp ${orderDir}, e.rowid ${orderDir}
           LIMIT ? OFFSET ?`,
        )
        .all(...params);

      return rows.map((row) => rowToEvaluationRecord(row));
    });
  }

  public getEvaluationDetail(idOrS2SessionId: string): EvaluationDetail | null {
    const cleanKey = nonEmptyStringOrNull(idOrS2SessionId);
    if (!cleanKey) return null;

    return this.runRead<EvaluationDetail | null>(null, () => {
      const evaluation = this.getEvaluation(cleanKey);
      if (!evaluation) return null;

      const s2Session = evaluation.s2SessionId ? this.getS2Session(evaluation.s2SessionId) : null;
      const promptTemplate = s2Session?.templateHash
        ? this.getPromptTemplate(s2Session.templateHash)
        : null;

      return {
        evaluation,
        s2Session,
        promptTemplate,
      };
    });
  }

  public getStats(options: EvalStatsOptions = {}): EvalStats {
    return this.runRead<EvalStats>(emptyStats(), (db) => {
      const evalClauses: string[] = [];
      const evalParams: SQLInputValue[] = [];

      const sessionId = nonEmptyStringOrNull(options.sessionId);
      if (sessionId) {
        evalClauses.push("session_id = ?");
        evalParams.push(sessionId);
      }

      const sourceFormat = nonEmptyStringOrNull(options.sourceFormat);
      if (sourceFormat) {
        evalClauses.push("source_format = ?");
        evalParams.push(sourceFormat);
      }

      if (typeof options.since === "number" && Number.isFinite(options.since)) {
        evalClauses.push("timestamp >= ?");
        evalParams.push(Math.trunc(options.since));
      }

      if (typeof options.until === "number" && Number.isFinite(options.until)) {
        evalClauses.push("timestamp <= ?");
        evalParams.push(Math.trunc(options.until));
      }

      const evalWhereSql = evalClauses.length > 0 ? `WHERE ${evalClauses.join(" AND ")}` : "";

      const evalRow = db
        .prepare(
          `SELECT
             COUNT(*) AS total,
             COALESCE(SUM(CASE WHEN verdict = 'ALLOW' THEN 1 ELSE 0 END), 0) AS allow_count,
             COALESCE(SUM(CASE WHEN verdict = 'BLOCK' THEN 1 ELSE 0 END), 0) AS block_count,
             COALESCE(SUM(CASE WHEN verdict = 'UNSURE' THEN 1 ELSE 0 END), 0) AS unsure_count,
             COALESCE(SUM(duration_ms), 0) AS duration_sum,
             COALESCE(SUM(CASE WHEN cascade_winner = 'system1' THEN 1 ELSE 0 END), 0) AS s1_fast_path_count,
             COALESCE(SUM(CASE WHEN cascade_winner = 'system2' OR (cascade_winner IS NULL AND s2_session_id IS NOT NULL) THEN 1 ELSE 0 END), 0) AS s2_count,
             COALESCE(SUM(CASE WHEN s2_aborted = 1 THEN 1 ELSE 0 END), 0) AS s2_aborted_count,
             COALESCE(SUM(prompt_tokens), 0) AS total_prompt_tokens,
             COALESCE(SUM(output_tokens), 0) AS total_output_tokens,
             COALESCE(SUM(reasoning_tokens), 0) AS total_reasoning_tokens,
             COALESCE(SUM(cost), 0) AS total_cost
           FROM evaluations
           ${evalWhereSql}`,
        )
        .get(...evalParams);

      const s2Clauses: string[] = [];
      const s2Params: SQLInputValue[] = [];
      if (sessionId) {
        s2Clauses.push("target_session_id = ?");
        s2Params.push(sessionId);
      }
      if (sourceFormat) {
        s2Clauses.push(
          "s2_session_id IN (SELECT s2_session_id FROM evaluations WHERE source_format = ? AND s2_session_id IS NOT NULL)",
        );
        s2Params.push(sourceFormat);
      }
      if (typeof options.since === "number" && Number.isFinite(options.since)) {
        s2Clauses.push("COALESCE(created_at, updated_at, archived_at, 0) >= ?");
        s2Params.push(Math.trunc(options.since));
      }
      if (typeof options.until === "number" && Number.isFinite(options.until)) {
        s2Clauses.push("COALESCE(created_at, updated_at, archived_at, 0) <= ?");
        s2Params.push(Math.trunc(options.until));
      }
      const s2WhereSql = s2Clauses.length > 0 ? `WHERE ${s2Clauses.join(" AND ")}` : "";

      const s2Row = db
        .prepare(
          `SELECT
             COUNT(*) AS s2_session_count,
             COALESCE(SUM(raw_bytes), 0) AS total_raw_bytes,
             COALESCE(SUM(compressed_bytes), 0) AS total_compressed_bytes
           FROM s2_sessions
           ${s2WhereSql}`,
        )
        .get(...s2Params);

      const tplRow =
        s2Clauses.length > 0
          ? db
              .prepare(
                `SELECT COUNT(DISTINCT template_hash) AS prompt_template_count
                 FROM s2_sessions
                 ${s2WhereSql}
                 ${s2WhereSql ? "AND" : "WHERE"} template_hash IS NOT NULL`,
              )
              .get(...s2Params)
          : db.prepare("SELECT COUNT(*) AS prompt_template_count FROM prompt_templates").get();

      const total = finiteIntOrNull(evalRow?.total) ?? 0;
      const allow = finiteIntOrNull(evalRow?.allow_count) ?? 0;
      const block = finiteIntOrNull(evalRow?.block_count) ?? 0;
      const unsure = finiteIntOrNull(evalRow?.unsure_count) ?? 0;
      const durationSum = finiteNumberOrNull(evalRow?.duration_sum) ?? 0;
      const s1FastPathCount = finiteIntOrNull(evalRow?.s1_fast_path_count) ?? 0;

      const avgLatencyMs = total > 0 ? Math.round(durationSum / total) : 0;
      const s1FastPathPct = total > 0 ? Math.round((s1FastPathCount / total) * 100) : 0;

      return {
        total,
        allow,
        block,
        unsure,
        avgLatencyMs,
        s1FastPathCount,
        s1FastPathPct,
        s2Count: finiteIntOrNull(evalRow?.s2_count) ?? 0,
        s2AbortedCount: finiteIntOrNull(evalRow?.s2_aborted_count) ?? 0,
        totalPromptTokens: finiteIntOrNull(evalRow?.total_prompt_tokens) ?? 0,
        totalOutputTokens: finiteIntOrNull(evalRow?.total_output_tokens) ?? 0,
        totalReasoningTokens: finiteIntOrNull(evalRow?.total_reasoning_tokens) ?? 0,
        totalCost: finiteNumberOrNull(evalRow?.total_cost) ?? 0,
        s2SessionCount: finiteIntOrNull(s2Row?.s2_session_count) ?? 0,
        promptTemplateCount: finiteIntOrNull(tplRow?.prompt_template_count) ?? 0,
        totalRawBytes: finiteIntOrNull(s2Row?.total_raw_bytes) ?? 0,
        totalCompressedBytes: finiteIntOrNull(s2Row?.total_compressed_bytes) ?? 0,
      };
    });
  }

  public getExistingKeys(): {
    evalIds: Set<string>;
    evalS2Ids: Set<string>;
    dedupedEvalIds: Set<string>;
    s2SessionIds: Set<string>;
    s2TargetMap: Map<string, string | null>;
  } {
    const empty = {
      evalIds: new Set<string>(),
      evalS2Ids: new Set<string>(),
      dedupedEvalIds: new Set<string>(),
      s2SessionIds: new Set<string>(),
      s2TargetMap: new Map<string, string | null>(),
    };
    return this.runRead(empty, (db) => {
      const evalIds = new Set<string>();
      const evalS2Ids = new Set<string>();
      const dedupedEvalIds = new Set<string>();
      const s2SessionIds = new Set<string>();
      const s2TargetMap = new Map<string, string | null>();

      for (const row of this.prepareStmt(db, "SELECT id, s2_session_id FROM evaluations").all()) {
        const id = nonEmptyStringOrNull(row.id);
        if (id) evalIds.add(id);
        const s2Id = nonEmptyStringOrNull(row.s2_session_id);
        if (s2Id) evalS2Ids.add(s2Id);
      }

      for (const row of this.prepareStmt(db, "SELECT id FROM deduped_eval_ids").all()) {
        const id = nonEmptyStringOrNull(row.id);
        if (id) dedupedEvalIds.add(id);
      }

      for (const row of this.prepareStmt(
        db,
        "SELECT s2_session_id, target_session_id FROM s2_sessions",
      ).all()) {
        const s2Id = nonEmptyStringOrNull(row.s2_session_id);
        if (s2Id) {
          s2SessionIds.add(s2Id);
          s2TargetMap.set(s2Id, nonEmptyStringOrNull(row.target_session_id));
        }
      }

      return { evalIds, evalS2Ids, dedupedEvalIds, s2SessionIds, s2TargetMap };
    });
  }

  public getDedupedEvalIds(): Set<string> {
    return this.runRead<Set<string>>(new Set<string>(), (db) => {
      const rows = db.prepare("SELECT id FROM deduped_eval_ids").all();
      const ids = new Set<string>();
      for (const row of rows) {
        const id = nonEmptyStringOrNull(row.id);
        if (id) ids.add(id);
      }
      return ids;
    });
  }

  public recordDedupedEvalId(id: string, targetId: string, createdAt: number = Date.now()): void {
    const cleanId = nonEmptyStringOrNull(id);
    const cleanTargetId = nonEmptyStringOrNull(targetId);
    if (!cleanId || !cleanTargetId) {
      throw new TypeError("recordDedupedEvalId requires non-empty id and targetId");
    }
    const effectiveCreatedAt =
      typeof createdAt === "number" && Number.isFinite(createdAt)
        ? Math.trunc(createdAt)
        : Date.now();
    const db = this.getWriteDb();
    db.prepare(
      `INSERT INTO deduped_eval_ids (id, target_id, created_at)
       VALUES (?, ?, ?)
       ON CONFLICT(id) DO UPDATE SET
         target_id = excluded.target_id,
         created_at = excluded.created_at`,
    ).run(cleanId, cleanTargetId, effectiveCreatedAt);
  }

  public listUnlinkedOpenCodeJsonlEvaluations(): EvaluationRecord[] {
    return this.runRead<EvaluationRecord[]>([], (db) => {
      const rows = db
        .prepare(
          `SELECT
             e.*,
             CASE WHEN s.s2_session_id IS NOT NULL THEN 1 ELSE 0 END AS has_s2_session
           FROM evaluations e
           LEFT JOIN s2_sessions s ON s.s2_session_id = e.s2_session_id
           WHERE e.source_format = 'opencode'
             AND e.source_origin = 'jsonl-import'
             AND e.s2_session_id IS NULL
             AND NOT (
               COALESCE(e.cascade_winner, '') = 'system1'
               AND COALESCE(e.cascade_json, '') LIKE '%"mode":"cascade"%'
             )
           ORDER BY e.timestamp ASC, e.id ASC`,
        )
        .all();
      return rows.map((row) => rowToEvaluationRecord(row));
    });
  }

  public listCorrelationCandidateDbEvaluations(): EvaluationRecord[] {
    return this.runRead<EvaluationRecord[]>([], (db) => {
      const rows = db
        .prepare(
          `SELECT
             e.*,
             CASE WHEN s.s2_session_id IS NOT NULL THEN 1 ELSE 0 END AS has_s2_session
           FROM evaluations e
           LEFT JOIN s2_sessions s ON s.s2_session_id = e.s2_session_id
           WHERE e.source_format = 'opencode'
             AND e.source_origin = 'opencode-db-import'
             AND e.s2_session_id IS NOT NULL
             AND e.session_id = ''
             AND e.cascade_json IS NULL
           ORDER BY e.timestamp ASC, e.id ASC`,
        )
        .all();
      return rows.map((row) => rowToEvaluationRecord(row));
    });
  }

  public mergeCorrelatedEvaluation(input: MergeCorrelatedEvaluationInput): {
    s2TargetPopulated: boolean;
  } {
    const sourceId = nonEmptyStringOrNull(input.sourceId);
    const targetId = nonEmptyStringOrNull(input.targetId);
    if (!sourceId || !targetId) {
      throw new TypeError("mergeCorrelatedEvaluation requires non-empty sourceId and targetId");
    }
    if (sourceId === targetId) {
      throw new Error("Cannot merge an evaluation row into itself");
    }

    const sessionId = typeof input.sessionId === "string" ? input.sessionId.trim() : "";
    const rawVerdict = typeof input.verdict === "string" ? input.verdict.trim().toUpperCase() : "";
    const verdict = isClassifierVerdict(rawVerdict) ? rawVerdict : "UNSURE";

    const rawRisk = typeof input.riskLevel === "string" ? input.riskLevel.trim().toUpperCase() : "";
    const riskLevel = isRiskLevel(rawRisk) ? rawRisk : null;

    const rawAuth =
      typeof input.userAuthorization === "string"
        ? input.userAuthorization.trim().toUpperCase()
        : "";
    const userAuthorization = isUserAuthorization(rawAuth) ? rawAuth : null;

    const reasoning = nonEmptyStringOrNull(input.reasoning);
    const userPrompt = typeof input.userPrompt === "string" ? input.userPrompt : "";
    const durationMs =
      typeof input.durationMs === "number" &&
      Number.isFinite(input.durationMs) &&
      input.durationMs > 0
        ? Math.round(input.durationMs)
        : 0;
    const timestamp =
      typeof input.timestamp === "number" && Number.isFinite(input.timestamp) && input.timestamp > 0
        ? Math.trunc(input.timestamp)
        : 0;

    const cascadeJson = nonEmptyStringOrNull(input.cascadeJson);
    const cascadeWinner = nonEmptyStringOrNull(input.cascadeWinner);
    const s2Aborted = input.s2Aborted ? 1 : 0;
    const s2SessionId = nonEmptyStringOrNull(input.s2SessionId);
    const createdAt =
      typeof input.createdAt === "number" && Number.isFinite(input.createdAt)
        ? Math.trunc(input.createdAt)
        : Date.now();

    return this.withTransaction(() => {
      const db = this.getWriteDb();

      const updateRes = db
        .prepare(
          `UPDATE evaluations
           SET
             session_id = COALESCE(NULLIF(?, ''), session_id),
             verdict = COALESCE(NULLIF(?, ''), verdict),
             risk_level = COALESCE(NULLIF(?, ''), risk_level),
             user_authorization = COALESCE(NULLIF(?, ''), user_authorization),
             reasoning = COALESCE(NULLIF(?, ''), reasoning),
             user_prompt = CASE WHEN ? != '' THEN ? ELSE user_prompt END,
             duration_ms = CASE WHEN ? > 0 THEN ? ELSE duration_ms END,
             timestamp = CASE WHEN ? > 0 THEN ? ELSE timestamp END,
             cascade_json = COALESCE(NULLIF(?, ''), cascade_json),
             cascade_winner = COALESCE(NULLIF(?, ''), cascade_winner),
             s2_aborted = MAX(s2_aborted, ?)
           WHERE id = ?`,
        )
        .run(
          sessionId,
          verdict,
          riskLevel,
          userAuthorization,
          reasoning,
          userPrompt,
          userPrompt,
          durationMs,
          durationMs,
          timestamp,
          timestamp,
          cascadeJson,
          cascadeWinner,
          s2Aborted,
          targetId,
        );

      if (Number(updateRes.changes ?? 0) === 0) {
        throw new Error(`Target evaluation row not found: ${targetId}`);
      }

      let s2TargetPopulated = false;
      if (s2SessionId && sessionId) {
        const s2Res = db
          .prepare(
            `UPDATE s2_sessions
             SET target_session_id = ?
             WHERE s2_session_id = ?
               AND (target_session_id IS NULL OR target_session_id = '')`,
          )
          .run(sessionId, s2SessionId);
        s2TargetPopulated = Number(s2Res.changes ?? 0) > 0;
      }

      this.recordDedupedEvalId(sourceId, targetId, createdAt);
      db.prepare("DELETE FROM evaluations WHERE id = ?").run(sourceId);

      return { s2TargetPopulated };
    });
  }
}
