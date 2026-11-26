import { createHash } from "node:crypto";
import os from "node:os";
import path from "node:path";
import type { SQLOutputValue } from "node:sqlite";
import { zstdCompressSync, zstdDecompressSync } from "node:zlib";
import { isClassifierVerdict, isRiskLevel, isUserAuthorization } from "../classifier.js";
import { isRecord } from "../config.js";
import type { CascadeTrace, ClassifierVerdict, RiskLevel, UserAuthorization } from "../types.js";
import type {
  EvalStats,
  EvaluationRecord,
  PromptTemplateRecord,
  S2SessionSummary,
} from "./types.js";

export function expandDbPath(inputPath: string): string {
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

export function stableSerializeJson(value: unknown, seen: WeakSet<object> = new WeakSet()): string {
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

export function normalizeAgentConfig(
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

export function nonEmptyStringOrNull(val: unknown): string | null {
  if (typeof val !== "string") return null;
  const trimmed = val.trim();
  return trimmed.length > 0 ? trimmed : null;
}

export function stringOrEmpty(val: unknown): string {
  return typeof val === "string" ? val : "";
}

export function finiteNumberOrNull(val: unknown): number | null {
  if (typeof val === "number" && Number.isFinite(val)) return val;
  if (typeof val === "bigint") return Number(val);
  return null;
}

export function finiteIntOrNull(val: unknown): number | null {
  const num = finiteNumberOrNull(val);
  return num !== null ? Math.trunc(num) : null;
}

export function asBytes(val: unknown): Uint8Array | null {
  if (val instanceof Uint8Array) return val;
  return null;
}

export function normalizeStoredVerdict(val: unknown): ClassifierVerdict {
  if (typeof val === "string") {
    const upper = val.trim().toUpperCase();
    if (isClassifierVerdict(upper)) return upper;
  }
  return "UNSURE";
}

export function normalizeStoredRiskLevel(val: unknown): RiskLevel | null {
  if (typeof val === "string") {
    const upper = val.trim().toUpperCase();
    if (isRiskLevel(upper)) return upper;
  }
  return null;
}

export function normalizeStoredUserAuthorization(val: unknown): UserAuthorization | null {
  if (typeof val === "string") {
    const upper = val.trim().toUpperCase();
    if (isUserAuthorization(upper)) return upper;
  }
  return null;
}

export function normalizeCascadeWinner(val: unknown): "system1" | "system2" | null {
  if (val === "system1" || val === "system2") return val;
  return null;
}

export function parseCascadeJson(raw: string | null): CascadeTrace | null {
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

export function compressPayloadZstd(payload: unknown): {
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

export function decompressPayloadZstd(compressed: Uint8Array): {
  payload: unknown;
  payloadText: string;
} {
  const raw = zstdDecompressSync(compressed);
  const payloadText = raw.toString("utf8");
  try {
    const payload: unknown = JSON.parse(payloadText);
    return { payload, payloadText };
  } catch {
    return { payload: payloadText, payloadText };
  }
}

export function isMissingTableError(err: unknown): boolean {
  const message = err instanceof Error ? err.message : String(err);
  return message.toLowerCase().includes("no such table");
}

export function escapeSqlLikePattern(term: string): string {
  const escaped = term.replace(/\\/g, "\\\\").replace(/%/g, "\\%").replace(/_/g, "\\_");
  return `%${escaped}%`;
}

export function rowToPromptTemplate(row: Record<string, SQLOutputValue>): PromptTemplateRecord {
  return {
    hash: String(row.hash ?? ""),
    systemPrompt: String(row.system_prompt ?? ""),
    agentConfig: typeof row.agent_config === "string" ? row.agent_config : null,
    createdAt: finiteIntOrNull(row.created_at) ?? 0,
  };
}

export function rowToS2SessionSummary(row: Record<string, SQLOutputValue>): S2SessionSummary {
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

export function rowToEvaluationRecord(
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

export function emptyStats(): EvalStats {
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
