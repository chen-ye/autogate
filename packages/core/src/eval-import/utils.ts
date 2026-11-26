import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { DatabaseSync } from "node:sqlite";
import { isRiskLevel, isUserAuthorization } from "../classifier.js";
import { isRecord } from "../config.js";
import type { CascadeTrace, RiskLevel, UserAuthorization } from "../types.js";
import type { SqliteFileSizes } from "./types.js";

export function expandImporterPath(inputPath: string): string {
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

export function getDefaultJsonlPaths(): string[] {
  const home = os.homedir();
  const raw = [
    path.join(home, ".omp", "logs", "autogate-evals.jsonl"),
    path.join(home, ".config", "autogate", "logs", "evals.jsonl"),
  ];
  return Array.from(new Set(raw.map((p) => path.resolve(p))));
}

export function getDefaultOpenCodeDbPath(): string {
  return path.resolve(path.join(os.homedir(), ".local", "share", "opencode", "opencode.db"));
}

export function measureSqliteFileSizes(dbPath: string): SqliteFileSizes {
  if (!dbPath || dbPath === ":memory:") {
    return {
      exists: false,
      dbBytes: 0,
      walBytes: 0,
      shmBytes: 0,
      totalBytes: 0,
    };
  }
  const resolved = expandImporterPath(dbPath);
  const statBytes = (p: string): number => {
    try {
      if (!fs.existsSync(p)) return 0;
      return fs.statSync(p).size;
    } catch {
      return 0;
    }
  };
  const exists = fs.existsSync(resolved);
  const dbBytes = statBytes(resolved);
  const walBytes = statBytes(`${resolved}-wal`);
  const shmBytes = statBytes(`${resolved}-shm`);
  return {
    exists,
    dbBytes,
    walBytes,
    shmBytes,
    totalBytes: dbBytes + walBytes + shmBytes,
  };
}

export function nonEmptyString(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

export function rawStringOrUndefined(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

export function finiteNumber(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "bigint") return Number(value);
  return undefined;
}

export function finiteInt(value: unknown): number | undefined {
  const num = finiteNumber(value);
  return num !== undefined ? Math.trunc(num) : undefined;
}

export function nonNegInt(value: unknown): number | undefined {
  const n = finiteInt(value);
  return n !== undefined && n >= 0 ? n : undefined;
}

export function parseJsonObjectSafe(raw: unknown): Record<string, unknown> | undefined {
  if (isRecord(raw)) return raw;
  if (typeof raw !== "string" || !raw.trim()) return undefined;
  try {
    const parsed: unknown = JSON.parse(raw);
    return isRecord(parsed) ? parsed : undefined;
  } catch {
    return undefined;
  }
}

export function parseJsonUnknownSafe(raw: unknown): unknown {
  if (typeof raw !== "string") return raw;
  const trimmed = raw.trim();
  if (!trimmed) return undefined;
  try {
    return JSON.parse(trimmed) as unknown;
  } catch {
    return undefined;
  }
}

export function normalizeRiskLevel(val: unknown): RiskLevel | null {
  if (typeof val !== "string") return null;
  const upper = val.trim().toUpperCase();
  return isRiskLevel(upper) ? upper : null;
}

export function normalizeUserAuth(val: unknown): UserAuthorization | null {
  if (typeof val !== "string") return null;
  const upper = val.trim().toUpperCase();
  return isUserAuthorization(upper) ? upper : null;
}

export function normalizeCascade(val: unknown): CascadeTrace | null {
  if (!isRecord(val)) return null;
  if (
    (val.mode === "race" || val.mode === "cascade") &&
    (val.winner === "system1" || val.winner === "system2")
  ) {
    return val as unknown as CascadeTrace;
  }
  return null;
}

export function getExistingTables(db: DatabaseSync): Set<string> {
  const rows = db
    .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")
    .all();
  return new Set(rows.map((r) => String(r.name ?? "")));
}

export function getTableColumns(
  db: DatabaseSync,
  tableName: "session_v2" | "session",
): Set<string> {
  const rows = db.prepare(`PRAGMA table_info(${tableName})`).all();
  const columns = new Set<string>();
  for (const row of rows) {
    const name = nonEmptyString(row.name);
    if (name) {
      columns.add(name);
    }
  }
  return columns;
}

export function extractTargetSessionIdFromRow(
  parentId: unknown,
  metadataRaw: unknown,
  sessionId: string,
): string | null {
  const parent = nonEmptyString(parentId);
  if (parent && parent !== sessionId) {
    return parent;
  }
  const meta = parseJsonObjectSafe(metadataRaw);
  if (meta) {
    const candidate =
      nonEmptyString(meta.targetSessionId) ??
      nonEmptyString(meta.target_session_id) ??
      nonEmptyString(meta.sessionID) ??
      nonEmptyString(meta.sessionId);
    if (candidate && candidate !== sessionId) {
      return candidate;
    }
  }
  return null;
}
