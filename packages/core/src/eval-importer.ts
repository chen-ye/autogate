import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import readline from "node:readline";
import { DatabaseSync, type SQLInputValue, type SQLOutputValue } from "node:sqlite";
import { loadEvalAgentDefinition, parseModelRef, PASSIVE_EVALUATOR_DIRECTIVE } from "./agent.js";
import {
  isClassifierVerdict,
  isRiskLevel,
  isUserAuthorization,
  parseVerdict,
} from "./classifier.js";
import { resolveEvalDbFile } from "./config.js";
import {
  AutoGateEvalStore,
  type EvaluationRecord,
  type MergeCorrelatedEvaluationInput,
  type RecordEvaluationInput,
  type S2SessionStatus,
} from "./eval-store.js";
import type { CascadeTrace, ClassifierVerdict, RiskLevel, UserAuthorization } from "./types.js";

export const DEFAULT_IMPORT_BATCH_SIZE = 250;
export const DEFAULT_OPENCODE_BUSY_TIMEOUT_MS = 5000;
export const DEFAULT_MIN_DELETE_AGE_MINUTES = 10;
const AUTOGATE_EVAL_TITLE_PREFIX = "[auto-gate-eval]";
const AUTOGATE_PROMPT_MARKER = "You are an autonomous security and permission classifier";

export interface SqliteFileSizes {
  exists: boolean;
  dbBytes: number;
  walBytes: number;
  shmBytes: number;
  totalBytes: number;
}

export interface ImportJsonlOptions {
  store?: AutoGateEvalStore;
  evalDbFile?: string;
  jsonlFiles?: readonly string[];
  opencodeDbPath?: string;
  skipOpenCodeDbLookup?: boolean;
  dryRun?: boolean;
  batchSize?: number;
  ignoreMissingFiles?: boolean;
}

export interface JsonlFileImportSummary {
  filePath: string;
  exists: boolean;
  totalLines: number;
  blankLines: number;
  malformedLines: number;
  parsedRecords: number;
  importedCount: number;
  insertedCount: number;
  mergedCount: number;
  linkedS2Count: number;
  recoveredTargetSessionCount: number;
}

export interface ImportJsonlResult {
  evalDbFile: string;
  dryRun: boolean;
  files: JsonlFileImportSummary[];
  totalLines: number;
  blankLines: number;
  malformedLines: number;
  parsedRecords: number;
  importedCount: number;
  insertedCount: number;
  mergedCount: number;
  linkedS2Count: number;
  recoveredTargetSessionCount: number;
}

export interface ImportOpenCodeDbOptions {
  store?: AutoGateEvalStore;
  evalDbFile?: string;
  opencodeDbPath?: string;
  dryRun?: boolean;
  deleteOpenCodeSessions?: boolean;
  deleteAutoGateChildren?: boolean;
  minAgeMinutes?: number;
  vacuum?: boolean;
  batchSize?: number;
  busyTimeoutMs?: number;
}

export interface ImportOpenCodeDbResult {
  evalDbFile: string;
  opencodeDbPath: string;
  opencodeDbFound: boolean;
  dryRun: boolean;
  v2SessionsFound: number;
  v1SessionsFound: number;
  overlappingSessionsDeduplicated: number;
  uniqueSessionsFound: number;
  s2SessionsInserted: number;
  s2SessionsExisting: number;
  evaluationsInserted: number;
  evaluationsMerged: number;
  promptTemplatesBefore: number;
  promptTemplatesAfter: number;
  deletedV2Sessions: number;
  deletedV1Sessions: number;
  deletedChildSessions: number;
  skippedUnsafeForDeletion: number;
  vacuumed: boolean;
  skippedReason?: string;
}

export interface CorrelateUnlinkedJsonlOptions {
  store?: AutoGateEvalStore;
  evalDbFile?: string;
  dryRun?: boolean;
}

export interface CorrelateUnlinkedJsonlResult {
  evalDbFile: string;
  dryRun: boolean;
  unlinkedJsonlFound: number;
  candidateDbRowsFound: number;
  correlatedCount: number;
  unmatchedCount: number;
  s1WinnerMergedCount: number;
  s2WinnerMergedCount: number;
  s2TargetsPopulatedCount: number;
}

export interface MigrateToEvalStoreOptions {
  evalDbFile?: string;
  opencodeDbPath?: string;
  jsonlFiles?: readonly string[];
  skipJsonl?: boolean;
  skipOpenCodeDb?: boolean;
  skipCorrelate?: boolean;
  dryRun?: boolean;
  deleteOpenCodeSessions?: boolean;
  deleteAutoGateChildren?: boolean;
  minAgeMinutes?: number;
  vacuum?: boolean;
  batchSize?: number;
}

export interface MigrateToEvalStoreResult {
  evalDbFile: string;
  opencodeDbPath: string;
  dryRun: boolean;
  skipJsonl: boolean;
  skipOpenCodeDb: boolean;
  skipCorrelate: boolean;
  deleteOpenCodeSessions: boolean;
  deleteAutoGateChildren: boolean;
  vacuumRequested: boolean;
  jsonl?: ImportJsonlResult;
  opencodeDb?: ImportOpenCodeDbResult;
  correlate?: CorrelateUnlinkedJsonlResult;
  evalDbSizeBefore: SqliteFileSizes;
  evalDbSizeAfter: SqliteFileSizes;
  opencodeDbSizeBefore: SqliteFileSizes;
  opencodeDbSizeAfter: SqliteFileSizes;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

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

export function computeJsonlLineId(filePath: string, lineNumber: number, rawLine: string): string {
  const absPath = path.resolve(filePath);
  const digest = createHash("sha256").update(`${absPath}:${lineNumber}:${rawLine}`).digest("hex");
  return `jsonl:${digest}`;
}

function nonEmptyString(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function rawStringOrUndefined(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function finiteNumber(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "bigint") return Number(value);
  return undefined;
}

function finiteInt(value: unknown): number | undefined {
  const num = finiteNumber(value);
  return num !== undefined ? Math.trunc(num) : undefined;
}

function nonNegInt(value: unknown): number | undefined {
  const n = finiteInt(value);
  return n !== undefined && n >= 0 ? n : undefined;
}

function parseTimestampMs(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) {
    return Math.trunc(value);
  }
  if (typeof value === "bigint") {
    return Number(value);
  }
  if (typeof value === "string") {
    const trimmed = value.trim();
    if (!trimmed) return undefined;
    if (/^-?\d+$/.test(trimmed)) {
      const n = Number(trimmed);
      if (Number.isFinite(n)) return Math.trunc(n);
    }
    const parsed = Date.parse(trimmed);
    if (Number.isFinite(parsed)) {
      return Math.trunc(parsed);
    }
  }
  return undefined;
}

function parseJsonObjectSafe(raw: unknown): Record<string, unknown> | undefined {
  if (isRecord(raw)) return raw;
  if (typeof raw !== "string" || !raw.trim()) return undefined;
  try {
    const parsed: unknown = JSON.parse(raw);
    return isRecord(parsed) ? parsed : undefined;
  } catch {
    return undefined;
  }
}

function parseJsonUnknownSafe(raw: unknown): unknown {
  if (typeof raw !== "string") return raw;
  const trimmed = raw.trim();
  if (!trimmed) return undefined;
  try {
    return JSON.parse(trimmed) as unknown;
  } catch {
    return undefined;
  }
}

function normalizeRiskLevel(val: unknown): RiskLevel | null {
  if (typeof val !== "string") return null;
  const upper = val.trim().toUpperCase();
  return isRiskLevel(upper) ? upper : null;
}

function normalizeUserAuth(val: unknown): UserAuthorization | null {
  if (typeof val !== "string") return null;
  const upper = val.trim().toUpperCase();
  return isUserAuthorization(upper) ? upper : null;
}

function normalizeCascade(val: unknown): CascadeTrace | null {
  if (!isRecord(val)) return null;
  if (
    (val.mode === "race" || val.mode === "cascade") &&
    (val.winner === "system1" || val.winner === "system2")
  ) {
    return val as unknown as CascadeTrace;
  }
  return null;
}

function loadExistingEvalKeys(store: AutoGateEvalStore): {
  evalIds: Set<string>;
  evalS2Ids: Set<string>;
  dedupedEvalIds: Set<string>;
  s2SessionIds: Set<string>;
  s2TargetMap: Map<string, string | null>;
} {
  return store.getExistingKeys();
}

function getExistingTables(db: DatabaseSync): Set<string> {
  const rows = db
    .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")
    .all();
  return new Set(rows.map((r) => String(r.name ?? "")));
}

function getTableColumns(db: DatabaseSync, tableName: "session_v2" | "session"): Set<string> {
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

function extractTargetSessionIdFromRow(
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

export function readOpenCodeS2TargetMap(
  opencodeDbPath: string,
  busyTimeoutMs: number = DEFAULT_OPENCODE_BUSY_TIMEOUT_MS,
): Map<string, string | null> {
  const map = new Map<string, string | null>();
  const resolved = expandImporterPath(opencodeDbPath);
  if (!resolved || !fs.existsSync(resolved)) {
    return map;
  }

  const db = new DatabaseSync(resolved, {
    readOnly: true,
    timeout: busyTimeoutMs,
  });
  try {
    db.exec(`PRAGMA busy_timeout = ${Math.trunc(busyTimeoutMs)};`);
    const tables = getExistingTables(db);

    const readFromTable = (tableName: "session_v2" | "session") => {
      if (!tables.has(tableName)) return;
      const cols = getTableColumns(db, tableName);
      if (!cols.has("id") || !cols.has("title")) return;
      const parentExpr = cols.has("parent_id") ? "parent_id" : "NULL AS parent_id";
      const metadataExpr = cols.has("metadata") ? "metadata" : "NULL AS metadata";
      const rows = db
        .prepare(
          `SELECT id, ${parentExpr}, title, ${metadataExpr} FROM ${tableName} WHERE title LIKE '[auto-gate-eval]%'`,
        )
        .all();
      for (const row of rows) {
        const id = nonEmptyString(row.id);
        const title = typeof row.title === "string" ? row.title : "";
        if (!id || !title.startsWith(AUTOGATE_EVAL_TITLE_PREFIX)) continue;
        const target = extractTargetSessionIdFromRow(row.parent_id, row.metadata, id);
        if (!map.has(id) || (target !== null && map.get(id) === null)) {
          map.set(id, target);
        }
      }
    };

    readFromTable("session_v2");
    readFromTable("session");
  } finally {
    db.close();
  }

  return map;
}

interface ParsedJsonlOutcome {
  kind: "blank" | "malformed" | "valid";
  input?: RecordEvaluationInput;
  linkedS2?: boolean;
  recoveredTargetSession?: boolean;
}

function serializeCommandValue(val: unknown): string | undefined {
  if (typeof val === "string") return val;
  if (Array.isArray(val) || isRecord(val)) {
    return JSON.stringify(val);
  }
  return undefined;
}

function parseJsonlEntry(
  rawLine: string,
  filePath: string,
  lineNumber: number,
  s2TargetMap: ReadonlyMap<string, string | null>,
): ParsedJsonlOutcome {
  if (rawLine.trim().length === 0) {
    return { kind: "blank" };
  }

  let parsedRaw: unknown;
  try {
    parsedRaw = JSON.parse(rawLine);
  } catch {
    return { kind: "malformed" };
  }

  if (!isRecord(parsedRaw)) {
    return { kind: "malformed" };
  }

  const parsed = parsedRaw;
  const actionObj = isRecord(parsed.action) ? parsed.action : undefined;
  const decisionObj = isRecord(parsed.decision) ? parsed.decision : undefined;
  const inferenceObj = isRecord(parsed.inference) ? parsed.inference : undefined;
  const modelObj = isRecord(parsed.model) ? parsed.model : undefined;
  const hasNestedSchema = Boolean(
    actionObj || decisionObj || (inferenceObj && parsed.verdict === undefined),
  );

  const id = computeJsonlLineId(filePath, lineNumber, rawLine);

  if (hasNestedSchema) {
    const rawVerdict =
      nonEmptyString(decisionObj?.verdict) ??
      nonEmptyString(parsed.verdict) ??
      (typeof parsed.error === "string" && actionObj ? "UNSURE" : undefined);
    const upperVerdict = rawVerdict?.toUpperCase();
    if (!upperVerdict || !isClassifierVerdict(upperVerdict)) {
      return { kind: "malformed" };
    }

    const rawSessionId =
      nonEmptyString(actionObj?.sessionID) ??
      nonEmptyString(actionObj?.sessionId) ??
      nonEmptyString(parsed.sessionID) ??
      nonEmptyString(parsed.sessionId) ??
      "";
    const explicitS2 =
      nonEmptyString(parsed.s2SessionId) ?? nonEmptyString(parsed.s2_session_id) ?? null;

    let sessionId = rawSessionId;
    let s2SessionId = explicitS2;
    let linkedS2 = false;
    let recoveredTargetSession = false;

    if (rawSessionId && s2TargetMap.has(rawSessionId)) {
      s2SessionId = explicitS2 ?? rawSessionId;
      const recovered = s2TargetMap.get(rawSessionId) ?? null;
      if (recovered) {
        sessionId = recovered;
        recoveredTargetSession = true;
      } else {
        sessionId = rawSessionId;
      }
      linkedS2 = true;
    }

    const cascade = normalizeCascade(parsed.cascade);
    const commandString =
      serializeCommandValue(actionObj?.command) ??
      serializeCommandValue(actionObj?.commandString) ??
      serializeCommandValue(parsed.commandString) ??
      "";

    return {
      kind: "valid",
      linkedS2,
      recoveredTargetSession,
      input: {
        id,
        sourceFormat: nonEmptyString(parsed.sourceFormat) ?? "omp",
        timestamp: parseTimestampMs(parsed.timestamp) ?? 0,
        sessionId,
        s2SessionId,
        actionId: nonEmptyString(actionObj?.id) ?? nonEmptyString(parsed.actionId) ?? null,
        toolName:
          nonEmptyString(actionObj?.toolName) ?? nonEmptyString(parsed.toolName) ?? "permission",
        commandString,
        targetPath:
          nonEmptyString(actionObj?.targetPath) ?? nonEmptyString(parsed.targetPath) ?? null,
        workspaceRoot:
          nonEmptyString(actionObj?.workspaceRoot) ?? nonEmptyString(parsed.workspaceRoot) ?? null,
        userPrompt:
          rawStringOrUndefined(parsed.userPrompt) ??
          rawStringOrUndefined(actionObj?.userPrompt) ??
          "",
        reasoning:
          rawStringOrUndefined(decisionObj?.reason) ??
          rawStringOrUndefined(parsed.reasoning) ??
          rawStringOrUndefined(parsed.error) ??
          null,
        thinking:
          rawStringOrUndefined(inferenceObj?.thinking) ??
          rawStringOrUndefined(parsed.thinking) ??
          null,
        verdict: upperVerdict,
        riskLevel: normalizeRiskLevel(
          decisionObj?.riskLevel ??
            decisionObj?.risk_level ??
            parsed.riskLevel ??
            parsed.risk_level,
        ),
        userAuthorization: normalizeUserAuth(
          decisionObj?.userAuthorization ??
            decisionObj?.user_authorization ??
            parsed.userAuthorization ??
            parsed.user_authorization,
        ),
        durationMs: nonNegInt(inferenceObj?.durationMs ?? parsed.durationMs) ?? 0,
        modelId: nonEmptyString(modelObj?.id) ?? nonEmptyString(parsed.modelId) ?? null,
        modelProvider:
          nonEmptyString(modelObj?.provider) ?? nonEmptyString(parsed.modelProvider) ?? null,
        promptTokens: finiteInt(inferenceObj?.promptTokens ?? parsed.promptTokens) ?? null,
        outputTokens: finiteInt(inferenceObj?.outputTokens ?? parsed.outputTokens) ?? null,
        reasoningTokens: finiteInt(inferenceObj?.reasoningTokens ?? parsed.reasoningTokens) ?? null,
        cost: finiteNumber(inferenceObj?.cost ?? parsed.cost) ?? null,
        attempts: finiteInt(inferenceObj?.attempts ?? parsed.attempts) ?? null,
        error: nonEmptyString(parsed.error) ?? null,
        cascade,
        cascadeWinner: cascade?.winner ?? null,
        s2Aborted: cascade?.s2Aborted ?? false,
        sourceOrigin: "jsonl-import",
      },
    };
  }

  // OpenCode flat schema
  const rawVerdict = nonEmptyString(parsed.verdict);
  const upperVerdict = rawVerdict?.toUpperCase();
  if (!upperVerdict || !isClassifierVerdict(upperVerdict)) {
    return { kind: "malformed" };
  }

  const rawSessionId = nonEmptyString(parsed.sessionID) ?? nonEmptyString(parsed.sessionId) ?? "";
  const explicitS2 =
    nonEmptyString(parsed.s2SessionId) ?? nonEmptyString(parsed.s2_session_id) ?? null;

  let sessionId = rawSessionId;
  let s2SessionId = explicitS2;
  let linkedS2 = Boolean(explicitS2);
  let recoveredTargetSession = false;

  if (rawSessionId && s2TargetMap.has(rawSessionId)) {
    s2SessionId = explicitS2 ?? rawSessionId;
    const recovered = s2TargetMap.get(rawSessionId) ?? null;
    if (recovered) {
      sessionId = recovered;
      recoveredTargetSession = true;
    } else {
      sessionId = rawSessionId;
    }
    linkedS2 = true;
  }

  const modelRef =
    typeof parsed.model === "string" && parsed.model.trim()
      ? parseModelRef(parsed.model.trim())
      : undefined;
  const cascade = normalizeCascade(parsed.cascade);

  return {
    kind: "valid",
    linkedS2,
    recoveredTargetSession,
    input: {
      id,
      sourceFormat: nonEmptyString(parsed.sourceFormat) ?? "opencode",
      timestamp: parseTimestampMs(parsed.timestamp) ?? 0,
      sessionId,
      s2SessionId,
      actionId: nonEmptyString(parsed.actionId) ?? nonEmptyString(parsed.action_id) ?? null,
      toolName: nonEmptyString(parsed.toolName) ?? "permission",
      commandString: serializeCommandValue(parsed.commandString) ?? "",
      targetPath: nonEmptyString(parsed.targetPath) ?? null,
      workspaceRoot: nonEmptyString(parsed.workspaceRoot) ?? null,
      userPrompt: rawStringOrUndefined(parsed.userPrompt) ?? "",
      reasoning: rawStringOrUndefined(parsed.reasoning) ?? null,
      thinking: rawStringOrUndefined(parsed.thinking) ?? null,
      verdict: upperVerdict,
      riskLevel: normalizeRiskLevel(parsed.risk_level ?? parsed.riskLevel),
      userAuthorization: normalizeUserAuth(parsed.user_authorization ?? parsed.userAuthorization),
      durationMs: nonNegInt(parsed.durationMs) ?? 0,
      modelId:
        nonEmptyString(parsed.modelId) ?? nonEmptyString(modelObj?.id) ?? modelRef?.modelID ?? null,
      modelProvider:
        nonEmptyString(parsed.modelProvider) ??
        nonEmptyString(modelObj?.provider) ??
        modelRef?.providerID ??
        null,
      promptTokens: finiteInt(parsed.promptTokens) ?? null,
      outputTokens: finiteInt(parsed.outputTokens) ?? null,
      reasoningTokens: finiteInt(parsed.reasoningTokens) ?? null,
      cost: finiteNumber(parsed.cost) ?? null,
      attempts: finiteInt(parsed.attempts) ?? null,
      error: nonEmptyString(parsed.error) ?? null,
      cascade,
      cascadeWinner: cascade?.winner ?? null,
      s2Aborted: cascade?.s2Aborted ?? false,
      sourceOrigin: "jsonl-import",
    },
  };
}

async function importSingleJsonlFile(params: {
  filePath: string;
  store?: AutoGateEvalStore;
  dryRun: boolean;
  batchSize: number;
  s2TargetMap: ReadonlyMap<string, string | null>;
  evalIds: Set<string>;
  evalS2Ids: Set<string>;
  dedupedEvalIds: ReadonlySet<string>;
}): Promise<JsonlFileImportSummary> {
  const { filePath, store, dryRun, batchSize, s2TargetMap, evalIds, evalS2Ids, dedupedEvalIds } =
    params;
  const resolved = expandImporterPath(filePath);

  const summary: JsonlFileImportSummary = {
    filePath: resolved,
    exists: fs.existsSync(resolved),
    totalLines: 0,
    blankLines: 0,
    malformedLines: 0,
    parsedRecords: 0,
    importedCount: 0,
    insertedCount: 0,
    mergedCount: 0,
    linkedS2Count: 0,
    recoveredTargetSessionCount: 0,
  };

  if (!summary.exists) {
    return summary;
  }

  const batch: RecordEvaluationInput[] = [];

  const flushBatch = () => {
    if (batch.length === 0) return;
    if (!dryRun && store) {
      store.recordEvaluations(batch);
    }
    for (const item of batch) {
      const itemId = item.id!;
      const itemS2 = item.s2SessionId ?? null;
      const alreadyExists = evalIds.has(itemId) || (itemS2 !== null && evalS2Ids.has(itemS2));
      if (alreadyExists) {
        summary.mergedCount += 1;
      } else {
        summary.insertedCount += 1;
        evalIds.add(itemId);
        if (itemS2 !== null) {
          evalS2Ids.add(itemS2);
        }
      }
      summary.importedCount += 1;
    }
    batch.length = 0;
  };

  const stream = fs.createReadStream(resolved, { encoding: "utf8" });
  const rl = readline.createInterface({
    input: stream,
    crlfDelay: Infinity,
  });

  try {
    let lineNumber = 0;
    for await (const rawLine of rl) {
      lineNumber += 1;
      summary.totalLines += 1;

      const outcome = parseJsonlEntry(rawLine, resolved, lineNumber, s2TargetMap);
      if (outcome.kind === "blank") {
        summary.blankLines += 1;
        continue;
      }
      if (outcome.kind === "malformed" || !outcome.input) {
        summary.malformedLines += 1;
        continue;
      }

      summary.parsedRecords += 1;
      if (outcome.linkedS2) {
        summary.linkedS2Count += 1;
      }
      if (outcome.recoveredTargetSession) {
        summary.recoveredTargetSessionCount += 1;
      }

      if (outcome.input.id && dedupedEvalIds.has(outcome.input.id)) {
        summary.mergedCount += 1;
        summary.importedCount += 1;
        continue;
      }

      batch.push(outcome.input);
      if (batch.length >= batchSize) {
        flushBatch();
      }
    }
    flushBatch();
  } finally {
    rl.close();
    stream.destroy();
  }

  return summary;
}

export async function importJsonlToEvalStore(
  options: ImportJsonlOptions = {},
): Promise<ImportJsonlResult> {
  const dryRun = Boolean(options.dryRun);
  const batchSize =
    typeof options.batchSize === "number" &&
    Number.isFinite(options.batchSize) &&
    options.batchSize > 0
      ? Math.trunc(options.batchSize)
      : DEFAULT_IMPORT_BATCH_SIZE;

  const evalDbFile = options.store
    ? options.store.getDbPath()
    : expandImporterPath(nonEmptyString(options.evalDbFile) ?? resolveEvalDbFile());

  const explicitFiles = options.jsonlFiles !== undefined;
  const candidateFiles = explicitFiles
    ? Array.from(new Set(options.jsonlFiles!.map((p) => expandImporterPath(p))))
    : getDefaultJsonlPaths();

  if (explicitFiles && !options.ignoreMissingFiles) {
    for (const filePath of candidateFiles) {
      if (!fs.existsSync(filePath)) {
        throw new Error(`JSONL file not found: ${filePath}`);
      }
    }
  }

  let ownedStore: AutoGateEvalStore | undefined;
  const activeStore =
    options.store ??
    (ownedStore = new AutoGateEvalStore(evalDbFile, {
      readonly: dryRun,
    }));

  try {
    const existing = loadExistingEvalKeys(activeStore);
    const s2TargetMap = new Map<string, string | null>(existing.s2TargetMap);

    if (!options.skipOpenCodeDbLookup) {
      const openCodePath = expandImporterPath(
        nonEmptyString(options.opencodeDbPath) ?? getDefaultOpenCodeDbPath(),
      );
      if (fs.existsSync(openCodePath)) {
        const dbTargets = readOpenCodeS2TargetMap(openCodePath);
        for (const [s2Id, target] of dbTargets.entries()) {
          if (!s2TargetMap.has(s2Id) || (target !== null && s2TargetMap.get(s2Id) === null)) {
            s2TargetMap.set(s2Id, target);
          }
        }
      }
    }

    const fileSummaries: JsonlFileImportSummary[] = [];
    for (const filePath of candidateFiles) {
      const fileSummary = await importSingleJsonlFile({
        filePath,
        store: activeStore,
        dryRun,
        batchSize,
        s2TargetMap,
        evalIds: existing.evalIds,
        evalS2Ids: existing.evalS2Ids,
        dedupedEvalIds: existing.dedupedEvalIds,
      });
      fileSummaries.push(fileSummary);
    }

    return {
      evalDbFile,
      dryRun,
      files: fileSummaries,
      totalLines: fileSummaries.reduce((sum, f) => sum + f.totalLines, 0),
      blankLines: fileSummaries.reduce((sum, f) => sum + f.blankLines, 0),
      malformedLines: fileSummaries.reduce((sum, f) => sum + f.malformedLines, 0),
      parsedRecords: fileSummaries.reduce((sum, f) => sum + f.parsedRecords, 0),
      importedCount: fileSummaries.reduce((sum, f) => sum + f.importedCount, 0),
      insertedCount: fileSummaries.reduce((sum, f) => sum + f.insertedCount, 0),
      mergedCount: fileSummaries.reduce((sum, f) => sum + f.mergedCount, 0),
      linkedS2Count: fileSummaries.reduce((sum, f) => sum + f.linkedS2Count, 0),
      recoveredTargetSessionCount: fileSummaries.reduce(
        (sum, f) => sum + f.recoveredTargetSessionCount,
        0,
      ),
    };
  } finally {
    if (ownedStore) {
      ownedStore.close();
    }
  }
}

interface RawOpenCodeSessionCandidate {
  sourceTable: "session_v2" | "session";
  id: string;
  projectId: string | null;
  workspaceId: string | null;
  parentId: string | null;
  slug: string | null;
  directory: string | null;
  path: string | null;
  title: string;
  version: string | null;
  metadataRaw: unknown;
  cost: number;
  tokensInput: number;
  tokensOutput: number;
  tokensReasoning: number;
  tokensCacheRead: number;
  tokensCacheWrite: number;
  agent: string | null;
  modelRaw: unknown;
  timeCreated: number | null;
  timeUpdated: number | null;
  timeArchived: number | null;
  timeSuspended: number | null;
  timeCompacting: number | null;
  timeIdle: number | null;
  idleOutcome: string | null;
  messages: Record<string, unknown>[];
}

function rowToSessionCandidate(
  row: Record<string, SQLOutputValue>,
  sourceTable: "session_v2" | "session",
): RawOpenCodeSessionCandidate | null {
  const id = nonEmptyString(row.id);
  const title = typeof row.title === "string" ? row.title : "";
  if (!id || !title.startsWith(AUTOGATE_EVAL_TITLE_PREFIX)) {
    return null;
  }

  return {
    sourceTable,
    id,
    projectId: nonEmptyString(row.project_id) ?? null,
    workspaceId: nonEmptyString(row.workspace_id) ?? null,
    parentId: nonEmptyString(row.parent_id) ?? null,
    slug: nonEmptyString(row.slug) ?? null,
    directory: nonEmptyString(row.directory) ?? null,
    path: nonEmptyString(row.path) ?? null,
    title,
    version: nonEmptyString(row.version) ?? null,
    metadataRaw: row.metadata,
    cost: finiteNumber(row.cost) ?? 0,
    tokensInput: finiteInt(row.tokens_input) ?? 0,
    tokensOutput: finiteInt(row.tokens_output) ?? 0,
    tokensReasoning: finiteInt(row.tokens_reasoning) ?? 0,
    tokensCacheRead: finiteInt(row.tokens_cache_read) ?? 0,
    tokensCacheWrite: finiteInt(row.tokens_cache_write) ?? 0,
    agent: nonEmptyString(row.agent) ?? null,
    modelRaw: row.model,
    timeCreated: finiteInt(row.time_created) ?? null,
    timeUpdated: finiteInt(row.time_updated) ?? null,
    timeArchived: finiteInt(row.time_archived) ?? null,
    timeSuspended: finiteInt(row.time_suspended) ?? null,
    timeCompacting: finiteInt(row.time_compacting) ?? null,
    timeIdle: finiteInt(row.time_idle) ?? null,
    idleOutcome: nonEmptyString(row.idle_outcome) ?? null,
    messages: [],
  };
}

function populateV2Messages(
  db: DatabaseSync,
  tables: Set<string>,
  candidates: Map<string, RawOpenCodeSessionCandidate>,
): void {
  if (candidates.size === 0 || !tables.has("session_message")) {
    return;
  }

  const allIds = Array.from(candidates.keys());
  const hasParts = tables.has("session_part");
  const chunkSize = 200;

  for (let i = 0; i < allIds.length; i += chunkSize) {
    const chunk = allIds.slice(i, i + chunkSize);
    const placeholders = chunk.map(() => "?").join(", ");
    const params: SQLInputValue[] = chunk;

    const msgRows = db
      .prepare(
        `SELECT * FROM session_message
         WHERE session_id IN (${placeholders})
         ORDER BY session_id ASC, seq ASC, time_created ASC, id ASC`,
      )
      .all(...params);

    const partsByMsg = new Map<string, Record<string, unknown>[]>();
    if (hasParts) {
      const partRows = db
        .prepare(
          `SELECT * FROM session_part
           WHERE session_id IN (${placeholders})
           ORDER BY session_id ASC, message_id ASC, ordinal ASC`,
        )
        .all(...params);
      for (const pRow of partRows) {
        const msgId = nonEmptyString(pRow.message_id);
        if (!msgId) continue;
        const parsedData = parseJsonObjectSafe(pRow.data) ?? {};
        const partObj: Record<string, unknown> = {
          ...parsedData,
          type: nonEmptyString(parsedData.type) ?? nonEmptyString(pRow.type) ?? "text",
          ...(pRow.ordinal !== undefined && pRow.ordinal !== null
            ? { ordinal: finiteInt(pRow.ordinal) }
            : {}),
          ...(nonEmptyString(pRow.call_id) && !nonEmptyString(parsedData.id)
            ? { id: nonEmptyString(pRow.call_id) }
            : {}),
        };
        let list = partsByMsg.get(msgId);
        if (!list) {
          list = [];
          partsByMsg.set(msgId, list);
        }
        list.push(partObj);
      }
    }

    for (const mRow of msgRows) {
      const sessionId = nonEmptyString(mRow.session_id);
      const msgId = nonEmptyString(mRow.id);
      if (!sessionId || !msgId) continue;
      const cand = candidates.get(sessionId);
      if (!cand) continue;

      const parsedData = parseJsonObjectSafe(mRow.data) ?? {};
      const msgType = nonEmptyString(mRow.type) ?? nonEmptyString(parsedData.type) ?? "user";
      const attachedParts = partsByMsg.get(msgId);
      const inlineContent = Array.isArray(parsedData.content) ? parsedData.content : undefined;
      const combinedContent =
        attachedParts && attachedParts.length > 0
          ? inlineContent
            ? [...attachedParts, ...inlineContent]
            : attachedParts
          : inlineContent;

      const reconstructed: Record<string, unknown> = {
        ...parsedData,
        id: msgId,
        sessionID: sessionId,
        type: msgType,
        ...(mRow.seq !== undefined && mRow.seq !== null ? { seq: finiteInt(mRow.seq) } : {}),
        ...(mRow.time_created !== undefined && mRow.time_created !== null && !parsedData.time
          ? { time: { created: finiteInt(mRow.time_created) } }
          : {}),
        ...(combinedContent !== undefined ? { content: combinedContent } : {}),
      };

      cand.messages.push(reconstructed);
    }
  }
}

function populateV1Messages(
  db: DatabaseSync,
  tables: Set<string>,
  candidates: Map<string, RawOpenCodeSessionCandidate>,
): void {
  if (candidates.size === 0 || !tables.has("message")) {
    return;
  }

  const allIds = Array.from(candidates.keys());
  const hasParts = tables.has("part");
  const chunkSize = 200;

  for (let i = 0; i < allIds.length; i += chunkSize) {
    const chunk = allIds.slice(i, i + chunkSize);
    const placeholders = chunk.map(() => "?").join(", ");
    const params: SQLInputValue[] = chunk;

    const msgRows = db
      .prepare(
        `SELECT * FROM message
         WHERE session_id IN (${placeholders})
         ORDER BY session_id ASC, time_created ASC, id ASC`,
      )
      .all(...params);

    const partsByMsg = new Map<string, Record<string, unknown>[]>();
    if (hasParts) {
      const partRows = db
        .prepare(
          `SELECT * FROM part
           WHERE session_id IN (${placeholders})
           ORDER BY session_id ASC, message_id ASC, time_created ASC, id ASC`,
        )
        .all(...params);
      for (const pRow of partRows) {
        const msgId = nonEmptyString(pRow.message_id);
        if (!msgId) continue;
        const parsedData = parseJsonObjectSafe(pRow.data) ?? {};
        const partObj: Record<string, unknown> = {
          ...parsedData,
          id: nonEmptyString(pRow.id) ?? nonEmptyString(parsedData.id),
          messageID: msgId,
          sessionID: nonEmptyString(pRow.session_id) ?? nonEmptyString(parsedData.sessionID),
        };
        let list = partsByMsg.get(msgId);
        if (!list) {
          list = [];
          partsByMsg.set(msgId, list);
        }
        list.push(partObj);
      }
    }

    for (const mRow of msgRows) {
      const sessionId = nonEmptyString(mRow.session_id);
      const msgId = nonEmptyString(mRow.id);
      if (!sessionId || !msgId) continue;
      const cand = candidates.get(sessionId);
      if (!cand) continue;

      const parsedData = parseJsonObjectSafe(mRow.data) ?? {};
      const attachedParts = partsByMsg.get(msgId) ?? [];
      const inlineParts = Array.isArray(parsedData.parts) ? parsedData.parts : [];
      const parts = attachedParts.length > 0 ? attachedParts : inlineParts;

      const reconstructed: Record<string, unknown> = {
        ...parsedData,
        id: msgId,
        sessionID: sessionId,
        ...(mRow.time_created !== undefined && mRow.time_created !== null && !parsedData.time
          ? { time: { created: finiteInt(mRow.time_created) } }
          : {}),
        ...(parts.length > 0 ? { parts } : {}),
      };

      cand.messages.push(reconstructed);
    }
  }
}

interface MergedOpenCodeSession {
  primary: RawOpenCodeSessionCandidate;
  v2Present: boolean;
  v1Present: boolean;
  sourceTables: ("session_v2" | "session")[];
}

function mergeSessionCandidates(
  v2Map: Map<string, RawOpenCodeSessionCandidate>,
  v1Map: Map<string, RawOpenCodeSessionCandidate>,
): { merged: MergedOpenCodeSession[]; overlappingCount: number } {
  const orderedIds: string[] = [];
  const seen = new Set<string>();
  for (const id of v2Map.keys()) {
    seen.add(id);
    orderedIds.push(id);
  }
  for (const id of v1Map.keys()) {
    if (!seen.has(id)) {
      seen.add(id);
      orderedIds.push(id);
    }
  }

  const merged: MergedOpenCodeSession[] = [];
  let overlappingCount = 0;

  for (const id of orderedIds) {
    const v2 = v2Map.get(id);
    const v1 = v1Map.get(id);

    if (v2 && v1) {
      overlappingCount += 1;
      const preferV1Messages = v2.messages.length === 0 && v1.messages.length > 0;
      const base = preferV1Messages ? v1 : v2;
      const secondary = preferV1Messages ? v2 : v1;

      const mergedTitle =
        /->\s*(ALLOW|BLOCK|UNSURE)\b/i.test(v2.title) ||
        !/->\s*(ALLOW|BLOCK|UNSURE)\b/i.test(v1.title)
          ? v2.title
          : v1.title;

      const primary: RawOpenCodeSessionCandidate = {
        ...base,
        title: mergedTitle,
        projectId: base.projectId ?? secondary.projectId,
        workspaceId: base.workspaceId ?? secondary.workspaceId,
        parentId: base.parentId ?? secondary.parentId,
        slug: base.slug ?? secondary.slug,
        directory: base.directory ?? secondary.directory,
        path: base.path ?? secondary.path,
        version: base.version ?? secondary.version,
        metadataRaw: base.metadataRaw ?? secondary.metadataRaw,
        cost: base.cost > 0 ? base.cost : secondary.cost,
        tokensInput: base.tokensInput > 0 ? base.tokensInput : secondary.tokensInput,
        tokensOutput: base.tokensOutput > 0 ? base.tokensOutput : secondary.tokensOutput,
        tokensReasoning:
          base.tokensReasoning > 0 ? base.tokensReasoning : secondary.tokensReasoning,
        tokensCacheRead:
          base.tokensCacheRead > 0 ? base.tokensCacheRead : secondary.tokensCacheRead,
        tokensCacheWrite:
          base.tokensCacheWrite > 0 ? base.tokensCacheWrite : secondary.tokensCacheWrite,
        agent: base.agent ?? secondary.agent,
        modelRaw: base.modelRaw ?? secondary.modelRaw,
        timeCreated: base.timeCreated ?? secondary.timeCreated,
        timeUpdated: base.timeUpdated ?? secondary.timeUpdated,
        timeArchived: base.timeArchived ?? secondary.timeArchived,
        timeSuspended: base.timeSuspended ?? secondary.timeSuspended,
        timeCompacting: base.timeCompacting ?? secondary.timeCompacting,
        timeIdle: base.timeIdle ?? secondary.timeIdle,
        idleOutcome: base.idleOutcome ?? secondary.idleOutcome,
      };

      merged.push({
        primary,
        v2Present: true,
        v1Present: true,
        sourceTables: ["session_v2", "session"],
      });
    } else if (v2) {
      merged.push({
        primary: v2,
        v2Present: true,
        v1Present: false,
        sourceTables: ["session_v2"],
      });
    } else if (v1) {
      merged.push({
        primary: v1,
        v2Present: false,
        v1Present: true,
        sourceTables: ["session"],
      });
    }
  }

  return { merged, overlappingCount };
}

function getKnownEvalSystemPrompts(): { fullSystem?: string; bodyWithoutDirective?: string } {
  try {
    const def = loadEvalAgentDefinition();
    const fullSystem = def.system.trim();
    const directiveSuffix = `\n\n${PASSIVE_EVALUATOR_DIRECTIVE}`;
    const bodyWithoutDirective = fullSystem.endsWith(directiveSuffix)
      ? fullSystem.slice(0, -directiveSuffix.length).trim()
      : undefined;
    return { fullSystem, bodyWithoutDirective };
  } catch {
    return {};
  }
}

function matchesStaticEvalPrompt(
  text: string,
  known: { fullSystem?: string; bodyWithoutDirective?: string },
): boolean {
  const trimmed = text.trim();
  if (!trimmed) return false;
  if (known.fullSystem && trimmed === known.fullSystem) return true;
  if (known.bodyWithoutDirective && trimmed === known.bodyWithoutDirective) return true;
  if (trimmed.startsWith(AUTOGATE_PROMPT_MARKER)) return true;
  return false;
}

function stripPromptPrefixFromText(
  text: string,
  known: { fullSystem?: string; bodyWithoutDirective?: string },
): { strippedText: string; extractedSystemPrompt?: string } {
  if (known.fullSystem && text.startsWith(known.fullSystem)) {
    const remainder = text.slice(known.fullSystem.length).replace(/^\s+/, "");
    return {
      strippedText: remainder,
      extractedSystemPrompt: known.fullSystem,
    };
  }
  if (known.bodyWithoutDirective && text.startsWith(known.bodyWithoutDirective)) {
    let remainder = text.slice(known.bodyWithoutDirective.length).replace(/^\s+/, "");
    let extracted = known.bodyWithoutDirective;
    if (remainder.startsWith(PASSIVE_EVALUATOR_DIRECTIVE)) {
      extracted = `${known.bodyWithoutDirective}\n\n${PASSIVE_EVALUATOR_DIRECTIVE}`;
      remainder = remainder.slice(PASSIVE_EVALUATOR_DIRECTIVE.length).replace(/^\s+/, "");
    }
    return {
      strippedText: remainder,
      extractedSystemPrompt: extracted,
    };
  }
  if (text.startsWith(AUTOGATE_PROMPT_MARKER)) {
    const boundaryIdx = text.indexOf("\n\n## Environment Trust Boundaries:");
    if (boundaryIdx > 0) {
      const prefix = text.slice(0, boundaryIdx).trim();
      const remainder = text.slice(boundaryIdx).replace(/^\s+/, "");
      return {
        strippedText: remainder,
        extractedSystemPrompt: prefix,
      };
    }
  }
  return { strippedText: text };
}

function extractAndStripSystemPrompt(
  messages: Record<string, unknown>[],
  known: { fullSystem?: string; bodyWithoutDirective?: string },
): { systemPrompt?: string; sanitizedMessages: Record<string, unknown>[] } {
  let extractedSystemPrompt: string | undefined;
  const sanitizedMessages: Record<string, unknown>[] = [];

  for (const msg of messages) {
    const clone: Record<string, unknown> = { ...msg };
    const msgRole = nonEmptyString(clone.type) ?? nonEmptyString(clone.role);

    if (typeof clone.system === "string" && clone.system.trim().length > 0) {
      if (!extractedSystemPrompt) {
        extractedSystemPrompt = clone.system.trim();
      }
      delete clone.system;
    }

    if (msgRole === "system" && typeof clone.text === "string") {
      if (matchesStaticEvalPrompt(clone.text, known)) {
        if (!extractedSystemPrompt) {
          extractedSystemPrompt = clone.text.trim();
        }
        continue;
      }
    }

    if (msgRole === "user") {
      if (typeof clone.text === "string") {
        const res = stripPromptPrefixFromText(clone.text, known);
        if (res.extractedSystemPrompt) {
          if (!extractedSystemPrompt) {
            extractedSystemPrompt = res.extractedSystemPrompt;
          }
          clone.text = res.strippedText;
        }
      }
      if (Array.isArray(clone.parts)) {
        let partsModified = false;
        const nextParts = clone.parts.map((part) => {
          if (!isRecord(part) || part.type !== "text" || typeof part.text !== "string") {
            return part;
          }
          const res = stripPromptPrefixFromText(part.text, known);
          if (res.extractedSystemPrompt) {
            if (!extractedSystemPrompt) {
              extractedSystemPrompt = res.extractedSystemPrompt;
            }
            partsModified = true;
            return { ...part, text: res.strippedText };
          }
          return part;
        });
        if (partsModified) {
          clone.parts = nextParts;
        }
      }
    }

    sanitizedMessages.push(clone);
  }

  return {
    ...(extractedSystemPrompt ? { systemPrompt: extractedSystemPrompt } : {}),
    sanitizedMessages,
  };
}

function getMessageRole(msg: Record<string, unknown>): string | undefined {
  const info = isRecord(msg.info) ? msg.info : undefined;
  return nonEmptyString(msg.type) ?? nonEmptyString(msg.role) ?? nonEmptyString(info?.role);
}

function getMessageParts(msg: Record<string, unknown>): unknown[] {
  if (Array.isArray(msg.content)) return msg.content;
  if (Array.isArray(msg.parts)) return msg.parts;
  return [];
}

function extractUserMessageText(msg: Record<string, unknown>): string {
  if (typeof msg.text === "string" && msg.text.trim().length > 0) {
    return msg.text;
  }
  if (typeof msg.content === "string" && msg.content.trim().length > 0) {
    return msg.content;
  }
  const parts = getMessageParts(msg);
  const textParts: string[] = [];
  for (const part of parts) {
    if (typeof part === "string" && part.trim().length > 0) {
      textParts.push(part);
    } else if (isRecord(part)) {
      if (part.type === "text" && part.ignored !== true && part.synthetic !== true) {
        if (typeof part.text === "string" && part.text.length > 0) {
          textParts.push(part.text);
        }
      } else if (part.type === undefined && typeof part.text === "string") {
        textParts.push(part.text);
      }
    }
  }
  if (textParts.length > 0) {
    return textParts.join("\n\n");
  }
  // Fallback if all text parts were marked synthetic
  for (const part of parts) {
    if (isRecord(part) && part.type === "text" && typeof part.text === "string") {
      textParts.push(part.text);
    }
  }
  return textParts.join("\n\n");
}

function extractFencedBlock(section: string, labelPattern: RegExp): string | undefined {
  const match = section.match(labelPattern);
  if (!match || typeof match[2] !== "string") return undefined;
  return match[2];
}

function parseClassifierUserPromptFields(rawText: string): {
  userPrompt: string;
  toolName?: string;
  commandString: string;
  targetPath?: string;
  workspaceRoot?: string;
} {
  const text = rawText.trim();
  if (!text) {
    return { userPrompt: "", commandString: "" };
  }

  const isStructuredClassifierPrompt =
    text.includes("## Environment Trust Boundaries:") ||
    text.includes("### Proposed Action:") ||
    text.includes("## Context:");

  if (!isStructuredClassifierPrompt) {
    return { userPrompt: text, commandString: "" };
  }

  const wsMatch = text.match(/^-\s*\*\*Workspace Root\*\*:\s*([^\r\n]+)/im);
  const workspaceRoot = wsMatch?.[1]?.trim() || undefined;

  let userPrompt = "";
  const humanIntentMatch = text.match(/<human_user_intent[^>]*>([\s\S]*?)<\/human_user_intent>/i);
  if (humanIntentMatch && typeof humanIntentMatch[1] === "string") {
    const inner = humanIntentMatch[1].trim();
    userPrompt = inner === "*(No conversation transcript available)*" ? "" : inner;
  } else {
    const transcriptMatch = text.match(
      /###\s*Conversation Transcript(?:\s*\(User's Recent Intent\))?:\s*\r?\n([\s\S]*?)(?:\r?\n###\s*Proposed Action:|\r?\n-\s*\*\*Proposed Action|$)/i,
    );
    if (transcriptMatch && typeof transcriptMatch[1] === "string") {
      const inner = transcriptMatch[1].trim();
      userPrompt = inner === "*(No conversation transcript available)*" ? "" : inner;
    }
  }

  const proposedIdx = text.search(/###\s*Proposed Action:/i);
  const actionSection = proposedIdx >= 0 ? text.slice(proposedIdx) : text;

  const toolMatch = actionSection.match(/-\s*\*\*Tool\s*\/\s*Permission\*\*:\s*([^\r\n]+)/i);
  const toolName = toolMatch?.[1]?.trim() || undefined;

  const cmdFromFence = extractFencedBlock(
    actionSection,
    /-\s*\*\*Command\*\*:\s*\r?\n(`{3,})[^\r\n]*\r?\n([\s\S]*?)\r?\n\1/i,
  );
  const evalFromFence = extractFencedBlock(
    actionSection,
    /-\s*\*\*Eval Code\s*\([^)]*\)\*\*:\s*\r?\n(`{3,})[^\r\n]*\r?\n([\s\S]*?)\r?\n\1/i,
  );
  const argsFromFence = extractFencedBlock(
    actionSection,
    /-\s*\*\*Action Arguments\*\*:\s*\r?\n(`{3,})[^\r\n]*\r?\n([\s\S]*?)\r?\n\1/i,
  );

  const targetPathMatch = actionSection.match(
    /-\s*\*\*(?:Target Path \/ Patterns|Requested External Directory)\*\*:\s*`([^`]+)`/i,
  );
  const targetPath = targetPathMatch?.[1]?.trim() || undefined;

  const commandString = cmdFromFence ?? evalFromFence ?? argsFromFence ?? targetPath ?? "";

  return {
    userPrompt,
    ...(toolName ? { toolName } : {}),
    commandString,
    ...(targetPath ? { targetPath } : {}),
    ...(workspaceRoot ? { workspaceRoot } : {}),
  };
}

function parseTitleMetadata(title: string): {
  toolName?: string;
  verdict?: ClassifierVerdict;
} {
  if (!title.startsWith(AUTOGATE_EVAL_TITLE_PREFIX)) {
    return {};
  }
  const rest = title.slice(AUTOGATE_EVAL_TITLE_PREFIX.length).trim();
  if (!rest) return {};

  const arrowMatch = rest.match(/^(.*?)\s*->\s*(ALLOW|BLOCK|UNSURE)\s*$/i);
  if (arrowMatch) {
    const rawTool = arrowMatch[1]?.trim();
    const rawVerdict = arrowMatch[2]?.trim().toUpperCase();
    return {
      ...(rawTool ? { toolName: rawTool } : {}),
      ...(rawVerdict && isClassifierVerdict(rawVerdict) ? { verdict: rawVerdict } : {}),
    };
  }

  return { toolName: rest };
}

function extractClassifyResultFromPart(part: unknown): {
  verdict: ClassifierVerdict;
  riskLevel?: RiskLevel;
  userAuthorization?: UserAuthorization;
  reasoning?: string;
} | null {
  if (!isRecord(part)) return null;
  const fn = isRecord(part.function) ? part.function : undefined;
  const isClassifyTool =
    (part.type === "tool" &&
      (part.tool === "classify_result" || part.name === "classify_result")) ||
    (part.type === "tool_use" && part.name === "classify_result") ||
    part.tool === "classify_result" ||
    part.name === "classify_result" ||
    (fn !== undefined && (fn.name === "classify_result" || fn.tool === "classify_result"));

  if (!isClassifyTool) return null;

  const state = isRecord(part.state) ? part.state : undefined;
  let toolInput: unknown =
    state?.input ?? part.input ?? part.args ?? part.arguments ?? fn?.arguments ?? fn?.args;
  if (typeof toolInput === "string") {
    toolInput = parseJsonUnknownSafe(toolInput);
  }
  if (!isRecord(toolInput)) return null;

  const rawVerdict = nonEmptyString(toolInput.verdict)?.toUpperCase();
  if (!rawVerdict || !isClassifierVerdict(rawVerdict)) return null;

  const riskLevel = normalizeRiskLevel(toolInput.risk_level) ?? undefined;
  const userAuthorization = normalizeUserAuth(toolInput.user_authorization) ?? undefined;
  const reasoning = rawStringOrUndefined(toolInput.reason);

  return {
    verdict: rawVerdict,
    ...(riskLevel ? { riskLevel } : {}),
    ...(userAuthorization ? { userAuthorization } : {}),
    ...(reasoning !== undefined ? { reasoning } : {}),
  };
}

function extractModelFromSessionOrMessage(
  rawModel: unknown,
  fallbackProvider?: unknown,
): {
  modelId?: string;
  modelProvider?: string;
} {
  if (typeof rawModel === "string" && rawModel.trim()) {
    const parsedJson = parseJsonObjectSafe(rawModel);
    if (parsedJson) {
      const modelId = nonEmptyString(parsedJson.id) ?? nonEmptyString(parsedJson.modelID);
      const modelProvider =
        nonEmptyString(parsedJson.providerID) ??
        nonEmptyString(parsedJson.providerId) ??
        nonEmptyString(parsedJson.provider) ??
        nonEmptyString(fallbackProvider);
      return {
        ...(modelId ? { modelId } : {}),
        ...(modelProvider ? { modelProvider } : {}),
      };
    }
    const parsedRef = parseModelRef(rawModel.trim());
    return {
      modelId: parsedRef.modelID,
      modelProvider: nonEmptyString(fallbackProvider) ?? parsedRef.providerID,
    };
  }
  if (isRecord(rawModel)) {
    const modelId = nonEmptyString(rawModel.id) ?? nonEmptyString(rawModel.modelID);
    const modelProvider =
      nonEmptyString(rawModel.providerID) ??
      nonEmptyString(rawModel.providerId) ??
      nonEmptyString(rawModel.provider) ??
      nonEmptyString(fallbackProvider);
    return {
      ...(modelId ? { modelId } : {}),
      ...(modelProvider ? { modelProvider } : {}),
    };
  }
  const prov = nonEmptyString(fallbackProvider);
  return prov ? { modelProvider: prov } : {};
}

function extractAssistantErrorText(err: unknown): {
  message?: string;
  isAborted: boolean;
  isTimeout: boolean;
} {
  if (!err) return { isAborted: false, isTimeout: false };
  if (typeof err === "string") {
    const lower = err.toLowerCase();
    return {
      message: nonEmptyString(err),
      isAborted: lower.includes("abort"),
      isTimeout: lower.includes("timeout") || lower.includes("timed out"),
    };
  }
  if (isRecord(err)) {
    const errData = isRecord(err.data) ? err.data : undefined;
    const errName = nonEmptyString(err.name) ?? nonEmptyString(err.type) ?? "";
    const msg =
      nonEmptyString(err.message) ?? nonEmptyString(errData?.message) ?? nonEmptyString(errName);
    const combined = `${errName} ${msg ?? ""}`.toLowerCase();
    return {
      message: msg,
      isAborted: combined.includes("abort"),
      isTimeout: combined.includes("timeout") || combined.includes("timed out"),
    };
  }
  return { isAborted: false, isTimeout: false };
}

interface ExtractedOpenCodeSessionDetails {
  targetSessionId: string | null;
  toolName: string;
  commandString: string;
  targetPath: string | null;
  workspaceRoot: string | null;
  userPrompt: string;
  verdict: ClassifierVerdict;
  riskLevel: RiskLevel | null;
  userAuthorization: UserAuthorization | null;
  reasoning: string | null;
  thinking: string | null;
  error: string | null;
  status: S2SessionStatus;
  modelId: string | null;
  modelProvider: string | null;
  promptTokens: number | null;
  outputTokens: number | null;
  reasoningTokens: number | null;
  cacheReadTokens: number | null;
  cacheWriteTokens: number | null;
  cost: number | null;
  durationMs: number;
  createdAt: number | null;
  updatedAt: number | null;
  archivedAt: number | null;
  info: Record<string, unknown>;
}

function extractOpenCodeSessionDetails(
  cand: RawOpenCodeSessionCandidate,
  sanitizedMessages: Record<string, unknown>[],
): ExtractedOpenCodeSessionDetails {
  const parsedMetadata = parseJsonObjectSafe(cand.metadataRaw);
  const parsedSessionModel = extractModelFromSessionOrMessage(cand.modelRaw);
  const titleMeta = parseTitleMetadata(cand.title);
  const targetSessionId = extractTargetSessionIdFromRow(cand.parentId, parsedMetadata, cand.id);

  let promptFields: ReturnType<typeof parseClassifierUserPromptFields> | undefined;
  let firstUserCreatedAt: number | undefined;
  let lastAssistantCompletedAt: number | undefined;

  let msgModelId: string | undefined;
  let msgModelProvider: string | undefined;
  let msgHasTokens = false;
  let msgPromptTokens = 0;
  let msgOutputTokens = 0;
  let msgReasoningTokens = 0;
  let msgCacheReadTokens = 0;
  let msgCacheWriteTokens = 0;
  let msgHasCost = false;
  let msgCost = 0;

  let toolVerdict: ClassifierVerdict | undefined;
  let toolRiskLevel: RiskLevel | undefined;
  let toolUserAuth: UserAuthorization | undefined;
  let toolReasoning: string | undefined;
  let textVerdict: ClassifierVerdict | undefined;
  let textRiskLevel: RiskLevel | undefined;
  let textUserAuth: UserAuthorization | undefined;
  let textReasoning: string | undefined;

  const thinkingSegments: string[] = [];
  let assistantError: string | undefined;
  let isAborted = false;
  let isTimeout = false;

  for (const msg of sanitizedMessages) {
    const role = getMessageRole(msg);
    const msgTime = isRecord(msg.time) ? msg.time : undefined;

    if (role === "user") {
      if (firstUserCreatedAt === undefined) {
        firstUserCreatedAt = parseTimestampMs(msgTime?.created);
      }
      const userText = extractUserMessageText(msg);
      if (
        userText.trim() &&
        !userText.startsWith("You must record your decision by calling the classify_result tool")
      ) {
        if (!promptFields) {
          promptFields = parseClassifierUserPromptFields(userText);
        }
      }
      if (!msgModelId || !msgModelProvider) {
        const uModel = extractModelFromSessionOrMessage(msg.model);
        msgModelId = msgModelId ?? uModel.modelId;
        msgModelProvider = msgModelProvider ?? uModel.modelProvider;
      }
      continue;
    }

    if (role === "idle") {
      const outcome = nonEmptyString(msg.outcome);
      if (outcome === "interrupted") isAborted = true;
      const errInfo = extractAssistantErrorText(msg.error);
      if (errInfo.message) assistantError = errInfo.message;
      if (errInfo.isAborted) isAborted = true;
      if (errInfo.isTimeout) isTimeout = true;
      continue;
    }

    if (role !== "assistant") continue;

    const completedTs = parseTimestampMs(msgTime?.completed);
    if (completedTs !== undefined) {
      lastAssistantCompletedAt = completedTs;
    }

    const mModel =
      msg.model !== undefined
        ? extractModelFromSessionOrMessage(msg.model)
        : extractModelFromSessionOrMessage(msg.modelID, msg.providerID);
    if (mModel.modelId) msgModelId = mModel.modelId;
    if (mModel.modelProvider) msgModelProvider = mModel.modelProvider;

    const tokensObj = isRecord(msg.tokens) ? msg.tokens : undefined;
    if (tokensObj) {
      const cacheObj = isRecord(tokensObj.cache) ? tokensObj.cache : undefined;
      const tIn = finiteInt(tokensObj.input);
      const tOut = finiteInt(tokensObj.output);
      const tReason = finiteInt(tokensObj.reasoning);
      const tCacheR = finiteInt(cacheObj?.read);
      const tCacheW = finiteInt(cacheObj?.write);
      if (
        tIn !== undefined ||
        tOut !== undefined ||
        tReason !== undefined ||
        tCacheR !== undefined ||
        tCacheW !== undefined
      ) {
        msgHasTokens = true;
        msgPromptTokens += tIn ?? 0;
        msgOutputTokens += tOut ?? 0;
        msgReasoningTokens += tReason ?? 0;
        msgCacheReadTokens += tCacheR ?? 0;
        msgCacheWriteTokens += tCacheW ?? 0;
      }
    }

    const mCost = finiteNumber(msg.cost);
    if (mCost !== undefined) {
      msgHasCost = true;
      msgCost += mCost;
    }

    const errInfo = extractAssistantErrorText(msg.error);
    if (errInfo.message) assistantError = errInfo.message;
    if (errInfo.isAborted) isAborted = true;
    if (errInfo.isTimeout) isTimeout = true;

    const parts = getMessageParts(msg);
    const assistantTextSegments: string[] = [];

    for (const part of parts) {
      if (!isRecord(part)) continue;
      const partType = nonEmptyString(part.type);
      if (partType === "reasoning" || partType === "thinking" || partType === "reasoning_text") {
        const thought =
          nonEmptyString(part.text) ??
          nonEmptyString(part.thinking) ??
          nonEmptyString(part.reasoning);
        if (thought) {
          thinkingSegments.push(thought);
        }
      } else if (partType === "text" && typeof part.text === "string" && part.text.trim()) {
        assistantTextSegments.push(part.text);
      }

      const classifyRes = extractClassifyResultFromPart(part);
      if (classifyRes) {
        toolVerdict = classifyRes.verdict;
        toolRiskLevel = classifyRes.riskLevel ?? toolRiskLevel;
        toolUserAuth = classifyRes.userAuthorization ?? toolUserAuth;
        toolReasoning = classifyRes.reasoning ?? toolReasoning;
      }
    }

    if (assistantTextSegments.length > 0) {
      const parsedText = parseVerdict(assistantTextSegments.join("\n"));
      if (
        parsedText.reason !== "Classifier response did not contain a valid structured verdict" &&
        parsedText.reason !== "Empty or invalid classifier output"
      ) {
        textVerdict = parsedText.verdict;
        textRiskLevel = parsedText.risk_level ?? textRiskLevel;
        textUserAuth = parsedText.user_authorization ?? textUserAuth;
        textReasoning = parsedText.reason || textReasoning;
      }
    }
  }

  const rowHasTokens =
    cand.tokensInput > 0 ||
    cand.tokensOutput > 0 ||
    cand.tokensReasoning > 0 ||
    cand.tokensCacheRead > 0 ||
    cand.tokensCacheWrite > 0;

  const promptTokens = rowHasTokens ? cand.tokensInput : msgHasTokens ? msgPromptTokens : null;
  const outputTokens = rowHasTokens ? cand.tokensOutput : msgHasTokens ? msgOutputTokens : null;
  const reasoningTokens = rowHasTokens
    ? cand.tokensReasoning
    : msgHasTokens
      ? msgReasoningTokens
      : null;
  const cacheReadTokens = rowHasTokens
    ? cand.tokensCacheRead
    : msgHasTokens
      ? msgCacheReadTokens
      : null;
  const cacheWriteTokens = rowHasTokens
    ? cand.tokensCacheWrite
    : msgHasTokens
      ? msgCacheWriteTokens
      : null;

  const cost = cand.cost > 0 ? cand.cost : msgHasCost ? msgCost : null;

  const modelId = msgModelId ?? parsedSessionModel.modelId ?? null;
  const modelProvider = msgModelProvider ?? parsedSessionModel.modelProvider ?? null;

  const verdict: ClassifierVerdict = toolVerdict ?? titleMeta.verdict ?? textVerdict ?? "UNSURE";
  const riskLevel = toolRiskLevel ?? textRiskLevel ?? null;
  const userAuthorization = toolUserAuth ?? textUserAuth ?? null;
  const thinking = thinkingSegments.length > 0 ? thinkingSegments.join("\n") : null;

  if (cand.idleOutcome === "interrupted") {
    isAborted = true;
  }

  let status: S2SessionStatus;
  if (toolVerdict || textVerdict || (titleMeta.verdict && !assistantError && !isAborted)) {
    status = "completed";
  } else if (isAborted) {
    status = "aborted";
  } else if (isTimeout) {
    status = "timeout";
  } else if (assistantError || cand.idleOutcome === "failed") {
    status = "error";
  } else {
    status = "partial";
  }

  const isPostVerdictInterrupt =
    status === "completed" &&
    typeof assistantError === "string" &&
    /^(?:step\s+interrupted|aborted(?:\s+by\s+signal)?)$/i.test(assistantError.trim());
  const effectiveError = isPostVerdictInterrupt ? null : (assistantError ?? null);
  const effectiveReasoning = toolReasoning ?? textReasoning ?? effectiveError ?? null;

  const createdAt = cand.timeCreated ?? firstUserCreatedAt ?? null;
  const updatedAt = cand.timeUpdated ?? lastAssistantCompletedAt ?? null;
  const archivedAt = cand.timeArchived ?? null;

  let durationMs = 0;
  if (
    firstUserCreatedAt !== undefined &&
    lastAssistantCompletedAt !== undefined &&
    lastAssistantCompletedAt >= firstUserCreatedAt
  ) {
    durationMs = lastAssistantCompletedAt - firstUserCreatedAt;
  } else if (createdAt !== null && updatedAt !== null && updatedAt >= createdAt) {
    durationMs = updatedAt - createdAt;
  }

  const toolName = titleMeta.toolName ?? promptFields?.toolName ?? "permission";

  const info: Record<string, unknown> = {
    id: cand.id,
    ...(cand.projectId ? { projectID: cand.projectId } : {}),
    ...(cand.workspaceId ? { workspaceID: cand.workspaceId } : {}),
    ...(cand.parentId ? { parentID: cand.parentId } : {}),
    ...(cand.slug ? { slug: cand.slug } : {}),
    ...(cand.directory ? { directory: cand.directory } : {}),
    ...(cand.path ? { path: cand.path } : {}),
    title: cand.title,
    ...(cand.version ? { version: cand.version } : {}),
    ...(cand.agent ? { agent: cand.agent } : {}),
    ...(parsedSessionModel.modelId || parsedSessionModel.modelProvider
      ? {
          model: {
            ...(parsedSessionModel.modelId ? { id: parsedSessionModel.modelId } : {}),
            ...(parsedSessionModel.modelProvider
              ? { providerID: parsedSessionModel.modelProvider }
              : {}),
          },
        }
      : {}),
    ...(parsedMetadata ? { metadata: parsedMetadata } : {}),
    cost: cost ?? 0,
    tokens: {
      input: promptTokens ?? 0,
      output: outputTokens ?? 0,
      reasoning: reasoningTokens ?? 0,
      cache: {
        read: cacheReadTokens ?? 0,
        write: cacheWriteTokens ?? 0,
      },
    },
    time: {
      ...(createdAt !== null ? { created: createdAt } : {}),
      ...(updatedAt !== null ? { updated: updatedAt } : {}),
      ...(cand.timeCompacting !== null ? { compacting: cand.timeCompacting } : {}),
      ...(archivedAt !== null ? { archived: archivedAt } : {}),
      ...(cand.timeIdle !== null ? { idle: cand.timeIdle } : {}),
    },
    ...(cand.idleOutcome ? { outcome: cand.idleOutcome } : {}),
  };

  return {
    targetSessionId,
    toolName,
    commandString: promptFields?.commandString ?? "",
    targetPath: promptFields?.targetPath ?? null,
    workspaceRoot: promptFields?.workspaceRoot ?? cand.directory ?? null,
    userPrompt: promptFields?.userPrompt ?? "",
    verdict,
    riskLevel,
    userAuthorization,
    reasoning: effectiveReasoning,
    thinking,
    error: effectiveError,
    status,
    modelId,
    modelProvider,
    promptTokens,
    outputTokens,
    reasoningTokens,
    cacheReadTokens,
    cacheWriteTokens,
    cost,
    durationMs,
    createdAt,
    updatedAt,
    archivedAt,
    info,
  };
}

function verifyExportedSessionIds(
  store: AutoGateEvalStore,
  candidateIds: readonly string[],
): Set<string> {
  const afterKeys = loadExistingEvalKeys(store);
  const verified = new Set<string>();
  for (const id of candidateIds) {
    if (afterKeys.s2SessionIds.has(id) && afterKeys.evalS2Ids.has(id)) {
      verified.add(id);
    }
  }
  return verified;
}

function isSessionSafeForDeletion(
  cand: RawOpenCodeSessionCandidate,
  cutoffMs: number | null,
): boolean {
  if (cand.timeArchived === null) return false;
  if (cand.timeSuspended !== null) return false;
  if (cutoffMs !== null && (cand.timeUpdated === null || cand.timeUpdated >= cutoffMs)) {
    return false;
  }
  return true;
}

function deleteVerifiedOpenCodeSessions(params: {
  opencodeDbPath: string;
  v2Ids: readonly string[];
  v1Ids: readonly string[];
  deleteAutoGateChildren: boolean;
  minAgeMinutes: number;
  nowMs: number;
  vacuum: boolean;
  batchSize: number;
  busyTimeoutMs: number;
}): {
  deletedV2: number;
  deletedV1: number;
  deletedChildSessions: number;
  deletedBlobs: number;
  skippedUnsafeIds: Set<string>;
  vacuumed: boolean;
} {
  const {
    opencodeDbPath,
    v2Ids,
    v1Ids,
    deleteAutoGateChildren,
    minAgeMinutes,
    nowMs,
    vacuum,
    batchSize,
    busyTimeoutMs,
  } = params;
  const cutoffMs = minAgeMinutes > 0 ? Math.floor(nowMs - minAgeMinutes * 60 * 1000) : null;
  const db = new DatabaseSync(opencodeDbPath, { timeout: busyTimeoutMs });
  let deletedV2 = 0;
  let deletedV1 = 0;
  let deletedChildSessions = 0;
  let deletedBlobs = 0;
  let vacuumed = false;
  const skippedUnsafeIds = new Set<string>();
  const candidateBlobHashes = new Set<string>();

  try {
    db.exec(`PRAGMA busy_timeout = ${Math.trunc(busyTimeoutMs)};`);
    db.exec("PRAGMA foreign_keys = ON;");
    const tables = getExistingTables(db);
    const hasEventSequence = tables.has("event_sequence");
    const hasBlobTables = tables.has("blob") && tables.has("blob_ref");

    const forEachChunk = (
      items: readonly string[],
      fn: (chunk: string[], placeholders: string) => void,
    ): void => {
      for (let idx = 0; idx < items.length; idx += batchSize) {
        const chunk = items.slice(idx, idx + batchSize);
        const placeholders = chunk.map(() => "?").join(", ");
        fn(chunk, placeholders);
      }
    };

    const deleteFromTable = (
      tableName: "session_v2" | "session",
      ids: readonly string[],
    ): number => {
      if (!tables.has(tableName) || ids.length === 0) return 0;
      const tableColumns = getTableColumns(db, tableName);
      if (!tableColumns.has("time_archived") || !tableColumns.has("time_updated")) {
        for (const id of ids) {
          skippedUnsafeIds.add(id);
        }
        return 0;
      }

      const hasTimeSuspended = tableColumns.has("time_suspended");
      const hasParentId = tableColumns.has("parent_id");
      const allTargetIdSet = new Set(ids);

      let total = 0;
      for (let i = 0; i < ids.length; i += batchSize) {
        const chunk = ids.slice(i, i + batchSize);
        const placeholders = chunk.map(() => "?").join(", ");
        const conditions = [
          `id IN (${placeholders})`,
          `title LIKE '[auto-gate-eval]%'`,
          `time_archived IS NOT NULL`,
        ];
        const selectParams: SQLInputValue[] = [...chunk];
        if (hasTimeSuspended) {
          conditions.push(`time_suspended IS NULL`);
        }
        if (cutoffMs !== null) {
          conditions.push(`time_updated < ?`);
          selectParams.push(cutoffMs);
        }

        db.exec("BEGIN IMMEDIATE");
        try {
          const eligibleRows = db
            .prepare(`SELECT id FROM ${tableName} WHERE ${conditions.join(" AND ")}`)
            .all(...selectParams);
          const eligibleIds: string[] = [];
          const eligibleSet = new Set<string>();
          for (const row of eligibleRows) {
            const id = nonEmptyString(row.id);
            if (id && !eligibleSet.has(id)) {
              eligibleSet.add(id);
              eligibleIds.push(id);
            }
          }
          for (const id of chunk) {
            if (!eligibleSet.has(id)) {
              skippedUnsafeIds.add(id);
            }
          }

          if (eligibleIds.length > 0) {
            const eligiblePlaceholders = eligibleIds.map(() => "?").join(", ");
            const eligibleParams: SQLInputValue[] = eligibleIds;

            const eligibleChildIds: string[] = [];
            if (deleteAutoGateChildren && hasParentId) {
              const childConditions = [
                `parent_id IN (${eligiblePlaceholders})`,
                `(title IS NULL OR title NOT LIKE '[auto-gate-eval]%')`,
                `time_archived IS NOT NULL`,
              ];
              const childSelectParams: SQLInputValue[] = [...eligibleIds];
              if (hasTimeSuspended) {
                childConditions.push(`time_suspended IS NULL`);
              }
              if (cutoffMs !== null) {
                childConditions.push(`time_updated < ?`);
                childSelectParams.push(cutoffMs);
              }
              const childRows = db
                .prepare(`SELECT id FROM ${tableName} WHERE ${childConditions.join(" AND ")}`)
                .all(...childSelectParams);
              const eligibleChildSet = new Set<string>();
              for (const childRow of childRows) {
                const childId = nonEmptyString(childRow.id);
                if (childId && !allTargetIdSet.has(childId) && !eligibleChildSet.has(childId)) {
                  eligibleChildSet.add(childId);
                  eligibleChildIds.push(childId);
                }
              }
            }

            const idsToCleanup =
              eligibleChildIds.length > 0 ? [...eligibleIds, ...eligibleChildIds] : eligibleIds;

            if (tableName === "session_v2" && hasBlobTables) {
              forEachChunk(idsToCleanup, (idChunk, idPlaceholders) => {
                const hashRows = db
                  .prepare(
                    `SELECT DISTINCT hash FROM blob_ref WHERE session_id IN (${idPlaceholders})`,
                  )
                  .all(...idChunk);
                for (const hashRow of hashRows) {
                  const hash = nonEmptyString(hashRow.hash);
                  if (hash) {
                    candidateBlobHashes.add(hash);
                  }
                }
              });
            }

            if (hasParentId) {
              forEachChunk(idsToCleanup, (idChunk, idPlaceholders) => {
                db.prepare(
                  `UPDATE ${tableName} SET parent_id = NULL WHERE parent_id IN (${idPlaceholders})`,
                ).run(...idChunk);
              });
            }

            if (hasEventSequence) {
              forEachChunk(idsToCleanup, (idChunk, idPlaceholders) => {
                if (tableName === "session_v2" || !tables.has("session_v2")) {
                  db.prepare(
                    `DELETE FROM event_sequence WHERE aggregate_id IN (${idPlaceholders})`,
                  ).run(...idChunk);
                } else {
                  db.prepare(
                    `DELETE FROM event_sequence
                     WHERE aggregate_id IN (${idPlaceholders})
                       AND NOT EXISTS (SELECT 1 FROM session_v2 WHERE session_v2.id = event_sequence.aggregate_id)`,
                  ).run(...idChunk);
                }
              });
            }

            const res = db
              .prepare(
                `DELETE FROM ${tableName}
                 WHERE id IN (${eligiblePlaceholders}) AND title LIKE '[auto-gate-eval]%'`,
              )
              .run(...eligibleParams);
            total += Number(res.changes ?? 0);

            if (eligibleChildIds.length > 0) {
              forEachChunk(eligibleChildIds, (childChunk, childPlaceholders) => {
                const childRes = db
                  .prepare(`DELETE FROM ${tableName} WHERE id IN (${childPlaceholders})`)
                  .run(...childChunk);
                deletedChildSessions += Number(childRes.changes ?? 0);
              });
            }
          }

          db.exec("COMMIT");
        } catch (err) {
          try {
            if (db.isTransaction) db.exec("ROLLBACK");
          } catch {}
          throw err;
        }
      }
      return total;
    };

    deletedV2 = deleteFromTable("session_v2", v2Ids);
    deletedV1 = deleteFromTable("session", v1Ids);

    if (hasBlobTables && candidateBlobHashes.size > 0) {
      const candidateHashes = Array.from(candidateBlobHashes);
      for (let i = 0; i < candidateHashes.length; i += batchSize) {
        const hashChunk = candidateHashes.slice(i, i + batchSize);
        const placeholders = hashChunk.map(() => "?").join(", ");
        const hashParams: SQLInputValue[] = hashChunk;
        db.exec("BEGIN IMMEDIATE");
        try {
          const res = db
            .prepare(
              `DELETE FROM blob
               WHERE hash IN (${placeholders})
                 AND NOT EXISTS (SELECT 1 FROM blob_ref WHERE blob_ref.hash = blob.hash)`,
            )
            .run(...hashParams);
          db.exec("COMMIT");
          deletedBlobs += Number(res.changes ?? 0);
        } catch (err) {
          try {
            if (db.isTransaction) db.exec("ROLLBACK");
          } catch {}
          throw err;
        }
      }
    }

    if (vacuum) {
      db.exec("VACUUM;");
      vacuumed = true;
    }
  } finally {
    db.close();
  }

  return { deletedV2, deletedV1, deletedChildSessions, deletedBlobs, skippedUnsafeIds, vacuumed };
}

export async function importOpenCodeDbToEvalStore(
  options: ImportOpenCodeDbOptions = {},
): Promise<ImportOpenCodeDbResult> {
  const dryRun = Boolean(options.dryRun);
  const deleteSessions = Boolean(options.deleteOpenCodeSessions);
  const deleteAutoGateChildren = Boolean(options.deleteAutoGateChildren);
  const minAgeMinutes =
    typeof options.minAgeMinutes === "number" &&
    Number.isFinite(options.minAgeMinutes) &&
    options.minAgeMinutes >= 0
      ? options.minAgeMinutes
      : DEFAULT_MIN_DELETE_AGE_MINUTES;
  const vacuum = Boolean(options.vacuum);
  const batchSize =
    typeof options.batchSize === "number" &&
    Number.isFinite(options.batchSize) &&
    options.batchSize > 0
      ? Math.trunc(options.batchSize)
      : DEFAULT_IMPORT_BATCH_SIZE;
  const busyTimeoutMs =
    typeof options.busyTimeoutMs === "number" &&
    Number.isFinite(options.busyTimeoutMs) &&
    options.busyTimeoutMs > 0
      ? Math.trunc(options.busyTimeoutMs)
      : DEFAULT_OPENCODE_BUSY_TIMEOUT_MS;

  const evalDbFile = options.store
    ? options.store.getDbPath()
    : expandImporterPath(nonEmptyString(options.evalDbFile) ?? resolveEvalDbFile());

  const explicitOpenCodeDb = nonEmptyString(options.opencodeDbPath);
  const opencodeDbPath = expandImporterPath(explicitOpenCodeDb ?? getDefaultOpenCodeDbPath());

  if (!fs.existsSync(opencodeDbPath)) {
    if (explicitOpenCodeDb) {
      throw new Error(`OpenCode database not found: ${opencodeDbPath}`);
    }
    return {
      evalDbFile,
      opencodeDbPath,
      opencodeDbFound: false,
      dryRun,
      v2SessionsFound: 0,
      v1SessionsFound: 0,
      overlappingSessionsDeduplicated: 0,
      uniqueSessionsFound: 0,
      s2SessionsInserted: 0,
      s2SessionsExisting: 0,
      evaluationsInserted: 0,
      evaluationsMerged: 0,
      promptTemplatesBefore: 0,
      promptTemplatesAfter: 0,
      deletedV2Sessions: 0,
      deletedV1Sessions: 0,
      deletedChildSessions: 0,
      skippedUnsafeForDeletion: 0,
      vacuumed: false,
      skippedReason: "opencode.db not found",
    };
  }

  const v2Map = new Map<string, RawOpenCodeSessionCandidate>();
  const v1Map = new Map<string, RawOpenCodeSessionCandidate>();

  const roDb = new DatabaseSync(opencodeDbPath, {
    readOnly: true,
    timeout: busyTimeoutMs,
  });
  try {
    roDb.exec(`PRAGMA busy_timeout = ${Math.trunc(busyTimeoutMs)};`);
    const tables = getExistingTables(roDb);

    if (tables.has("session_v2")) {
      const rows = roDb
        .prepare(
          "SELECT * FROM session_v2 WHERE title LIKE '[auto-gate-eval]%' ORDER BY time_created ASC, id ASC",
        )
        .all();
      for (const row of rows) {
        const cand = rowToSessionCandidate(row, "session_v2");
        if (cand) {
          v2Map.set(cand.id, cand);
        }
      }
      populateV2Messages(roDb, tables, v2Map);
    }

    if (tables.has("session")) {
      const rows = roDb
        .prepare(
          "SELECT * FROM session WHERE title LIKE '[auto-gate-eval]%' ORDER BY time_created ASC, id ASC",
        )
        .all();
      for (const row of rows) {
        const cand = rowToSessionCandidate(row, "session");
        if (cand) {
          v1Map.set(cand.id, cand);
        }
      }
      populateV1Messages(roDb, tables, v1Map);
    }
  } finally {
    roDb.close();
  }

  const { merged, overlappingCount } = mergeSessionCandidates(v2Map, v1Map);
  const knownSystemPrompts = getKnownEvalSystemPrompts();

  let ownedStore: AutoGateEvalStore | undefined;
  const activeStore =
    options.store ??
    (ownedStore = new AutoGateEvalStore(evalDbFile, {
      readonly: dryRun,
    }));

  try {
    const promptTemplatesBefore = activeStore.getStats().promptTemplateCount;
    const existing = loadExistingEvalKeys(activeStore);

    let s2SessionsInserted = 0;
    let s2SessionsExisting = 0;
    let evaluationsInserted = 0;
    let evaluationsMerged = 0;

    const exportedAllIds: string[] = [];
    const exportedV2Ids: string[] = [];
    const exportedV1Ids: string[] = [];

    for (let i = 0; i < merged.length; i += batchSize) {
      const chunk = merged.slice(i, i + batchSize);
      const prepared = chunk.map((entry) => {
        const cand = entry.primary;
        const { systemPrompt, sanitizedMessages } = extractAndStripSystemPrompt(
          cand.messages,
          knownSystemPrompts,
        );
        const extracted = extractOpenCodeSessionDetails(cand, sanitizedMessages);

        const s2Input = {
          s2SessionId: cand.id,
          targetSessionId: extracted.targetSessionId,
          title: cand.title,
          agent: cand.agent ?? "auto-gate-eval",
          directory: cand.directory,
          status: extracted.status,
          ...(systemPrompt ? { systemPrompt } : {}),
          modelId: extracted.modelId,
          modelProvider: extracted.modelProvider,
          promptTokens: extracted.promptTokens,
          outputTokens: extracted.outputTokens,
          reasoningTokens: extracted.reasoningTokens,
          cacheReadTokens: extracted.cacheReadTokens,
          cacheWriteTokens: extracted.cacheWriteTokens,
          cost: extracted.cost,
          messageCount: sanitizedMessages.length,
          createdAt: extracted.createdAt,
          updatedAt: extracted.updatedAt,
          archivedAt: extracted.archivedAt,
          payload: {
            info: extracted.info,
            messages: sanitizedMessages,
            sourceTables: entry.sourceTables,
          },
        };

        const evalInput: RecordEvaluationInput = {
          id: `opencode-db:${cand.id}`,
          sourceFormat: "opencode",
          timestamp: extracted.createdAt ?? 0,
          sessionId: extracted.targetSessionId ?? "",
          s2SessionId: cand.id,
          toolName: extracted.toolName,
          commandString: extracted.commandString,
          targetPath: extracted.targetPath,
          workspaceRoot: extracted.workspaceRoot,
          userPrompt: extracted.userPrompt,
          reasoning: extracted.reasoning,
          thinking: extracted.thinking,
          verdict: extracted.verdict,
          riskLevel: extracted.riskLevel,
          userAuthorization: extracted.userAuthorization,
          durationMs: extracted.durationMs,
          modelId: extracted.modelId,
          modelProvider: extracted.modelProvider,
          promptTokens: extracted.promptTokens,
          outputTokens: extracted.outputTokens,
          reasoningTokens: extracted.reasoningTokens,
          cost: extracted.cost,
          error: extracted.error,
          s2Aborted: extracted.status === "aborted",
          sourceOrigin: "opencode-db-import",
        };

        return { entry, s2Input, evalInput };
      });

      if (!dryRun) {
        activeStore.withTransaction(() => {
          for (const item of prepared) {
            activeStore.recordS2Session(item.s2Input);
          }
          activeStore.recordEvaluations(prepared.map((item) => item.evalInput));
        });
      }

      for (const item of prepared) {
        const s2Id = item.s2Input.s2SessionId;
        if (existing.s2SessionIds.has(s2Id)) {
          s2SessionsExisting += 1;
        } else {
          s2SessionsInserted += 1;
          existing.s2SessionIds.add(s2Id);
        }

        const evalId = item.evalInput.id!;
        if (existing.evalIds.has(evalId) || existing.evalS2Ids.has(s2Id)) {
          evaluationsMerged += 1;
        } else {
          evaluationsInserted += 1;
          existing.evalIds.add(evalId);
          existing.evalS2Ids.add(s2Id);
        }

        exportedAllIds.push(s2Id);
        if (item.entry.v2Present) exportedV2Ids.push(s2Id);
        if (item.entry.v1Present) exportedV1Ids.push(s2Id);
      }
    }

    const promptTemplatesAfter = dryRun
      ? promptTemplatesBefore
      : activeStore.getStats().promptTemplateCount;

    let deletedV2Sessions = 0;
    let deletedV1Sessions = 0;
    let deletedChildSessions = 0;
    let skippedUnsafeForDeletion = 0;
    let vacuumed = false;
    const nowMs = Date.now();
    const cutoffMs = minAgeMinutes > 0 ? Math.floor(nowMs - minAgeMinutes * 60 * 1000) : null;

    if (deleteSessions && dryRun) {
      const skippedDryIds = new Set<string>();
      for (const id of exportedV2Ids) {
        const cand = v2Map.get(id);
        if (!cand || !isSessionSafeForDeletion(cand, cutoffMs)) {
          skippedDryIds.add(id);
        }
      }
      for (const id of exportedV1Ids) {
        const cand = v1Map.get(id);
        if (!cand || !isSessionSafeForDeletion(cand, cutoffMs)) {
          skippedDryIds.add(id);
        }
      }
      skippedUnsafeForDeletion = skippedDryIds.size;
    } else if (deleteSessions && !dryRun) {
      const verifiedIds = verifyExportedSessionIds(activeStore, exportedAllIds);
      const verifiedV2Ids = exportedV2Ids.filter((id) => verifiedIds.has(id));
      const verifiedV1Ids = exportedV1Ids.filter((id) => verifiedIds.has(id));

      const deleteRes = deleteVerifiedOpenCodeSessions({
        opencodeDbPath,
        v2Ids: verifiedV2Ids,
        v1Ids: verifiedV1Ids,
        deleteAutoGateChildren,
        minAgeMinutes,
        nowMs,
        vacuum,
        batchSize,
        busyTimeoutMs,
      });
      deletedV2Sessions = deleteRes.deletedV2;
      deletedV1Sessions = deleteRes.deletedV1;
      deletedChildSessions = deleteRes.deletedChildSessions;
      skippedUnsafeForDeletion = deleteRes.skippedUnsafeIds.size;
      vacuumed = deleteRes.vacuumed;
    }

    return {
      evalDbFile,
      opencodeDbPath,
      opencodeDbFound: true,
      dryRun,
      v2SessionsFound: v2Map.size,
      v1SessionsFound: v1Map.size,
      overlappingSessionsDeduplicated: overlappingCount,
      uniqueSessionsFound: merged.length,
      s2SessionsInserted,
      s2SessionsExisting,
      evaluationsInserted,
      evaluationsMerged,
      promptTemplatesBefore,
      promptTemplatesAfter,
      deletedV2Sessions,
      deletedV1Sessions,
      deletedChildSessions,
      skippedUnsafeForDeletion,
      vacuumed,
    };
  } finally {
    if (ownedStore) {
      ownedStore.close();
    }
  }
}

function normalizeCommandVariantText(value: string): string {
  return value.replace(/[;\s]+/g, " ").trim();
}

export function parseCommandVariants(raw: string): string[] {
  if (typeof raw !== "string") return [];
  const trimmed = raw.trim();
  if (!trimmed) return [];

  const variants = new Set<string>();
  const addVariant = (val: unknown) => {
    if (typeof val !== "string") return;
    const normalized = normalizeCommandVariantText(val);
    if (normalized.length > 0) {
      variants.add(normalized);
    }
  };

  const addArrayVariants = (arr: unknown[]) => {
    const items = arr
      .filter((item): item is string => typeof item === "string")
      .map((item) => item.trim())
      .filter((item) => item.length > 0);
    if (items.length === 0) return;
    addVariant(items.join(" "));
    addVariant(items[0]);
  };

  addVariant(trimmed);

  if (trimmed.startsWith("[") || trimmed.startsWith("{")) {
    const parsed = parseJsonUnknownSafe(trimmed);
    if (Array.isArray(parsed)) {
      addArrayVariants(parsed);
    } else if (isRecord(parsed)) {
      for (const key of ["command", "cmd", "filepath", "filePath", "path", "pattern"] as const) {
        const val = parsed[key];
        if (typeof val === "string") {
          addVariant(val);
        } else if (Array.isArray(val)) {
          addArrayVariants(val);
        }
      }
      if (Array.isArray(parsed.patterns)) {
        addArrayVariants(parsed.patterns);
      }
    }
  }

  return Array.from(variants);
}

function areToolsCompatible(toolA: string, toolB: string): boolean {
  const a = toolA.trim().toLowerCase();
  const b = toolB.trim().toLowerCase();
  if (!a || !b) return false;
  if (a === b) return true;
  if (a === "permission" || b === "permission") return true;
  if ((a === "bash" && b === "shell") || (a === "shell" && b === "bash")) return true;
  return false;
}

interface CorrelationPoolEntry {
  rec: EvaluationRecord;
  variants: Set<string>;
  used: boolean;
}

function lowerBoundCandidateTimestamp(
  pool: readonly CorrelationPoolEntry[],
  minTimestamp: number,
): number {
  let lo = 0;
  let hi = pool.length;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    if (pool[mid]!.rec.timestamp < minTimestamp) {
      lo = mid + 1;
    } else {
      hi = mid;
    }
  }
  return lo;
}

export async function correlateUnlinkedJsonlEvaluations(
  options: CorrelateUnlinkedJsonlOptions = {},
): Promise<CorrelateUnlinkedJsonlResult> {
  const dryRun = Boolean(options.dryRun);
  const evalDbFile = options.store
    ? options.store.getDbPath()
    : expandImporterPath(nonEmptyString(options.evalDbFile) ?? resolveEvalDbFile());

  let ownedStore: AutoGateEvalStore | undefined;
  const activeStore =
    options.store ??
    (ownedStore = new AutoGateEvalStore(evalDbFile, {
      readonly: dryRun,
    }));

  try {
    const unlinkedJsonl = activeStore.listUnlinkedOpenCodeJsonlEvaluations();
    const dbCandidates = activeStore.listCorrelationCandidateDbEvaluations();

    if (unlinkedJsonl.length === 0 || dbCandidates.length === 0) {
      return {
        evalDbFile,
        dryRun,
        unlinkedJsonlFound: unlinkedJsonl.length,
        candidateDbRowsFound: dbCandidates.length,
        correlatedCount: 0,
        unmatchedCount: unlinkedJsonl.length,
        s1WinnerMergedCount: 0,
        s2WinnerMergedCount: 0,
        s2TargetsPopulatedCount: 0,
      };
    }

    const pool: CorrelationPoolEntry[] = dbCandidates.map((rec) => ({
      rec,
      variants: new Set(parseCommandVariants(rec.commandString)),
      used: false,
    }));

    const matches: Array<{
      jsonl: EvaluationRecord;
      target: EvaluationRecord;
      mergeInput: MergeCorrelatedEvaluationInput;
    }> = [];

    let unmatchedCount = 0;
    let s1WinnerMergedCount = 0;
    let s2WinnerMergedCount = 0;

    const normalizeNonSandboxWorkspace = (ws: string | null | undefined): string | null => {
      if (!ws) return null;
      const trimmed = ws.trim();
      if (!trimmed) return null;
      const resolved = path.resolve(expandImporterPath(trimmed));
      if (resolved === "/tmp/opencode-auto-gate/sandbox") {
        return null;
      }
      return resolved;
    };

    for (const j of unlinkedJsonl) {
      if (j.cascade?.mode === "cascade" && j.cascadeWinner === "system1") {
        unmatchedCount += 1;
        continue;
      }
      const jVariants = parseCommandVariants(j.commandString);
      if (jVariants.length === 0) {
        unmatchedCount += 1;
        continue;
      }

      const jWs = normalizeNonSandboxWorkspace(j.workspaceRoot);
      const estStart = j.timestamp - Math.max(0, j.durationMs);
      const winMin = estStart - 3000;
      const winMax = j.timestamp + 1500;
      const startIdx = lowerBoundCandidateTimestamp(pool, winMin);

      let best: {
        entry: CorrelationPoolEntry;
        verdictMatch: boolean;
        timeDiff: number;
      } | null = null;

      for (let idx = startIdx; idx < pool.length; idx++) {
        const entry = pool[idx]!;
        if (entry.rec.timestamp > winMax) break;
        if (entry.used) continue;
        if (!areToolsCompatible(j.toolName, entry.rec.toolName)) continue;
        const dbWs = normalizeNonSandboxWorkspace(entry.rec.workspaceRoot);
        if (jWs && dbWs && jWs !== dbWs) continue;
        if (!jVariants.some((variant) => entry.variants.has(variant))) continue;

        const verdictMatch = j.verdict === entry.rec.verdict;
        const timeDiff = Math.abs(estStart - entry.rec.timestamp);

        if (
          !best ||
          (verdictMatch && !best.verdictMatch) ||
          (verdictMatch === best.verdictMatch && timeDiff < best.timeDiff) ||
          (verdictMatch === best.verdictMatch &&
            timeDiff === best.timeDiff &&
            entry.rec.id < best.entry.rec.id)
        ) {
          best = { entry, verdictMatch, timeDiff };
        }
      }

      if (!best) {
        unmatchedCount += 1;
        continue;
      }

      best.entry.used = true;
      if (j.cascadeWinner === "system1") {
        s1WinnerMergedCount += 1;
      } else if (j.cascadeWinner === "system2") {
        s2WinnerMergedCount += 1;
      }

      matches.push({
        jsonl: j,
        target: best.entry.rec,
        mergeInput: {
          sourceId: j.id,
          targetId: best.entry.rec.id,
          sessionId: j.sessionId,
          verdict: j.verdict,
          riskLevel: j.riskLevel,
          userAuthorization: j.userAuthorization,
          reasoning: j.reasoning,
          userPrompt: j.userPrompt,
          durationMs: j.durationMs,
          timestamp: j.timestamp,
          cascadeJson: j.cascadeJson,
          cascadeWinner: j.cascadeWinner,
          s2Aborted: j.s2Aborted,
          s2SessionId: best.entry.rec.s2SessionId,
        },
      });
    }

    let s2TargetsPopulatedCount = 0;

    if (matches.length > 0) {
      if (!dryRun) {
        activeStore.withTransaction(() => {
          for (const match of matches) {
            const res = activeStore.mergeCorrelatedEvaluation(match.mergeInput);
            if (res.s2TargetPopulated) {
              s2TargetsPopulatedCount += 1;
            }
          }
        });
      } else {
        const s2TargetMap = new Map<string, string | null>();
        const pageSize = 5000;
        for (let offset = 0; ; offset += pageSize) {
          const batch = activeStore.listS2Sessions({ limit: pageSize, offset });
          for (const s2 of batch) {
            s2TargetMap.set(s2.s2SessionId, s2.targetSessionId);
          }
          if (batch.length < pageSize) break;
        }

        const populatedS2Ids = new Set<string>();
        for (const match of matches) {
          const s2Id = match.target.s2SessionId;
          const sessionId = match.jsonl.sessionId.trim();
          if (
            s2Id &&
            sessionId &&
            s2TargetMap.has(s2Id) &&
            !s2TargetMap.get(s2Id) &&
            !populatedS2Ids.has(s2Id)
          ) {
            populatedS2Ids.add(s2Id);
            s2TargetsPopulatedCount += 1;
          }
        }
      }
    }

    return {
      evalDbFile,
      dryRun,
      unlinkedJsonlFound: unlinkedJsonl.length,
      candidateDbRowsFound: dbCandidates.length,
      correlatedCount: matches.length,
      unmatchedCount,
      s1WinnerMergedCount,
      s2WinnerMergedCount,
      s2TargetsPopulatedCount,
    };
  } finally {
    if (ownedStore) {
      ownedStore.close();
    }
  }
}

export async function migrateToEvalStore(
  options: MigrateToEvalStoreOptions = {},
): Promise<MigrateToEvalStoreResult> {
  const dryRun = Boolean(options.dryRun);
  const skipJsonl = Boolean(options.skipJsonl);
  const skipOpenCodeDb = Boolean(options.skipOpenCodeDb);
  const skipCorrelate = Boolean(options.skipCorrelate);
  const deleteOpenCodeSessions = Boolean(options.deleteOpenCodeSessions);
  const deleteAutoGateChildren = Boolean(options.deleteAutoGateChildren);
  const vacuumRequested = Boolean(options.vacuum);

  const evalDbFile = expandImporterPath(nonEmptyString(options.evalDbFile) ?? resolveEvalDbFile());
  const explicitOpenCodeDb = nonEmptyString(options.opencodeDbPath);
  const opencodeDbPath = expandImporterPath(explicitOpenCodeDb ?? getDefaultOpenCodeDbPath());

  const evalDbSizeBefore = measureSqliteFileSizes(evalDbFile);
  const opencodeDbSizeBefore = measureSqliteFileSizes(opencodeDbPath);

  const store = new AutoGateEvalStore(evalDbFile, { readonly: dryRun });
  let jsonlResult: ImportJsonlResult | undefined;
  let opencodeResult: ImportOpenCodeDbResult | undefined;
  let correlateResult: CorrelateUnlinkedJsonlResult | undefined;

  try {
    if (!skipJsonl) {
      jsonlResult = await importJsonlToEvalStore({
        store,
        evalDbFile,
        jsonlFiles: options.jsonlFiles,
        opencodeDbPath,
        skipOpenCodeDbLookup: skipOpenCodeDb && !explicitOpenCodeDb,
        dryRun,
        batchSize: options.batchSize,
      });
    }

    if (!skipOpenCodeDb) {
      opencodeResult = await importOpenCodeDbToEvalStore({
        store,
        evalDbFile,
        ...(explicitOpenCodeDb ? { opencodeDbPath: explicitOpenCodeDb } : {}),
        dryRun,
        deleteOpenCodeSessions,
        deleteAutoGateChildren,
        ...(options.minAgeMinutes !== undefined ? { minAgeMinutes: options.minAgeMinutes } : {}),
        vacuum: vacuumRequested,
        batchSize: options.batchSize,
      });
    }

    if (!skipCorrelate) {
      correlateResult = await correlateUnlinkedJsonlEvaluations({
        store,
        evalDbFile,
        dryRun,
      });
    }
  } finally {
    store.close();
  }

  const evalDbSizeAfter = measureSqliteFileSizes(evalDbFile);
  const opencodeDbSizeAfter = measureSqliteFileSizes(opencodeDbPath);

  return {
    evalDbFile,
    opencodeDbPath,
    dryRun,
    skipJsonl,
    skipOpenCodeDb,
    skipCorrelate,
    deleteOpenCodeSessions,
    deleteAutoGateChildren,
    vacuumRequested,
    ...(jsonlResult ? { jsonl: jsonlResult } : {}),
    ...(opencodeResult ? { opencodeDb: opencodeResult } : {}),
    ...(correlateResult ? { correlate: correlateResult } : {}),
    evalDbSizeBefore,
    evalDbSizeAfter,
    opencodeDbSizeBefore,
    opencodeDbSizeAfter,
  };
}
