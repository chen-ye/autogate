import fs from "node:fs";
import path from "node:path";
import { randomUUID } from "node:crypto";
import {
  DatabaseSync,
  type SQLInputValue,
  type SQLOutputValue,
  type StatementSync,
} from "node:sqlite";
import { isClassifierVerdict, isRiskLevel, isUserAuthorization } from "./classifier.js";
import { resolveEvalDbFile } from "./config.js";
import type { CascadeTrace, ClassifierVerdict, RiskLevel, UserAuthorization } from "./types.js";
import {
  asBytes,
  compressPayloadZstd,
  computePromptTemplateHash,
  decompressPayloadZstd,
  emptyStats,
  escapeSqlLikePattern,
  expandDbPath,
  finiteIntOrNull,
  finiteNumberOrNull,
  isMissingTableError,
  nonEmptyStringOrNull,
  normalizeAgentConfig,
  parseCascadeJson,
  rowToEvaluationRecord,
  rowToPromptTemplate,
  rowToS2SessionSummary,
} from "./eval-store/codec.js";
import {
  SCHEMA_SQL,
  UPSERT_EVALUATION_BY_ID_SQL,
  UPSERT_S2_SESSION_SQL,
} from "./eval-store/schema.js";
import {
  DEFAULT_EVAL_QUERY_LIMIT,
  DEFAULT_EVAL_STORE_BUSY_TIMEOUT_MS,
  type AutoGateEvalStoreOptions,
  type EvalStats,
  type EvalStatsOptions,
  type EvaluationDetail,
  type EvaluationQueryOptions,
  type EvaluationRecord,
  type LinkS2SessionInput,
  type ListS2SessionsOptions,
  type MergeCorrelatedEvaluationInput,
  type PromptTemplateRecord,
  type RecordEvaluationInput,
  type RecordS2SessionInput,
  type S2SessionRecord,
  type S2SessionSummary,
} from "./eval-store/types.js";

export * from "./eval-store/types.js";
export { computePromptTemplateHash };

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
