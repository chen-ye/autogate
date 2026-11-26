import fs from "node:fs";
import { DatabaseSync, type SQLInputValue, type SQLOutputValue } from "node:sqlite";
import { resolveEvalDbFile } from "../config.js";
import { AutoGateEvalStore, type RecordEvaluationInput } from "../eval-store.js";
import { extractAndStripSystemPrompt, getKnownEvalSystemPrompts } from "../s2-transcript.js";
import {
  deleteVerifiedOpenCodeSessions,
  isSessionSafeForDeletion,
  verifyExportedSessionIds,
} from "./opencode-delete.js";
import {
  extractOpenCodeSessionDetails,
  type RawOpenCodeSessionCandidate,
} from "./opencode-extract.js";
import {
  AUTOGATE_EVAL_TITLE_PREFIX,
  DEFAULT_IMPORT_BATCH_SIZE,
  DEFAULT_MIN_DELETE_AGE_MINUTES,
  DEFAULT_OPENCODE_BUSY_TIMEOUT_MS,
  type ImportOpenCodeDbOptions,
  type ImportOpenCodeDbResult,
} from "./types.js";
import {
  expandImporterPath,
  extractTargetSessionIdFromRow,
  finiteInt,
  finiteNumber,
  getDefaultOpenCodeDbPath,
  getExistingTables,
  getTableColumns,
  nonEmptyString,
  parseJsonObjectSafe,
} from "./utils.js";

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
    const existing = activeStore.getExistingKeys();

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
