import { DatabaseSync, type SQLInputValue } from "node:sqlite";
import type { AutoGateEvalStore } from "../eval-store.js";
import type { RawOpenCodeSessionCandidate } from "./opencode-extract.js";
import { getExistingTables, getTableColumns, nonEmptyString } from "./utils.js";

export function verifyExportedSessionIds(
  store: AutoGateEvalStore,
  candidateIds: readonly string[],
): Set<string> {
  const afterKeys = store.getExistingKeys();
  const verified = new Set<string>();
  for (const id of candidateIds) {
    if (afterKeys.s2SessionIds.has(id) && afterKeys.evalS2Ids.has(id)) {
      verified.add(id);
    }
  }
  return verified;
}

export function isSessionSafeForDeletion(
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

export function deleteVerifiedOpenCodeSessions(params: {
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
