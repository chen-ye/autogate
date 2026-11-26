import type { AutoGateEvalStore } from "../eval-store.js";

export const DEFAULT_IMPORT_BATCH_SIZE = 250;
export const DEFAULT_OPENCODE_BUSY_TIMEOUT_MS = 5000;
export const DEFAULT_MIN_DELETE_AGE_MINUTES = 10;
export const AUTOGATE_EVAL_TITLE_PREFIX = "[auto-gate-eval]";

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
