import { resolveEvalDbFile } from "./config.js";
import { AutoGateEvalStore } from "./eval-store.js";
import { correlateUnlinkedJsonlEvaluations } from "./eval-import/correlate.js";
import { importJsonlToEvalStore } from "./eval-import/jsonl.js";
import { importOpenCodeDbToEvalStore } from "./eval-import/opencode-db.js";
import type {
  CorrelateUnlinkedJsonlResult,
  ImportJsonlResult,
  ImportOpenCodeDbResult,
  MigrateToEvalStoreOptions,
  MigrateToEvalStoreResult,
} from "./eval-import/types.js";
import {
  expandImporterPath,
  getDefaultJsonlPaths,
  getDefaultOpenCodeDbPath,
  measureSqliteFileSizes,
  nonEmptyString,
} from "./eval-import/utils.js";

export * from "./eval-import/types.js";
export {
  expandImporterPath,
  getDefaultJsonlPaths,
  getDefaultOpenCodeDbPath,
  measureSqliteFileSizes,
};
export { computeJsonlLineId, importJsonlToEvalStore } from "./eval-import/jsonl.js";
export { importOpenCodeDbToEvalStore, readOpenCodeS2TargetMap } from "./eval-import/opencode-db.js";
export {
  correlateUnlinkedJsonlEvaluations,
  parseCommandVariants,
} from "./eval-import/correlate.js";

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
