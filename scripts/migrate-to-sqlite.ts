#!/usr/bin/env bun
import {
  migrateToEvalStore,
  type MigrateToEvalStoreResult,
  type SqliteFileSizes,
} from "@autogate/core/eval-importer";

export interface MigrateCliOptions {
  readonly evalDb?: string;
  readonly opencodeDb?: string;
  readonly jsonl: readonly string[];
  readonly skipJsonl: boolean;
  readonly skipOpenCodeDb: boolean;
  readonly skipCorrelate: boolean;
  readonly dryRun: boolean;
  readonly deleteOpenCodeSessions: boolean;
  readonly deleteAutoGateChildren: boolean;
  readonly minAgeMinutes?: number;
  readonly vacuum: boolean;
  readonly json: boolean;
  readonly help: boolean;
}

export function formatMigrateCliHelp(): string {
  return [
    "AutoGate SQLite Migration & Importer",
    "",
    "Usage: bun run scripts/migrate-to-sqlite.ts [options]",
    "",
    "Options:",
    "  --eval-db <path>             Target AutoGate evals.db path (default: config/evalDbFile)",
    "  --opencode-db <path>         Source OpenCode DB path (default: ~/.local/share/opencode/opencode.db)",
    "  --jsonl <path>               Source JSONL log file (repeatable; defaults to ~/.omp/logs/autogate-evals.jsonl",
    "                               and ~/.config/autogate/logs/evals.jsonl when omitted)",
    "  --skip-jsonl                 Skip importing JSONL audit logs",
    "  --skip-opencode-db           Skip importing [auto-gate-eval] sessions from opencode.db",
    "  --skip-correlate             Skip correlating unlinked OpenCode JSONL rows with S2 DB rows",
    "  --dry-run                    Preview counts without modifying evals.db or opencode.db",
    "  --delete-opencode-sessions   Delete verified-exported [auto-gate-eval] sessions from opencode.db",
    "  --delete-autogate-children   Also delete archived, aged child sessions of deleted [auto-gate-eval] parents",
    "  --min-age-minutes <n>        Minimum session age in minutes before deletion (default: 10; 0 disables)",
    "  --vacuum                     Run VACUUM on opencode.db (requires --delete-opencode-sessions and not --dry-run)",
    "  --json                       Print machine-readable JSON summary",
    "  --help, -h                   Show this help message",
  ].join("\n");
}

export function parseMigrateCliArgs(argv: readonly string[]): MigrateCliOptions {
  let evalDb: string | undefined;
  let opencodeDb: string | undefined;
  const jsonl: string[] = [];
  let skipJsonl = false;
  let skipOpenCodeDb = false;
  let skipCorrelate = false;
  let dryRun = false;
  let deleteOpenCodeSessions = false;
  let deleteAutoGateChildren = false;
  let minAgeMinutes: number | undefined;
  let vacuum = false;
  let json = false;
  let help = false;

  const readValue = (index: number, flag: string, inlineVal?: string): [string, number] => {
    if (inlineVal !== undefined) {
      if (inlineVal.length === 0) {
        throw new Error(`Missing value for ${flag}`);
      }
      return [inlineVal, index];
    }
    if (index + 1 >= argv.length) {
      throw new Error(`Missing value for ${flag}`);
    }
    const next = argv[index + 1]!;
    if (!next.trim()) {
      throw new Error(`Missing value for ${flag}`);
    }
    return [next, index + 1];
  };

  for (let i = 0; i < argv.length; i++) {
    const rawArg = argv[i]!;
    if (rawArg === "--help" || rawArg === "-h") {
      help = true;
      continue;
    }

    const eqIdx = rawArg.indexOf("=");
    const flag = eqIdx > 0 ? rawArg.slice(0, eqIdx) : rawArg;
    const inlineVal = eqIdx > 0 ? rawArg.slice(eqIdx + 1) : undefined;

    switch (flag) {
      case "--eval-db": {
        const [val, nextIdx] = readValue(i, flag, inlineVal);
        evalDb = val;
        i = nextIdx;
        break;
      }
      case "--opencode-db": {
        const [val, nextIdx] = readValue(i, flag, inlineVal);
        opencodeDb = val;
        i = nextIdx;
        break;
      }
      case "--jsonl": {
        const [val, nextIdx] = readValue(i, flag, inlineVal);
        jsonl.push(val);
        i = nextIdx;
        break;
      }
      case "--skip-jsonl":
        if (inlineVal !== undefined) throw new Error(`${flag} does not take a value`);
        skipJsonl = true;
        break;
      case "--skip-opencode-db":
        if (inlineVal !== undefined) throw new Error(`${flag} does not take a value`);
        skipOpenCodeDb = true;
        break;
      case "--skip-correlate":
        if (inlineVal !== undefined) throw new Error(`${flag} does not take a value`);
        skipCorrelate = true;
        break;
      case "--dry-run":
        if (inlineVal !== undefined) throw new Error(`${flag} does not take a value`);
        dryRun = true;
        break;
      case "--delete-opencode-sessions":
        if (inlineVal !== undefined) throw new Error(`${flag} does not take a value`);
        deleteOpenCodeSessions = true;
        break;
      case "--delete-autogate-children":
        if (inlineVal !== undefined) throw new Error(`${flag} does not take a value`);
        deleteAutoGateChildren = true;
        break;
      case "--min-age-minutes": {
        const [val, nextIdx] = readValue(i, flag, inlineVal);
        const parsedAge = Number(val);
        if (!Number.isFinite(parsedAge) || parsedAge < 0) {
          throw new Error(`Invalid value for ${flag}: ${val}`);
        }
        minAgeMinutes = parsedAge;
        i = nextIdx;
        break;
      }
      case "--vacuum":
        if (inlineVal !== undefined) throw new Error(`${flag} does not take a value`);
        vacuum = true;
        break;
      case "--json":
        if (inlineVal !== undefined) throw new Error(`${flag} does not take a value`);
        json = true;
        break;
      default:
        throw new Error(`Unknown option: ${rawArg}`);
    }
  }

  return {
    ...(evalDb ? { evalDb } : {}),
    ...(opencodeDb ? { opencodeDb } : {}),
    jsonl,
    skipJsonl,
    skipOpenCodeDb,
    skipCorrelate,
    dryRun,
    deleteOpenCodeSessions,
    deleteAutoGateChildren,
    ...(minAgeMinutes !== undefined ? { minAgeMinutes } : {}),
    vacuum,
    json,
    help,
  };
}

function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let value = bytes / 1024;
  let unitIdx = 0;
  while (value >= 1024 && unitIdx < units.length - 1) {
    value /= 1024;
    unitIdx += 1;
  }
  return `${value.toFixed(2)} ${units[unitIdx]}`;
}

function formatSizeChange(before: SqliteFileSizes, after: SqliteFileSizes): string {
  if (!before.exists && !after.exists) return "not present";
  return `${formatBytes(before.totalBytes)} -> ${formatBytes(after.totalBytes)}`;
}

export function formatMigrateSummary(result: MigrateToEvalStoreResult): string {
  const lines: string[] = [];
  lines.push(result.dryRun ? "AutoGate SQLite Migration (DRY RUN)" : "AutoGate SQLite Migration");
  lines.push(`Target evals.db: ${result.evalDbFile}`);
  lines.push(`  Size: ${formatSizeChange(result.evalDbSizeBefore, result.evalDbSizeAfter)}`);

  if (result.jsonl) {
    const j = result.jsonl;
    const skippedFiles = j.files.filter((f) => !f.exists).length;
    const skippedLines = j.blankLines + j.malformedLines;
    lines.push("");
    lines.push("JSONL Import:");
    lines.push(
      `  Files scanned: ${j.files.length - skippedFiles}/${j.files.length} (missing skipped: ${skippedFiles})`,
    );
    lines.push(
      `  Imported: ${j.insertedCount} new, ${j.mergedCount} deduplicated/merged (${j.importedCount} processed)`,
    );
    lines.push(
      `  Skipped lines: ${skippedLines} (${j.blankLines} blank, ${j.malformedLines} malformed)`,
    );
    if (j.linkedS2Count > 0) {
      lines.push(
        `  S2 links resolved: ${j.linkedS2Count} (${j.recoveredTargetSessionCount} target session IDs recovered)`,
      );
    }
    for (const f of j.files) {
      if (!f.exists) {
        lines.push(`  - [missing] ${f.filePath}`);
      } else {
        lines.push(
          `  - ${f.filePath}: ${f.insertedCount} new, ${f.mergedCount} deduplicated, ${f.malformedLines} malformed, ${f.blankLines} blank`,
        );
      }
    }
  } else if (result.skipJsonl) {
    lines.push("");
    lines.push("JSONL Import: skipped (--skip-jsonl)");
  }

  if (result.opencodeDb) {
    const o = result.opencodeDb;
    lines.push("");
    lines.push(`OpenCode DB Import (${o.opencodeDbPath}):`);
    if (!o.opencodeDbFound) {
      lines.push(`  Skipped: ${o.skippedReason ?? "not found"}`);
    } else {
      lines.push(
        `  Sessions found: ${o.uniqueSessionsFound} unique (session_v2: ${o.v2SessionsFound}, session: ${o.v1SessionsFound}, deduplicated overlap: ${o.overlappingSessionsDeduplicated})`,
      );
      lines.push(`  S2 sessions: ${o.s2SessionsInserted} new, ${o.s2SessionsExisting} existing`);
      lines.push(
        `  Evaluations: ${o.evaluationsInserted} new, ${o.evaluationsMerged} merged/deduplicated`,
      );
      lines.push(`  Prompt templates: ${o.promptTemplatesBefore} -> ${o.promptTemplatesAfter}`);
      const childSummary =
        o.deletedChildSessions > 0 || result.deleteAutoGateChildren
          ? `, child sessions: ${o.deletedChildSessions}`
          : "";
      lines.push(
        `  Deleted from opencode.db: ${o.deletedV2Sessions + o.deletedV1Sessions} (session_v2: ${o.deletedV2Sessions}, session: ${o.deletedV1Sessions})${childSummary}${o.skippedUnsafeForDeletion > 0 ? `, skipped unsafe/active/recent: ${o.skippedUnsafeForDeletion}` : ""}`,
      );
      lines.push(`  Vacuumed: ${o.vacuumed ? "yes" : "no"}`);
      if (result.deleteAutoGateChildren && (!result.deleteOpenCodeSessions || result.dryRun)) {
        lines.push(
          "  Note: --delete-autogate-children skipped (requires --delete-opencode-sessions without --dry-run)",
        );
      }
      if (result.vacuumRequested && (!result.deleteOpenCodeSessions || result.dryRun)) {
        lines.push(
          "  Note: --vacuum skipped (requires --delete-opencode-sessions without --dry-run)",
        );
      }
      lines.push(
        `  opencode.db size: ${formatSizeChange(result.opencodeDbSizeBefore, result.opencodeDbSizeAfter)}`,
      );
    }
  } else if (result.skipOpenCodeDb) {
    lines.push("");
    lines.push("OpenCode DB Import: skipped (--skip-opencode-db)");
  }

  if (result.correlate) {
    const c = result.correlate;
    lines.push("");
    lines.push("JSONL <-> S2 Correlation:");
    lines.push(
      `  Candidates: ${c.unlinkedJsonlFound} unlinked JSONL, ${c.candidateDbRowsFound} unlinked S2 DB rows`,
    );
    lines.push(
      `  Correlated/merged: ${c.correlatedCount} (unmatched JSONL: ${c.unmatchedCount}, S2 target_session_id populated: ${c.s2TargetsPopulatedCount})`,
    );
  } else if (result.skipCorrelate) {
    lines.push("");
    lines.push("JSONL <-> S2 Correlation: skipped (--skip-correlate)");
  }

  return lines.join("\n");
}

export async function runMigrateCli(
  argv: readonly string[],
  io: { log?: (line: string) => void } = {},
): Promise<MigrateToEvalStoreResult | null> {
  const log = io.log ?? ((line: string) => console.log(line));
  const opts = parseMigrateCliArgs(argv);

  if (opts.help) {
    log(formatMigrateCliHelp());
    return null;
  }

  const result = await migrateToEvalStore({
    ...(opts.evalDb ? { evalDbFile: opts.evalDb } : {}),
    ...(opts.opencodeDb ? { opencodeDbPath: opts.opencodeDb } : {}),
    ...(opts.jsonl.length > 0 ? { jsonlFiles: opts.jsonl } : {}),
    skipJsonl: opts.skipJsonl,
    skipOpenCodeDb: opts.skipOpenCodeDb,
    skipCorrelate: opts.skipCorrelate,
    dryRun: opts.dryRun,
    deleteOpenCodeSessions: opts.deleteOpenCodeSessions,
    deleteAutoGateChildren: opts.deleteAutoGateChildren,
    ...(opts.minAgeMinutes !== undefined ? { minAgeMinutes: opts.minAgeMinutes } : {}),
    vacuum: opts.vacuum,
  });

  if (opts.json) {
    log(JSON.stringify(result, null, 2));
  } else {
    log(formatMigrateSummary(result));
  }

  return result;
}

if (import.meta.main) {
  runMigrateCli(process.argv.slice(2)).catch((err) => {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`[migrate-to-sqlite] Error: ${message}`);
    process.exit(1);
  });
}
