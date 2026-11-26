import path from "node:path";
import { isRecord, resolveEvalDbFile } from "../config.js";
import {
  AutoGateEvalStore,
  type EvaluationRecord,
  type MergeCorrelatedEvaluationInput,
} from "../eval-store.js";
import type { CorrelateUnlinkedJsonlOptions, CorrelateUnlinkedJsonlResult } from "./types.js";
import { expandImporterPath, nonEmptyString, parseJsonUnknownSafe } from "./utils.js";

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
