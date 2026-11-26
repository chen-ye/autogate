import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import readline from "node:readline";
import { parseModelRef } from "../agent.js";
import { isClassifierVerdict } from "../classifier.js";
import { isRecord, resolveEvalDbFile } from "../config.js";
import { AutoGateEvalStore, type RecordEvaluationInput } from "../eval-store.js";
import { parseTimestampMs } from "../s2-transcript.js";
import { readOpenCodeS2TargetMap } from "./opencode-db.js";
import {
  DEFAULT_IMPORT_BATCH_SIZE,
  type ImportJsonlOptions,
  type ImportJsonlResult,
  type JsonlFileImportSummary,
} from "./types.js";
import {
  expandImporterPath,
  finiteInt,
  finiteNumber,
  getDefaultJsonlPaths,
  getDefaultOpenCodeDbPath,
  nonEmptyString,
  nonNegInt,
  normalizeCascade,
  normalizeRiskLevel,
  normalizeUserAuth,
  rawStringOrUndefined,
} from "./utils.js";

export function computeJsonlLineId(filePath: string, lineNumber: number, rawLine: string): string {
  const absPath = path.resolve(filePath);
  const digest = createHash("sha256").update(`${absPath}:${lineNumber}:${rawLine}`).digest("hex");
  return `jsonl:${digest}`;
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
    const existing = activeStore.getExistingKeys();
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
