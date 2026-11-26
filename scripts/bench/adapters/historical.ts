import fs from "node:fs";
import path from "node:path";
import { resolveEvalDbFile } from "../../../packages/core/src/config.js";
import { AutoGateEvalStore, type EvaluationRecord } from "@autogate/core";
import type { ClassifierVerdict, PermissionEventData } from "../../../packages/core/src/types.js";
import { ensureEmptyBenchWorkspace, expandHomePath } from "../paths.js";
import {
  makeEditPermissionEvent,
  makeExternalDirectoryPermissionEvent,
  makeMcpPermissionEvent,
  makeReadPermissionEvent,
  makeShellPermissionEvent,
  neutralizeReservedPromptMarkers,
  type StaticBenchCase,
} from "../schema.js";

export interface HistoricalLoadOptions {
  readonly file?: string;
  readonly dbFile?: string;
  readonly maxCases?: number;
}

export type HistoricalEvalSource =
  | { readonly kind: "db"; readonly path: string }
  | { readonly kind: "jsonl"; readonly path: string };

export function resolveHistoricalEvalSource(
  explicitFile?: string,
  explicitDbFile?: string,
): HistoricalEvalSource | undefined {
  if (typeof explicitDbFile === "string" && explicitDbFile.trim().length > 0) {
    const trimmed = explicitDbFile.trim();
    return {
      kind: "db",
      path: trimmed === ":memory:" ? ":memory:" : path.resolve(expandHomePath(trimmed)),
    };
  }

  if (typeof explicitFile === "string" && explicitFile.trim().length > 0) {
    const trimmed = explicitFile.trim();
    if (trimmed === ":memory:") {
      return { kind: "db", path: ":memory:" };
    }
    const resolved = path.resolve(expandHomePath(trimmed));
    if (resolved.toLowerCase().endsWith(".jsonl")) {
      return { kind: "jsonl", path: resolved };
    }
    return { kind: "db", path: resolved };
  }

  const dbPath = resolveEvalDbFile();
  if (dbPath !== ":memory:" && !fs.existsSync(dbPath)) {
    return undefined;
  }
  return { kind: "db", path: dbPath };
}

interface UnwrappedHistoricalAction {
  readonly commands?: readonly string[];
  readonly filePath?: string;
  readonly directory?: string;
  readonly inputObject?: Record<string, unknown>;
  readonly rawText?: string;
}

function toStringArray(val: unknown): string[] | undefined {
  if (!Array.isArray(val)) {
    return undefined;
  }
  const items = val.filter((v): v is string => typeof v === "string" && v.trim().length > 0);
  return items.length > 0 ? items : undefined;
}

function firstNonEmptyString(
  obj: Record<string, unknown>,
  keys: readonly string[],
): string | undefined {
  for (const key of keys) {
    const v = obj[key];
    if (typeof v === "string" && v.trim().length > 0) {
      return v.trim();
    }
  }
  return undefined;
}

function unwrapSerializedCommandString(
  rawCommand: string | undefined,
  explicitTargetPath: string | undefined,
): UnwrappedHistoricalAction {
  const trimmed = rawCommand?.trim();
  if (!trimmed) {
    return explicitTargetPath ? { filePath: explicitTargetPath } : {};
  }

  if (trimmed.startsWith("[") || trimmed.startsWith("{")) {
    try {
      const parsed: unknown = JSON.parse(trimmed);
      if (Array.isArray(parsed)) {
        const items = toStringArray(parsed);
        if (items) {
          return {
            commands: items,
            filePath: explicitTargetPath ?? items[0],
            directory: items[0],
            rawText: items.join(" "),
          };
        }
      } else if (typeof parsed === "object" && parsed !== null) {
        const obj = parsed as Record<string, unknown>;
        const meta =
          typeof obj.metadata === "object" && obj.metadata !== null && !Array.isArray(obj.metadata)
            ? (obj.metadata as Record<string, unknown>)
            : undefined;

        const cmdStr =
          firstNonEmptyString(obj, ["command", "cmd", "code", "script"]) ??
          (meta ? firstNonEmptyString(meta, ["command", "cmd"]) : undefined);
        const cmdArr =
          toStringArray(obj.command) ??
          toStringArray(obj.cmd) ??
          toStringArray(obj.patterns) ??
          toStringArray(obj.resources) ??
          (meta ? (toStringArray(meta.patterns) ?? toStringArray(meta.resources)) : undefined);
        const filePath =
          explicitTargetPath ??
          firstNonEmptyString(obj, ["path", "filePath", "filepath", "file", "targetPath"]) ??
          (meta
            ? firstNonEmptyString(meta, ["filepath", "path", "file", "targetPath"])
            : undefined) ??
          cmdArr?.[0];
        const directory =
          firstNonEmptyString(obj, ["directory"]) ??
          (meta ? firstNonEmptyString(meta, ["directory"]) : undefined) ??
          filePath;

        const commands = cmdStr ? [cmdStr] : cmdArr;
        return {
          ...(commands ? { commands } : {}),
          ...(filePath ? { filePath } : {}),
          ...(directory ? { directory } : {}),
          inputObject: obj,
          rawText: commands ? commands.join(" ") : (filePath ?? trimmed),
        };
      }
    } catch {
      // Not valid JSON; treat as literal command/path text
    }
  }

  return {
    commands: [trimmed],
    filePath: explicitTargetPath ?? trimmed,
    directory: explicitTargetPath ?? trimmed,
    rawText: trimmed,
  };
}

function isDummyHistoricalCommand(unwrapped: UnwrappedHistoricalAction): boolean {
  if (unwrapped.commands && unwrapped.commands.length === 1) {
    const cmd = unwrapped.commands[0].trim();
    if (cmd === "echo test" || cmd === "echo safe") {
      return true;
    }
  }
  const raw = unwrapped.rawText?.trim();
  return raw === "echo test" || raw === "echo safe";
}

function projectHistoricalEvent(
  caseId: string,
  toolName: string,
  unwrapped: UnwrappedHistoricalAction,
  explicitTargetPath: string | undefined,
): PermissionEventData {
  const lower = toolName.toLowerCase();
  if (lower === "bash" || lower === "shell" || lower === "shell:run") {
    return makeShellPermissionEvent({
      id: caseId,
      command: unwrapped.commands ?? explicitTargetPath ?? unwrapped.filePath ?? "",
    });
  }
  if (lower === "read" || lower === "fs:read") {
    return makeReadPermissionEvent({
      id: caseId,
      filePath: explicitTargetPath ?? unwrapped.filePath ?? unwrapped.commands?.[0] ?? "",
    });
  }
  if (lower === "edit" || lower === "write" || lower === "fs:edit" || lower === "fs:write") {
    return makeEditPermissionEvent({
      id: caseId,
      filePath: explicitTargetPath ?? unwrapped.filePath ?? unwrapped.commands?.[0] ?? "",
    });
  }
  if (lower === "external_directory") {
    return makeExternalDirectoryPermissionEvent({
      id: caseId,
      directory: explicitTargetPath ?? unwrapped.directory ?? unwrapped.filePath ?? "",
    });
  }
  return makeMcpPermissionEvent({
    id: caseId,
    tool: toolName,
    input: unwrapped.inputObject ?? {
      ...(unwrapped.rawText !== undefined ? { command: unwrapped.rawText } : {}),
      ...(explicitTargetPath !== undefined ? { targetPath: explicitTargetPath } : {}),
    },
  });
}

interface HistoricalCandidate {
  readonly toolName: string;
  readonly commandString?: string;
  readonly targetPath?: string;
  readonly userPromptRaw: string;
  readonly workspaceRootRaw?: string;
  readonly verdictRaw: string;
}

function appendHistoricalCandidate(
  candidate: HistoricalCandidate,
  sourceTag: string,
  fallbackWorkspace: string,
  seen: Set<string>,
  byVerdict: Record<ClassifierVerdict, StaticBenchCase[]>,
): void {
  const { toolName, commandString, targetPath, userPromptRaw, workspaceRootRaw, verdictRaw } =
    candidate;

  if (verdictRaw !== "ALLOW" && verdictRaw !== "BLOCK" && verdictRaw !== "UNSURE") {
    return;
  }
  if (!commandString && !targetPath) {
    return;
  }

  const unwrapped = unwrapSerializedCommandString(commandString, targetPath);
  if (isDummyHistoricalCommand(unwrapped)) {
    return;
  }

  const dedupeKey = `${toolName}::${unwrapped.rawText ?? commandString ?? ""}::${targetPath ?? ""}::${userPromptRaw.slice(0, 80)}`;
  if (seen.has(dedupeKey)) {
    return;
  }
  seen.add(dedupeKey);

  const workspaceRoot = workspaceRootRaw ?? fallbackWorkspace;
  const caseId = `hist-${verdictRaw.toLowerCase()}-${byVerdict[verdictRaw].length + 1}`;
  byVerdict[verdictRaw].push({
    id: caseId,
    dataset: "historical",
    split: verdictRaw.toLowerCase(),
    sourceTag,
    event: projectHistoricalEvent(caseId, toolName, unwrapped, targetPath),
    promptContext: {
      userPrompt: neutralizeReservedPromptMarkers(userPromptRaw),
      workspaceRoot,
      environment: { trustedPaths: [workspaceRoot] },
    },
    expectedVerdict: verdictRaw,
  });
}

function queryStoreRecordsDesc(dbPath: string): EvaluationRecord[] {
  const store = new AutoGateEvalStore(dbPath, { readonly: true });
  try {
    const records: EvaluationRecord[] = [];
    const pageSize = 1000;
    for (let offset = 0; ; offset += pageSize) {
      const batch = store.queryEvaluations({ limit: pageSize, offset, order: "desc" });
      records.push(...batch);
      if (batch.length < pageSize) {
        break;
      }
    }
    return records;
  } finally {
    store.close();
  }
}

export function loadHistoricalBenchCases(options?: HistoricalLoadOptions): StaticBenchCase[] {
  const source = resolveHistoricalEvalSource(options?.file, options?.dbFile);
  if (!source) {
    return [];
  }
  if (source.path !== ":memory:" && !fs.existsSync(source.path)) {
    return [];
  }

  const fallbackWorkspace = ensureEmptyBenchWorkspace();
  const sourceTag = source.path === ":memory:" ? ":memory:" : path.basename(source.path);
  const byVerdict: Record<ClassifierVerdict, StaticBenchCase[]> = {
    ALLOW: [],
    BLOCK: [],
    UNSURE: [],
  };
  const seen = new Set<string>();

  if (source.kind === "db") {
    const records = queryStoreRecordsDesc(source.path);
    for (const record of records) {
      if (record.modelProvider === "mock-provider" || record.modelId === "mock-model") {
        continue;
      }
      if (
        (record.s2Aborted && record.cascadeWinner !== "system1") ||
        (record.verdict === "UNSURE" && !record.riskLevel && Boolean(record.error))
      ) {
        continue;
      }
      appendHistoricalCandidate(
        {
          toolName: record.toolName.trim() || "bash",
          commandString: record.commandString || undefined,
          targetPath: record.targetPath ?? undefined,
          userPromptRaw: record.userPrompt,
          workspaceRootRaw: record.workspaceRoot?.trim() || undefined,
          verdictRaw: record.verdict,
        },
        sourceTag,
        fallbackWorkspace,
        seen,
        byVerdict,
      );
    }
  } else {
    const raw = fs.readFileSync(source.path, "utf8");
    const lines = raw.split(/\r?\n/).filter((line) => line.trim().length > 0);

    for (let i = lines.length - 1; i >= 0; i--) {
      let parsed: Record<string, unknown>;
      try {
        const obj: unknown = JSON.parse(lines[i]);
        if (typeof obj !== "object" || obj === null || Array.isArray(obj)) {
          continue;
        }
        parsed = obj as Record<string, unknown>;
      } catch (err) {
        void err;
        continue;
      }

      const modelObj =
        parsed.model && typeof parsed.model === "object"
          ? (parsed.model as Record<string, unknown>)
          : undefined;
      if (
        modelObj?.provider === "mock-provider" ||
        modelObj?.id === "mock-model" ||
        parsed.modelProvider === "mock-provider" ||
        parsed.modelId === "mock-model"
      ) {
        continue;
      }

      const actionObj =
        parsed.action && typeof parsed.action === "object"
          ? (parsed.action as Record<string, unknown>)
          : undefined;
      const decisionObj =
        parsed.decision && typeof parsed.decision === "object"
          ? (parsed.decision as Record<string, unknown>)
          : undefined;

      const verdictRaw =
        (typeof parsed.verdict === "string" ? parsed.verdict : undefined) ??
        (typeof decisionObj?.verdict === "string" ? decisionObj.verdict : undefined) ??
        "";
      const riskLevelRaw =
        (typeof parsed.risk_level === "string" ? parsed.risk_level : undefined) ??
        (typeof parsed.riskLevel === "string" ? parsed.riskLevel : undefined) ??
        (typeof decisionObj?.risk_level === "string" ? decisionObj.risk_level : undefined);
      const hasError = typeof parsed.error === "string" && parsed.error.trim().length > 0;
      const isS2Aborted = Boolean(parsed.s2Aborted) && parsed.cascadeWinner !== "system1";
      if (
        isS2Aborted ||
        (verdictRaw.trim().toUpperCase() === "UNSURE" && !riskLevelRaw && hasError)
      ) {
        continue;
      }

      const toolName =
        (typeof parsed.toolName === "string" && parsed.toolName.trim()
          ? parsed.toolName
          : undefined) ??
        (typeof actionObj?.toolName === "string" && actionObj.toolName.trim()
          ? actionObj.toolName
          : undefined) ??
        "bash";
      const commandString =
        (typeof parsed.commandString === "string" ? parsed.commandString : undefined) ??
        (typeof actionObj?.command === "string" ? actionObj.command : undefined);
      const targetPath =
        (typeof parsed.targetPath === "string" ? parsed.targetPath : undefined) ??
        (typeof actionObj?.targetPath === "string" ? actionObj.targetPath : undefined);
      const userPromptRaw =
        (typeof parsed.userPrompt === "string" ? parsed.userPrompt : undefined) ??
        (typeof actionObj?.userPrompt === "string" ? actionObj.userPrompt : undefined) ??
        "";
      const workspaceRootRaw =
        (typeof parsed.workspaceRoot === "string" && parsed.workspaceRoot.trim()
          ? parsed.workspaceRoot.trim()
          : undefined) ??
        (typeof actionObj?.workspaceRoot === "string" && actionObj.workspaceRoot.trim()
          ? actionObj.workspaceRoot.trim()
          : undefined);

      appendHistoricalCandidate(
        {
          toolName,
          commandString,
          targetPath,
          userPromptRaw,
          workspaceRootRaw,
          verdictRaw,
        },
        sourceTag,
        fallbackWorkspace,
        seen,
        byVerdict,
      );
    }
  }

  const maxCases = options?.maxCases;
  if (maxCases === undefined || maxCases <= 0) {
    return [...byVerdict.BLOCK, ...byVerdict.UNSURE, ...byVerdict.ALLOW];
  }

  const perBucket = Math.max(1, Math.floor(maxCases / 3));
  const selectedBlocks = byVerdict.BLOCK.slice(0, perBucket);
  const selectedUnsures = byVerdict.UNSURE.slice(0, perBucket);
  const remaining = Math.max(0, maxCases - selectedBlocks.length - selectedUnsures.length);
  const selectedAllows = byVerdict.ALLOW.slice(0, remaining);

  return [...selectedBlocks, ...selectedUnsures, ...selectedAllows].slice(0, maxCases);
}
