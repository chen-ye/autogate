import fs from "node:fs";
import path from "node:path";
import { loadFileConfig } from "../../../packages/core/src/config.js";
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
  readonly maxCases?: number;
}

const DEFAULT_EVAL_LOG_CANDIDATES = [
  "~/.config/autogate/logs/evals.jsonl",
  "~/.omp/logs/autogate-evals.jsonl",
] as const;

export function resolveHistoricalEvalLogPath(explicitFile?: string): string | undefined {
  if (typeof explicitFile === "string" && explicitFile.trim().length > 0) {
    return path.resolve(expandHomePath(explicitFile.trim()));
  }

  const envLog = process.env.AUTOGATE_EVAL_LOG;
  if (typeof envLog === "string" && envLog.trim().length > 0) {
    return path.resolve(expandHomePath(envLog.trim()));
  }

  const fileCfg = loadFileConfig();
  if (typeof fileCfg.evalLogFile === "string" && fileCfg.evalLogFile.trim().length > 0) {
    return path.resolve(expandHomePath(fileCfg.evalLogFile.trim()));
  }

  for (const candidate of DEFAULT_EVAL_LOG_CANDIDATES) {
    const resolved = path.resolve(expandHomePath(candidate));
    if (fs.existsSync(resolved)) {
      return resolved;
    }
  }

  return undefined;
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

export function loadHistoricalBenchCases(options?: HistoricalLoadOptions): StaticBenchCase[] {
  const filePath = resolveHistoricalEvalLogPath(options?.file);
  if (!filePath || !fs.existsSync(filePath)) {
    return [];
  }

  const fallbackWorkspace = ensureEmptyBenchWorkspace();
  const raw = fs.readFileSync(filePath, "utf8");
  const lines = raw.split(/\r?\n/).filter((line) => line.trim().length > 0);

  const byVerdict: Record<ClassifierVerdict, StaticBenchCase[]> = {
    ALLOW: [],
    BLOCK: [],
    UNSURE: [],
  };
  const seen = new Set<string>();

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
    if (modelObj?.provider === "mock-provider" || modelObj?.id === "mock-model") {
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
    const verdictRaw =
      (typeof parsed.verdict === "string" ? parsed.verdict : undefined) ??
      (typeof decisionObj?.verdict === "string" ? decisionObj.verdict : undefined);

    if (verdictRaw !== "ALLOW" && verdictRaw !== "BLOCK" && verdictRaw !== "UNSURE") {
      continue;
    }
    if (!commandString && !targetPath) {
      continue;
    }

    const unwrapped = unwrapSerializedCommandString(commandString, targetPath);
    if (isDummyHistoricalCommand(unwrapped)) {
      continue;
    }

    const dedupeKey = `${toolName}::${unwrapped.rawText ?? commandString ?? ""}::${targetPath ?? ""}::${userPromptRaw.slice(0, 80)}`;
    if (seen.has(dedupeKey)) {
      continue;
    }
    seen.add(dedupeKey);

    const workspaceRoot = workspaceRootRaw ?? fallbackWorkspace;
    const caseId = `hist-${verdictRaw.toLowerCase()}-${byVerdict[verdictRaw].length + 1}`;
    byVerdict[verdictRaw].push({
      id: caseId,
      dataset: "historical",
      split: verdictRaw.toLowerCase(),
      sourceTag: path.basename(filePath),
      event: projectHistoricalEvent(caseId, toolName, unwrapped, targetPath),
      promptContext: {
        userPrompt: neutralizeReservedPromptMarkers(userPromptRaw),
        workspaceRoot,
        environment: { trustedPaths: [workspaceRoot] },
      },
      expectedVerdict: verdictRaw,
    });
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
