import { fetchDataset, readJsonlFile, type FetchDatasetsOptions } from "../fetch.js";
import { ensureEmptyBenchWorkspace } from "../paths.js";
import {
  makeEditPermissionEvent,
  makeMcpPermissionEvent,
  makeReadPermissionEvent,
  makeShellPermissionEvent,
  neutralizeReservedPromptMarkers,
  type StaticBenchCase,
  type StaticBenchFlags,
} from "../schema.js";
import type { ClassifierVerdict, PermissionEventData } from "../../../packages/core/src/types.js";

export type TsBenchSplit = "agentharm" | "asb" | "agentdojo" | "validation";

export interface TsBenchRawRow {
  readonly id?: unknown;
  readonly instruction?: unknown;
  readonly history?: unknown;
  readonly current_action?: unknown;
  readonly score?: unknown;
  readonly source_file?: unknown;
  readonly attacker_tool?: unknown;
  readonly prompt?: readonly { readonly role?: unknown; readonly content?: unknown }[];
  readonly reward_model?: {
    readonly ground_truth?: {
      readonly Harmfulness_Rating?: unknown;
      readonly Prompt_Injection?: unknown;
      readonly Malicious_User_Request?: unknown;
    };
  };
  readonly extra_info?: {
    readonly user_request?: unknown;
    readonly history?: unknown;
    readonly current_action?: unknown;
  };
}

export interface TsBenchLoadOptions {
  readonly cacheDir?: string;
  readonly includeSplits?: readonly TsBenchSplit[];
  readonly splitPaths?: Partial<Record<TsBenchSplit, string>>;
  readonly fetchOptions?: FetchDatasetsOptions;
}

const SPLIT_RELATIVE_PATHS: Readonly<Record<TsBenchSplit, string>> = {
  agentharm: "data/eval/AgentHarm-Traj.jsonl",
  asb: "data/eval/ASB-Traj.jsonl",
  agentdojo: "data/eval/AgentDojo-Traj.jsonl",
  validation: "data/train/validation.jsonl",
};

function mapScoreToVerdict(
  rawScore: unknown,
  rowId: string,
): {
  readonly score: number;
  readonly verdict: ClassifierVerdict;
} {
  const num = typeof rawScore === "number" ? rawScore : Number(rawScore);
  if (num === 0) {
    return { score: 0, verdict: "ALLOW" };
  }
  if (num === 0.5) {
    return { score: 0.5, verdict: "UNSURE" };
  }
  if (num === 1) {
    return { score: 1, verdict: "BLOCK" };
  }
  throw new Error(`Unexpected TS-Bench score at ${rowId}: ${String(rawScore)}`);
}

function extractBalancedJson(text: string): string | null {
  let start = -1;
  let openChar = "";
  let closeChar = "";
  for (let i = 0; i < text.length; i++) {
    if (text[i] === "{" || text[i] === "[") {
      start = i;
      openChar = text[i];
      closeChar = openChar === "{" ? "}" : "]";
      break;
    }
  }
  if (start === -1) {
    return null;
  }

  let depth = 0;
  let inString = false;
  let escaped = false;
  for (let i = start; i < text.length; i++) {
    const ch = text[i];
    if (inString) {
      if (escaped) {
        escaped = false;
      } else if (ch === "\\") {
        escaped = true;
      } else if (ch === '"') {
        inString = false;
      }
      continue;
    }
    if (ch === '"') {
      inString = true;
      continue;
    }
    if (ch === openChar) {
      depth++;
    } else if (ch === closeChar) {
      depth--;
      if (depth === 0) {
        return text.slice(start, i + 1);
      }
    }
  }
  return null;
}

function parseActionInputPayload(rawInput: string): unknown {
  let cleaned = rawInput.trim();
  if (!cleaned || cleaned === "None") {
    return {};
  }

  const closedFence = cleaned.match(/^```(?:json)?\s*([\s\S]*?)\s*```/i);
  if (closedFence && closedFence[1] !== undefined) {
    cleaned = closedFence[1].trim();
  } else {
    cleaned = cleaned.replace(/^```(?:json)?\s*\n?/i, "").trim();
  }

  try {
    return JSON.parse(cleaned);
  } catch (err) {
    void err;
  }

  const balanced = extractBalancedJson(cleaned);
  if (balanced !== null) {
    try {
      return JSON.parse(balanced);
    } catch (err) {
      void err;
    }
  }

  return { raw: cleaned };
}

export interface ParsedTsBenchAction {
  readonly tool: string;
  readonly input: unknown;
}

export function parseTsBenchCurrentAction(rawAction: string): ParsedTsBenchAction {
  const actionMatch = rawAction.match(/(?:\(\d+\)\s*)?Action:\s*([^\n\r]*)/i);
  if (!actionMatch) {
    return {
      tool: "assistant_step",
      input: { rawAction: rawAction.trim() },
    };
  }

  const rawTool = actionMatch[1].trim();
  const tool =
    !rawTool || rawTool === "None" || rawTool.startsWith("Final Answer")
      ? "assistant_response"
      : rawTool;

  const afterAction = rawAction.slice((actionMatch.index ?? 0) + actionMatch[0].length);
  const inputMatch = afterAction.match(/(?:\(\d+\)\s*)?Action Input:\s*([\s\S]*)$/i);
  const input = inputMatch
    ? parseActionInputPayload(inputMatch[1])
    : rawTool !== tool
      ? { response: rawTool }
      : {};

  return { tool, input };
}

function isRecordObject(val: unknown): val is Record<string, unknown> {
  return typeof val === "object" && val !== null && !Array.isArray(val);
}

function readNonEmptyString(
  obj: Record<string, unknown>,
  keys: readonly string[],
): string | undefined {
  for (const key of keys) {
    const val = obj[key];
    if (typeof val === "string" && val.trim().length > 0) {
      return val;
    }
  }
  return undefined;
}

function projectTsBenchAction(caseId: string, parsed: ParsedTsBenchAction): PermissionEventData {
  const toolLower = parsed.tool.toLowerCase();
  const inputObj = isRecordObject(parsed.input) ? parsed.input : undefined;

  if (
    inputObj &&
    (toolLower === "terminal" ||
      toolLower === "execute_command" ||
      toolLower === "bash" ||
      toolLower === "shell")
  ) {
    const cmd = readNonEmptyString(inputObj, ["command", "cmd"]);
    if (cmd !== undefined) {
      return makeShellPermissionEvent({ id: caseId, command: cmd });
    }
  }

  if (inputObj && (toolLower === "read_file" || toolLower === "read")) {
    const filePath = readNonEmptyString(inputObj, ["file_path", "file", "path", "filepath"]);
    if (filePath !== undefined) {
      return makeReadPermissionEvent({ id: caseId, filePath });
    }
  }

  if (
    inputObj &&
    (toolLower === "edit_txt" ||
      toolLower === "edit" ||
      toolLower === "write" ||
      toolLower === "create_file")
  ) {
    const filePath = readNonEmptyString(inputObj, [
      "file_path",
      "file",
      "path",
      "filepath",
      "filename",
    ]);
    if (filePath !== undefined) {
      const after = readNonEmptyString(inputObj, ["new_content", "content"]);
      return makeEditPermissionEvent({ id: caseId, filePath, after });
    }
  }

  if (inputObj && toolLower === "file_operation") {
    const op = typeof inputObj.operation === "string" ? inputObj.operation.toLowerCase() : "";
    const filePath = readNonEmptyString(inputObj, ["path", "file_path", "file"]);
    if (filePath !== undefined) {
      if (op === "read") {
        return makeReadPermissionEvent({ id: caseId, filePath });
      }
      if (op === "write" || op === "edit" || op === "append") {
        const after = typeof inputObj.content === "string" ? inputObj.content : undefined;
        return makeEditPermissionEvent({ id: caseId, filePath, after });
      }
    }
  }

  return makeMcpPermissionEvent({
    id: caseId,
    tool: parsed.tool,
    input: parsed.input,
  });
}

function resolveValidationInstruction(row: TsBenchRawRow): string {
  if (typeof row.extra_info?.user_request === "string" && row.extra_info.user_request.trim()) {
    return row.extra_info.user_request;
  }
  if (Array.isArray(row.prompt)) {
    for (let i = row.prompt.length - 1; i >= 0; i--) {
      const msg = row.prompt[i];
      if (msg && msg.role === "user" && typeof msg.content === "string") {
        return msg.content;
      }
    }
  }
  return "";
}

export function mapTsBenchRow(
  row: TsBenchRawRow,
  split: TsBenchSplit,
  rowIndex: number,
  workspaceRoot: string = ensureEmptyBenchWorkspace(),
): StaticBenchCase {
  const rawId =
    typeof row.id === "string" && row.id.trim().length > 0 ? row.id.trim() : `${split}:${rowIndex}`;
  const caseId = `tsbench:${split}:${rawId}`;

  const rawScore =
    split === "validation" ? row.reward_model?.ground_truth?.Harmfulness_Rating : row.score;
  const { score, verdict } = mapScoreToVerdict(rawScore, caseId);

  const instruction =
    split === "validation"
      ? resolveValidationInstruction(row)
      : typeof row.instruction === "string"
        ? row.instruction
        : "";
  const history =
    split === "validation"
      ? typeof row.extra_info?.history === "string"
        ? row.extra_info.history
        : ""
      : typeof row.history === "string"
        ? row.history
        : "";
  const rawCurrentAction =
    split === "validation"
      ? typeof row.extra_info?.current_action === "string"
        ? row.extra_info.current_action
        : ""
      : typeof row.current_action === "string"
        ? row.current_action
        : "";

  const promptParts: string[] = [];
  if (instruction.trim().length > 0) {
    promptParts.push(`User Instruction:\n${instruction.trim()}`);
  }
  if (history.trim().length > 0) {
    promptParts.push(`Interaction History:\n${history.trim()}`);
  }
  const userPrompt = neutralizeReservedPromptMarkers(promptParts.join("\n\n"));

  const parsedAction = parseTsBenchCurrentAction(rawCurrentAction);
  const event = projectTsBenchAction(caseId, parsedAction);

  const sourceFile =
    typeof row.source_file === "string" && row.source_file.trim().length > 0
      ? row.source_file.trim()
      : undefined;

  let flags: StaticBenchFlags | undefined;
  if (split === "validation") {
    const gt = row.reward_model?.ground_truth;
    const promptInjection = Boolean(gt?.Prompt_Injection);
    const maliciousUserRequest = Boolean(gt?.Malicious_User_Request);
    if (promptInjection || maliciousUserRequest) {
      flags = {
        ...(promptInjection ? { promptInjection: true } : {}),
        ...(maliciousUserRequest ? { maliciousUserRequest: true } : {}),
      };
    }
  } else if (split === "asb") {
    const isAttackSource =
      sourceFile !== undefined && (sourceFile.includes("DPI") || sourceFile.includes("OPI"));
    const hasAttackerTool =
      typeof row.attacker_tool === "string" && row.attacker_tool.trim().length > 0;
    if (score > 0 && (isAttackSource || hasAttackerTool)) {
      flags = { promptInjection: true };
    }
  } else if (split === "agentdojo") {
    if (score === 1) {
      flags = { promptInjection: true };
    }
  } else if (split === "agentharm") {
    if (score > 0 && sourceFile !== undefined && sourceFile.includes("harmful")) {
      flags = { maliciousUserRequest: true };
    }
  }

  return {
    id: caseId,
    dataset: "tsbench",
    split,
    ...(sourceFile !== undefined ? { sourceTag: sourceFile } : {}),
    event,
    promptContext: {
      userPrompt,
      workspaceRoot,
      environment: { trustedPaths: [workspaceRoot] },
    },
    expectedVerdict: verdict,
    ...(flags !== undefined ? { flags } : {}),
  };
}

export function mapTsBenchRows(
  rows: readonly TsBenchRawRow[],
  split: TsBenchSplit,
  workspaceRoot: string = ensureEmptyBenchWorkspace(),
): StaticBenchCase[] {
  return rows.map((row, idx) => mapTsBenchRow(row, split, idx, workspaceRoot));
}

export async function loadTsBenchCases(options?: TsBenchLoadOptions): Promise<StaticBenchCase[]> {
  const workspaceRoot = ensureEmptyBenchWorkspace();
  const splits = options?.includeSplits ?? ["agentharm", "asb", "agentdojo", "validation"];

  const needsFetch = splits.some((split) => !options?.splitPaths?.[split]);
  const fetched = needsFetch
    ? await fetchDataset("tsbench", options?.cacheDir, options?.fetchOptions)
    : undefined;

  const cases: StaticBenchCase[] = [];
  for (const split of splits) {
    const filePath =
      options?.splitPaths?.[split] ?? fetched?.filesByRelativePath.get(SPLIT_RELATIVE_PATHS[split]);
    if (!filePath) {
      throw new Error(`TS-Bench split ${split} file unavailable`);
    }
    const rows = readJsonlFile<TsBenchRawRow>(filePath);
    cases.push(...mapTsBenchRows(rows, split, workspaceRoot));
  }

  return cases;
}
