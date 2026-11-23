import { fetchDataset, readJsonlFile, type FetchDatasetsOptions } from "../fetch.js";
import { ensureEmptyBenchWorkspace } from "../paths.js";
import {
  makeEditPermissionEvent,
  makeMcpPermissionEvent,
  makeReadPermissionEvent,
  makeShellPermissionEvent,
  neutralizeReservedPromptMarkers,
  type StaticBenchCase,
} from "../schema.js";
import type { PermissionEventData } from "../../../packages/core/src/types.js";

export interface AuthGateTrajectoryStep {
  readonly tool?: unknown;
  readonly args?: unknown;
  readonly result?: unknown;
}

export interface AuthGateEnvironmentSignal {
  readonly signal_id?: unknown;
  readonly source?: unknown;
  readonly channel?: unknown;
  readonly value?: unknown;
  readonly note?: unknown;
}

export interface AuthGateProposedAction {
  readonly tool?: unknown;
  readonly args?: Record<string, unknown>;
}

export interface AuthGateRawRow {
  readonly id?: unknown;
  readonly pair_id?: unknown;
  readonly role_in_pair?: unknown;
  readonly category?: unknown;
  readonly environment?: unknown;
  readonly user_request?: unknown;
  readonly trajectory?: readonly AuthGateTrajectoryStep[];
  readonly proposed_action?: AuthGateProposedAction;
  readonly gold_label?: unknown;
  readonly environment_signals?: readonly AuthGateEnvironmentSignal[];
}

export interface AuthGateLoadOptions {
  readonly cacheDir?: string;
  readonly jsonlPath?: string;
  readonly views?: readonly ("bare" | "signals")[];
  readonly fetchOptions?: FetchDatasetsOptions;
}

function formatAuthGateTrajectory(
  trajectory: readonly AuthGateTrajectoryStep[] | undefined,
): string {
  if (!trajectory || trajectory.length === 0) {
    return "";
  }
  const lines: string[] = ["Prior Tool Trajectory:"];
  for (let i = 0; i < trajectory.length; i++) {
    const step = trajectory[i];
    const tool = typeof step.tool === "string" ? step.tool : "tool";
    const argsText = step.args !== undefined ? ` ${JSON.stringify(step.args)}` : "";
    const resultText =
      typeof step.result === "string" && step.result.trim().length > 0
        ? `\n  Output: ${step.result.trim()}`
        : "";
    lines.push(`- Step ${i + 1} [${tool}]${argsText}${resultText}`);
  }
  return lines.join("\n");
}

function formatAuthGateSignals(signals: readonly AuthGateEnvironmentSignal[] | undefined): string {
  if (!signals || signals.length === 0) {
    return "";
  }
  const lines: string[] = ["Environment Signals:"];
  for (const sig of signals) {
    const label =
      (typeof sig.channel === "string" && sig.channel.trim()) ||
      (typeof sig.signal_id === "string" && sig.signal_id.trim()) ||
      (typeof sig.source === "string" && sig.source.trim()) ||
      "signal";
    const value = sig.value !== undefined && sig.value !== null ? String(sig.value) : "";
    const note = typeof sig.note === "string" && sig.note.trim() ? ` (${sig.note.trim()})` : "";
    lines.push(`- [${label}]: ${value}${note}`);
  }
  return lines.join("\n");
}

function getStringProp(obj: Record<string, unknown>, keys: readonly string[]): string | undefined {
  for (const key of keys) {
    const val = obj[key];
    if (typeof val === "string" && val.trim().length > 0) {
      return val;
    }
  }
  return undefined;
}

function projectAuthGateAction(
  caseId: string,
  proposed: AuthGateProposedAction | undefined,
): PermissionEventData {
  const tool =
    typeof proposed?.tool === "string" && proposed.tool.trim().length > 0
      ? proposed.tool.trim()
      : "unknown";
  const args = proposed?.args && typeof proposed.args === "object" ? proposed.args : {};

  if (tool === "bash" || tool === "gh" || tool === "shell" || tool === "sh") {
    const cmd = getStringProp(args, ["cmd", "command"]) ?? JSON.stringify(args);
    return makeShellPermissionEvent({ id: caseId, command: cmd });
  }

  if (tool === "read") {
    const filePath = getStringProp(args, ["file_path", "filepath", "path", "file"]) ?? "*";
    return makeReadPermissionEvent({ id: caseId, filePath });
  }

  if (tool === "edit" || tool === "write") {
    const filePath = getStringProp(args, ["file_path", "filepath", "path", "file"]) ?? "*";
    const before = getStringProp(args, ["old_string", "oldString"]);
    const after = getStringProp(args, ["new_string", "newString", "content"]);
    return makeEditPermissionEvent({ id: caseId, filePath, before, after });
  }

  return makeMcpPermissionEvent({
    id: caseId,
    tool,
    input: args,
  });
}

export function mapAuthGateRows(
  rows: readonly AuthGateRawRow[],
  workspaceRoot: string = ensureEmptyBenchWorkspace(),
  views: readonly ("bare" | "signals")[] = ["bare", "signals"],
): StaticBenchCase[] {
  const cases: StaticBenchCase[] = [];

  for (let i = 0; i < rows.length; i++) {
    const row = rows[i];
    const rowId =
      typeof row.id === "string" && row.id.trim().length > 0 ? row.id.trim() : `row-${i}`;
    const pairId =
      typeof row.pair_id === "string" && row.pair_id.trim().length > 0 ? row.pair_id.trim() : rowId;
    const goldLabel = row.gold_label;
    if (goldLabel !== "allow" && goldLabel !== "block") {
      throw new Error(`Unexpected AuthGateBench gold_label at ${rowId}: ${String(goldLabel)}`);
    }

    const expectedVerdict = goldLabel === "allow" ? "ALLOW" : "BLOCK";
    const role: "allow" | "block" = goldLabel;
    const userRequest = typeof row.user_request === "string" ? row.user_request.trim() : "";
    const trajectoryText = formatAuthGateTrajectory(
      Array.isArray(row.trajectory) ? row.trajectory : undefined,
    );
    const barePrompt = neutralizeReservedPromptMarkers(
      [userRequest, trajectoryText].filter((part) => part.length > 0).join("\n\n"),
    );

    const signalsText = formatAuthGateSignals(
      Array.isArray(row.environment_signals) ? row.environment_signals : undefined,
    );
    const signalsPrompt = neutralizeReservedPromptMarkers(
      [barePrompt, signalsText].filter((part) => part.length > 0).join("\n\n"),
    );

    const category =
      typeof row.category === "string" && row.category.trim().length > 0
        ? row.category.trim()
        : undefined;

    for (const view of views) {
      const caseId = `authgate:${rowId}::${view}`;
      cases.push({
        id: caseId,
        dataset: "authgate",
        split: view,
        ...(category !== undefined ? { sourceTag: category } : {}),
        event: projectAuthGateAction(caseId, row.proposed_action),
        promptContext: {
          userPrompt: view === "bare" ? barePrompt : signalsPrompt,
          workspaceRoot,
          environment: { trustedPaths: [workspaceRoot] },
        },
        expectedVerdict,
        contrastGroup: {
          pairId: `${pairId}::${view}`,
          role,
          view,
        },
      });
    }
  }

  return cases;
}

export async function loadAuthGateCases(options?: AuthGateLoadOptions): Promise<StaticBenchCase[]> {
  const workspaceRoot = ensureEmptyBenchWorkspace();
  let jsonlPath = options?.jsonlPath;

  if (!jsonlPath) {
    const fetched = await fetchDataset("authgate", options?.cacheDir, options?.fetchOptions);
    jsonlPath = fetched.filesByRelativePath.get("data/authgatebench.jsonl");
    if (!jsonlPath) {
      throw new Error("AuthGateBench jsonl file missing from fetched snapshot");
    }
  }

  const rows = readJsonlFile<AuthGateRawRow>(jsonlPath);
  return mapAuthGateRows(rows, workspaceRoot, options?.views);
}
