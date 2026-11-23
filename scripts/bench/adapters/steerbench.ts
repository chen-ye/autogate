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
import type { ClassifierVerdict, PermissionEventData } from "../../../packages/core/src/types.js";

export const DEFAULT_STEERBENCH_DOMAINS: ReadonlySet<string> = new Set([
  "developer_ops",
  "engineering_ops",
  "security_engineering",
]);

export interface SteerBenchEvidenceItem {
  readonly id?: unknown;
  readonly raw_ref?: unknown;
  readonly source_type?: unknown;
  readonly status?: unknown;
  readonly title?: unknown;
}

export interface SteerBenchMissingEvidenceItem {
  readonly src?: unknown;
  readonly reason?: unknown;
}

export interface SteerBenchUsedEvidenceItem {
  readonly src?: unknown;
  readonly status?: unknown;
  readonly title?: unknown;
}

export interface SteerBenchRawRow {
  readonly id?: unknown;
  readonly domain?: unknown;
  readonly title?: unknown;
  readonly user_request?: unknown;
  readonly action_verb?: unknown;
  readonly irreversibility_class?: unknown;
  readonly context?: {
    readonly goal?: unknown;
  };
  readonly decision_point?: {
    readonly proposed_action?: unknown;
    readonly draft?: unknown;
  } | null;
  readonly expected_behavior?: {
    readonly correct_action?: unknown;
  };
  readonly evidence?: readonly SteerBenchEvidenceItem[];
  readonly evidence_used?: readonly SteerBenchUsedEvidenceItem[];
  readonly evidence_missing?: readonly SteerBenchMissingEvidenceItem[];
  readonly metadata?: {
    readonly legacy_action?: {
      readonly draft?: unknown;
      readonly proposed_action?: unknown;
    };
  };
}

export interface SteerBenchLoadOptions {
  readonly cacheDir?: string;
  readonly scenariosPath?: string;
  readonly includeAllDomains?: boolean;
  readonly domains?: readonly string[];
  readonly fetchOptions?: FetchDatasetsOptions;
}

function mapSteerBenchVerdict(rawAction: unknown, rowId: string): ClassifierVerdict {
  if (rawAction === "continue" || rawAction === "allow") {
    return "ALLOW";
  }
  if (rawAction === "block") {
    return "BLOCK";
  }
  if (rawAction === "escalate" || rawAction === "request_approval") {
    return "UNSURE";
  }
  throw new Error(
    `Unexpected SteerBench expected_behavior.correct_action at ${rowId}: ${String(rawAction)}`,
  );
}

function mapSeverityWeight(irrev: unknown): 1 | 2 | 4 {
  if (irrev === "low" || irrev === "soft_to_reverse" || irrev === "none") {
    return 1;
  }
  if (irrev === "medium") {
    return 2;
  }
  if (irrev === "high" || irrev === "hard_to_reverse") {
    return 4;
  }
  return 2;
}

function extractFilePathCandidate(
  row: SteerBenchRawRow,
  textPool: readonly string[],
): string | undefined {
  for (const text of textPool) {
    const match = text.match(
      /(?:^|[\s`'"])((?:[a-zA-Z0-9_.-]+\/)*[a-zA-Z0-9_.-]+\.(?:ts|tsx|js|jsx|py|sh|md|json|yaml|yml|pdf|xlsx|csv|sql|toml))(?:$|[\s`'",:;])/,
    );
    if (match && match[1]) {
      return match[1];
    }
  }

  if (Array.isArray(row.evidence)) {
    for (const ev of row.evidence) {
      if (typeof ev.raw_ref === "string") {
        const ref = ev.raw_ref.trim();
        if (ref.startsWith("workspace/")) {
          return ref.slice("workspace/".length);
        }
        if (ev.source_type === "file_snapshot" && ref.length > 0 && !ref.startsWith("cmd:")) {
          return ref;
        }
      }
    }
  }

  return undefined;
}

function extractShellCommandCandidate(
  proposedAction: string,
  draft: string | undefined,
  actionVerb: string,
): string | undefined {
  if (draft) {
    const trimmed = draft.trim();
    if (/^(?:rm|git|curl|wget|bash|sh|python3?|bun|npm|yarn|chmod|chown|mv|cp)\b/.test(trimmed)) {
      return trimmed;
    }
    const execMatch = trimmed.match(/^Execute\s+((?:nuclei|curl|rm|git|bash|sh|kubectl)\b[^\n]*)/i);
    if (execMatch && execMatch[1]) {
      return execMatch[1].trim();
    }
  }

  if (
    actionVerb === "privileged_tool_call" ||
    actionVerb === "network_egress" ||
    actionVerb === "destructive_write" ||
    (actionVerb === "durable_write" && /^Run\s+git\b/i.test(proposedAction))
  ) {
    const runScriptMatch = proposedAction.match(/^Run\s+(scripts\/[^\s,]+|git\s+[^\n]+)/i);
    if (runScriptMatch && runScriptMatch[1]) {
      return runScriptMatch[1].trim();
    }
    if (/^(?:Run|Curl|Execute)\b/i.test(proposedAction)) {
      return draft ? `${proposedAction}\n${draft}` : proposedAction;
    }
  }

  return undefined;
}

function projectSteerBenchAction(caseId: string, row: SteerBenchRawRow): PermissionEventData {
  const actionVerb =
    typeof row.action_verb === "string" && row.action_verb.trim().length > 0
      ? row.action_verb.trim()
      : "action";
  const proposedAction =
    typeof row.decision_point?.proposed_action === "string" &&
    row.decision_point.proposed_action.trim().length > 0
      ? row.decision_point.proposed_action.trim()
      : typeof row.metadata?.legacy_action?.proposed_action === "string" &&
          row.metadata.legacy_action.proposed_action.trim().length > 0
        ? row.metadata.legacy_action.proposed_action.trim()
        : typeof row.title === "string" && row.title.trim().length > 0
          ? row.title.trim()
          : actionVerb;

  const draft =
    typeof row.decision_point?.draft === "string" && row.decision_point.draft.trim().length > 0
      ? row.decision_point.draft.trim()
      : typeof row.metadata?.legacy_action?.draft === "string" &&
          row.metadata.legacy_action.draft.trim().length > 0
        ? row.metadata.legacy_action.draft.trim()
        : undefined;

  const shellCmd = extractShellCommandCandidate(proposedAction, draft, actionVerb);
  if (shellCmd !== undefined) {
    return makeShellPermissionEvent({ id: caseId, command: shellCmd });
  }

  const filePath = extractFilePathCandidate(row, [proposedAction, ...(draft ? [draft] : [])]);

  if (actionVerb === "read" && filePath !== undefined) {
    return makeReadPermissionEvent({ id: caseId, filePath });
  }

  if (
    (actionVerb === "durable_write" || actionVerb === "destructive_write") &&
    filePath !== undefined
  ) {
    return makeEditPermissionEvent({
      id: caseId,
      filePath,
      after: draft ?? proposedAction,
    });
  }

  return makeMcpPermissionEvent({
    id: caseId,
    tool: actionVerb,
    input: {
      proposedAction,
      ...(draft !== undefined ? { draft } : {}),
    },
  });
}

function buildSteerBenchUserPrompt(row: SteerBenchRawRow): string {
  const sections: string[] = [];

  const userRequest = typeof row.user_request === "string" ? row.user_request.trim() : "";
  const goal = typeof row.context?.goal === "string" ? row.context.goal.trim() : "";
  const title = typeof row.title === "string" ? row.title.trim() : "";

  if (userRequest) {
    sections.push(`User Request:\n${userRequest}`);
  } else if (title) {
    sections.push(`Task:\n${title}`);
  }

  if (goal && goal !== userRequest) {
    sections.push(`Goal:\n${goal}`);
  }

  const evidenceLines: string[] = [];
  if (Array.isArray(row.evidence)) {
    for (const ev of row.evidence) {
      const evTitle = typeof ev.title === "string" ? ev.title.trim() : "";
      const evStatus = typeof ev.status === "string" ? ev.status.trim() : "";
      const evRef = typeof ev.raw_ref === "string" ? ev.raw_ref.trim() : "";
      if (evTitle || evRef) {
        const statusPrefix = evStatus ? `[${evStatus}] ` : "";
        const refSuffix = evRef ? ` (${evRef})` : "";
        evidenceLines.push(`- ${statusPrefix}${evTitle || evRef}${evTitle ? refSuffix : ""}`);
      }
    }
  } else if (Array.isArray(row.evidence_used)) {
    for (const ev of row.evidence_used) {
      const evTitle = typeof ev.title === "string" ? ev.title.trim() : "";
      const evStatus = typeof ev.status === "string" ? ev.status.trim() : "";
      const evSrc = typeof ev.src === "string" ? ev.src.trim() : "";
      if (evTitle || evSrc) {
        const statusPrefix = evStatus ? `[${evStatus}] ` : "";
        const srcSuffix = evSrc ? ` (${evSrc})` : "";
        evidenceLines.push(`- ${statusPrefix}${evTitle || evSrc}${evTitle ? srcSuffix : ""}`);
      }
    }
  }
  if (evidenceLines.length > 0) {
    sections.push(`Available Evidence:\n${evidenceLines.join("\n")}`);
  }

  if (Array.isArray(row.evidence_missing) && row.evidence_missing.length > 0) {
    const missingLines: string[] = [];
    for (const item of row.evidence_missing) {
      const src = typeof item.src === "string" ? item.src.trim() : "evidence";
      const reason = typeof item.reason === "string" ? item.reason.trim() : "";
      missingLines.push(`- ${src}${reason ? `: ${reason}` : ""}`);
    }
    sections.push(`Missing Evidence:\n${missingLines.join("\n")}`);
  }

  return neutralizeReservedPromptMarkers(sections.join("\n\n"));
}

export function mapSteerBenchRows(
  rows: readonly SteerBenchRawRow[],
  workspaceRoot: string = ensureEmptyBenchWorkspace(),
  options?: { readonly includeAllDomains?: boolean; readonly domains?: readonly string[] },
): StaticBenchCase[] {
  const allowedDomains = options?.includeAllDomains
    ? null
    : options?.domains
      ? new Set(options.domains)
      : DEFAULT_STEERBENCH_DOMAINS;

  const cases: StaticBenchCase[] = [];
  for (let i = 0; i < rows.length; i++) {
    const row = rows[i];
    const domain = typeof row.domain === "string" ? row.domain.trim() : "unknown";
    if (allowedDomains && !allowedDomains.has(domain)) {
      continue;
    }

    const rowId =
      typeof row.id === "string" && row.id.trim().length > 0 ? row.id.trim() : `row-${i}`;
    const caseId = `steerbench:${rowId}`;
    const expectedVerdict = mapSteerBenchVerdict(row.expected_behavior?.correct_action, rowId);
    const severityWeight = mapSeverityWeight(row.irreversibility_class);

    cases.push({
      id: caseId,
      dataset: "steerbench",
      split: domain,
      ...(typeof row.action_verb === "string" && row.action_verb.trim()
        ? { sourceTag: row.action_verb.trim() }
        : {}),
      event: projectSteerBenchAction(caseId, row),
      promptContext: {
        userPrompt: buildSteerBenchUserPrompt(row),
        workspaceRoot,
        environment: { trustedPaths: [workspaceRoot] },
      },
      expectedVerdict,
      flags: {
        severityWeight,
        ...(expectedVerdict === "UNSURE" ? { expectOod: true } : {}),
      },
    });
  }

  return cases;
}

export async function loadSteerBenchCases(
  options?: SteerBenchLoadOptions,
): Promise<StaticBenchCase[]> {
  const workspaceRoot = ensureEmptyBenchWorkspace();
  let scenariosPath = options?.scenariosPath;

  if (!scenariosPath) {
    const fetched = await fetchDataset("steerbench", options?.cacheDir, options?.fetchOptions);
    scenariosPath = fetched.filesByRelativePath.get("scenarios.jsonl");
    if (!scenariosPath) {
      throw new Error("SteerBench scenarios.jsonl missing from fetched snapshot");
    }
  }

  const rows = readJsonlFile<SteerBenchRawRow>(scenariosPath);
  return mapSteerBenchRows(rows, workspaceRoot, {
    includeAllDomains: options?.includeAllDomains,
    domains: options?.domains,
  });
}
