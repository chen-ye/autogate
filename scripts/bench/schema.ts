import type {
  ClassifierVerdict,
  EnvironmentConfig,
  PermissionEventData,
} from "../../packages/core/src/types.js";

export type BenchDatasetId =
  | "synthetic"
  | "historical"
  | "shellrisk"
  | "nl2sh-redcode"
  | "authgate"
  | "tsbench"
  | "steerbench";

export const ALL_BENCH_DATASET_IDS: readonly BenchDatasetId[] = [
  "synthetic",
  "historical",
  "shellrisk",
  "nl2sh-redcode",
  "authgate",
  "tsbench",
  "steerbench",
];

export const EXTERNAL_BENCH_DATASET_IDS: readonly BenchDatasetId[] = [
  "shellrisk",
  "nl2sh-redcode",
  "authgate",
  "tsbench",
  "steerbench",
];

export interface StaticBenchPromptContext {
  readonly userPrompt: string;
  readonly subagentPrompt?: string;
  readonly subagentTitle?: string;
  readonly workspaceRoot: string;
  readonly environment?: EnvironmentConfig;
}

export interface StaticBenchContrastGroup {
  readonly pairId: string;
  readonly role: "allow" | "block";
  readonly view: "bare" | "signals";
}

export interface StaticBenchFlags {
  readonly promptInjection?: boolean;
  readonly maliciousUserRequest?: boolean;
  readonly expectOod?: boolean;
  readonly severityWeight?: 1 | 2 | 4;
}

export interface StaticBenchCase {
  readonly id: string;
  readonly dataset: BenchDatasetId;
  readonly split: string;
  readonly sourceTag?: string;
  readonly event: PermissionEventData;
  readonly promptContext: StaticBenchPromptContext;
  readonly expectedVerdict: ClassifierVerdict;
  readonly contrastGroup?: StaticBenchContrastGroup;
  readonly flags?: StaticBenchFlags;
}

export interface DatasetManifestFile {
  readonly relativePath: string;
  readonly url: string;
  readonly sha256: string;
  readonly sizeBytes: number;
}

export interface DatasetManifest {
  readonly dataset: BenchDatasetId;
  readonly sha: string;
  readonly fetchedAt: string;
  readonly files: readonly DatasetManifestFile[];
}

export function neutralizeReservedPromptMarkers(text: string): string {
  return text
    .replaceAll("## Environment Trust Boundaries:", "Environment Trust Boundaries:")
    .replaceAll("## Context:", "Context:")
    .replaceAll("### Conversation Transcript", "Conversation Transcript")
    .replaceAll("[SYSTEM DIRECTIVE:", "[SYSTEM_DIRECTIVE:")
    .replaceAll("[restore checkpointed", "[restore_checkpointed")
    .replaceAll("<!-- OMO_INTERNAL", "<!-- OMO-INTERNAL")
    .replaceAll("[auto-gate-eval]", "[auto_gate_eval]")
    .replace(/<(\/?)auto-slash-command/gi, "<$1slash-command")
    .replace(/<(\/?)user-request/gi, "<$1user_request");
}

export interface BasePermissionEventInput {
  readonly id?: string;
  readonly sessionID?: string;
  readonly save?: string[];
  readonly source?: PermissionEventData["source"];
}

export interface ShellPermissionEventInput extends BasePermissionEventInput {
  readonly command: string | readonly string[];
}

export function makeShellPermissionEvent(input: ShellPermissionEventInput): PermissionEventData {
  const resources = typeof input.command === "string" ? [input.command] : [...input.command];
  return {
    ...(input.id !== undefined ? { id: input.id } : {}),
    ...(input.sessionID !== undefined ? { sessionID: input.sessionID } : {}),
    action: "shell",
    resources,
    save: input.save ?? ["*"],
    ...(input.source !== undefined ? { source: input.source } : {}),
  };
}

export interface ReadPermissionEventInput extends BasePermissionEventInput {
  readonly filePath: string;
}

export function makeReadPermissionEvent(input: ReadPermissionEventInput): PermissionEventData {
  return {
    ...(input.id !== undefined ? { id: input.id } : {}),
    ...(input.sessionID !== undefined ? { sessionID: input.sessionID } : {}),
    action: "read",
    resources: [input.filePath],
    save: input.save ?? ["*"],
    ...(input.source !== undefined ? { source: input.source } : {}),
  };
}

export interface EditPermissionEventInput extends BasePermissionEventInput {
  readonly filePath: string;
  readonly patch?: string;
  readonly status?: string;
  readonly before?: string;
  readonly after?: string;
  readonly additions?: number;
  readonly deletions?: number;
}

export function makeEditPermissionEvent(input: EditPermissionEventInput): PermissionEventData {
  return {
    ...(input.id !== undefined ? { id: input.id } : {}),
    ...(input.sessionID !== undefined ? { sessionID: input.sessionID } : {}),
    action: "edit",
    resources: [input.filePath],
    save: input.save ?? ["*"],
    metadata: {
      files: [
        {
          file: input.filePath,
          ...(input.patch !== undefined ? { patch: input.patch } : {}),
          ...(input.status !== undefined ? { status: input.status } : {}),
          ...(input.before !== undefined ? { before: input.before } : {}),
          ...(input.after !== undefined ? { after: input.after } : {}),
          ...(input.additions !== undefined ? { additions: input.additions } : {}),
          ...(input.deletions !== undefined ? { deletions: input.deletions } : {}),
        },
      ],
    },
    ...(input.source !== undefined ? { source: input.source } : {}),
  };
}

export interface ExternalDirectoryPermissionEventInput extends BasePermissionEventInput {
  readonly directory: string;
}

export function makeExternalDirectoryPermissionEvent(
  input: ExternalDirectoryPermissionEventInput,
): PermissionEventData {
  return {
    ...(input.id !== undefined ? { id: input.id } : {}),
    ...(input.sessionID !== undefined ? { sessionID: input.sessionID } : {}),
    action: "external_directory",
    resources: [input.directory],
    save: input.save ?? [input.directory],
    ...(input.source !== undefined ? { source: input.source } : {}),
  };
}

export interface McpPermissionEventInput extends BasePermissionEventInput {
  readonly tool: string;
  readonly input?: unknown;
}

export function makeMcpPermissionEvent(input: McpPermissionEventInput): PermissionEventData {
  return {
    ...(input.id !== undefined ? { id: input.id } : {}),
    ...(input.sessionID !== undefined ? { sessionID: input.sessionID } : {}),
    action: input.tool,
    resources: ["*"],
    save: input.save ?? ["*"],
    metadata: {
      input: input.input ?? {},
    },
    ...(input.source !== undefined ? { source: input.source } : {}),
  };
}
