import type { EnvironmentConfig, GateAction, PermissionEventData } from "@autogate/core";
import { buildOpenCodeGateAction, formatOpenCodePromptHierarchy } from "@autogate/opencode";

export {
  makeEditPermissionEvent,
  makeExternalDirectoryPermissionEvent,
  makeMcpPermissionEvent,
  makeReadPermissionEvent,
  makeShellPermissionEvent,
  type BasePermissionEventInput,
  type EditPermissionEventInput,
  type ExternalDirectoryPermissionEventInput,
  type McpPermissionEventInput,
  type ReadPermissionEventInput,
  type ShellPermissionEventInput,
} from "./schema.js";

export function projectOpenCodeBenchCase(input: {
  event: PermissionEventData;
  userPrompt: string;
  subagentPrompt?: string;
  subagentTitle?: string;
  workspaceRoot: string;
  environment?: EnvironmentConfig;
}): GateAction {
  const formatted = formatOpenCodePromptHierarchy({
    userPrompt: input.userPrompt,
    subagentPrompt: input.subagentPrompt,
    subagentTitle: input.subagentTitle,
  });

  if (input.userPrompt.trim().length > 0 && formatted.userPrompt.length === 0) {
    throw new Error(
      "projectOpenCodeBenchCase: non-empty userPrompt collapsed to empty string after formatOpenCodePromptHierarchy",
    );
  }

  return buildOpenCodeGateAction(input.event, {
    workspaceRoot: input.workspaceRoot,
    userPrompt: formatted.userPrompt,
    subagentPrompt: formatted.subagentPrompt,
    environment: input.environment,
  });
}
