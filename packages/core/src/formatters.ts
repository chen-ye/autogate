import type {
  RiskLevel,
  UserAuthorization,
  NtfyVerbosity,
  EnvironmentConfig,
  CascadeTrace,
} from "./types";

export interface NotificationBodyInput {
  target: string | string[];
  reason?: string;
  warning?: string;
  risk_level?: RiskLevel;
  user_authorization?: UserAuthorization;
  verbosity?: NtfyVerbosity;
  toolName?: string;
  workspaceRoot?: string;
  sessionID?: string;
  rawArgs?: unknown;
  userPrompt?: string;
  subagentPrompt?: string;
  reasoning?: string;
  environment?: EnvironmentConfig;
  cascade?: CascadeTrace;
}

export function formatCascadeSummary(cascade: CascadeTrace): string {
  const parts = [`${cascade.mode} -> ${cascade.winner}`];
  if (cascade.escalationReason) {
    parts.push(`reason=${cascade.escalationReason}`);
  }
  if (cascade.s1LatencyMs !== undefined) {
    parts.push(`s1=${cascade.s1LatencyMs}ms`);
  }
  if (cascade.s2LatencyMs !== undefined) {
    parts.push(`s2=${cascade.s2LatencyMs}ms`);
  }
  if (cascade.s2Aborted !== undefined) {
    parts.push(`s2Aborted=${cascade.s2Aborted}`);
  }
  return parts.join(" | ");
}

export function formatNotificationTitle(verdictOrType: string, permission: string): string {
  return `[${verdictOrType}] ${permission}`;
}

export function formatNotificationBody(input: NotificationBodyInput): string {
  const targetStr = Array.isArray(input.target) ? input.target.join(", ") : input.target;

  if (input.verbosity === "verbose") {
    const sections: string[] = [];

    // 1. Target & Execution Specs
    const targetLines = [`Target: ${targetStr}`];
    if (input.toolName) {
      targetLines.push(`Tool: ${input.toolName}`);
    }
    if (input.workspaceRoot) {
      targetLines.push(`Directory: ${input.workspaceRoot}`);
    }
    if (input.sessionID) {
      targetLines.push(`Session: ${input.sessionID}`);
    }
    if (input.rawArgs !== undefined && input.rawArgs !== null) {
      const rawStr =
        typeof input.rawArgs === "string"
          ? input.rawArgs
          : JSON.stringify(input.rawArgs);
      if (rawStr && rawStr !== targetStr && rawStr !== "{}" && rawStr !== "[]") {
        targetLines.push(`Arguments: ${rawStr}`);
      }
    }
    sections.push(targetLines.join("\n"));

    // 2. Evaluation Assessment
    const evalLines: string[] = ["--- Evaluation ---"];
    const riskAuth: string[] = [];
    if (input.risk_level) riskAuth.push(`Risk: ${input.risk_level}`);
    if (input.user_authorization) riskAuth.push(`Auth: ${input.user_authorization}`);
    if (riskAuth.length > 0) {
      evalLines.push(riskAuth.join(" | "));
    }
    if (input.reason) {
      evalLines.push(`Reason: ${input.reason}`);
    }
    if (input.cascade) {
      evalLines.push(`Cascade: ${formatCascadeSummary(input.cascade)}`);
    }
    if (input.warning) {
      evalLines.push(`Warning: ${input.warning}`);
    }
    if (evalLines.length > 1) {
      sections.push(evalLines.join("\n"));
    }

    // 3. Model Reasoning Trace (if captured)
    if (input.reasoning && input.reasoning.trim().length > 0) {
      sections.push(`--- Model Reasoning ---\n${input.reasoning.trim()}`);
    }

    // 4. Intent & Hierarchy
    const intentLines: string[] = [];
    if (input.userPrompt && input.userPrompt.trim().length > 0) {
      intentLines.push(`User Prompt:\n${input.userPrompt.trim()}`);
    }
    if (input.subagentPrompt && input.subagentPrompt.trim().length > 0) {
      intentLines.push(`Subagent Task:\n${input.subagentPrompt.trim()}`);
    }
    if (intentLines.length > 0) {
      sections.push(`--- Context & Hierarchy ---\n${intentLines.join("\n\n")}`);
    }

    // 5. Trust Boundaries
    if (input.environment) {
      const envLines: string[] = ["--- Trust Boundaries ---"];
      if (input.environment.trustedDomains && input.environment.trustedDomains.length > 0) {
        envLines.push(`Domains: ${input.environment.trustedDomains.join(", ")}`);
      }
      if (input.environment.trustedGitRemotes && input.environment.trustedGitRemotes.length > 0) {
        envLines.push(`Remotes: ${input.environment.trustedGitRemotes.join(", ")}`);
      }
      if (input.environment.trustedPaths && input.environment.trustedPaths.length > 0) {
        envLines.push(`Paths: ${input.environment.trustedPaths.join(", ")}`);
      }
      if (envLines.length > 1) {
        sections.push(envLines.join("\n"));
      }
    }

    return sections.join("\n\n");
  }

  const lines: string[] = [`Target: ${targetStr}`];

  if (input.reason) {
    if (input.risk_level && input.user_authorization) {
      lines.push(
        `Reason: ${input.reason} [Risk: ${input.risk_level}, Auth: ${input.user_authorization}]`,
      );
    } else if (input.risk_level) {
      lines.push(`Reason: ${input.reason} [Risk: ${input.risk_level}]`);
    } else if (input.user_authorization) {
      lines.push(`Reason: ${input.reason} [Auth: ${input.user_authorization}]`);
    } else {
      lines.push(`Reason: ${input.reason}`);
    }
  }

  if (input.cascade) {
    lines.push(`Cascade: ${formatCascadeSummary(input.cascade)}`);
  }

  if (input.warning) {
    lines.push(`Warning: ${input.warning}`);
  }

  return lines.join("\n");
}

export function formatStatusBody(
  status: string,
  details?: string,
  preservedBody?: string,
): string {
  if (preservedBody && preservedBody.trim().length > 0) {
    const header = `${status}${details ? `\n${details}` : ""}`;
    return `${header}\n\n========================================\n${preservedBody.trim()}`;
  }
  return `${status}${details ? `\n${details}` : ""}`;
}
