import type { RiskLevel, UserAuthorization } from "./types";

export interface NotificationBodyInput {
  target: string | string[];
  reason?: string;
  warning?: string;
  risk_level?: RiskLevel;
  user_authorization?: UserAuthorization;
}

export function formatNotificationTitle(verdictOrType: string, permission: string): string {
  return `[${verdictOrType}] ${permission}`;
}

export function formatNotificationBody(input: NotificationBodyInput): string {
  const targetStr = Array.isArray(input.target) ? input.target.join(", ") : input.target;
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

  if (input.warning) {
    lines.push(`Warning: ${input.warning}`);
  }

  return lines.join("\n");
}

export function formatStatusBody(status: string, details?: string): string {
  return `${status}${details ? `\n${details}` : ""}`;
}
