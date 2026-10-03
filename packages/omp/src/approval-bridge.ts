import { verdictStore } from "./hook.ts";

export function resolveShadowedApproval(
  args: unknown,
  store = verdictStore,
): {
  tier: "write" | "exec";
  policy?: "allow" | "deny" | "prompt";
  override?: boolean;
  reason?: string;
} {
  let command: string | undefined;
  let toolCallId: string | undefined;

  if (typeof args === "string") {
    command = args;
  } else if (typeof args === "object" && args !== null) {
    const obj = args as any;
    command = obj.command || obj.commandString || obj.code || obj.script;
    toolCallId = obj.toolCallId || obj.id || obj.tool_call_id;
  }

  let decisionRecord:
    | { verdict: string; policy: "allow" | "deny" | "prompt"; reason?: string }
    | undefined;

  if (toolCallId && store.has(toolCallId)) {
    decisionRecord = store.get(toolCallId);
  } else if (command && store.has(command)) {
    decisionRecord = store.get(command);
  }

  if (!decisionRecord) {
    return { tier: "write" };
  }

  if (decisionRecord.policy === "allow") {
    return { tier: "write", policy: "allow" };
  } else if (decisionRecord.policy === "deny") {
    return {
      tier: "exec",
      override: true,
      policy: "deny",
      reason: decisionRecord.reason,
    };
  } else if (decisionRecord.policy === "prompt") {
    return {
      tier: "exec",
      override: true,
      policy: "prompt",
      reason: decisionRecord.reason,
    };
  }

  return { tier: "write" };
}
