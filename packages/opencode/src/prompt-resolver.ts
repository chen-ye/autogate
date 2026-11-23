import type { OpenCodeSessionClient } from "./types.js";

interface MessageEntry {
  type?: string;
  role?: string;
  info?: { role?: string };
  text?: string;
  parts?: unknown[];
  content?: unknown;
}

function unwrapOpenCodePromptText(raw: string): string {
  let text = raw;
  const reqMatch = text.match(/<user-request>([\s\S]*?)<\/user-request>/i);
  if (reqMatch && reqMatch[1]) {
    text = reqMatch[1].trim();
  } else {
    const slashMatch = text.match(/<auto-slash-command[^>]*>([\s\S]*?)<\/auto-slash-command>/i);
    if (slashMatch && slashMatch[1]) {
      const innerReq = slashMatch[1].match(/<user-request>([\s\S]*?)<\/user-request>/i);
      if (innerReq && innerReq[1]) {
        text = innerReq[1].trim();
      } else {
        text = slashMatch[1].trim();
      }
    }
  }
  return text.trim();
}

export function formatOpenCodePromptHierarchy(input: {
  userPrompt: string;
  subagentPrompt?: string;
  subagentTitle?: string;
  unwrap?: boolean;
}): { userPrompt: string; subagentPrompt?: string } {
  const shouldUnwrap = input.unwrap !== false;
  const userPrompt = shouldUnwrap
    ? unwrapOpenCodePromptText(input.userPrompt)
    : input.userPrompt.trim();
  let subagentPrompt = input.subagentPrompt
    ? shouldUnwrap
      ? unwrapOpenCodePromptText(input.subagentPrompt)
      : input.subagentPrompt.trim()
    : "";
  const cleanTitle = input.subagentTitle?.trim();
  if (cleanTitle) {
    if (subagentPrompt) {
      if (!subagentPrompt.includes(cleanTitle)) {
        subagentPrompt = `[Subagent: ${cleanTitle}]\n${subagentPrompt}`;
      }
    } else {
      subagentPrompt = `[Subagent: ${cleanTitle}]`;
    }
  }
  return {
    userPrompt,
    subagentPrompt: subagentPrompt || undefined,
  };
}

export class OpenCodePromptResolver {
  private sessionParentCache = new Map<string, string>();

  constructor(private client: OpenCodeSessionClient) {}

  public setSessionParent(sessionID: string, parentID: string): void {
    this.sessionParentCache.set(sessionID, parentID);
  }

  public getParentSessionID(sessionID: string): string | undefined {
    return this.sessionParentCache.get(sessionID);
  }

  public cleanupSession(sessionID: string): void {
    if (!sessionID) return;
    this.sessionParentCache.delete(sessionID);
    for (const [childID, parentID] of this.sessionParentCache.entries()) {
      if (parentID === sessionID) {
        this.sessionParentCache.delete(childID);
      }
    }
  }

  public async fetchLatestUserMessage(sessionID: string): Promise<string> {
    if (typeof this.client?.session?.context !== "function") return "";
    try {
      const res = await this.client.session.context({ sessionID });
      const messages = Array.isArray(res) ? res : (res as { data?: unknown[] })?.data;
      if (Array.isArray(messages) && messages.length > 0) {
        for (let i = messages.length - 1; i >= 0; i--) {
          const item = messages[i];
          if (!item || typeof item !== "object") continue;
          const m = item as MessageEntry;
          const role = m.type ?? m.info?.role ?? m.role;
          if (role === "user") {
            let text = "";
            if (typeof m.text === "string") {
              text = m.text;
            } else if (typeof m.content === "string" && !m.parts) {
              text = m.content;
            } else {
              const parts = Array.isArray(m.parts)
                ? m.parts
                : Array.isArray(m.content)
                  ? m.content
                  : [];
              text = parts
                .filter(
                  (p: unknown): p is string | { text: string } =>
                    typeof p === "string" ||
                    (typeof p === "object" &&
                      p !== null &&
                      "text" in p &&
                      typeof (p as { text: unknown }).text === "string"),
                )
                .map((p) => (typeof p === "string" ? p : p.text))
                .join("\n");
            }
            if (text) {
              text = unwrapOpenCodePromptText(text);

              const isSlashCmd = /<auto-slash-command[^>]*>/i.test(text);
              if (
                text.includes("[SYSTEM DIRECTIVE:") ||
                text.includes("[restore checkpointed") ||
                (text.includes("<!-- OMO_INTERNAL") && !isSlashCmd) ||
                text.includes("[auto-gate-eval]") ||
                text.includes("## Environment Trust Boundaries:") ||
                text.includes("## Context:") ||
                text.includes("### Conversation Transcript")
              ) {
                continue;
              }

              return text;
            }
          }
        }
      }
    } catch {}
    return "";
  }

  public async resolveSessionPrompts(
    sessionID?: string,
    userPrompts?: Map<string, string>,
    defaultPrompt: string = "",
    signal?: AbortSignal,
  ): Promise<{ userPrompt: string; subagentPrompt?: string }> {
    if (!sessionID || signal?.aborted) {
      return { userPrompt: defaultPrompt };
    }

    let parentID: string | undefined = undefined;
    let sessionTitle: string | undefined = undefined;

    try {
      if (this.sessionParentCache.has(sessionID)) {
        parentID = this.sessionParentCache.get(sessionID);
      }
      if (this.client?.session?.get) {
        const sessionRes = await this.client.session.get({ sessionID });
        if (signal?.aborted) {
          return { userPrompt: defaultPrompt };
        }
        const data = sessionRes?.data ?? sessionRes;
        if (data?.parentID) {
          parentID = data.parentID;
          this.sessionParentCache.set(sessionID, data.parentID);
        } else {
          parentID = undefined;
          this.sessionParentCache.delete(sessionID);
        }
        sessionTitle = data?.title;
      }
    } catch {
      // Fall back to cached parentID / user prompt when session.get fails
    }

    if (signal?.aborted) {
      return { userPrompt: defaultPrompt };
    }

    if (!parentID) {
      const userPrompt =
        userPrompts?.get(sessionID) ||
        (await this.fetchLatestUserMessage(sessionID)) ||
        defaultPrompt;
      return formatOpenCodePromptHierarchy({ userPrompt, unwrap: false });
    }

    const rawSubagentText =
      userPrompts?.get(sessionID) || (await this.fetchLatestUserMessage(sessionID)) || "";

    let rootSessionID = sessionID;
    const visited = new Set<string>([sessionID]);
    let iterID: string | undefined = parentID;

    while (iterID && !visited.has(iterID) && !signal?.aborted) {
      visited.add(iterID);
      try {
        let parentData: Record<string, unknown> | null = null;
        if (this.client?.session?.get) {
          const res = await this.client.session.get({ sessionID: iterID });
          if (signal?.aborted) {
            return { userPrompt: defaultPrompt };
          }
          parentData = res?.data ?? res;
        }
        rootSessionID = iterID;
        let nextParentID: string | undefined = undefined;
        if (
          parentData &&
          typeof parentData === "object" &&
          typeof parentData.parentID === "string"
        ) {
          nextParentID = parentData.parentID;
        } else {
          nextParentID = this.sessionParentCache.get(iterID);
        }
        if (nextParentID) {
          if (!signal?.aborted) {
            this.sessionParentCache.set(iterID, nextParentID);
          }
          iterID = nextParentID;
        } else {
          break;
        }
      } catch {
        break;
      }
    }

    if (signal?.aborted) {
      return { userPrompt: defaultPrompt };
    }

    const rootUserPrompt =
      userPrompts?.get(rootSessionID) ||
      (await this.fetchLatestUserMessage(rootSessionID)) ||
      defaultPrompt;

    return formatOpenCodePromptHierarchy({
      userPrompt: rootUserPrompt,
      subagentPrompt: rawSubagentText,
      subagentTitle: sessionTitle,
      unwrap: false,
    });
  }
}
