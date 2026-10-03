import type { OpenCodeSessionClient } from "./types.js";
import { resolveServerPassword } from "./index.js";

interface MessageEntry {
  role?: string;
  info?: { role?: string };
  parts?: unknown[];
  content?: string;
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

  public async fetchLatestUserMessage(sessionID: string): Promise<string> {
    let messages: unknown[] | undefined;
    if (typeof this.client?.session?.messages === "function") {
      try {
        const res = await this.client.session.messages({
          path: { id: sessionID, sessionID },
          query: { limit: 50 },
        });
        messages = Array.isArray(res) ? res : (res as { data?: unknown[] })?.data;
      } catch {}
    }

    if (!Array.isArray(messages) || messages.length === 0) {
      try {
        const targetServer =
          this.client?.serverUrl ||
          process.env.OPENCODE_SERVER_URL ||
          (process.env.OPENCODE_CONFIG_DIR?.includes("opencode2")
            ? "http://localhost:4097"
            : "http://localhost:4096");
        const password = resolveServerPassword();
        const auth = password
          ? "Basic " + Buffer.from(`opencode:${password}`).toString("base64")
          : "";
        const res = await fetch(`${targetServer}/api/session/${sessionID}/message?limit=50`, {
          headers: auth ? { Authorization: auth } : {},
        });
        if (res.ok) {
          const json = (await res.json()) as { data?: unknown[] } | unknown[];
          messages = Array.isArray(json) ? json : json?.data;
        }
      } catch {}
    }

    try {
      if (Array.isArray(messages) && messages.length > 0) {
        for (let i = messages.length - 1; i >= 0; i--) {
          const item = messages[i];
          if (!item || typeof item !== "object") continue;
          const m = item as MessageEntry;
          const role = m.info?.role ?? m.role ?? (m as { type?: string }).type;
          if (role === "user") {
            const parts = m.parts || (m.content ? [m.content] : []);
            let text = "";
            if (typeof (m as { text?: unknown }).text === "string") {
              text = (m as { text: string }).text;
            } else if (typeof m.content === "string" && !m.parts) {
              text = m.content;
            } else if (Array.isArray(parts)) {
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
              const reqMatch = text.match(/<user-request>([\s\S]*?)<\/user-request>/i);
              if (reqMatch && reqMatch[1]) {
                text = reqMatch[1].trim();
              } else {
                const slashMatch = text.match(
                  /<auto-slash-command[^>]*>([\s\S]*?)<\/auto-slash-command>/i,
                );
                if (slashMatch && slashMatch[1]) {
                  const innerReq = slashMatch[1].match(/<user-request>([\s\S]*?)<\/user-request>/i);
                  if (innerReq && innerReq[1]) {
                    text = innerReq[1].trim();
                  } else {
                    text = slashMatch[1].trim();
                  }
                }
              }

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

              return text.trim();
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
  ): Promise<{ userPrompt: string; subagentPrompt?: string }> {
    if (!sessionID) {
      return { userPrompt: defaultPrompt };
    }

    let parentID: string | undefined = undefined;
    let sessionTitle: string | undefined = undefined;

    try {
      if (this.sessionParentCache.has(sessionID)) {
        parentID = this.sessionParentCache.get(sessionID);
      }
      if (this.client?.session?.get) {
        const sessionRes = await this.client.session.get({
          path: { id: sessionID, sessionID },
        });
        const data = sessionRes?.data ?? sessionRes;
        if (data?.parentID) {
          parentID = data.parentID;
          this.sessionParentCache.set(sessionID, data.parentID);
        }
        sessionTitle = data?.title;
      }
    } catch {}

    if (!parentID) {
      const userPrompt =
        userPrompts?.get(sessionID) ||
        (await this.fetchLatestUserMessage(sessionID)) ||
        defaultPrompt;
      return { userPrompt };
    }

    const rawSubagentText =
      userPrompts?.get(sessionID) || (await this.fetchLatestUserMessage(sessionID)) || "";
    let subagentPrompt = rawSubagentText;
    const cleanTitle = sessionTitle?.trim();
    if (cleanTitle) {
      if (subagentPrompt) {
        if (!subagentPrompt.includes(cleanTitle)) {
          subagentPrompt = `[Subagent: ${cleanTitle}]\n${subagentPrompt}`;
        }
      } else {
        subagentPrompt = `[Subagent: ${cleanTitle}]`;
      }
    }

    let rootSessionID = sessionID;
    const visited = new Set<string>([sessionID]);
    let iterID: string | undefined = parentID;

    while (iterID && !visited.has(iterID)) {
      visited.add(iterID);
      try {
        let parentData: Record<string, unknown> | null = null;
        if (this.client?.session?.get) {
          const res = await this.client.session.get({
            path: { id: iterID, sessionID: iterID },
          });
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
          this.sessionParentCache.set(iterID, nextParentID);
          iterID = nextParentID;
        } else {
          break;
        }
      } catch {
        break;
      }
    }

    const rootUserPrompt =
      userPrompts?.get(rootSessionID) ||
      (await this.fetchLatestUserMessage(rootSessionID)) ||
      defaultPrompt;

    return {
      userPrompt: rootUserPrompt,
      subagentPrompt: subagentPrompt || undefined,
    };
  }
}
