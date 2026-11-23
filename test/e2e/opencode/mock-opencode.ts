export interface MockOpenCodeOptions {
  classifierVerdict?: "ALLOW" | "BLOCK" | "UNSURE";
  classifierReason?: string;
  customClassifierHandler?: (promptText: string) => {
    verdict: "ALLOW" | "BLOCK" | "UNSURE";
    reason?: string;
  };
}

export interface MockSessionUpdateArgs {
  sessionID?: string;
  path?: { id?: string; sessionID?: string };
  title?: string;
  archived?: boolean;
  body?: { title?: string; archived?: boolean };
}

export function createMockOpenCodeClient(options?: MockOpenCodeOptions) {
  const replies: any[] = [];
  const createdSessions: any[] = [];
  const updatedSessions: MockSessionUpdateArgs[] = [];
  const deletedSessions: any[] = [];
  const prompts: any[] = [];

  let sessionIdCounter = 1;

  const client = {
    session: {
      create: async () => {
        const id = `session-${sessionIdCounter++}`;
        createdSessions.push(id);
        return { data: { id } };
      },
      get: async (args: { sessionID?: string; path?: { id?: string } }) => {
        const targetID = args?.sessionID ?? args?.path?.id;
        let title: string | undefined;
        let archived: boolean | undefined;
        for (const entry of updatedSessions) {
          const entryID = entry.sessionID ?? entry.path?.sessionID ?? entry.path?.id;
          if (targetID && entryID === targetID) {
            const nextTitle = entry.title ?? entry.body?.title;
            const nextArchived = entry.archived ?? entry.body?.archived;
            if (nextTitle !== undefined) title = nextTitle;
            if (nextArchived !== undefined) archived = nextArchived;
          }
        }
        return {
          data: {
            id: targetID,
            ...(title !== undefined ? { title } : {}),
            ...(archived ? { time: { archived: Date.now() } } : {}),
          },
        };
      },
      update: async (args: MockSessionUpdateArgs) => {
        updatedSessions.push(args);
        return { data: { success: true } };
      },
      delete: async (args: any) => {
        deletedSessions.push(args);
        return { data: { success: true } };
      },
      prompt: async (args: any) => {
        prompts.push(args);
        const promptText = args?.body?.parts?.[0]?.text ?? args?.text ?? "";

        let verdict = options?.classifierVerdict ?? "ALLOW";
        let reason = options?.classifierReason ?? "Mock classifier approved";

        if (options?.customClassifierHandler) {
          const res = options.customClassifierHandler(promptText);
          verdict = res.verdict;
          reason = res.reason ?? reason;
        }

        const sessionID = args?.sessionID ?? args?.path?.id;
        if (sessionID) {
          try {
            const { recordEvaluationVerdict } =
              await import("../../../packages/opencode/src/evaluator.js");
            recordEvaluationVerdict(sessionID, {
              verdict,
              reason,
              risk_level: "LOW",
              user_authorization: "HIGH",
            });
          } catch {}
        }

        return {
          data: {
            parts: [
              {
                type: "tool",
                tool: "classify_result",
                input: {
                  verdict,
                  reason,
                  risk_level: "LOW",
                  user_authorization: "HIGH",
                },
              },
            ],
          },
        };
      },
    },
    permission: {
      reply: async (args: any) => {
        const payload = args?.path
          ? {
              ...args,
              requestID: args.path.requestID,
              reply: args?.body?.reply,
              message: args?.body?.message,
            }
          : args;
        replies.push(payload);
        return { data: { success: true } };
      },
    },
  };

  return {
    client,
    replies,
    createdSessions,
    updatedSessions,
    deletedSessions,
    prompts,
  };
}

export function createMockPluginContext(client: any, directory = process.cwd()) {
  return {
    client,
    directory,
    worktree: directory,
  };
}
