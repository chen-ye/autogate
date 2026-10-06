export interface MockOpenCodeOptions {
  classifierVerdict?: "ALLOW" | "BLOCK" | "UNSURE";
  classifierReason?: string;
  customClassifierHandler?: (promptText: string) => {
    verdict: "ALLOW" | "BLOCK" | "UNSURE";
    reason?: string;
  };
}

export function createMockOpenCodeClient(options?: MockOpenCodeOptions) {
  const replies: any[] = [];
  const createdSessions: any[] = [];
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
            const { recordEvaluationVerdict } = await import(
              "../../../packages/opencode/src/evaluator.js"
            );
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
