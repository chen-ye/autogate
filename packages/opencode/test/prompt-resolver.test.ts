import { describe, expect, it } from "bun:test";
import { OpenCodePromptResolver } from "../src/prompt-resolver.js";
import type { OpenCodeSessionClient } from "../src/types.js";

describe("OpenCodePromptResolver (OpenCode v2)", () => {
  it("resolves user prompt from single root session context", async () => {
    const mockClient = {
      session: {
        get: async () => ({ data: { id: "ses-root", title: "Root Task" } }),
        context: async () => [
          { type: "user", text: "Please check git status and test." },
          { type: "assistant", content: [{ type: "text", text: "Running git status..." }] },
        ],
      },
    } as unknown as OpenCodeSessionClient;

    const resolver = new OpenCodePromptResolver(mockClient);
    const result = await resolver.resolveSessionPrompts("ses-root");

    expect(result.userPrompt).toBe("Please check git status and test.");
    expect(result.subagentPrompt).toBeUndefined();
  });

  it("resolves multi-level hierarchy: child subagent -> parent subagent -> root", async () => {
    const mockClient = {
      session: {
        get: async ({ sessionID }: { sessionID: string }) => {
          if (sessionID === "ses-leaf") {
            return {
              data: {
                id: "ses-leaf",
                parentID: "ses-mid",
                title: "Deep Fixer",
              },
            };
          }
          if (sessionID === "ses-mid") {
            return {
              data: {
                id: "ses-mid",
                parentID: "ses-root",
                title: "Architect",
              },
            };
          }
          return { data: { id: "ses-root", title: "User Root" } };
        },
        context: async ({ sessionID }: { sessionID: string }) => {
          if (sessionID === "ses-leaf") {
            return [
              {
                type: "user",
                text: "Run oxlint and fix types in file.ts",
              },
            ];
          }
          if (sessionID === "ses-root") {
            return [
              {
                type: "user",
                text: "Refactor core architecture",
              },
            ];
          }
          return [];
        },
      },
    } as unknown as OpenCodeSessionClient;

    const resolver = new OpenCodePromptResolver(mockClient);
    const result = await resolver.resolveSessionPrompts("ses-leaf");

    expect(result.userPrompt).toBe("Refactor core architecture");
    expect(result.subagentPrompt).toBe(
      "[Subagent: Deep Fixer]\nRun oxlint and fix types in file.ts",
    );
  });

  it("filters out system directives and internal tags from user messages", async () => {
    const mockClient = {
      session: {
        get: async () => ({ data: { id: "ses-1" } }),
        context: async () => [
          {
            type: "user",
            text: "<!-- OMO_INTERNAL: some checkpoint data -->\n[SYSTEM DIRECTIVE: ignore]",
          },
          {
            type: "user",
            text: "<user-request>Real user prompt here</user-request>\n## Context:",
          },
        ],
      },
    } as unknown as OpenCodeSessionClient;

    const resolver = new OpenCodePromptResolver(mockClient);
    const prompt = await resolver.fetchLatestUserMessage("ses-1");

    expect(prompt).toBe("Real user prompt here");
  });

  it("handles missing client methods or API errors gracefully without throwing", async () => {
    const brokenClient = {
      session: {
        get: async () => {
          throw new Error("404 Not Found");
        },
        context: async () => {
          throw new Error("500 Server Error");
        },
      },
    } as unknown as OpenCodeSessionClient;

    const resolver = new OpenCodePromptResolver(brokenClient);
    const result = await resolver.resolveSessionPrompts(
      "ses-err",
      new Map([["ses-err", "Cached prompt"]]),
      "Fallback Default",
    );

    expect(result.userPrompt).toBe("Cached prompt");
    expect(result.subagentPrompt).toBeUndefined();
  });
});
