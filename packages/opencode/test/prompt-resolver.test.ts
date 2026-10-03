import { describe, expect, it } from "bun:test";
import { OpenCodePromptResolver } from "../src/prompt-resolver.js";

describe("OpenCodePromptResolver", () => {
  it("resolves user prompt from single root session message history", async () => {
    const mockClient = {
      session: {
        get: async () => ({ data: { id: "ses-root", title: "Root Task" } }),
        messages: async () => ({
          data: [
            { role: "user", parts: ["Please check git status and test."] },
            { role: "assistant", parts: ["Running git status..."] },
          ],
        }),
      },
    };

    const resolver = new OpenCodePromptResolver(mockClient as any);
    const result = await resolver.resolveSessionPrompts("ses-root");

    expect(result.userPrompt).toBe("Please check git status and test.");
    expect(result.subagentPrompt).toBeUndefined();
  });

  it("resolves multi-level hierarchy: child subagent -> parent subagent -> root", async () => {
    const mockClient = {
      session: {
        get: async ({ path }: any) => {
          if (path.id === "ses-leaf") {
            return {
              data: {
                id: "ses-leaf",
                parentID: "ses-mid",
                title: "Deep Fixer",
              },
            };
          }
          if (path.id === "ses-mid") {
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
        messages: async ({ path }: any) => {
          if (path.id === "ses-leaf") {
            return {
              data: [
                {
                  role: "user",
                  content: "Run oxlint and fix types in file.ts",
                },
              ],
            };
          }
          if (path.id === "ses-root") {
            return {
              data: [
                {
                  role: "user",
                  parts: [{ type: "text", text: "Refactor core architecture" }],
                },
              ],
            };
          }
          return { data: [] };
        },
      },
    };

    const resolver = new OpenCodePromptResolver(mockClient as any);
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
        messages: async () => ({
          data: [
            {
              role: "user",
              content: "<!-- OMO_INTERNAL: some checkpoint data -->\n[SYSTEM DIRECTIVE: ignore]",
            },
            {
              role: "user",
              content: "<user-request>Real user prompt here</user-request>\n## Context:",
            },
          ],
        }),
      },
    };

    const resolver = new OpenCodePromptResolver(mockClient as any);
    const prompt = await resolver.fetchLatestUserMessage("ses-1");

    expect(prompt).toBe("Real user prompt here");
  });

  it("handles missing client methods or API errors gracefully without throwing", async () => {
    const brokenClient = {
      session: {
        get: async () => {
          throw new Error("404 Not Found");
        },
        messages: async () => {
          throw new Error("500 Server Error");
        },
      },
    };

    const resolver = new OpenCodePromptResolver(brokenClient as any);
    const result = await resolver.resolveSessionPrompts(
      "ses-err",
      new Map([["ses-err", "Cached prompt"]]),
      "Fallback Default",
    );

    expect(result.userPrompt).toBe("Cached prompt");
    expect(result.subagentPrompt).toBeUndefined();
  });
});
