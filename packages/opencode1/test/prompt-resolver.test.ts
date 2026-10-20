import { describe, expect, it } from "bun:test";
import { OpenCodeV1PromptResolver } from "../src/prompt-resolver.js";
import type { OpenCodeV1SessionClient } from "../src/types.js";

describe("OpenCodeV1PromptResolver", () => {
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
    } as unknown as OpenCodeV1SessionClient;

    const resolver = new OpenCodeV1PromptResolver(mockClient);
    const result = await resolver.resolveSessionPrompts("ses-root");

    expect(result.userPrompt).toBe("Please check git status and test.");
    expect(result.subagentPrompt).toBeUndefined();
  });

  it("resolves multi-level hierarchy: child subagent -> parent subagent -> root", async () => {
    const mockClient = {
      session: {
        get: async ({ path }: { path: { id?: string } }) => {
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
        messages: async ({ path }: { path: { id?: string } }) => {
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
    } as unknown as OpenCodeV1SessionClient;

    const resolver = new OpenCodeV1PromptResolver(mockClient);
    const result = await resolver.resolveSessionPrompts("ses-leaf");

    expect(result.userPrompt).toBe("Refactor core architecture");
    expect(result.subagentPrompt).toBe(
      "[Subagent: Deep Fixer]\nRun oxlint and fix types in file.ts",
    );
  });
});
