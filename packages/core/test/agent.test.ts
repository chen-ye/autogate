import { describe, it, expect } from "bun:test";
import {
  EVAL_AGENT_ID,
  PASSIVE_EVALUATOR_DIRECTIVE,
  buildClassifierSystemPrompt,
  getDefaultClassifierModel,
  loadEvalAgentDefinition,
  parseAgentMarkdown,
  parseModelRef,
} from "../src/index.js";

describe("@autogate/core agent loader", () => {
  it("loads auto-gate-eval.md frontmatter and body as single source of truth", () => {
    const def = loadEvalAgentDefinition();
    expect(def.id).toBe(EVAL_AGENT_ID);
    expect(def.name).toBe(EVAL_AGENT_ID);
    expect(def.description).toBe("Autonomous security evaluation classifier for AutoGate");
    expect(def.mode).toBe("subagent");
    expect(def.hidden).toBe(true);
    expect(def.model).toBe("google/gemini-3.5-flash-lite");
    expect(def.steps).toBe(3);
    expect(def.request).toEqual({
      body: {
        temperature: 0.1,
      },
    });
    expect(def.permissions).toEqual([
      { action: "*", resource: "*", effect: "deny" },
      { action: "classify_result", resource: "*", effect: "allow" },
    ]);
    expect(def.system).toContain("2D Evaluation Framework");
    expect(def.system).toContain(PASSIVE_EVALUATOR_DIRECTIVE);
  });

  it("buildClassifierSystemPrompt matches loadEvalAgentDefinition().system", () => {
    expect(buildClassifierSystemPrompt()).toBe(loadEvalAgentDefinition().system);
  });

  it("getDefaultClassifierModel matches auto-gate-eval.md model", () => {
    expect(getDefaultClassifierModel()).toBe("google/gemini-3.5-flash-lite");
  });

  it("parses custom agent markdown with object permissions and model variant", () => {
    const md = `---
name: custom-eval
description: Custom: evaluator
mode: all
hidden: false
color: "#ff00aa"
model: anthropic/claude-sonnet-4#high
steps: 5
request:
  body:
    temperature: 0.25
permissions:
  "*": deny
  classify_result: allow
---

Evaluate carefully.`;
    const parsed = parseAgentMarkdown(md, "custom-id");
    expect(parsed.id).toBe("custom-id");
    expect(parsed.name).toBe("custom-eval");
    expect(parsed.description).toBe("Custom: evaluator");
    expect(parsed.mode).toBe("all");
    expect(parsed.hidden).toBe(false);
    expect(parsed.color).toBe("#ff00aa");
    expect(parsed.model).toBe("anthropic/claude-sonnet-4#high");
    expect(parsed.steps).toBe(5);
    expect(parsed.request).toEqual({ body: { temperature: 0.25 } });
    expect(parsed.permissions).toEqual([
      { action: "*", resource: "*", effect: "deny" },
      { action: "classify_result", resource: "*", effect: "allow" },
    ]);
    expect(parsed.system).toStartWith("Evaluate carefully.");
    expect(parsed.system).toContain(PASSIVE_EVALUATOR_DIRECTIVE);
  });

  it("parseModelRef parses provider, model, variant, and dot normalizations", () => {
    expect(parseModelRef("google/gemini.3.5.flash.lite#low")).toEqual({
      providerID: "google",
      modelID: "gemini.3.5-flash-lite",
      variant: "low",
    });
    expect(parseModelRef(undefined)).toEqual({
      providerID: "google",
      modelID: "gemini-3.5-flash-lite",
    });
  });

  it("throws when explicit agent markdown path does not exist", () => {
    expect(() => loadEvalAgentDefinition("/tmp/nonexistent-autogate-agent.md")).toThrow(
      "AutoGate agent definition not found",
    );
  });
});
