import { describe, expect, it } from "bun:test";
import {
  parseSessionId,
  parseRequestId,
  parseActionId,
  parseTopicName,
  createGateAction,
  type GateDecision,
  type ClassifierResult,
} from "../src/types.js";

describe("Type System Discipline - Branded Types & Discriminated Unions", () => {
  it("brands and validates SessionId", () => {
    const s1 = parseSessionId("ses-123");
    expect(s1).toBe("ses-123" as any);

    // Fallback on empty or non-string
    const sFallback = parseSessionId("");
    expect(sFallback).toBe("default-session" as any);
  });

  it("brands and validates RequestId and ActionId", () => {
    const r1 = parseRequestId("req-abc");
    expect(r1).toBe("req-abc" as any);

    const a1 = parseActionId("act-xyz");
    expect(a1).toBe("act-xyz" as any);

    expect(() => parseRequestId("")).toThrow(TypeError);
    expect(() => parseActionId("   ")).toThrow(TypeError);
    expect(() => parseTopicName(null)).toThrow(TypeError);
  });

  it("constructs valid GateAction via createGateAction", () => {
    const action = createGateAction({
      toolName: "bash",
      commandString: "git status",
      sessionID: "ses-test",
    });

    expect(action.toolName).toBe("bash");
    expect(action.commandString).toBe("git status");
    expect(action.sessionID).toBe("ses-test" as any);
    expect(typeof action.id).toBe("string");
  });

  it("enforces discriminated union invariants on GateDecision", () => {
    const allowDecision: GateDecision = {
      verdict: "ALLOW",
      reason: "Safe check",
      cached: true,
      reply: "once",
    };
    expect(allowDecision.verdict).toBe("ALLOW");

    const blockDecision: GateDecision = {
      verdict: "BLOCK",
      reason: "Dangerous check",
      safeTransformAlternative: "trash-cli",
      reply: "reject",
    };
    expect(blockDecision.verdict).toBe("BLOCK");

    const unsureDecision: GateDecision = {
      verdict: "UNSURE",
      reason: "Needs review",
      reply: "always",
    };
    expect(unsureDecision.verdict).toBe("UNSURE");
  });

  it("enforces discriminated union invariants on ClassifierResult", () => {
    const allowResult: ClassifierResult = {
      verdict: "ALLOW",
      reason: "OK",
      risk_level: "LOW",
      user_authorization: "HIGH",
    };
    expect(allowResult.verdict).toBe("ALLOW");

    const blockResult: ClassifierResult = {
      verdict: "BLOCK",
      reason: "Bad",
      risk_level: "CRITICAL",
      user_authorization: "NONE",
    };
    expect(blockResult.verdict).toBe("BLOCK");
  });

  it("formatNotificationBody formats normal and verbose outputs correctly", async () => {
    const { formatNotificationBody, formatStatusBody } = await import("../src/formatters.js");

    const normal = formatNotificationBody({
      target: "echo test",
      reason: "Safe test",
      risk_level: "LOW",
      user_authorization: "HIGH",
    });
    expect(normal).toBe("Target: echo test\nReason: Safe test [Risk: LOW, Auth: HIGH]");

    const verbose = formatNotificationBody({
      target: "echo test",
      reason: "Safe test",
      risk_level: "LOW",
      user_authorization: "HIGH",
      verbosity: "verbose",
      toolName: "bash",
      workspaceRoot: "/workspace/project",
      sessionID: "ses-123",
      userPrompt: "Please run test",
      subagentPrompt: "Task: execute test",
      reasoning: "Confirmed read-only test",
      environment: {
        trustedDomains: ["github.com"],
        trustedGitRemotes: ["origin"],
      },
    });
    expect(verbose).toContain("Target: echo test\nTool: bash\nDirectory: /workspace/project\nSession: ses-123");
    expect(verbose).toContain("--- Evaluation ---\nRisk: LOW | Auth: HIGH\nReason: Safe test");
    expect(verbose).toContain("--- Model Reasoning ---\nConfirmed read-only test");
    expect(verbose).toContain("--- Context & Hierarchy ---\nUser Prompt:\nPlease run test\n\nSubagent Task:\nTask: execute test");
    expect(verbose).toContain("--- Trust Boundaries ---\nDomains: github.com\nRemotes: origin");

    const statusWithoutPreserve = formatStatusBody("✅ Approved", "Answered via ntfy");
    expect(statusWithoutPreserve).toBe("✅ Approved\nAnswered via ntfy");

    const statusWithPreserve = formatStatusBody("✅ Approved", "Answered via ntfy", verbose);
    expect(statusWithPreserve).toContain("✅ Approved\nAnswered via ntfy");
    expect(statusWithPreserve).toContain("========================================");
    expect(statusWithPreserve).toContain("Target: echo test");
  });
});
