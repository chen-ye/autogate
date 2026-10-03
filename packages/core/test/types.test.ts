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
});
