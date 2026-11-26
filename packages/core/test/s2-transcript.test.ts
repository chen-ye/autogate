import { describe, expect, it } from "bun:test";
import {
  AUTOGATE_PROMPT_MARKER,
  extractAndStripSystemPrompt,
  extractModelFromModelValue,
  extractModelFromRecord,
  extractS2SessionDetails,
  getKnownEvalSystemPrompts,
} from "../src/index.js";

describe("s2-transcript", () => {
  describe("extractModelFromRecord and extractModelFromModelValue", () => {
    it("never misreads session or message .id fields as modelId", () => {
      const sessionInfo = {
        id: "ses_abc123",
        title: "[auto-gate-eval] bash",
        agent: "auto-gate-eval",
      };
      expect(extractModelFromRecord(sessionInfo)).toBeUndefined();

      const msgWithInfoModel = {
        id: "msg_999",
        info: {
          id: "msg_999",
          role: "assistant",
          modelID: "gemini-3.5-flash-lite",
          providerID: "google",
        },
        parts: [],
      };
      expect(extractModelFromRecord(msgWithInfoModel)).toEqual({
        modelId: "gemini-3.5-flash-lite",
        modelProvider: "google",
      });

      const msgWithoutModel = {
        id: "msg_no_model",
        type: "assistant",
        content: [],
      };
      expect(extractModelFromRecord(msgWithoutModel)).toBeUndefined();
    });

    it("handles direct model objects, bare dot-notation strings, and provider-only fallback", () => {
      expect(
        extractModelFromModelValue({ id: "claude-haiku-4-5", providerID: "anthropic" }),
      ).toEqual({
        modelId: "claude-haiku-4-5",
        modelProvider: "anthropic",
      });

      expect(extractModelFromModelValue("gemini.3.5.flash.lite", "google")).toEqual({
        modelId: "gemini.3.5-flash-lite",
        modelProvider: "google",
      });

      expect(extractModelFromModelValue("anthropic/claude-haiku-4-5#low", "google")).toEqual({
        modelId: "claude-haiku-4-5",
        modelProvider: "anthropic",
      });

      expect(extractModelFromRecord(undefined, "google")).toEqual({
        modelProvider: "google",
      });
    });

    it("falls back to configuredModel in extractS2SessionDetails when sessionInfo has .id but no model", () => {
      const details = extractS2SessionDetails({
        sessionInfo: {
          id: "ses_aborted_1",
          title: "[auto-gate-eval] bash",
          agent: "auto-gate-eval",
        },
        messages: [
          {
            id: "msg_1",
            info: { id: "msg_1", role: "assistant" },
            parts: [],
          },
        ],
        configuredModel: "google/gemini-3.5-flash-lite",
      });

      expect(details.modelId).toBe("gemini-3.5-flash-lite");
      expect(details.modelProvider).toBe("google");
    });
  });

  describe("extractAndStripSystemPrompt", () => {
    it("recognizes wrapped info.role messages for both system and user entries", () => {
      const known = getKnownEvalSystemPrompts();
      const staticSystem = known.fullSystem ?? `${AUTOGATE_PROMPT_MARKER} test system prompt`;

      const { systemPrompt, sanitizedMessages } = extractAndStripSystemPrompt(
        [
          { info: { role: "system" }, text: staticSystem },
          {
            info: { role: "user" },
            parts: [
              {
                type: "text",
                text: `${staticSystem}\n\n## Environment Trust Boundaries:\n- Trusted`,
              },
            ],
          },
        ],
        known,
      );

      expect(systemPrompt).toBe(staticSystem);
      expect(sanitizedMessages).toHaveLength(1);
      const userParts = sanitizedMessages[0]?.parts as Array<{ text?: string }>;
      expect(userParts[0]?.text).toBe("## Environment Trust Boundaries:\n- Trusted");
    });
  });
});
