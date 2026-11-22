import type { GateEvaluator, GateAction, ClassifierResult } from "./types";
import { CLASSIFIER_JSON_SCHEMA } from "./types";
import { getDefaultClassifierModel } from "./agent";
import { buildClassifierPrompt, parseVerdict, resolveClassifierActionArgs } from "./classifier";

export interface DirectApiEvaluatorOptions {
  apiKey?: string;
  model?: string;
  baseUrl?: string;
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
}

function extractCandidateTextFromResponse(data: unknown): string {
  if (typeof data === "string") return data;
  if (!data || typeof data !== "object") return "";

  const obj = data as Record<string, unknown>;
  if (Array.isArray(obj.candidates) && obj.candidates.length > 0) {
    const firstCandidate = obj.candidates[0];
    if (firstCandidate && typeof firstCandidate === "object") {
      const candObj = firstCandidate as Record<string, unknown>;
      if (typeof candObj.output === "string") return candObj.output;
      if (candObj.content && typeof candObj.content === "object") {
        const contentObj = candObj.content as Record<string, unknown>;
        if (Array.isArray(contentObj.parts) && contentObj.parts.length > 0) {
          const firstPart = contentObj.parts[0];
          if (firstPart && typeof firstPart === "object") {
            const partObj = firstPart as Record<string, unknown>;
            if (typeof partObj.text === "string") return partObj.text;
          }
        }
      }
    }
  }

  return JSON.stringify(data);
}

export class DirectApiEvaluator implements GateEvaluator {
  readonly name = "direct-api-evaluator";

  constructor(private defaultOptions?: DirectApiEvaluatorOptions) {}

  async evaluate(
    action: GateAction,
    runtimeOptions?: Record<string, unknown>,
  ): Promise<ClassifierResult> {
    const opts: DirectApiEvaluatorOptions = {
      ...this.defaultOptions,
      ...(runtimeOptions as DirectApiEvaluatorOptions),
    };

    try {
      const apiKey =
        opts.apiKey ||
        process.env.GEMINI_API_KEY ||
        process.env.GOOGLE_API_KEY ||
        process.env.AUTOGATE_API_KEY;

      if (!apiKey) {
        return {
          verdict: "UNSURE",
          reason:
            "DirectApiEvaluator error: API key not found (set GEMINI_API_KEY, GOOGLE_API_KEY, or AUTOGATE_API_KEY)",
        };
      }

      let model = opts.model || process.env.CLASSIFIER_MODEL || getDefaultClassifierModel();
      if (model.startsWith("google/")) {
        model = model.slice(7);
      }

      const promptText = buildClassifierPrompt({
        userPrompt: action.userPrompt,
        subagentPrompt: action.subagentPrompt,
        actionName: action.toolName,
        actionArgs: resolveClassifierActionArgs(action),
        workspaceRoot: action.workspaceRoot,
        environment: action.environment,
      });

      const baseUrl = opts.baseUrl || "https://generativelanguage.googleapis.com";
      const normalizedBase = baseUrl.endsWith("/v1beta")
        ? baseUrl
        : `${baseUrl.replace(/\/$/, "")}/v1beta`;
      const url = `${normalizedBase}/models/${model}:generateContent?key=${encodeURIComponent(apiKey)}`;

      const fetchFn = opts.fetchImpl ?? fetch;
      const timeoutMs = opts.timeoutMs ?? 45000;

      if (action.signal?.aborted) {
        return {
          verdict: "UNSURE",
          reason: "DirectApiEvaluator error: Evaluation aborted by signal",
        };
      }

      const timeoutSignal = AbortSignal.timeout(timeoutMs);
      const combinedSignal = action.signal
        ? AbortSignal.any([action.signal, timeoutSignal])
        : timeoutSignal;

      const response = await fetchFn(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-goog-api-key": apiKey,
        },
        body: JSON.stringify({
          contents: [
            {
              parts: [
                {
                  text: promptText,
                },
              ],
            },
          ],
          generationConfig: {
            responseMimeType: "application/json",
            responseSchema: CLASSIFIER_JSON_SCHEMA,
          },
        }),
        signal: combinedSignal,
      });

      if (!response.ok) {
        const errorText = await response.text().catch(() => response.statusText);
        throw new Error(`HTTP error ${response.status}: ${errorText}`);
      }

      const data: unknown = await response.json();
      const candidateText = extractCandidateTextFromResponse(data);

      return parseVerdict(candidateText);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        verdict: "UNSURE",
        reason: `DirectApiEvaluator error: ${message}`,
      };
    }
  }
}
