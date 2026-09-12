import type { GateEvaluator, GateAction, ClassifierResult } from "./types"
import { CLASSIFIER_JSON_SCHEMA } from "./types"
import { buildClassifierPrompt, parseVerdict } from "./classifier"

export interface DirectApiEvaluatorOptions {
  apiKey?: string
  model?: string
  baseUrl?: string
  timeoutMs?: number
  fetchImpl?: typeof fetch
}

export class DirectApiEvaluator implements GateEvaluator {
  readonly name = "direct-api-evaluator"

  constructor(private defaultOptions?: DirectApiEvaluatorOptions) {}

  async evaluate(action: GateAction, runtimeOptions?: Record<string, unknown>): Promise<ClassifierResult> {
    const opts: DirectApiEvaluatorOptions = {
      ...this.defaultOptions,
      ...(runtimeOptions as DirectApiEvaluatorOptions),
    }

    try {
      const apiKey =
        opts.apiKey ||
        process.env.GEMINI_API_KEY ||
        process.env.GOOGLE_API_KEY ||
        process.env.AUTOGATE_API_KEY

      if (!apiKey) {
        return {
          verdict: "UNSURE",
          reason: "DirectApiEvaluator error: API key not found (set GEMINI_API_KEY, GOOGLE_API_KEY, or AUTOGATE_API_KEY)",
        }
      }

      let model = opts.model || process.env.CLASSIFIER_MODEL || "gemini-2.5-flash-lite"
      if (model.startsWith("google/")) {
        model = model.slice(7)
      }

      const promptText = buildClassifierPrompt({
        userPrompt: action.userPrompt,
        subagentPrompt: action.subagentPrompt,
        actionName: action.toolName,
        actionArgs: action.rawArgs ?? action.metadata ?? action.commandString,
        workspaceRoot: action.workspaceRoot,
        environment: action.environment,
      })

      const baseUrl = opts.baseUrl || "https://generativelanguage.googleapis.com"
      const normalizedBase = baseUrl.endsWith("/v1beta") ? baseUrl : `${baseUrl.replace(/\/$/, "")}/v1beta`
      const url = `${normalizedBase}/models/${model}:generateContent?key=${encodeURIComponent(apiKey)}`

      const fetchFn = opts.fetchImpl ?? fetch
      const timeoutMs = opts.timeoutMs ?? 45000

      const controller = new AbortController()
      const timeoutId = setTimeout(() => controller.abort(), timeoutMs)

      try {
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
          signal: controller.signal,
        })

        if (!response.ok) {
          const errorText = await response.text().catch(() => response.statusText)
          throw new Error(`HTTP error ${response.status}: ${errorText}`)
        }

        const data = await response.json()
        const candidateText =
          data?.candidates?.[0]?.content?.parts?.[0]?.text ??
          data?.candidates?.[0]?.output ??
          (typeof data === "string" ? data : JSON.stringify(data))

        return parseVerdict(candidateText)
      } finally {
        clearTimeout(timeoutId)
      }
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err)
      return {
        verdict: "UNSURE",
        reason: `DirectApiEvaluator error: ${message}`,
      }
    }
  }
}
