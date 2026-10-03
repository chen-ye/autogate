import fs from "fs";
import path from "path";
import os from "os";
import type {
  ClassifierResult,
  ClassifierVerdict,
  ClassifyInput,
  RiskLevel,
  UserAuthorization,
  GateEvaluator,
  GateAction,
  AutoGateConfig,
} from "@autogate/core";
import {
  buildClassifierSystemPrompt,
  buildClassifierUserPrompt,
  parseVerdict,
} from "@autogate/core";

export interface EvaluationAuditEntry {
  timestamp: number;
  sessionID: string;
  toolName: string;
  commandString: string;
  userPrompt: string;
  reasoning?: string;
  verdict: ClassifierVerdict;
  risk_level?: RiskLevel;
  user_authorization?: UserAuthorization;
  durationMs: number;
}

export function logEvaluationDecision(entry: EvaluationAuditEntry, logFilePath?: string): void {
  try {
    const filePath =
      logFilePath ?? path.join(os.homedir(), ".config", "autogate", "logs", "evals.jsonl");
    const dir = path.dirname(filePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.appendFileSync(filePath, JSON.stringify(entry) + "\n", "utf8");
  } catch (err) {
    console.warn("[AutoGate] Failed to write evaluation audit log:", err);
  }
}

export const evaluationSessions = new Set<string>();
export const evaluationResolvers = new Map<string, (res: ClassifierResult) => void>();

export function isEvaluationSession(sessionID: string): boolean {
  return evaluationSessions.has(sessionID);
}

export function registerEvaluationSession(
  sessionID: string,
  resolve: (res: ClassifierResult) => void,
): void {
  evaluationSessions.add(sessionID);
  evaluationResolvers.set(sessionID, resolve);
}

export function recordEvaluationVerdict(sessionID: string, result: ClassifierResult): boolean {
  const resolve = evaluationResolvers.get(sessionID);
  if (resolve) {
    resolve(result);
    evaluationResolvers.delete(sessionID);
    return true;
  }
  return false;
}

export function clearEvaluationSession(sessionID: string): void {
  evaluationSessions.delete(sessionID);
  evaluationResolvers.delete(sessionID);
}

export async function archiveEvaluationSession(
  client: any,
  sessionID: string,
  actionName: string,
  verdict: string,
): Promise<void> {
  const archivePayload = {
    title: `[auto-gate-eval] ${actionName} -> ${verdict}`,
    time: {
      archived: Date.now(),
    },
  };
  if (typeof client?.session?.update === "function") {
    await client.session
      .update({
        path: { id: sessionID, sessionID },
        body: archivePayload,
      })
      .catch(async () => {
        await client.session
          .update({
            sessionID,
            ...archivePayload,
          })
          .catch(() => {});
      });
  }
}

export const DEDICATED_AUTO_GATE_DIR = "/tmp/opencode-auto-gate/sandbox";

export function ensureSandboxDirectory(): string {
  try {
    if (!fs.existsSync(DEDICATED_AUTO_GATE_DIR)) {
      fs.mkdirSync(DEDICATED_AUTO_GATE_DIR, { recursive: true });
    }
    return DEDICATED_AUTO_GATE_DIR;
  } catch {
    return "/tmp";
  }
}

export function parseModelRef(modelRef?: string): {
  providerID: string;
  modelID: string;
  provider?: string;
  model?: string;
} {
  const ref = modelRef?.trim() || "google/gemini-3.5-flash-lite";
  const slashIdx = ref.indexOf("/");
  const providerID = slashIdx > 0 ? ref.slice(0, slashIdx) : "google";
  let modelID = slashIdx > 0 ? ref.slice(slashIdx + 1) : ref;
  modelID = modelID
    .replace(/\.flash/gi, "-flash")
    .replace(/\.lite/gi, "-lite")
    .replace(/\.pro/gi, "-pro");
  return {
    providerID,
    modelID,
    provider: providerID,
    model: modelID,
  };
}

export const PASSIVE_EVALUATOR_DIRECTIVE =
  "CRITICAL: You are an isolated security evaluation judge. Your ONLY tool is classify_result. You must NEVER execute the command, run bash, edit files, or perform any operational action. Immediately invoke classify_result and stop.";

export const EVAL_SESSION_TOOLS = {
  subagent: false,
  shell: false,
  task: false,
  read: false,
  glob: false,
  grep: false,
  bash: false,
  edit: false,
  write: false,
  question: false,
  classify_result: true,
  "*": false,
};

let cachedEvalAgent: string | undefined;

export async function resolveEvaluationAgent(client: any): Promise<string> {
  if (cachedEvalAgent) return cachedEvalAgent;
  try {
    const res = await client?.app?.agents?.();
    const agents = res?.data ?? [];
    if (
      Array.isArray(agents) &&
      agents.length > 0 &&
      !agents.some((a: any) => a.name === "auto-gate-eval")
    ) {
      cachedEvalAgent = "build";
      return "build";
    }
  } catch {}
  cachedEvalAgent = "auto-gate-eval";
  return "auto-gate-eval";
}

export function extractVerdictFromParts(partsList: any[]): ClassifierResult | null {
  if (!Array.isArray(partsList) || partsList.length === 0) return null;

  // 1. First scan for classify_result tool call
  for (const part of partsList) {
    if (part && typeof part === "object") {
      const isToolCall =
        (part.type === "tool" && part.tool === "classify_result") ||
        (part.type === "tool_use" && part.name === "classify_result") ||
        part.tool === "classify_result" ||
        part.name === "classify_result" ||
        (part.function &&
          (part.function.name === "classify_result" || part.function.tool === "classify_result"));

      if (isToolCall) {
        let toolInput =
          (part as any).state?.input ??
          (part as any).input ??
          (part as any).args ??
          (part as any).arguments ??
          (part as any).function?.arguments ??
          (part as any).function?.args;

        if (typeof toolInput === "string") {
          try {
            toolInput = JSON.parse(toolInput);
          } catch {}
        }

        if (toolInput && typeof toolInput === "object" && toolInput.verdict) {
          const rawVerdict = String(toolInput.verdict).toUpperCase().trim();
          if (rawVerdict === "ALLOW" || rawVerdict === "BLOCK" || rawVerdict === "UNSURE") {
            const riskRaw = String(toolInput.risk_level ?? "")
              .toUpperCase()
              .trim();
            const authRaw = String(toolInput.user_authorization ?? "")
              .toUpperCase()
              .trim();
            const risk_level = ["LOW", "MEDIUM", "HIGH", "CRITICAL"].includes(riskRaw)
              ? (riskRaw as RiskLevel)
              : undefined;
            const user_authorization = ["NONE", "LOW", "MEDIUM", "HIGH"].includes(authRaw)
              ? (authRaw as UserAuthorization)
              : undefined;
            const reason = typeof toolInput.reason === "string" ? toolInput.reason : undefined;
            return {
              verdict: rawVerdict as ClassifierVerdict,
              risk_level,
              user_authorization,
              reason,
            };
          }
        }
      }
    }
  }

  // 2. Scan for text parts containing a valid JSON verdict
  let textContent = "";
  for (const part of partsList) {
    if (part && typeof part === "object") {
      const text = (part as any).text ?? (part as any).content;
      if (typeof text === "string") {
        textContent += text + "\n";
      }
    } else if (typeof part === "string") {
      textContent += part + "\n";
    }
  }

  if (textContent.trim()) {
    const parsed = parseVerdict(textContent);
    if (
      parsed &&
      parsed.reason !== "Classifier response did not contain a valid structured verdict" &&
      parsed.reason !== "Empty or invalid classifier output"
    ) {
      return parsed;
    }
  }

  return null;
}

export async function extractVerdictFromSession(
  client: any,
  sessionID: string,
  currentParts: any[] = [],
): Promise<ClassifierResult | null> {
  const currentResult = extractVerdictFromParts(currentParts);
  if (currentResult) {
    return currentResult;
  }

  if (typeof client?.session?.messages === "function") {
    try {
      const msgsRes = await client.session.messages({ path: { id: sessionID } }).catch(async () => {
        return client.session.messages({ sessionID }).catch(() => null);
      });
      const allMessages = Array.isArray(msgsRes)
        ? msgsRes
        : Array.isArray(msgsRes?.data)
          ? msgsRes.data
          : Array.isArray(msgsRes?.data?.data)
            ? msgsRes.data.data
            : Array.isArray(msgsRes?.data?.messages)
              ? msgsRes.data.messages
              : Array.isArray(msgsRes?.messages)
                ? msgsRes.messages
                : [];

      if (allMessages.length > 0) {
        for (let i = allMessages.length - 1; i >= 0; i--) {
          const msg = allMessages[i];
          const parts = [
            ...(Array.isArray(msg?.parts) ? msg.parts : msg?.parts ? [msg.parts] : []),
            ...(Array.isArray(msg?.content) ? msg.content : msg?.content ? [msg.content] : []),
            ...(Array.isArray(msg?.tool_calls)
              ? msg.tool_calls
              : msg?.tool_calls
                ? [msg.tool_calls]
                : []),
          ];
          const result = extractVerdictFromParts(parts);
          if (result) {
            return result;
          }
        }
      }
    } catch {}
  }

  return null;
}
export function resetCachedEvaluationAgent(): void {
  cachedEvalAgent = undefined;
}

export async function classifyRequest(input: ClassifyInput): Promise<ClassifierResult> {
  // Entry
  const sandboxDir = ensureSandboxDirectory();
  const userPrompt = input.userPrompt ?? "";
  const subagentPrompt = input.subagentPrompt;
  const actionName = input.actionName ?? input.request?.permission ?? "permission";
  const actionArgs = input.actionArgs ?? input.request?.patterns ?? input.request?.metadata ?? {};
  const workspaceRoot = input.workspaceRoot ?? input.directory ?? process.cwd();

  const evalAgent = await resolveEvaluationAgent(input.client);
  const evalTitle = `[auto-gate-eval] ${actionName}`;
  const sessionRes = await input.client.session
    .create({
      body: {
        title: evalTitle,
        directory: sandboxDir,
        agent: evalAgent,
      },
      title: evalTitle,
      directory: sandboxDir,
      agent: evalAgent,
    })
    .catch(() =>
      input.client.session.create({
        title: evalTitle,
        agent: evalAgent,
        body: { title: evalTitle, agent: evalAgent },
      }),
    );
  const sessionID = sessionRes.data?.id ?? (sessionRes as any).id;
  if (!sessionID) {
    throw new Error("Failed to create ephemeral classifier session: missing session ID");
  }

  const modelRef = parseModelRef(input.model);
  const systemPrompt = buildClassifierSystemPrompt();
  const userPromptText = buildClassifierUserPrompt({
    userPrompt,
    subagentPrompt,
    actionName,
    actionArgs,
    workspaceRoot,
    environment: input.environment,
  });

  const startTime = Date.now();
  let capturedReasoning: string | undefined;
  let verdictResult: ClassifierResult | undefined;

  try {
    const generateTextFn = input.client?.generate?.text ?? input.client?.ctx?.generate?.text;
    if (typeof generateTextFn === "function") {
      try {
        const fullPrompt = `${systemPrompt}\n\n${userPromptText}`;
        const genRes = await generateTextFn({
          prompt: fullPrompt,
          model: {
            providerID: modelRef.providerID,
            id: modelRef.modelID,
          },
        });
        const responseText =
          genRes?.text ?? genRes?.content ?? (typeof genRes === "string" ? genRes : "");
        capturedReasoning = genRes?.reasoning ?? genRes?.thinking ?? genRes?.metadata?.reasoning;
        if (responseText) {
          const parsed = parseVerdict(responseText);
          if (
            parsed &&
            parsed.reason !== "Classifier response did not contain a valid structured verdict" &&
            parsed.reason !== "Empty or invalid classifier output"
          ) {
            verdictResult = parsed;
          } else {
            const retryRes = await generateTextFn({
              prompt: `${fullPrompt}\n\nYour previous response was malformed JSON or invalid verdict. You must output a single JSON object with keys: risk_level, user_authorization, verdict, reason.`,
              model: {
                providerID: modelRef.providerID,
                id: modelRef.modelID,
              },
            });
            const retryText =
              retryRes?.text ?? retryRes?.content ?? (typeof retryRes === "string" ? retryRes : "");
            if (retryRes?.reasoning || retryRes?.thinking) {
              capturedReasoning = retryRes.reasoning ?? retryRes.thinking;
            }
            if (retryText) {
              const retryParsed = parseVerdict(retryText);
              if (
                retryParsed &&
                retryParsed.reason !==
                  "Classifier response did not contain a valid structured verdict" &&
                retryParsed.reason !== "Empty or invalid classifier output"
              ) {
                verdictResult = retryParsed;
              }
            }
          }
        }
      } catch (err) {
        // Fall back to session prompt path if generate.text throws or fails
      }
    }

    if (!verdictResult) {
      const timeoutMs = (input.config as any)?.classifierTimeout ?? 45000;
      let timeoutId: any;
      const verdictPromise = new Promise<ClassifierResult>((resolve) => {
        registerEvaluationSession(sessionID, resolve);
      });

      const timeoutPromise = new Promise<ClassifierResult>((resolve) => {
        timeoutId = setTimeout(() => {
          try {
            const maybePromise = input.client?.session?.abort?.({ path: { id: sessionID } });
            if (maybePromise && typeof (maybePromise as any).catch === "function") {
              (maybePromise as any).catch(() => {});
            }
          } catch {}
          resolve({
            verdict: "UNSURE",
            reason: `Classifier evaluation timed out after ${Math.round(timeoutMs / 1000)} seconds`,
          });
        }, timeoutMs);
      });

      const promptPromise = input.client.session.prompt({
        path: { id: sessionID },
        agent: evalAgent,
        body: {
          agent: evalAgent,
          model: {
            providerID: modelRef.providerID,
            modelID: modelRef.modelID,
          },
          tools: { ...EVAL_SESSION_TOOLS },
          system: systemPrompt,
          parts: [
            {
              type: "text",
              text: userPromptText,
            },
          ],
        },
      });

      promptPromise
        .then(async (promptRes: any) => {
          if (!promptRes) return;
          if (
            promptRes?.data?.reasoning ||
            promptRes?.reasoning ||
            promptRes?.data?.thinking ||
            promptRes?.thinking
          ) {
            capturedReasoning =
              promptRes?.data?.reasoning ??
              promptRes?.reasoning ??
              promptRes?.data?.thinking ??
              promptRes?.thinking;
          }
          const parts = promptRes?.data?.parts ?? (promptRes as any)?.parts ?? [];
          const verdict = await extractVerdictFromSession(input.client, sessionID, parts);
          if (verdict) {
            recordEvaluationVerdict(sessionID, verdict);
            return;
          }

          let attempts = 0;
          const maxRetries = 2;
          while (attempts < maxRetries) {
            attempts++;
            const repromptRes = await input.client.session
              .prompt({
                path: { id: sessionID },
                agent: evalAgent,
                body: {
                  agent: evalAgent,
                  model: {
                    providerID: modelRef.providerID,
                    modelID: modelRef.modelID,
                  },
                  tools: { ...EVAL_SESSION_TOOLS },
                  system: systemPrompt,
                  parts: [
                    {
                      type: "text",
                      text: "You must record your decision by calling the classify_result tool with { risk_level, user_authorization, verdict, reason }. If tool calling is unavailable, output a single JSON object conforming to the schema.",
                    },
                  ],
                },
              })
              .catch(() => null);
            if (repromptRes) {
              if (
                repromptRes?.data?.reasoning ||
                repromptRes?.reasoning ||
                repromptRes?.data?.thinking ||
                repromptRes?.thinking
              ) {
                capturedReasoning =
                  repromptRes?.data?.reasoning ??
                  repromptRes?.reasoning ??
                  repromptRes?.data?.thinking ??
                  repromptRes?.thinking;
              }
              const repromptParts = repromptRes.data?.parts ?? (repromptRes as any)?.parts ?? [];
              const repromptVerdict = await extractVerdictFromSession(
                input.client,
                sessionID,
                repromptParts,
              );
              if (repromptVerdict) {
                recordEvaluationVerdict(sessionID, repromptVerdict);
                return;
              }
            }
          }

          recordEvaluationVerdict(sessionID, {
            verdict: "UNSURE",
            reason:
              "Classifier failed to call classify_result tool or produce structured JSON after retries",
          });
        })
        .catch(() => {});

      verdictResult = await Promise.race([verdictPromise, timeoutPromise]);
      if (timeoutId) clearTimeout(timeoutId);
    }

    return verdictResult;
  } finally {
    clearEvaluationSession(sessionID);
    const durationMs = Date.now() - startTime;
    const finalVerdict = verdictResult?.verdict ?? "UNKNOWN";
    await archiveEvaluationSession(input.client, sessionID, actionName, finalVerdict);
    logEvaluationDecision(
      {
        timestamp: Date.now(),
        sessionID,
        toolName: actionName,
        commandString: typeof actionArgs === "string" ? actionArgs : JSON.stringify(actionArgs),
        userPrompt,
        reasoning: capturedReasoning ?? verdictResult?.reason,
        verdict: finalVerdict as ClassifierVerdict,
        risk_level: verdictResult?.risk_level,
        user_authorization: verdictResult?.user_authorization,
        durationMs,
      },
      (input.config as any)?.evalLogFile,
    );
  }
}

export class OpenCodeSessionEvaluator implements GateEvaluator {
  readonly name = "opencode-session-evaluator";
  constructor(
    private client: any,
    private config?: AutoGateConfig,
  ) {}
  async evaluate(action: GateAction): Promise<ClassifierResult> {
    return classifyRequest({
      client: this.client,
      userPrompt: action.userPrompt,
      subagentPrompt: action.subagentPrompt,
      actionName: action.toolName,
      actionArgs: action.rawArgs ?? action.metadata ?? action.commandString,
      workspaceRoot: action.workspaceRoot,
      environment: action.environment,
      model: this.config?.classifierModel,
      config: this.config,
    });
  }
}
