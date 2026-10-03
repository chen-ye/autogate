import * as fs from "fs";
import * as path from "path";
import * as os from "os";
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
  isRiskLevel,
  isUserAuthorization,
  isClassifierVerdict,
} from "@autogate/core";
import { resolveServerPassword } from "./index.js";
import type { OpenCodeClassifyInput, OpenCodeSessionClient } from "./types.js";
export type { OpenCodeClassifyInput, OpenCodeSessionClient };

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
  client: OpenCodeSessionClient | undefined,
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
  if (client?.session && typeof client.session.update === "function") {
    const updateFn = client.session.update.bind(client.session);
    await updateFn({
      path: { id: sessionID, sessionID },
      body: archivePayload,
    }).catch(async () => {
      await updateFn({
        path: { id: sessionID, sessionID },
        body: archivePayload,
      }).catch(() => {});
    });
  }

  try {
    const oc2Archive = path.join(os.homedir(), ".config", "openchamber2", "sessions-archive.json");
    if (fs.existsSync(oc2Archive)) {
      const raw = fs.readFileSync(oc2Archive, "utf8");
      const parsed = JSON.parse(raw);
      if (!parsed[sessionID]) {
        parsed[sessionID] = Date.now();
        fs.writeFileSync(oc2Archive, JSON.stringify(parsed));
      }
    }
  } catch {}
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

export async function resolveEvaluationAgent(client?: OpenCodeSessionClient): Promise<string> {
  if (cachedEvalAgent) return cachedEvalAgent;
  try {
    const res = await client?.app?.agents?.();
    const agents = res?.data ?? [];
    if (
      Array.isArray(agents) &&
      agents.length > 0 &&
      !agents.some(
        (a) => typeof a === "object" && a !== null && "name" in a && a.name === "auto-gate-eval",
      )
    ) {
      cachedEvalAgent = "build";
      return "build";
    }
  } catch {}
  cachedEvalAgent = "auto-gate-eval";
  return "auto-gate-eval";
}

function extractToolInput(part: Record<string, unknown>): Record<string, unknown> | null {
  const state =
    part.state && typeof part.state === "object"
      ? (part.state as Record<string, unknown>)
      : undefined;
  const fn =
    part.function && typeof part.function === "object"
      ? (part.function as Record<string, unknown>)
      : undefined;

  let toolInput: unknown =
    state?.input ?? part.input ?? part.args ?? part.arguments ?? fn?.arguments ?? fn?.args;

  if (typeof toolInput === "string") {
    try {
      toolInput = JSON.parse(toolInput);
    } catch {}
  }

  if (toolInput && typeof toolInput === "object" && !Array.isArray(toolInput)) {
    return toolInput as Record<string, unknown>;
  }
  return null;
}

export function extractVerdictFromParts(partsList: readonly unknown[]): ClassifierResult | null {
  if (!Array.isArray(partsList) || partsList.length === 0) return null;

  // 1. First scan for classify_result tool call
  for (const part of partsList) {
    if (part && typeof part === "object") {
      const p = part as Record<string, unknown>;
      const fn =
        p.function && typeof p.function === "object"
          ? (p.function as Record<string, unknown>)
          : undefined;
      const isToolCall =
        (p.type === "tool" && p.tool === "classify_result") ||
        (p.type === "tool_use" && p.name === "classify_result") ||
        p.tool === "classify_result" ||
        p.name === "classify_result" ||
        (fn && (fn.name === "classify_result" || fn.tool === "classify_result"));

      if (isToolCall) {
        const toolInput = extractToolInput(p);
        if (toolInput && typeof toolInput.verdict === "string") {
          const rawVerdict = toolInput.verdict.toUpperCase().trim();
          if (isClassifierVerdict(rawVerdict)) {
            const riskRaw =
              typeof toolInput.risk_level === "string"
                ? toolInput.risk_level.toUpperCase().trim()
                : "";
            const authRaw =
              typeof toolInput.user_authorization === "string"
                ? toolInput.user_authorization.toUpperCase().trim()
                : "";
            const risk_level = isRiskLevel(riskRaw) ? riskRaw : undefined;
            const user_authorization = isUserAuthorization(authRaw) ? authRaw : undefined;
            const reason = typeof toolInput.reason === "string" ? toolInput.reason : "";
            return {
              verdict: rawVerdict,
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
      const p = part as Record<string, unknown>;
      const text =
        typeof p.text === "string" ? p.text : typeof p.content === "string" ? p.content : undefined;
      if (text) {
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
  client: OpenCodeSessionClient | undefined,
  sessionID: string,
  currentParts: readonly unknown[] = [],
): Promise<ClassifierResult | null> {
  const currentResult = extractVerdictFromParts(currentParts);
  if (currentResult) {
    return currentResult;
  }

  if (typeof client?.session?.messages === "function") {
    try {
      const msgsRes = await client.session
        .messages({ path: { id: sessionID, sessionID }, query: { limit: 50 } })
        .catch(async () => {
          return client.session.messages({ sessionID, query: { limit: 50 } }).catch(() => null);
        });
      const resObj = (msgsRes && typeof msgsRes === "object" ? msgsRes : {}) as Record<
        string,
        unknown
      >;
      const allMessages: unknown[] = Array.isArray(msgsRes)
        ? msgsRes
        : Array.isArray(resObj.data)
          ? resObj.data
          : [];

      if (allMessages.length > 0) {
        for (let i = allMessages.length - 1; i >= 0; i--) {
          const msg = allMessages[i];
          const m = (msg && typeof msg === "object" ? msg : {}) as {
            parts?: unknown[];
            content?: unknown;
            tool_calls?: unknown[];
          };
          const parts = [
            ...(Array.isArray(m.parts) ? m.parts : m.parts ? [m.parts] : []),
            ...(Array.isArray(m.content) ? m.content : m.content ? [m.content] : []),
            ...(Array.isArray(m.tool_calls) ? m.tool_calls : m.tool_calls ? [m.tool_calls] : []),
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

export async function classifyRequest(input: OpenCodeClassifyInput): Promise<ClassifierResult> {
  if (!input.client) {
    return {
      verdict: "UNSURE",
      reason: "No client provided for classification",
    };
  }
  const client = input.client;

  // Entry
  const sandboxDir = ensureSandboxDirectory();
  const userPrompt = input.userPrompt ?? "";
  const subagentPrompt = input.subagentPrompt;
  const actionName = input.actionName ?? input.request?.permission ?? "permission";
  const actionArgs = input.actionArgs ?? input.request?.patterns ?? input.request?.metadata ?? {};
  const workspaceRoot = input.workspaceRoot ?? input.directory ?? process.cwd();

  const evalAgent = await resolveEvaluationAgent(client);
  const evalTitle = `[auto-gate-eval] ${actionName}`;
  let sessionRes: { data?: { id?: string }; id?: string } | undefined;
  if (typeof client.session.create === "function") {
    try {
      sessionRes = await client.session.create({
        title: evalTitle,
        agent: evalAgent,
        location: { directory: sandboxDir },
        body: {
          title: evalTitle,
          agent: evalAgent,
          location: { directory: sandboxDir },
        },
      });
    } catch {}

    if (!sessionRes?.data?.id && !sessionRes?.id) {
      try {
        sessionRes = await input.client.session.create({
          body: {
            title: evalTitle,
            directory: sandboxDir,
            agent: evalAgent,
          },
          title: evalTitle,
          directory: sandboxDir,
          agent: evalAgent,
        });
      } catch {}
    }

    if (!sessionRes?.data?.id && !sessionRes?.id) {
      try {
        sessionRes = await input.client.session.create({
          title: evalTitle,
          agent: evalAgent,
          body: { title: evalTitle, agent: evalAgent },
        });
      } catch {}
    }
  }

  // Fallback to direct HTTP API if client method was unavailable or did not return an ID
  if (!sessionRes?.data?.id && !sessionRes?.id) {
    const cfg = input.config;
    const serverUrl =
      cfg?.serverUrl ||
      input.client?.serverUrl ||
      process.env.OPENCODE_SERVER_URL ||
      "http://localhost:4097";
    const password = resolveServerPassword(
      typeof cfg?.opencode?.serverUrl === "string" ? undefined : undefined,
    );
    const authHeader = password
      ? "Basic " + Buffer.from(`opencode:${password}`).toString("base64")
      : "";
    const urls = [`${serverUrl}/api/session`, `${serverUrl}/session`];
    for (const url of urls) {
      try {
        const res = await fetch(url, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            ...(authHeader ? { Authorization: authHeader } : {}),
          },
          body: JSON.stringify({
            title: evalTitle,
            agent: evalAgent,
            location: { directory: sandboxDir },
          }),
          signal: AbortSignal.timeout(5000),
        });
        if (res.ok) {
          const json: unknown = await res.json();
          if (json && typeof json === "object" && ("data" in json || "id" in json)) {
            sessionRes = json as { data?: { id?: string }; id?: string };
            break;
          }
        }
      } catch {}
    }
  }

  const sessionID = sessionRes?.data?.id ?? sessionRes?.id;
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
        const metaObj =
          genRes?.metadata && typeof genRes.metadata === "object"
            ? (genRes.metadata as { reasoning?: string })
            : undefined;
        capturedReasoning = genRes?.reasoning ?? genRes?.thinking ?? metaObj?.reasoning;
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
      const timeoutMs = input.config?.classifierTimeout ?? 45000;
      let timeoutId: ReturnType<typeof setTimeout> | undefined;
      const verdictPromise = new Promise<ClassifierResult>((resolve) => {
        registerEvaluationSession(sessionID, resolve);
      });

      const timeoutPromise = new Promise<ClassifierResult>((resolve) => {
        timeoutId = setTimeout(() => {
          try {
            input.client?.session?.abort?.({ path: { id: sessionID } })?.catch(() => {});
          } catch {}
          resolve({
            verdict: "UNSURE",
            reason: `Classifier evaluation timed out after ${Math.round(timeoutMs / 1000)} seconds`,
          });
        }, timeoutMs);
      });

      const promptPromise = client.session.prompt({
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
        .then(async (promptRes) => {
          if (!promptRes) return;
          const resObj = promptRes as Record<string, unknown>;
          const resData = (
            resObj.data && typeof resObj.data === "object" ? resObj.data : {}
          ) as Record<string, unknown>;
          const reasoning =
            typeof resData.reasoning === "string"
              ? resData.reasoning
              : typeof resObj.reasoning === "string"
                ? resObj.reasoning
                : typeof resData.thinking === "string"
                  ? resData.thinking
                  : typeof resObj.thinking === "string"
                    ? resObj.thinking
                    : undefined;
          if (reasoning) {
            capturedReasoning = reasoning;
          }
          const parts = Array.isArray(resData.parts)
            ? resData.parts
            : Array.isArray(resObj.parts)
              ? resObj.parts
              : [];
          const verdict = await extractVerdictFromSession(client, sessionID, parts);
          if (verdict) {
            recordEvaluationVerdict(sessionID, verdict);
            return;
          }

          let attempts = 0;
          const maxRetries = 2;
          while (attempts < maxRetries) {
            attempts++;
            const repromptRes = await client.session
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
              const repObj = repromptRes as Record<string, unknown>;
              const repData = (
                repObj.data && typeof repObj.data === "object" ? repObj.data : {}
              ) as Record<string, unknown>;
              const repReasoning =
                typeof repData.reasoning === "string"
                  ? repData.reasoning
                  : typeof repObj.reasoning === "string"
                    ? repObj.reasoning
                    : typeof repData.thinking === "string"
                      ? repData.thinking
                      : typeof repObj.thinking === "string"
                        ? repObj.thinking
                        : undefined;
              if (repReasoning) {
                capturedReasoning = repReasoning;
              }
              const repromptParts = Array.isArray(repData.parts)
                ? repData.parts
                : Array.isArray(repObj.parts)
                  ? repObj.parts
                  : [];
              const repromptVerdict = await extractVerdictFromSession(
                client,
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
    const rawVerdict = verdictResult?.verdict;
    const finalVerdict: ClassifierVerdict =
      rawVerdict && isClassifierVerdict(rawVerdict) ? rawVerdict : "UNSURE";
    await archiveEvaluationSession(client, sessionID, actionName, finalVerdict);
    logEvaluationDecision(
      {
        timestamp: Date.now(),
        sessionID,
        toolName: actionName,
        commandString: typeof actionArgs === "string" ? actionArgs : JSON.stringify(actionArgs),
        userPrompt,
        reasoning: capturedReasoning ?? verdictResult?.reason,
        verdict: finalVerdict,
        risk_level: verdictResult?.risk_level,
        user_authorization: verdictResult?.user_authorization,
        durationMs,
      },
      input.config?.evalLogFile,
    );
  }
}

export class OpenCodeSessionEvaluator implements GateEvaluator {
  readonly name = "opencode-session-evaluator";
  constructor(
    private client: OpenCodeSessionClient,
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
