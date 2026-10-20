import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import * as crypto from "crypto";
import type {
  ClassifierResult,
  ClassifierVerdict,
  RiskLevel,
  UserAuthorization,
  GateEvaluator,
  GateAction,
  AutoGateConfig,
} from "@autogate/core";
import {
  buildClassifierUserPrompt,
  parseVerdict,
  isRiskLevel,
  isUserAuthorization,
  isClassifierVerdict,
} from "@autogate/core";
import type { OpenCodeV1ClassifyInput, OpenCodeV1SessionClient } from "./types.js";
export type { OpenCodeV1ClassifyInput, OpenCodeV1SessionClient };

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

const g = globalThis as unknown as {
  __autogate_evaluation_sessions__?: Set<string>;
  __autogate_evaluation_resolvers__?: Map<string, (res: ClassifierResult) => void>;
};
export const evaluationSessions: Set<string> =
  g.__autogate_evaluation_sessions__ ?? (g.__autogate_evaluation_sessions__ = new Set<string>());
export const evaluationResolvers: Map<string, (res: ClassifierResult) => void> =
  g.__autogate_evaluation_resolvers__ ??
  (g.__autogate_evaluation_resolvers__ = new Map<string, (res: ClassifierResult) => void>());

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

async function notifyOpenChamber1Archive(sessionID: string): Promise<void> {
  const secretFile = path.join(os.homedir(), ".config", "openchamber1", "jwt-secret");
  if (!fs.existsSync(secretFile)) return;

  try {
    const secret = fs.readFileSync(secretFile, "utf8").trim();
    if (!secret) return;

    const header = { alg: "HS256", typ: "JWT" };
    const nowSec = Math.floor(Date.now() / 1000);
    const payload = { type: "ui-session", iat: nowSec, exp: nowSec + 3600 };
    const encHeader = Buffer.from(JSON.stringify(header)).toString("base64url");
    const encPayload = Buffer.from(JSON.stringify(payload)).toString("base64url");
    const data = `${encHeader}.${encPayload}`;
    const sig = crypto.createHmac("sha256", secret).update(data).digest("base64url");
    const token = `${data}.${sig}`;

    await fetch("http://localhost:14097/api/openchamber/sessions/archive", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Cookie: `oc_ui_session_14097=${token}`,
      },
      body: JSON.stringify({ ids: [sessionID], archivedAt: Date.now() }),
      signal: AbortSignal.timeout(2000),
    }).catch(() => null);
  } catch {}
}

export async function archiveEvaluationSession(
  client: OpenCodeV1SessionClient | undefined,
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
    await client.session
      .update({
        path: { id: sessionID, sessionID },
        body: archivePayload,
      })
      .catch(() => {});
  }

  await notifyOpenChamber1Archive(sessionID);

  try {
    const ocArchive = path.join(os.homedir(), ".config", "openchamber1", "sessions-archive.json");
    if (fs.existsSync(ocArchive)) {
      const raw = fs.readFileSync(ocArchive, "utf8");
      const parsed = JSON.parse(raw) as Record<string, number>;
      if (!parsed[sessionID]) {
        parsed[sessionID] = Date.now();
        fs.writeFileSync(ocArchive, JSON.stringify(parsed));
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

export async function resolveEvaluationAgent(client?: OpenCodeV1SessionClient): Promise<string> {
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
  client: OpenCodeV1SessionClient | undefined,
  sessionID: string,
  currentParts: readonly unknown[] = [],
): Promise<ClassifierResult | null> {
  const currentResult = extractVerdictFromParts(currentParts);
  if (currentResult) {
    return currentResult;
  }

  if (typeof client?.session?.messages === "function") {
    try {
      const msgsRes = await client.session.messages({
        path: { id: sessionID, sessionID },
        query: { limit: 50 },
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

export async function classifyRequest(input: OpenCodeV1ClassifyInput): Promise<ClassifierResult> {
  if (!input.client) {
    return {
      verdict: "UNSURE",
      reason: "No client provided for classification",
    };
  }
  const client = input.client;

  const sandboxDir = ensureSandboxDirectory();
  const userPrompt = input.userPrompt ?? "";
  const subagentPrompt = input.subagentPrompt;
  const actionName = input.actionName ?? input.request?.permission ?? "permission";
  const actionArgs = input.actionArgs ?? input.request?.patterns ?? input.request?.metadata ?? {};
  const workspaceRoot = input.workspaceRoot ?? input.directory ?? process.cwd();

  const evalAgent = await resolveEvaluationAgent(client);
  const evalTitle = `[auto-gate-eval] ${actionName}`;
  const sessionRes = await client.session.create({
    body: {
      title: evalTitle,
      directory: sandboxDir,
      agent: evalAgent,
    },
    title: evalTitle,
    directory: sandboxDir,
    agent: evalAgent,
  });

  const sessionID = sessionRes?.data?.id ?? sessionRes?.id;
  if (!sessionID) {
    throw new Error("Failed to create ephemeral classifier session: missing session ID");
  }

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
    const timeoutMs = input.config?.classifierTimeout ?? 45000;
    let timeoutId: ReturnType<typeof setTimeout> | undefined;
    const verdictPromise = new Promise<ClassifierResult>((resolve) => {
      registerEvaluationSession(sessionID, resolve);
    });

    const timeoutPromise = new Promise<ClassifierResult>((resolve) => {
      timeoutId = setTimeout(() => {
        try {
          client.session.abort?.({ path: { id: sessionID } })?.catch(() => {});
        } catch {}
        resolve({
          verdict: "UNSURE",
          reason: `Classifier evaluation timed out after ${Math.round(timeoutMs / 1000)} seconds`,
        });
      }, timeoutMs);
    });

    const modelRef = parseModelRef(input.model ?? input.config?.classifierModel);
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
        system: PASSIVE_EVALUATOR_DIRECTIVE,
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
          const repromptText =
            "You must record your decision by calling the classify_result tool with { risk_level, user_authorization, verdict, reason }.";
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
                system: PASSIVE_EVALUATOR_DIRECTIVE,
                parts: [
                  {
                    type: "text",
                    text: repromptText,
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
          reason: "Classifier failed to call classify_result tool after retries",
        });
      })
      .catch(() => {});

    verdictResult = await Promise.race([verdictPromise, timeoutPromise]);
    if (timeoutId) clearTimeout(timeoutId);

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

export class OpenCodeV1SessionEvaluator implements GateEvaluator {
  readonly name = "opencode1-session-evaluator";
  constructor(
    private client: OpenCodeV1SessionClient,
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
