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
  CascadeTrace,
} from "@autogate/core";
import {
  EVAL_AGENT_ID,
  buildClassifierUserPrompt,
  parseVerdict,
  parseModelRef,
  isRiskLevel,
  isUserAuthorization,
  isClassifierVerdict,
  resolveClassifierActionArgs,
  resolveRequestActionArgs,
} from "@autogate/core";
export { parseModelRef };
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
  cascade?: CascadeTrace;
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

async function notifyOpenChamberArchive(sessionID: string): Promise<void> {
  const secretFile = path.join(os.homedir(), ".config", "openchamber", "jwt-secret");
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

    await fetch("http://localhost:14096/api/openchamber/sessions/archive", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Cookie: `oc_ui_session_14096=${token}`,
      },
      body: JSON.stringify({ ids: [sessionID], archivedAt: Date.now() }),
      signal: AbortSignal.timeout(2000),
    }).catch(() => null);
  } catch {}
}

export interface ArchiveEvaluationSessionOptions {
  serverUrl?: string;
  configDir?: string;
}

function resolveExplicitArchiveServerUrl(
  client: OpenCodeSessionClient | undefined,
  options?: ArchiveEvaluationSessionOptions,
): string | undefined {
  const raw = options?.serverUrl || client?.serverUrl || process.env.OPENCODE_SERVER_URL;
  return typeof raw === "string" && raw.trim().length > 0
    ? raw.trim().replace(/\/+$/, "")
    : undefined;
}

export async function archiveEvaluationSession(
  client: OpenCodeSessionClient | undefined,
  sessionID: string,
  actionName: string,
  verdict: string,
  options?: ArchiveEvaluationSessionOptions,
): Promise<void> {
  const title = `[auto-gate-eval] ${actionName} -> ${verdict}`;
  let updateAttempted = false;
  let updateSucceeded = false;

  if (client?.session && typeof client.session.update === "function") {
    updateAttempted = true;
    try {
      await client.session.update({
        sessionID,
        title,
        archived: true,
      });
      updateSucceeded = true;
    } catch {
      try {
        await client.session.update({
          sessionID,
          title,
        });
        updateSucceeded = true;
      } catch {
        // Ignore session.update failure and allow HTTP PATCH fallback below
      }
    }
  }

  const serverUrl = resolveExplicitArchiveServerUrl(client, options);
  if (serverUrl) {
    let needsHttpPatch = true;
    if (updateAttempted && updateSucceeded && typeof client?.session?.get === "function") {
      try {
        const info = await client.session.get({ sessionID });
        const archivedAt = info?.data?.time?.archived ?? info?.time?.archived;
        if (typeof archivedAt === "number") {
          needsHttpPatch = false;
        }
      } catch {
        // Proceed with HTTP PATCH fallback if session.get fails
      }
    }

    if (needsHttpPatch) {
      const password = resolveServerPassword(options?.configDir);
      const authHeader = password
        ? "Basic " + Buffer.from(`opencode:${password}`).toString("base64")
        : "";
      const url = `${serverUrl}/api/session/${encodeURIComponent(sessionID)}`;
      const headers: Record<string, string> = {
        "Content-Type": "application/json",
        ...(authHeader ? { Authorization: authHeader } : {}),
      };
      const patchBody = updateSucceeded ? { archived: true } : { title, archived: true };
      try {
        const res = await fetch(url, {
          method: "PATCH",
          headers,
          body: JSON.stringify(patchBody),
          signal: AbortSignal.timeout(5000),
        });
        if (res.status === 400 && !updateSucceeded) {
          await fetch(url, {
            method: "PATCH",
            headers,
            body: JSON.stringify({ title }),
            signal: AbortSignal.timeout(5000),
          }).catch(() => {});
        }
      } catch {
        // Best-effort archive PATCH; swallow transient network errors
      }
    }
  }

  await notifyOpenChamberArchive(sessionID);

  try {
    const ocArchive = path.join(os.homedir(), ".config", "openchamber", "sessions-archive.json");
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

let cachedEvalAgent: string | undefined;

export async function resolveEvaluationAgent(client?: OpenCodeSessionClient): Promise<string> {
  if (cachedEvalAgent) return cachedEvalAgent;
  try {
    const res = await client?.agent?.list?.();
    const agents = Array.isArray(res) ? res : (res?.data ?? []);
    if (
      Array.isArray(agents) &&
      agents.length > 0 &&
      !agents.some(
        (a) =>
          typeof a === "object" &&
          a !== null &&
          (("id" in a && a.id === EVAL_AGENT_ID) || ("name" in a && a.name === EVAL_AGENT_ID)),
      )
    ) {
      cachedEvalAgent = "build";
      return "build";
    }
  } catch {}
  cachedEvalAgent = EVAL_AGENT_ID;
  return EVAL_AGENT_ID;
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
        (p.type === "tool" && (p.tool === "classify_result" || p.name === "classify_result")) ||
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
  client: OpenCodeSessionClient | undefined,
  sessionID: string,
  currentParts: readonly unknown[] = [],
): Promise<ClassifierResult | null> {
  const currentResult = extractVerdictFromParts(currentParts);
  if (currentResult) {
    return currentResult;
  }

  if (typeof client?.session?.context === "function") {
    try {
      const res = await client.session.context({ sessionID });
      const allMessages: unknown[] = Array.isArray(res)
        ? res
        : (res as { data?: unknown[] })?.data || [];

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
  if (input.signal?.aborted) {
    return {
      verdict: "UNSURE",
      reason: "Classifier evaluation aborted by signal",
    };
  }
  const client = input.client;

  const sandboxDir = ensureSandboxDirectory();
  const userPrompt = input.userPrompt ?? "";
  const subagentPrompt = input.subagentPrompt;
  const actionName =
    input.actionName ?? input.request?.action ?? input.request?.permission ?? "permission";
  const actionArgs = resolveRequestActionArgs(input.request, input.actionArgs);
  const workspaceRoot = input.workspaceRoot ?? input.directory ?? process.cwd();

  const evalAgent = await resolveEvaluationAgent(client);
  if (input.signal?.aborted) {
    return {
      verdict: "UNSURE",
      reason: "Classifier evaluation aborted by signal",
    };
  }
  const evalTitle = `[auto-gate-eval] ${actionName}`;
  let sessionRes: { data?: { id?: string }; id?: string } | undefined;
  if (typeof client.session.create === "function") {
    try {
      sessionRes = await client.session.create({
        title: evalTitle,
        agent: evalAgent,
        location: { directory: sandboxDir },
      });
    } catch {}
  }

  if (!sessionRes?.data?.id && !sessionRes?.id) {
    if (input.signal?.aborted) {
      return {
        verdict: "UNSURE",
        reason: "Classifier evaluation aborted by signal",
      };
    }
    const cfg = input.config;
    const serverUrl =
      input.serverUrl ||
      cfg?.opencode?.serverUrl ||
      cfg?.serverUrl ||
      client.serverUrl ||
      process.env.OPENCODE_SERVER_URL ||
      "http://localhost:4096";
    const password = resolveServerPassword(input.configDir);
    const authHeader = password
      ? "Basic " + Buffer.from(`opencode:${password}`).toString("base64")
      : "";
    try {
      const res = await fetch(`${serverUrl}/api/session`, {
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
        }
      }
    } catch {}
  }

  const sessionID = sessionRes?.data?.id ?? sessionRes?.id;
  if (!sessionID) {
    throw new Error("Failed to create ephemeral classifier session: missing session ID");
  }
  evaluationSessions.add(sessionID);

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
  let aborted = Boolean(input.signal?.aborted);
  let timeoutId: ReturnType<typeof setTimeout> | undefined;

  const onAbort = () => {
    aborted = true;
    if (timeoutId) {
      clearTimeout(timeoutId);
      timeoutId = undefined;
    }
    try {
      client.session.interrupt?.({ sessionID, resume: false })?.catch(() => {});
    } catch {
      // Ignore interrupt transport failures during abort
    }
    recordEvaluationVerdict(sessionID, {
      verdict: "UNSURE",
      reason: "Classifier evaluation aborted by signal",
    });
  };

  const archiveOptions: ArchiveEvaluationSessionOptions = {
    serverUrl: input.serverUrl || input.config?.opencode?.serverUrl || undefined,
    configDir: input.configDir,
  };

  if (aborted) {
    onAbort();
    evaluationResolvers.delete(sessionID);
    try {
      await archiveEvaluationSession(client, sessionID, actionName, "UNSURE", archiveOptions);
    } finally {
      clearEvaluationSession(sessionID);
    }
    return {
      verdict: "UNSURE",
      reason: "Classifier evaluation aborted by signal",
    };
  }

  if (input.signal) {
    input.signal.addEventListener("abort", onAbort, { once: true });
  }

  let promptLoopPromise: Promise<void> | undefined;

  try {
    const timeoutMs = input.config?.classifierTimeout ?? 45000;
    const verdictPromise = new Promise<ClassifierResult>((resolve) => {
      registerEvaluationSession(sessionID, resolve);
    });

    const timeoutPromise = new Promise<ClassifierResult>((resolve) => {
      timeoutId = setTimeout(() => {
        try {
          client.session.interrupt?.({ sessionID, resume: false })?.catch(() => {});
        } catch {}
        resolve({
          verdict: "UNSURE",
          reason: `Classifier evaluation timed out after ${Math.round(timeoutMs / 1000)} seconds`,
        });
      }, timeoutMs);
    });

    const maxRetries = 2;
    const repromptText =
      "You must record your decision by calling the classify_result tool with { risk_level, user_authorization, verdict, reason }.";

    promptLoopPromise = (async () => {
      for (let attempt = 0; attempt <= maxRetries; attempt++) {
        if (aborted || input.signal?.aborted) return;
        const promptText = attempt === 0 ? userPromptText : repromptText;
        const promptRes = await client.session
          .prompt({
            sessionID,
            text: promptText,
          })
          .then(async (res) => {
            if (aborted || input.signal?.aborted) return res;
            if (typeof client.session.wait === "function") {
              await client.session.wait({ sessionID }).catch(() => {});
            }
            return res;
          })
          .catch(() => null);

        if (!promptRes || aborted || input.signal?.aborted) {
          if (attempt === 0 && !promptRes) return;
          continue;
        }

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
        if (aborted || input.signal?.aborted) return;
        if (verdict) {
          recordEvaluationVerdict(
            sessionID,
            capturedReasoning && input.config?.systemOne?.enabled
              ? { ...verdict, metadata: { reasoning: capturedReasoning } }
              : verdict,
          );
          return;
        }
      }

      if (aborted || input.signal?.aborted) return;
      recordEvaluationVerdict(sessionID, {
        verdict: "UNSURE",
        reason: "Classifier failed to call classify_result tool after retries",
        ...(capturedReasoning && input.config?.systemOne?.enabled
          ? { metadata: { reasoning: capturedReasoning } }
          : {}),
      });
    })().catch(() => {});

    verdictResult = await Promise.race([verdictPromise, timeoutPromise]);
    if (timeoutId) clearTimeout(timeoutId);

    return verdictResult;
  } finally {
    if (input.signal) {
      input.signal.removeEventListener("abort", onAbort);
    }
    if (timeoutId) clearTimeout(timeoutId);
    evaluationResolvers.delete(sessionID);
    let archiveDone = false;
    let loopDone = !promptLoopPromise;
    const maybeClearEvalSession = () => {
      if (archiveDone && loopDone) {
        evaluationSessions.delete(sessionID);
      }
    };
    if (promptLoopPromise) {
      void promptLoopPromise.finally(() => {
        loopDone = true;
        maybeClearEvalSession();
      });
    }
    const durationMs = Date.now() - startTime;
    const rawVerdict = verdictResult?.verdict;
    const finalVerdict: ClassifierVerdict =
      rawVerdict && isClassifierVerdict(rawVerdict) ? rawVerdict : "UNSURE";
    try {
      await archiveEvaluationSession(client, sessionID, actionName, finalVerdict, archiveOptions);
    } finally {
      archiveDone = true;
      maybeClearEvalSession();
    }
    if (!aborted && !input.signal?.aborted && !input.config?.systemOne?.enabled) {
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
}

export class OpenCodeSessionEvaluator implements GateEvaluator {
  readonly name = "opencode-session-evaluator";
  constructor(
    private client: OpenCodeSessionClient,
    private config?: AutoGateConfig,
    private archiveOptions?: ArchiveEvaluationSessionOptions,
  ) {}
  async evaluate(action: GateAction): Promise<ClassifierResult> {
    return classifyRequest({
      client: this.client,
      userPrompt: action.userPrompt,
      subagentPrompt: action.subagentPrompt,
      actionName: action.toolName,
      actionArgs: resolveClassifierActionArgs(action),
      workspaceRoot: action.workspaceRoot,
      environment: action.environment,
      model: this.config?.classifierModel,
      config: this.config,
      signal: action.signal,
      ...(this.archiveOptions
        ? {
            serverUrl: this.archiveOptions.serverUrl,
            configDir: this.archiveOptions.configDir,
          }
        : {}),
    });
  }
}
