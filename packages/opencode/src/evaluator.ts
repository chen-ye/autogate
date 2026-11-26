import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import * as crypto from "crypto";
import type {
  ClassifierResult,
  ClassifierVerdict,
  GateEvaluator,
  GateAction,
  AutoGateConfig,
  EvalSessionCleanupMode,
  S2SessionStatus,
} from "@autogate/core";
import {
  AutoGateEvalStore,
  EVAL_AGENT_ID,
  buildClassifierUserPrompt,
  extractAndStripSystemPrompt,
  extractS2SessionDetails,
  extractVerdictFromMessages,
  extractVerdictFromParts,
  isClassifierVerdict,
  isPostVerdictInterruptError,
  isRecord,
  parseModelRef,
  resolveClassifierActionArgs,
  resolveEvalDbFile,
  resolveEvalPromptBundle,
  resolveRequestActionArgs,
} from "@autogate/core";
export { parseModelRef, extractVerdictFromParts };
import { resolveServerPassword } from "./helpers.js";
import type {
  OpenCodeClassifyInput,
  OpenCodeSessionClient,
  S2SessionCapturedEvent,
} from "./types.js";
export type { OpenCodeClassifyInput, OpenCodeSessionClient, S2SessionCapturedEvent };

const S2_CAPTURE_TIMEOUT_MS = 1500;
const S2_CLEANUP_TIMEOUT_MS = 1500;

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

export interface OpenCodeSessionEvaluatorOptions extends ArchiveEvaluationSessionOptions {
  evalDbFile?: string;
  getEvalDbFile?: () => string | undefined;
  evalSessionCleanup?: EvalSessionCleanupMode;
  getEvalSessionCleanup?: () => EvalSessionCleanupMode;
  evalStore?: AutoGateEvalStore;
  getEvalStore?: () => AutoGateEvalStore | undefined;
  skipEvaluationRecord?: boolean;
  onS2SessionRecorded?: (event: S2SessionCapturedEvent) => void;
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
      const extracted = extractVerdictFromMessages(allMessages);
      if (extracted) {
        return extracted;
      }
    } catch {
      // Ignore context fetch failures during verdict extraction
    }
  }

  return null;
}

export function resetCachedEvaluationAgent(): void {
  cachedEvalAgent = undefined;
}

function nonEmptyString(val: unknown): string | undefined {
  if (typeof val !== "string") return undefined;
  const trimmed = val.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

async function settleWithTimeout<T>(
  invoke: () => Promise<T>,
  timeoutMs: number,
): Promise<{ ok: true; value: T } | { ok: false; reason: "timeout" | "error"; error?: unknown }> {
  let promise: Promise<T>;
  try {
    promise = Promise.resolve(invoke());
  } catch (error) {
    return { ok: false, reason: "error", error };
  }

  const guarded = promise.then(
    (value) => ({ ok: true as const, value }),
    (error: unknown) => ({ ok: false as const, reason: "error" as const, error }),
  );

  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      guarded,
      new Promise<{ ok: false; reason: "timeout" }>((resolve) => {
        timer = setTimeout(() => resolve({ ok: false, reason: "timeout" }), timeoutMs);
      }),
    ]);
  } finally {
    if (timer !== undefined) {
      clearTimeout(timer);
    }
  }
}

function resolveInputCommandString(input: OpenCodeClassifyInput, actionArgs: unknown): string {
  if (typeof input.commandString === "string") {
    return input.commandString;
  }
  const req = input.request;
  if (req && typeof req.commandString === "string" && req.commandString.trim().length > 0) {
    return req.commandString;
  }
  if (
    req?.metadata &&
    typeof req.metadata.command === "string" &&
    req.metadata.command.trim().length > 0
  ) {
    return req.metadata.command;
  }
  if (req?.metadata && typeof req.metadata.cmd === "string" && req.metadata.cmd.trim().length > 0) {
    return req.metadata.cmd;
  }
  if (typeof actionArgs === "string") {
    return actionArgs;
  }
  if (isRecord(actionArgs)) {
    if (typeof actionArgs.command === "string") return actionArgs.command;
    if (typeof actionArgs.cmd === "string") return actionArgs.cmd;
  }
  if (actionArgs !== undefined) {
    return JSON.stringify(actionArgs);
  }
  return "";
}

function resolveInputTargetPath(
  input: OpenCodeClassifyInput,
  actionArgs: unknown,
): string | undefined {
  if (typeof input.targetPath === "string" && input.targetPath.trim().length > 0) {
    return input.targetPath.trim();
  }
  const req = input.request;
  const reqTarget =
    nonEmptyString(req?.targetPath) ??
    nonEmptyString(req?.metadata?.filepath) ??
    nonEmptyString(req?.metadata?.path) ??
    nonEmptyString(req?.metadata?.file);
  if (reqTarget) return reqTarget;
  if (isRecord(actionArgs)) {
    return (
      nonEmptyString(actionArgs.path) ??
      nonEmptyString(actionArgs.filePath) ??
      nonEmptyString(actionArgs.filepath) ??
      nonEmptyString(actionArgs.file)
    );
  }
  return undefined;
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
    input.toolName ??
    input.actionName ??
    input.request?.action ??
    input.request?.permission ??
    input.request?.toolName ??
    "permission";
  const syntheticRequest =
    !input.request &&
    input.actionArgs === undefined &&
    (input.commandString !== undefined || input.targetPath !== undefined)
      ? {
          toolName: actionName,
          ...(input.commandString !== undefined ? { commandString: input.commandString } : {}),
          ...(input.targetPath !== undefined ? { targetPath: input.targetPath } : {}),
        }
      : input.request;
  const actionArgs = resolveRequestActionArgs(syntheticRequest, input.actionArgs);
  const workspaceRoot =
    input.workspaceRoot ??
    input.directory ??
    input.request?.directory ??
    input.request?.metadata?.directory ??
    process.cwd();
  const targetSessionId =
    nonEmptyString(input.targetSessionId) ?? nonEmptyString(input.request?.sessionID);
  const actionId = nonEmptyString(input.actionId) ?? nonEmptyString(input.request?.id);
  const resolvedCommandString = resolveInputCommandString(input, actionArgs);
  const resolvedTargetPath = resolveInputTargetPath(input, actionArgs);
  const configuredModel =
    nonEmptyString(input.model) ?? nonEmptyString(input.config?.classifierModel);
  const resolvedEvalDbFile =
    nonEmptyString(input.getEvalDbFile?.()) ??
    nonEmptyString(input.evalDbFile) ??
    nonEmptyString(input.config?.evalDbFile) ??
    nonEmptyString(input.config?.opencode?.evalDbFile) ??
    resolveEvalDbFile(undefined, "opencode");

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
  const capturedParts: unknown[] = [];
  let verdictResult: ClassifierResult | undefined;
  let finalResult: ClassifierResult | undefined;
  let aborted = Boolean(input.signal?.aborted);
  let timedOut = false;
  let settledBy:
    | "tool-or-extract"
    | "abort"
    | "timeout"
    | "retries-exhausted"
    | "error"
    | undefined;
  let promptError: string | undefined;
  let evalErrorMessage: string | undefined;
  let attempts = 0;
  let timeoutId: ReturnType<typeof setTimeout> | undefined;

  const settleInternal = (
    source: "tool-or-extract" | "abort" | "timeout" | "retries-exhausted" | "error",
    result: ClassifierResult,
  ): boolean => {
    if (!settledBy) {
      settledBy = source;
    }
    return recordEvaluationVerdict(sessionID, result);
  };

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
    settleInternal("abort", {
      verdict: "UNSURE",
      reason: "Classifier evaluation aborted by signal",
    });
  };

  const archiveOptions: ArchiveEvaluationSessionOptions = {
    serverUrl: input.serverUrl || input.config?.opencode?.serverUrl || undefined,
    configDir: input.configDir,
  };

  if (!aborted && input.signal) {
    input.signal.addEventListener("abort", onAbort, { once: true });
  }

  let promptLoopPromise: Promise<void> | undefined;

  try {
    if (aborted) {
      onAbort();
      verdictResult = {
        verdict: "UNSURE",
        reason: "Classifier evaluation aborted by signal",
      };
    } else {
      const timeoutMs = input.config?.classifierTimeout ?? 45000;
      const verdictPromise = new Promise<ClassifierResult>((resolve) => {
        registerEvaluationSession(sessionID, (res) => {
          if (!settledBy) {
            settledBy = "tool-or-extract";
          }
          resolve(res);
        });
      });

      const timeoutPromise = new Promise<ClassifierResult>((resolve) => {
        timeoutId = setTimeout(() => {
          if (!settledBy) {
            settledBy = "timeout";
            timedOut = true;
          }
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
          attempts = attempt + 1;
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
            .catch((err: unknown) => {
              promptError = err instanceof Error ? err.message : String(err);
              return null;
            });

          if (aborted || input.signal?.aborted) {
            return;
          }

          if (!promptRes) {
            if (attempt === 0) {
              settleInternal(promptError ? "error" : "retries-exhausted", {
                verdict: "UNSURE",
                reason: promptError
                  ? `Classifier prompt failed: ${promptError}`
                  : "Classifier prompt returned empty response",
              });
              return;
            }
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
          if (parts.length > 0) {
            capturedParts.push(...parts);
          }
          const verdict = await extractVerdictFromSession(client, sessionID, parts);
          if (aborted || input.signal?.aborted) return;
          if (verdict) {
            settleInternal(
              "tool-or-extract",
              capturedReasoning && input.config?.systemOne?.enabled
                ? { ...verdict, metadata: { reasoning: capturedReasoning } }
                : verdict,
            );
            return;
          }
        }

        if (aborted || input.signal?.aborted) return;
        settleInternal("retries-exhausted", {
          verdict: "UNSURE",
          reason: "Classifier failed to call classify_result tool after retries",
          ...(capturedReasoning && input.config?.systemOne?.enabled
            ? { metadata: { reasoning: capturedReasoning } }
            : {}),
        });
      })().catch((err: unknown) => {
        promptError = err instanceof Error ? err.message : String(err);
      });

      verdictResult = await Promise.race([verdictPromise, timeoutPromise]);
      if (timeoutId) {
        clearTimeout(timeoutId);
        timeoutId = undefined;
      }
    }
  } catch (err: unknown) {
    evalErrorMessage = err instanceof Error ? err.message : String(err);
    throw err;
  } finally {
    if (input.signal) {
      input.signal.removeEventListener("abort", onAbort);
    }
    if (timeoutId) {
      clearTimeout(timeoutId);
      timeoutId = undefined;
    }
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

    let sessionInfo: Record<string, unknown> | undefined;
    let contextMessages: unknown[] | undefined;

    try {
      const getFn =
        typeof client.session.get === "function"
          ? client.session.get.bind(client.session)
          : undefined;
      const contextFn =
        typeof client.session.context === "function"
          ? client.session.context.bind(client.session)
          : undefined;
      const [getOutcome, contextOutcome] = await Promise.all([
        getFn
          ? settleWithTimeout(() => getFn({ sessionID }), S2_CAPTURE_TIMEOUT_MS)
          : Promise.resolve({ ok: false as const, reason: "error" as const }),
        contextFn
          ? settleWithTimeout(() => contextFn({ sessionID }), S2_CAPTURE_TIMEOUT_MS)
          : Promise.resolve({ ok: false as const, reason: "error" as const }),
      ]);

      if (getOutcome.ok && isRecord(getOutcome.value)) {
        sessionInfo = isRecord(getOutcome.value.data) ? getOutcome.value.data : getOutcome.value;
      }
      if (contextOutcome.ok) {
        const rawCtx = contextOutcome.value;
        if (Array.isArray(rawCtx)) {
          contextMessages = rawCtx;
        } else if (isRecord(rawCtx) && Array.isArray(rawCtx.data)) {
          contextMessages = rawCtx.data;
        }
      }
    } catch {
      // Best-effort capture; fall back to in-memory state
    }

    const details = extractS2SessionDetails({
      sessionInfo,
      messages: contextMessages,
      capturedParts,
      capturedReasoning,
      configuredModel,
    });

    const rawCombinedError = evalErrorMessage ?? promptError ?? details.assistantError;
    const s2Status: S2SessionStatus =
      settledBy === "tool-or-extract"
        ? "completed"
        : aborted || Boolean(input.signal?.aborted)
          ? "aborted"
          : timedOut
            ? "timeout"
            : rawCombinedError || details.outcome === "failed"
              ? "error"
              : "partial";
    const combinedError =
      s2Status === "completed" && isPostVerdictInterruptError(rawCombinedError)
        ? undefined
        : rawCombinedError;

    const s2Title =
      details.title && details.title !== evalTitle
        ? details.title
        : `[auto-gate-eval] ${actionName} -> ${finalVerdict}`;
    const s2Agent = details.agent ?? evalAgent;
    const s2Directory = details.directory ?? sandboxDir;
    const nowTs = Date.now();
    const { systemPrompt, agentConfig, knownSystemPrompts } = resolveEvalPromptBundle(
      evalAgent,
      configuredModel,
    );
    const messageRecords = Array.isArray(contextMessages)
      ? contextMessages.filter((m): m is Record<string, unknown> => isRecord(m))
      : [];
    const { sanitizedMessages } =
      messageRecords.length > 0
        ? extractAndStripSystemPrompt(messageRecords, knownSystemPrompts)
        : { sanitizedMessages: [] as Record<string, unknown>[] };

    const payload = {
      info: sessionInfo ?? {
        id: sessionID,
        title: s2Title,
        agent: s2Agent,
        directory: s2Directory,
      },
      messages: sanitizedMessages,
      capturedUserPrompt: userPromptText,
      ...(userPrompt ? { codingUserPrompt: userPrompt } : {}),
      ...(subagentPrompt ? { subagentPrompt } : {}),
      ...(capturedParts.length > 0 ? { capturedParts } : {}),
      ...(details.thinking ? { thinking: details.thinking } : {}),
      ...(verdictResult ? { verdict: verdictResult } : {}),
      durationMs,
      status: s2Status,
      ...(combinedError ? { error: combinedError } : {}),
    };

    let s2ExportSucceeded = false;
    let ownedStore: AutoGateEvalStore | undefined;
    try {
      const providedStore = input.evalStore ?? input.getEvalStore?.();
      const store =
        providedStore && providedStore.isOpen()
          ? providedStore
          : (ownedStore = new AutoGateEvalStore(resolvedEvalDbFile));

      store.recordS2Session({
        s2SessionId: sessionID,
        targetSessionId: targetSessionId ?? null,
        title: s2Title,
        agent: s2Agent,
        directory: s2Directory,
        status: s2Status,
        systemPrompt,
        agentConfig,
        modelId: details.modelId ?? null,
        modelProvider: details.modelProvider ?? null,
        promptTokens: details.promptTokens ?? null,
        outputTokens: details.outputTokens ?? null,
        reasoningTokens: details.reasoningTokens ?? null,
        cacheReadTokens: details.cacheReadTokens ?? null,
        cacheWriteTokens: details.cacheWriteTokens ?? null,
        cost: details.cost ?? null,
        messageCount: messageRecords.length > 0 ? sanitizedMessages.length : details.messageCount,
        createdAt: details.createdAt ?? startTime,
        updatedAt: details.updatedAt ?? nowTs,
        archivedAt: details.archivedAt ?? nowTs,
        payload,
      });
      s2ExportSucceeded = true;

      if (!input.skipEvaluationRecord) {
        store.recordEvaluation({
          ...(actionId ? { id: actionId } : {}),
          sourceFormat: "opencode",
          timestamp: startTime,
          sessionId: targetSessionId ?? "",
          s2SessionId: sessionID,
          actionId: actionId ?? null,
          toolName: actionName,
          commandString: resolvedCommandString,
          targetPath: resolvedTargetPath ?? null,
          workspaceRoot,
          userPrompt,
          reasoning: verdictResult?.reason ?? combinedError ?? null,
          thinking: details.thinking ?? null,
          verdict: finalVerdict,
          riskLevel: verdictResult?.risk_level ?? null,
          userAuthorization: verdictResult?.user_authorization ?? null,
          durationMs,
          modelId: details.modelId ?? null,
          modelProvider: details.modelProvider ?? null,
          promptTokens: details.promptTokens ?? null,
          outputTokens: details.outputTokens ?? null,
          reasoningTokens: details.reasoningTokens ?? null,
          cost: details.cost ?? null,
          attempts: attempts > 0 ? attempts : null,
          error: combinedError ?? null,
          sourceOrigin: "live",
        });
      }
    } catch (err) {
      console.warn("[AutoGate] Failed to persist S2 evaluation to evals.db:", err);
    } finally {
      if (ownedStore) {
        try {
          ownedStore.close();
        } catch {}
      }
    }

    if (input.skipEvaluationRecord && input.onS2SessionRecorded) {
      try {
        input.onS2SessionRecorded({
          ...(actionId ? { actionId } : {}),
          ...(targetSessionId ? { targetSessionId } : {}),
          s2SessionId: sessionID,
          status: s2Status,
          timestamp: startTime,
          toolName: actionName,
          commandString: resolvedCommandString,
          ...(resolvedTargetPath ? { targetPath: resolvedTargetPath } : {}),
          workspaceRoot,
          userPrompt,
          verdict: finalVerdict,
          ...(verdictResult?.risk_level ? { riskLevel: verdictResult.risk_level } : {}),
          ...(verdictResult?.user_authorization
            ? { userAuthorization: verdictResult.user_authorization }
            : {}),
          ...(verdictResult?.reason || combinedError
            ? { reasoning: verdictResult?.reason ?? combinedError }
            : {}),
          ...(details.thinking ? { thinking: details.thinking } : {}),
          durationMs,
          ...(details.modelId ? { modelId: details.modelId } : {}),
          ...(details.modelProvider ? { modelProvider: details.modelProvider } : {}),
          ...(details.promptTokens !== undefined ? { promptTokens: details.promptTokens } : {}),
          ...(details.outputTokens !== undefined ? { outputTokens: details.outputTokens } : {}),
          ...(details.reasoningTokens !== undefined
            ? { reasoningTokens: details.reasoningTokens }
            : {}),
          ...(details.cost !== undefined ? { cost: details.cost } : {}),
          ...(attempts > 0 ? { attempts } : {}),
          ...(combinedError ? { error: combinedError } : {}),
        });
      } catch (err) {
        console.warn("[AutoGate] onS2SessionRecorded hook failed:", err);
      }
    }

    const cleanupMode: EvalSessionCleanupMode =
      input.getEvalSessionCleanup?.() ??
      input.evalSessionCleanup ??
      input.config?.evalSessionCleanup ??
      input.config?.opencode?.evalSessionCleanup ??
      "export-and-delete";

    try {
      let removedSession = false;
      const removeFn =
        typeof client.session.remove === "function"
          ? client.session.remove.bind(client.session)
          : undefined;
      if (cleanupMode === "export-and-delete" && s2ExportSucceeded && removeFn) {
        const removeOutcome = await settleWithTimeout(
          () => removeFn({ sessionID }),
          S2_CLEANUP_TIMEOUT_MS,
        );
        removedSession = removeOutcome.ok;
      }

      if (!removedSession) {
        await archiveEvaluationSession(client, sessionID, actionName, finalVerdict, archiveOptions);
      }
    } finally {
      archiveDone = true;
      maybeClearEvalSession();
    }

    const baseResult: ClassifierResult = verdictResult ?? {
      verdict: finalVerdict,
      reason: combinedError
        ? `Classifier evaluation error: ${combinedError}`
        : "Classifier evaluation did not produce a verdict",
    };

    const enrichedMetadata: Record<string, unknown> = {
      ...(baseResult.metadata ?? {}),
      s2SessionId: sessionID,
      ...(details.modelId !== undefined ? { modelId: details.modelId } : {}),
      ...(details.modelProvider !== undefined ? { modelProvider: details.modelProvider } : {}),
      ...(details.promptTokens !== undefined ? { promptTokens: details.promptTokens } : {}),
      ...(details.outputTokens !== undefined ? { outputTokens: details.outputTokens } : {}),
      ...(details.reasoningTokens !== undefined
        ? { reasoningTokens: details.reasoningTokens }
        : {}),
      ...(details.cost !== undefined ? { cost: details.cost } : {}),
      ...(details.thinking !== undefined ? { thinking: details.thinking } : {}),
      ...(attempts > 0 ? { attempts } : {}),
      ...(combinedError !== undefined ? { error: combinedError } : {}),
    };

    finalResult = {
      ...baseResult,
      metadata: enrichedMetadata,
    };
  }

  return finalResult!;
}

export class OpenCodeSessionEvaluator implements GateEvaluator {
  readonly name = "opencode-session-evaluator";
  private readonly pendingEvaluations = new Set<Promise<ClassifierResult>>();

  constructor(
    private client: OpenCodeSessionClient,
    private config?: AutoGateConfig,
    private archiveOptions?: OpenCodeSessionEvaluatorOptions,
  ) {}

  public async waitForPending(): Promise<void> {
    while (this.pendingEvaluations.size > 0) {
      await Promise.allSettled(Array.from(this.pendingEvaluations));
    }
  }

  async evaluate(action: GateAction): Promise<ClassifierResult> {
    const task = classifyRequest({
      client: this.client,
      userPrompt: action.userPrompt,
      subagentPrompt: action.subagentPrompt,
      actionName: action.toolName,
      toolName: action.toolName,
      commandString: action.commandString,
      targetPath: action.targetPath,
      targetSessionId: action.sessionID || undefined,
      actionId: action.id || undefined,
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
            evalDbFile: this.archiveOptions.evalDbFile,
            getEvalDbFile: this.archiveOptions.getEvalDbFile,
            evalSessionCleanup: this.archiveOptions.evalSessionCleanup,
            getEvalSessionCleanup: this.archiveOptions.getEvalSessionCleanup,
            evalStore: this.archiveOptions.evalStore,
            getEvalStore: this.archiveOptions.getEvalStore,
            skipEvaluationRecord: this.archiveOptions.skipEvaluationRecord,
            onS2SessionRecorded: this.archiveOptions.onS2SessionRecorded,
          }
        : {}),
    });

    this.pendingEvaluations.add(task);
    try {
      return await task;
    } finally {
      this.pendingEvaluations.delete(task);
    }
  }
}
