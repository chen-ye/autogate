import { isClassifierVerdict, parseVerdict } from "../classifier.js";
import { isRecord } from "../config.js";
import type { S2SessionStatus } from "../eval-store.js";
import {
  extractAssistantErrorInfo,
  extractClassifyResultFromPart,
  extractModelFromModelValue,
  extractModelFromRecord,
  extractThinkingSegments,
  getMessageParts,
  getMessageRole,
  isPostVerdictInterruptError,
  parseTimestampMs,
  readTokenTotals,
} from "../s2-transcript.js";
import type { ClassifierVerdict, RiskLevel, UserAuthorization } from "../types.js";
import { AUTOGATE_EVAL_TITLE_PREFIX } from "./types.js";
import {
  extractTargetSessionIdFromRow,
  finiteNumber,
  nonEmptyString,
  parseJsonObjectSafe,
} from "./utils.js";

export interface RawOpenCodeSessionCandidate {
  sourceTable: "session_v2" | "session";
  id: string;
  projectId: string | null;
  workspaceId: string | null;
  parentId: string | null;
  slug: string | null;
  directory: string | null;
  path: string | null;
  title: string;
  version: string | null;
  metadataRaw: unknown;
  cost: number;
  tokensInput: number;
  tokensOutput: number;
  tokensReasoning: number;
  tokensCacheRead: number;
  tokensCacheWrite: number;
  agent: string | null;
  modelRaw: unknown;
  timeCreated: number | null;
  timeUpdated: number | null;
  timeArchived: number | null;
  timeSuspended: number | null;
  timeCompacting: number | null;
  timeIdle: number | null;
  idleOutcome: string | null;
  messages: Record<string, unknown>[];
}

export interface ExtractedOpenCodeSessionDetails {
  targetSessionId: string | null;
  toolName: string;
  commandString: string;
  targetPath: string | null;
  workspaceRoot: string | null;
  userPrompt: string;
  verdict: ClassifierVerdict;
  riskLevel: RiskLevel | null;
  userAuthorization: UserAuthorization | null;
  reasoning: string | null;
  thinking: string | null;
  error: string | null;
  status: S2SessionStatus;
  modelId: string | null;
  modelProvider: string | null;
  promptTokens: number | null;
  outputTokens: number | null;
  reasoningTokens: number | null;
  cacheReadTokens: number | null;
  cacheWriteTokens: number | null;
  cost: number | null;
  durationMs: number;
  createdAt: number | null;
  updatedAt: number | null;
  archivedAt: number | null;
  info: Record<string, unknown>;
}

function extractUserMessageText(msg: Record<string, unknown>): string {
  if (typeof msg.text === "string" && msg.text.trim().length > 0) {
    return msg.text;
  }
  if (typeof msg.content === "string" && msg.content.trim().length > 0) {
    return msg.content;
  }
  const parts = getMessageParts(msg);
  const textParts: string[] = [];
  for (const part of parts) {
    if (typeof part === "string" && part.trim().length > 0) {
      textParts.push(part);
    } else if (isRecord(part)) {
      if (part.type === "text" && part.ignored !== true && part.synthetic !== true) {
        if (typeof part.text === "string" && part.text.length > 0) {
          textParts.push(part.text);
        }
      } else if (part.type === undefined && typeof part.text === "string") {
        textParts.push(part.text);
      }
    }
  }
  if (textParts.length > 0) {
    return textParts.join("\n\n");
  }
  // Fallback if all text parts were marked synthetic
  for (const part of parts) {
    if (isRecord(part) && part.type === "text" && typeof part.text === "string") {
      textParts.push(part.text);
    }
  }
  return textParts.join("\n\n");
}

function extractFencedBlock(section: string, labelPattern: RegExp): string | undefined {
  const match = section.match(labelPattern);
  if (!match || typeof match[2] !== "string") return undefined;
  return match[2];
}

function parseClassifierUserPromptFields(rawText: string): {
  userPrompt: string;
  toolName?: string;
  commandString: string;
  targetPath?: string;
  workspaceRoot?: string;
} {
  const text = rawText.trim();
  if (!text) {
    return { userPrompt: "", commandString: "" };
  }

  const isStructuredClassifierPrompt =
    text.includes("## Environment Trust Boundaries:") ||
    text.includes("### Proposed Action:") ||
    text.includes("## Context:");

  if (!isStructuredClassifierPrompt) {
    return { userPrompt: text, commandString: "" };
  }

  const wsMatch = text.match(/^-\s*\*\*Workspace Root\*\*:\s*([^\r\n]+)/im);
  const workspaceRoot = wsMatch?.[1]?.trim() || undefined;

  let userPrompt = "";
  const humanIntentMatch = text.match(/<human_user_intent[^>]*>([\s\S]*?)<\/human_user_intent>/i);
  if (humanIntentMatch && typeof humanIntentMatch[1] === "string") {
    const inner = humanIntentMatch[1].trim();
    userPrompt = inner === "*(No conversation transcript available)*" ? "" : inner;
  } else {
    const transcriptMatch = text.match(
      /###\s*Conversation Transcript(?:\s*\(User's Recent Intent\))?:\s*\r?\n([\s\S]*?)(?:\r?\n###\s*Proposed Action:|\r?\n-\s*\*\*Proposed Action|$)/i,
    );
    if (transcriptMatch && typeof transcriptMatch[1] === "string") {
      const inner = transcriptMatch[1].trim();
      userPrompt = inner === "*(No conversation transcript available)*" ? "" : inner;
    }
  }

  const proposedIdx = text.search(/###\s*Proposed Action:/i);
  const actionSection = proposedIdx >= 0 ? text.slice(proposedIdx) : text;

  const toolMatch = actionSection.match(/-\s*\*\*Tool\s*\/\s*Permission\*\*:\s*([^\r\n]+)/i);
  const toolName = toolMatch?.[1]?.trim() || undefined;

  const cmdFromFence = extractFencedBlock(
    actionSection,
    /-\s*\*\*Command\*\*:\s*\r?\n(`{3,})[^\r\n]*\r?\n([\s\S]*?)\r?\n\1/i,
  );
  const evalFromFence = extractFencedBlock(
    actionSection,
    /-\s*\*\*Eval Code\s*\([^)]*\)\*\*:\s*\r?\n(`{3,})[^\r\n]*\r?\n([\s\S]*?)\r?\n\1/i,
  );
  const argsFromFence = extractFencedBlock(
    actionSection,
    /-\s*\*\*Action Arguments\*\*:\s*\r?\n(`{3,})[^\r\n]*\r?\n([\s\S]*?)\r?\n\1/i,
  );

  const targetPathMatch = actionSection.match(
    /-\s*\*\*(?:Target Path \/ Patterns|Requested External Directory)\*\*:\s*`([^`]+)`/i,
  );
  const targetPath = targetPathMatch?.[1]?.trim() || undefined;

  const commandString = cmdFromFence ?? evalFromFence ?? argsFromFence ?? targetPath ?? "";

  return {
    userPrompt,
    ...(toolName ? { toolName } : {}),
    commandString,
    ...(targetPath ? { targetPath } : {}),
    ...(workspaceRoot ? { workspaceRoot } : {}),
  };
}

function parseTitleMetadata(title: string): {
  toolName?: string;
  verdict?: ClassifierVerdict;
} {
  if (!title.startsWith(AUTOGATE_EVAL_TITLE_PREFIX)) {
    return {};
  }
  const rest = title.slice(AUTOGATE_EVAL_TITLE_PREFIX.length).trim();
  if (!rest) return {};

  const arrowMatch = rest.match(/^(.*?)\s*->\s*(ALLOW|BLOCK|UNSURE)\s*$/i);
  if (arrowMatch) {
    const rawTool = arrowMatch[1]?.trim();
    const rawVerdict = arrowMatch[2]?.trim().toUpperCase();
    return {
      ...(rawTool ? { toolName: rawTool } : {}),
      ...(rawVerdict && isClassifierVerdict(rawVerdict) ? { verdict: rawVerdict } : {}),
    };
  }

  return { toolName: rest };
}

export function extractOpenCodeSessionDetails(
  cand: RawOpenCodeSessionCandidate,
  sanitizedMessages: Record<string, unknown>[],
): ExtractedOpenCodeSessionDetails {
  const parsedMetadata = parseJsonObjectSafe(cand.metadataRaw);
  const parsedSessionModel = extractModelFromModelValue(cand.modelRaw) ?? {};
  const titleMeta = parseTitleMetadata(cand.title);
  const targetSessionId = extractTargetSessionIdFromRow(cand.parentId, parsedMetadata, cand.id);

  let promptFields: ReturnType<typeof parseClassifierUserPromptFields> | undefined;
  let firstUserCreatedAt: number | undefined;
  let lastAssistantCompletedAt: number | undefined;

  let msgModelId: string | undefined;
  let msgModelProvider: string | undefined;
  let msgHasTokens = false;
  let msgPromptTokens = 0;
  let msgOutputTokens = 0;
  let msgReasoningTokens = 0;
  let msgCacheReadTokens = 0;
  let msgCacheWriteTokens = 0;
  let msgHasCost = false;
  let msgCost = 0;

  let toolVerdict: ClassifierVerdict | undefined;
  let toolRiskLevel: RiskLevel | undefined;
  let toolUserAuth: UserAuthorization | undefined;
  let toolReasoning: string | undefined;
  let textVerdict: ClassifierVerdict | undefined;
  let textRiskLevel: RiskLevel | undefined;
  let textUserAuth: UserAuthorization | undefined;
  let textReasoning: string | undefined;

  const thinkingSegments: string[] = [];
  let assistantError: string | undefined;
  let isAborted = false;
  let isTimeout = false;

  for (const msg of sanitizedMessages) {
    const role = getMessageRole(msg);
    const msgTime = isRecord(msg.time) ? msg.time : undefined;

    if (role === "user") {
      if (firstUserCreatedAt === undefined) {
        firstUserCreatedAt = parseTimestampMs(msgTime?.created);
      }
      const userText = extractUserMessageText(msg);
      if (
        userText.trim() &&
        !userText.startsWith("You must record your decision by calling the classify_result tool")
      ) {
        if (!promptFields) {
          promptFields = parseClassifierUserPromptFields(userText);
        }
      }
      if (!msgModelId || !msgModelProvider) {
        const uModel = extractModelFromModelValue(msg.model);
        msgModelId = msgModelId ?? uModel?.modelId;
        msgModelProvider = msgModelProvider ?? uModel?.modelProvider;
      }
      continue;
    }

    if (role === "idle") {
      const outcome = nonEmptyString(msg.outcome);
      if (outcome === "interrupted") isAborted = true;
      const errInfo = extractAssistantErrorInfo(msg.error);
      if (errInfo.message) assistantError = errInfo.message;
      if (errInfo.isAborted) isAborted = true;
      if (errInfo.isTimeout) isTimeout = true;
      continue;
    }

    if (role !== "assistant") continue;

    const completedTs = parseTimestampMs(msgTime?.completed);
    if (completedTs !== undefined) {
      lastAssistantCompletedAt = completedTs;
    }

    const mModel = extractModelFromRecord(msg);
    if (mModel?.modelId) msgModelId = mModel.modelId;
    if (mModel?.modelProvider) msgModelProvider = mModel.modelProvider;

    const tokens = readTokenTotals(msg.tokens);
    if (tokens) {
      msgHasTokens = true;
      msgPromptTokens += tokens.promptTokens ?? 0;
      msgOutputTokens += tokens.outputTokens ?? 0;
      msgReasoningTokens += tokens.reasoningTokens ?? 0;
      msgCacheReadTokens += tokens.cacheReadTokens ?? 0;
      msgCacheWriteTokens += tokens.cacheWriteTokens ?? 0;
    }

    const mCost = finiteNumber(msg.cost);
    if (mCost !== undefined) {
      msgHasCost = true;
      msgCost += mCost;
    }

    const errInfo = extractAssistantErrorInfo(msg.error);
    if (errInfo.message) assistantError = errInfo.message;
    if (errInfo.isAborted) isAborted = true;
    if (errInfo.isTimeout) isTimeout = true;

    const parts = getMessageParts(msg);
    thinkingSegments.push(...extractThinkingSegments(parts));
    const assistantTextSegments: string[] = [];

    for (const part of parts) {
      if (!isRecord(part)) continue;
      if (part.type === "text" && typeof part.text === "string" && part.text.trim()) {
        assistantTextSegments.push(part.text);
      }

      const classifyRes = extractClassifyResultFromPart(part);
      if (classifyRes) {
        toolVerdict = classifyRes.verdict;
        toolRiskLevel = classifyRes.risk_level ?? toolRiskLevel;
        toolUserAuth = classifyRes.user_authorization ?? toolUserAuth;
        toolReasoning = classifyRes.reason || toolReasoning;
      }
    }

    if (assistantTextSegments.length > 0) {
      const parsedText = parseVerdict(assistantTextSegments.join("\n"));
      if (
        parsedText.reason !== "Classifier response did not contain a valid structured verdict" &&
        parsedText.reason !== "Empty or invalid classifier output"
      ) {
        textVerdict = parsedText.verdict;
        textRiskLevel = parsedText.risk_level ?? textRiskLevel;
        textUserAuth = parsedText.user_authorization ?? textUserAuth;
        textReasoning = parsedText.reason || textReasoning;
      }
    }
  }

  const rowHasTokens =
    cand.tokensInput > 0 ||
    cand.tokensOutput > 0 ||
    cand.tokensReasoning > 0 ||
    cand.tokensCacheRead > 0 ||
    cand.tokensCacheWrite > 0;

  const promptTokens = rowHasTokens ? cand.tokensInput : msgHasTokens ? msgPromptTokens : null;
  const outputTokens = rowHasTokens ? cand.tokensOutput : msgHasTokens ? msgOutputTokens : null;
  const reasoningTokens = rowHasTokens
    ? cand.tokensReasoning
    : msgHasTokens
      ? msgReasoningTokens
      : null;
  const cacheReadTokens = rowHasTokens
    ? cand.tokensCacheRead
    : msgHasTokens
      ? msgCacheReadTokens
      : null;
  const cacheWriteTokens = rowHasTokens
    ? cand.tokensCacheWrite
    : msgHasTokens
      ? msgCacheWriteTokens
      : null;

  const cost = cand.cost > 0 ? cand.cost : msgHasCost ? msgCost : null;

  const modelId = msgModelId ?? parsedSessionModel.modelId ?? null;
  const modelProvider = msgModelProvider ?? parsedSessionModel.modelProvider ?? null;

  const verdict: ClassifierVerdict = toolVerdict ?? titleMeta.verdict ?? textVerdict ?? "UNSURE";
  const riskLevel = toolRiskLevel ?? textRiskLevel ?? null;
  const userAuthorization = toolUserAuth ?? textUserAuth ?? null;
  const thinking = thinkingSegments.length > 0 ? thinkingSegments.join("\n") : null;

  if (cand.idleOutcome === "interrupted") {
    isAborted = true;
  }

  let status: S2SessionStatus;
  if (toolVerdict || textVerdict || (titleMeta.verdict && !assistantError && !isAborted)) {
    status = "completed";
  } else if (isAborted) {
    status = "aborted";
  } else if (isTimeout) {
    status = "timeout";
  } else if (assistantError || cand.idleOutcome === "failed") {
    status = "error";
  } else {
    status = "partial";
  }

  const isPostVerdictInterrupt =
    status === "completed" && isPostVerdictInterruptError(assistantError);
  const effectiveError = isPostVerdictInterrupt ? null : (assistantError ?? null);
  const effectiveReasoning = toolReasoning ?? textReasoning ?? effectiveError ?? null;

  const createdAt = cand.timeCreated ?? firstUserCreatedAt ?? null;
  const updatedAt = cand.timeUpdated ?? lastAssistantCompletedAt ?? null;
  const archivedAt = cand.timeArchived ?? null;

  let durationMs = 0;
  if (
    firstUserCreatedAt !== undefined &&
    lastAssistantCompletedAt !== undefined &&
    lastAssistantCompletedAt >= firstUserCreatedAt
  ) {
    durationMs = lastAssistantCompletedAt - firstUserCreatedAt;
  } else if (createdAt !== null && updatedAt !== null && updatedAt >= createdAt) {
    durationMs = updatedAt - createdAt;
  }

  const toolName = titleMeta.toolName ?? promptFields?.toolName ?? "permission";

  const info: Record<string, unknown> = {
    id: cand.id,
    ...(cand.projectId ? { projectID: cand.projectId } : {}),
    ...(cand.workspaceId ? { workspaceID: cand.workspaceId } : {}),
    ...(cand.parentId ? { parentID: cand.parentId } : {}),
    ...(cand.slug ? { slug: cand.slug } : {}),
    ...(cand.directory ? { directory: cand.directory } : {}),
    ...(cand.path ? { path: cand.path } : {}),
    title: cand.title,
    ...(cand.version ? { version: cand.version } : {}),
    ...(cand.agent ? { agent: cand.agent } : {}),
    ...(parsedSessionModel.modelId || parsedSessionModel.modelProvider
      ? {
          model: {
            ...(parsedSessionModel.modelId ? { id: parsedSessionModel.modelId } : {}),
            ...(parsedSessionModel.modelProvider
              ? { providerID: parsedSessionModel.modelProvider }
              : {}),
          },
        }
      : {}),
    ...(parsedMetadata ? { metadata: parsedMetadata } : {}),
    cost: cost ?? 0,
    tokens: {
      input: promptTokens ?? 0,
      output: outputTokens ?? 0,
      reasoning: reasoningTokens ?? 0,
      cache: {
        read: cacheReadTokens ?? 0,
        write: cacheWriteTokens ?? 0,
      },
    },
    time: {
      ...(createdAt !== null ? { created: createdAt } : {}),
      ...(updatedAt !== null ? { updated: updatedAt } : {}),
      ...(cand.timeCompacting !== null ? { compacting: cand.timeCompacting } : {}),
      ...(archivedAt !== null ? { archived: archivedAt } : {}),
      ...(cand.timeIdle !== null ? { idle: cand.timeIdle } : {}),
    },
    ...(cand.idleOutcome ? { outcome: cand.idleOutcome } : {}),
  };

  return {
    targetSessionId,
    toolName,
    commandString: promptFields?.commandString ?? "",
    targetPath: promptFields?.targetPath ?? null,
    workspaceRoot: promptFields?.workspaceRoot ?? cand.directory ?? null,
    userPrompt: promptFields?.userPrompt ?? "",
    verdict,
    riskLevel,
    userAuthorization,
    reasoning: effectiveReasoning,
    thinking,
    error: effectiveError,
    status,
    modelId,
    modelProvider,
    promptTokens,
    outputTokens,
    reasoningTokens,
    cacheReadTokens,
    cacheWriteTokens,
    cost,
    durationMs,
    createdAt,
    updatedAt,
    archivedAt,
    info,
  };
}
