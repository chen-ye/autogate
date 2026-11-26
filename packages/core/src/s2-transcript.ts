import { loadEvalAgentDefinition, parseModelRef } from "./agent.js";
import {
  PASSIVE_EVALUATOR_DIRECTIVE,
  isClassifierVerdict,
  isRiskLevel,
  isUserAuthorization,
  parseVerdict,
} from "./classifier.js";
import { isRecord } from "./config.js";
import type { ClassifierResult } from "./types.js";

export const AUTOGATE_PROMPT_MARKER = "You are an autonomous security and permission classifier";

export interface ExtractedTokenTotals {
  promptTokens?: number;
  outputTokens?: number;
  reasoningTokens?: number;
  cacheReadTokens?: number;
  cacheWriteTokens?: number;
}

export interface KnownEvalSystemPrompts {
  fullSystem?: string;
  bodyWithoutDirective?: string;
}

export interface AssistantErrorInfo {
  message?: string;
  isAborted: boolean;
  isTimeout: boolean;
}

export interface ExtractedS2SessionDetails {
  modelId?: string;
  modelProvider?: string;
  promptTokens?: number;
  outputTokens?: number;
  reasoningTokens?: number;
  cacheReadTokens?: number;
  cacheWriteTokens?: number;
  cost?: number;
  thinking?: string;
  messageCount: number;
  title?: string;
  agent?: string;
  directory?: string;
  createdAt?: number;
  updatedAt?: number;
  archivedAt?: number;
  outcome?: string;
  assistantError?: string;
}

function nonEmptyString(val: unknown): string | undefined {
  if (typeof val !== "string") return undefined;
  const trimmed = val.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function finiteNumber(val: unknown): number | undefined {
  return typeof val === "number" && Number.isFinite(val) ? val : undefined;
}

function finiteInt(val: unknown): number | undefined {
  const n = finiteNumber(val);
  return n !== undefined ? Math.trunc(n) : undefined;
}

export function parseTimestampMs(val: unknown): number | undefined {
  if (typeof val === "number" && Number.isFinite(val)) {
    return Math.trunc(val);
  }
  if (typeof val === "bigint") {
    const n = Number(val);
    return Number.isFinite(n) ? Math.trunc(n) : undefined;
  }
  if (typeof val === "string") {
    const trimmed = val.trim();
    if (!trimmed) return undefined;
    if (/^-?\d+$/.test(trimmed)) {
      const n = Number(trimmed);
      if (Number.isFinite(n)) return Math.trunc(n);
    }
    const parsed = Date.parse(trimmed);
    if (Number.isFinite(parsed)) {
      return Math.trunc(parsed);
    }
  }
  return undefined;
}

export function readTokenTotals(raw: unknown): ExtractedTokenTotals | undefined {
  if (!isRecord(raw)) return undefined;
  const cacheObj = isRecord(raw.cache) ? raw.cache : undefined;
  const completionDetails = isRecord(raw.completionTokensDetails)
    ? raw.completionTokensDetails
    : undefined;

  const promptTokens =
    finiteInt(raw.input) ??
    finiteInt(raw.promptTokens) ??
    finiteInt(raw.input_tokens) ??
    finiteInt(raw.prompt_tokens);
  const outputTokens =
    finiteInt(raw.output) ??
    finiteInt(raw.outputTokens) ??
    finiteInt(raw.completion_tokens) ??
    finiteInt(raw.output_tokens);
  const reasoningTokens =
    finiteInt(raw.reasoning) ??
    finiteInt(raw.reasoningTokens) ??
    finiteInt(raw.reasoning_tokens) ??
    finiteInt(completionDetails?.reasoningTokens);
  const cacheReadTokens =
    finiteInt(cacheObj?.read) ?? finiteInt(raw.cacheReadTokens) ?? finiteInt(raw.cache_read_tokens);
  const cacheWriteTokens =
    finiteInt(cacheObj?.write) ??
    finiteInt(raw.cacheWriteTokens) ??
    finiteInt(raw.cache_write_tokens);

  if (
    promptTokens === undefined &&
    outputTokens === undefined &&
    reasoningTokens === undefined &&
    cacheReadTokens === undefined &&
    cacheWriteTokens === undefined
  ) {
    return undefined;
  }

  return {
    ...(promptTokens !== undefined ? { promptTokens } : {}),
    ...(outputTokens !== undefined ? { outputTokens } : {}),
    ...(reasoningTokens !== undefined ? { reasoningTokens } : {}),
    ...(cacheReadTokens !== undefined ? { cacheReadTokens } : {}),
    ...(cacheWriteTokens !== undefined ? { cacheWriteTokens } : {}),
  };
}

export function hasPositiveTokenCount(tokens: ExtractedTokenTotals | undefined): boolean {
  if (!tokens) return false;
  return (
    (tokens.promptTokens ?? 0) > 0 ||
    (tokens.outputTokens ?? 0) > 0 ||
    (tokens.reasoningTokens ?? 0) > 0 ||
    (tokens.cacheReadTokens ?? 0) > 0 ||
    (tokens.cacheWriteTokens ?? 0) > 0
  );
}

export function extractThinkingSegments(parts: readonly unknown[]): string[] {
  const segments: string[] = [];
  for (const item of parts) {
    if (!isRecord(item)) continue;
    const partType = typeof item.type === "string" ? item.type : "";
    if (partType === "reasoning" || partType === "thinking" || partType === "reasoning_text") {
      const text =
        nonEmptyString(item.text) ??
        nonEmptyString(item.thinking) ??
        nonEmptyString(item.reasoning) ??
        nonEmptyString(item.reasoning_content);
      if (text) {
        segments.push(text);
      }
    }
  }
  return segments;
}

export function extractModelFromModelValue(
  rawModel: unknown,
  fallbackProvider?: string,
): { modelId?: string; modelProvider?: string } | undefined {
  const cleanFallbackProvider = nonEmptyString(fallbackProvider);
  if (typeof rawModel === "string") {
    const trimmed = rawModel.trim();
    if (!trimmed) {
      return cleanFallbackProvider ? { modelProvider: cleanFallbackProvider } : undefined;
    }
    if (trimmed.startsWith("{")) {
      try {
        return extractModelFromModelValue(JSON.parse(trimmed), cleanFallbackProvider);
      } catch {
        // Fall through to parseModelRef
      }
    }
    const parsed = parseModelRef(trimmed);
    const hasExplicitProvider = trimmed.includes("/");
    return {
      modelId: parsed.modelID,
      modelProvider: hasExplicitProvider
        ? parsed.providerID
        : (cleanFallbackProvider ?? parsed.providerID),
    };
  }
  if (isRecord(rawModel)) {
    const modelId =
      nonEmptyString(rawModel.id) ??
      nonEmptyString(rawModel.modelID) ??
      nonEmptyString(rawModel.modelId);
    const modelProvider =
      nonEmptyString(rawModel.providerID) ??
      nonEmptyString(rawModel.providerId) ??
      nonEmptyString(rawModel.provider) ??
      cleanFallbackProvider;
    if (modelId || modelProvider) {
      return {
        ...(modelId ? { modelId } : {}),
        ...(modelProvider ? { modelProvider } : {}),
      };
    }
    return undefined;
  }
  return cleanFallbackProvider ? { modelProvider: cleanFallbackProvider } : undefined;
}

export function extractModelFromRecord(
  raw: unknown,
  fallbackProvider?: string,
): { modelId?: string; modelProvider?: string } | undefined {
  const cleanFallbackProvider = nonEmptyString(fallbackProvider);
  if (!isRecord(raw)) {
    return extractModelFromModelValue(raw, cleanFallbackProvider);
  }

  const directProvider =
    nonEmptyString(raw.providerID) ??
    nonEmptyString(raw.providerId) ??
    nonEmptyString(raw.provider) ??
    cleanFallbackProvider;

  const fromModel =
    raw.model !== undefined && raw.model !== null
      ? extractModelFromModelValue(raw.model, directProvider)
      : undefined;

  const infoObj = isRecord(raw.info) ? raw.info : undefined;
  const fromInfo = infoObj ? extractModelFromRecord(infoObj, directProvider) : undefined;

  const modelId =
    fromModel?.modelId ??
    nonEmptyString(raw.modelID) ??
    nonEmptyString(raw.modelId) ??
    fromInfo?.modelId;
  const modelProvider =
    fromModel?.modelProvider ??
    nonEmptyString(raw.providerID) ??
    nonEmptyString(raw.providerId) ??
    nonEmptyString(raw.provider) ??
    fromInfo?.modelProvider ??
    cleanFallbackProvider;

  if (modelId || modelProvider) {
    return {
      ...(modelId ? { modelId } : {}),
      ...(modelProvider ? { modelProvider } : {}),
    };
  }
  return undefined;
}

export function extractAssistantErrorInfo(err: unknown): AssistantErrorInfo {
  if (!err) return { isAborted: false, isTimeout: false };
  let message: string | undefined;
  let errorName = "";
  if (typeof err === "string") {
    message = nonEmptyString(err);
  } else if (isRecord(err)) {
    errorName = (nonEmptyString(err.name) ?? nonEmptyString(err.type) ?? "").toLowerCase();
    const dataObj = isRecord(err.data) ? err.data : undefined;
    message =
      nonEmptyString(err.message) ??
      nonEmptyString(dataObj?.message) ??
      nonEmptyString(err.type) ??
      nonEmptyString(err.name);
  }
  const lowerMsg = (message ?? "").toLowerCase();
  const isAborted = errorName.includes("abort") || lowerMsg.includes("abort");
  const isTimeout =
    errorName.includes("timeout") || lowerMsg.includes("timed out") || lowerMsg.includes("timeout");
  return {
    ...(message ? { message } : {}),
    isAborted,
    isTimeout,
  };
}

export function isPostVerdictInterruptError(error: unknown): boolean {
  return (
    typeof error === "string" &&
    /^(?:step\s+interrupted|aborted(?:\s+by\s+signal)?)$/i.test(error.trim())
  );
}

export function getMessageRole(msg: Record<string, unknown>): string | undefined {
  const info = isRecord(msg.info) ? msg.info : undefined;
  return (
    nonEmptyString(msg.type) ??
    nonEmptyString(msg.role) ??
    nonEmptyString(info?.role) ??
    nonEmptyString(info?.type)
  );
}

export function getMessageParts(msg: Record<string, unknown>): unknown[] {
  if (Array.isArray(msg.content)) return msg.content;
  if (Array.isArray(msg.parts)) return msg.parts;
  return [];
}

export function isAssistantMessage(msg: Record<string, unknown>): boolean {
  return getMessageRole(msg) === "assistant";
}

export function extractToolInput(part: Record<string, unknown>): Record<string, unknown> | null {
  const state = isRecord(part.state) ? part.state : undefined;
  const fn = isRecord(part.function) ? part.function : undefined;

  let toolInput: unknown =
    state?.input ?? part.input ?? part.args ?? part.arguments ?? fn?.arguments ?? fn?.args;

  if (typeof toolInput === "string") {
    try {
      toolInput = JSON.parse(toolInput);
    } catch {
      // Ignore malformed JSON string tool input
    }
  }

  if (toolInput && typeof toolInput === "object" && !Array.isArray(toolInput)) {
    return toolInput as Record<string, unknown>;
  }
  return null;
}

export function extractClassifyResultFromPart(part: unknown): ClassifierResult | null {
  if (!isRecord(part)) return null;
  const fn = isRecord(part.function) ? part.function : undefined;
  const isToolCall =
    (part.type === "tool" &&
      (part.tool === "classify_result" || part.name === "classify_result")) ||
    (part.type === "tool_use" && part.name === "classify_result") ||
    part.tool === "classify_result" ||
    part.name === "classify_result" ||
    (fn !== undefined && (fn.name === "classify_result" || fn.tool === "classify_result"));

  if (!isToolCall) return null;

  const toolInput = extractToolInput(part);
  if (!toolInput || typeof toolInput.verdict !== "string") return null;

  const rawVerdict = toolInput.verdict.toUpperCase().trim();
  if (!isClassifierVerdict(rawVerdict)) return null;

  const riskRaw =
    typeof toolInput.risk_level === "string" ? toolInput.risk_level.toUpperCase().trim() : "";
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

export function extractVerdictFromParts(partsList: readonly unknown[]): ClassifierResult | null {
  if (!Array.isArray(partsList) || partsList.length === 0) return null;

  for (const part of partsList) {
    const result = extractClassifyResultFromPart(part);
    if (result) {
      return result;
    }
  }

  let textContent = "";
  for (const part of partsList) {
    if (isRecord(part)) {
      const text =
        typeof part.text === "string"
          ? part.text
          : typeof part.content === "string"
            ? part.content
            : undefined;
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

export function extractVerdictFromMessages(messages: readonly unknown[]): ClassifierResult | null {
  if (!Array.isArray(messages) || messages.length === 0) return null;
  for (let i = messages.length - 1; i >= 0; i--) {
    const msg = messages[i];
    if (!isRecord(msg)) continue;
    const parts = [
      ...(Array.isArray(msg.parts) ? msg.parts : msg.parts ? [msg.parts] : []),
      ...(Array.isArray(msg.content) ? msg.content : msg.content ? [msg.content] : []),
      ...(Array.isArray(msg.tool_calls) ? msg.tool_calls : msg.tool_calls ? [msg.tool_calls] : []),
    ];
    const result = extractVerdictFromParts(parts);
    if (result) {
      return result;
    }
  }
  return null;
}

export function extractS2SessionDetails(params: {
  sessionInfo?: Record<string, unknown>;
  messages?: readonly unknown[];
  capturedParts?: readonly unknown[];
  capturedReasoning?: string;
  configuredModel?: string;
}): ExtractedS2SessionDetails {
  const { sessionInfo, messages, capturedParts = [], capturedReasoning, configuredModel } = params;

  const infoModel = sessionInfo ? extractModelFromRecord(sessionInfo) : undefined;
  let modelId = infoModel?.modelId;
  let modelProvider = infoModel?.modelProvider;

  const infoTokens = sessionInfo ? readTokenTotals(sessionInfo.tokens) : undefined;
  const infoCost = sessionInfo ? finiteNumber(sessionInfo.cost) : undefined;

  let msgHasTokens = false;
  let msgPrompt = 0;
  let msgOutput = 0;
  let msgReasoning = 0;
  let msgCacheRead = 0;
  let msgCacheWrite = 0;
  let hasPromptSum = false;
  let hasOutputSum = false;
  let hasReasoningSum = false;
  let hasCacheReadSum = false;
  let hasCacheWriteSum = false;

  let msgHasCost = false;
  let msgCost = 0;

  const thinkingSegments: string[] = [];
  let assistantError: string | undefined;

  if (Array.isArray(messages)) {
    for (const rawMsg of messages) {
      if (!isRecord(rawMsg) || !isAssistantMessage(rawMsg)) continue;
      const info = isRecord(rawMsg.info) ? rawMsg.info : undefined;

      const msgModel = extractModelFromRecord(rawMsg);
      if (msgModel) {
        modelId = msgModel.modelId ?? modelId;
        modelProvider = msgModel.modelProvider ?? modelProvider;
      }

      const tokens =
        readTokenTotals(rawMsg.tokens) ??
        readTokenTotals(info?.tokens) ??
        readTokenTotals(rawMsg.usage) ??
        readTokenTotals(info?.usage);
      if (tokens) {
        msgHasTokens = true;
        if (tokens.promptTokens !== undefined) {
          msgPrompt += tokens.promptTokens;
          hasPromptSum = true;
        }
        if (tokens.outputTokens !== undefined) {
          msgOutput += tokens.outputTokens;
          hasOutputSum = true;
        }
        if (tokens.reasoningTokens !== undefined) {
          msgReasoning += tokens.reasoningTokens;
          hasReasoningSum = true;
        }
        if (tokens.cacheReadTokens !== undefined) {
          msgCacheRead += tokens.cacheReadTokens;
          hasCacheReadSum = true;
        }
        if (tokens.cacheWriteTokens !== undefined) {
          msgCacheWrite += tokens.cacheWriteTokens;
          hasCacheWriteSum = true;
        }
      }

      const mCost = finiteNumber(rawMsg.cost) ?? finiteNumber(info?.cost);
      if (mCost !== undefined) {
        msgHasCost = true;
        msgCost += mCost;
      }

      const contentList = getMessageParts(rawMsg);
      thinkingSegments.push(...extractThinkingSegments(contentList));

      const directReasoning =
        nonEmptyString(rawMsg.reasoning) ??
        nonEmptyString(rawMsg.thinking) ??
        nonEmptyString(rawMsg.reasoning_content) ??
        nonEmptyString(info?.reasoning) ??
        nonEmptyString(info?.thinking);
      if (directReasoning && !thinkingSegments.includes(directReasoning)) {
        thinkingSegments.push(directReasoning);
      }

      const errInfo = extractAssistantErrorInfo(rawMsg.error ?? info?.error);
      if (errInfo.message) {
        assistantError = errInfo.message;
      }
    }
  }

  if ((!modelId || !modelProvider) && configuredModel && configuredModel.trim().length > 0) {
    const parsed = parseModelRef(configuredModel.trim());
    modelId = modelId ?? parsed.modelID;
    modelProvider = modelProvider ?? parsed.providerID;
  }

  const useInfoTokens =
    infoTokens !== undefined && (hasPositiveTokenCount(infoTokens) || !msgHasTokens);
  const promptTokens = useInfoTokens
    ? infoTokens.promptTokens
    : hasPromptSum
      ? msgPrompt
      : undefined;
  const outputTokens = useInfoTokens
    ? infoTokens.outputTokens
    : hasOutputSum
      ? msgOutput
      : undefined;
  const reasoningTokens = useInfoTokens
    ? infoTokens.reasoningTokens
    : hasReasoningSum
      ? msgReasoning
      : undefined;
  const cacheReadTokens = useInfoTokens
    ? infoTokens.cacheReadTokens
    : hasCacheReadSum
      ? msgCacheRead
      : undefined;
  const cacheWriteTokens = useInfoTokens
    ? infoTokens.cacheWriteTokens
    : hasCacheWriteSum
      ? msgCacheWrite
      : undefined;

  const cost =
    infoCost !== undefined && (infoCost > 0 || !msgHasCost)
      ? infoCost
      : msgHasCost
        ? msgCost
        : undefined;

  if (thinkingSegments.length === 0) {
    thinkingSegments.push(...extractThinkingSegments(capturedParts));
  }
  const thinking =
    thinkingSegments.length > 0 ? thinkingSegments.join("\n") : nonEmptyString(capturedReasoning);

  const timeObj = sessionInfo && isRecord(sessionInfo.time) ? sessionInfo.time : undefined;
  const locationObj =
    sessionInfo && isRecord(sessionInfo.location) ? sessionInfo.location : undefined;

  return {
    ...(modelId ? { modelId } : {}),
    ...(modelProvider ? { modelProvider } : {}),
    ...(promptTokens !== undefined ? { promptTokens } : {}),
    ...(outputTokens !== undefined ? { outputTokens } : {}),
    ...(reasoningTokens !== undefined ? { reasoningTokens } : {}),
    ...(cacheReadTokens !== undefined ? { cacheReadTokens } : {}),
    ...(cacheWriteTokens !== undefined ? { cacheWriteTokens } : {}),
    ...(cost !== undefined ? { cost } : {}),
    ...(thinking ? { thinking } : {}),
    messageCount: Array.isArray(messages) ? messages.length : 0,
    ...(nonEmptyString(sessionInfo?.title) ? { title: nonEmptyString(sessionInfo?.title) } : {}),
    ...(nonEmptyString(sessionInfo?.agent) ? { agent: nonEmptyString(sessionInfo?.agent) } : {}),
    ...(nonEmptyString(locationObj?.directory) || nonEmptyString(sessionInfo?.directory)
      ? {
          directory:
            nonEmptyString(locationObj?.directory) ?? nonEmptyString(sessionInfo?.directory),
        }
      : {}),
    ...(parseTimestampMs(timeObj?.created) !== undefined
      ? { createdAt: parseTimestampMs(timeObj?.created) }
      : {}),
    ...(parseTimestampMs(timeObj?.updated) !== undefined
      ? { updatedAt: parseTimestampMs(timeObj?.updated) }
      : {}),
    ...(parseTimestampMs(timeObj?.archived) !== undefined
      ? { archivedAt: parseTimestampMs(timeObj?.archived) }
      : {}),
    ...(nonEmptyString(sessionInfo?.outcome)
      ? { outcome: nonEmptyString(sessionInfo?.outcome) }
      : {}),
    ...(assistantError ? { assistantError } : {}),
  };
}

function knownPromptsFromSystem(rawSystem: string): KnownEvalSystemPrompts {
  const fullSystem = rawSystem.trim();
  const directiveSuffix = `\n\n${PASSIVE_EVALUATOR_DIRECTIVE}`;
  const bodyWithoutDirective = fullSystem.endsWith(directiveSuffix)
    ? fullSystem.slice(0, -directiveSuffix.length).trim()
    : undefined;
  return { fullSystem, bodyWithoutDirective };
}

export function resolveEvalPromptBundle(
  evalAgent: string,
  configuredModel?: string,
): {
  systemPrompt: string;
  agentConfig: Record<string, unknown>;
  knownSystemPrompts: KnownEvalSystemPrompts;
} {
  try {
    const def = loadEvalAgentDefinition();
    const systemPrompt = def.system.includes(PASSIVE_EVALUATOR_DIRECTIVE)
      ? def.system
      : def.system
        ? `${def.system}\n\n${PASSIVE_EVALUATOR_DIRECTIVE}`
        : PASSIVE_EVALUATOR_DIRECTIVE;
    const effectiveModel = nonEmptyString(configuredModel) ?? def.model;
    return {
      systemPrompt,
      agentConfig: {
        agent: evalAgent,
        ...(effectiveModel ? { model: effectiveModel } : {}),
        ...(def.steps !== undefined ? { steps: def.steps } : {}),
        ...(def.request ? { request: def.request } : {}),
        ...(def.permissions ? { permissions: def.permissions } : {}),
      },
      knownSystemPrompts: knownPromptsFromSystem(def.system),
    };
  } catch {
    return {
      systemPrompt: PASSIVE_EVALUATOR_DIRECTIVE,
      agentConfig: {
        agent: evalAgent,
        ...(nonEmptyString(configuredModel) ? { model: nonEmptyString(configuredModel) } : {}),
      },
      knownSystemPrompts: {},
    };
  }
}

export function buildEvalPromptTemplate(
  evalAgent: string,
  configuredModel?: string,
): { systemPrompt: string; agentConfig: Record<string, unknown> } {
  const { systemPrompt, agentConfig } = resolveEvalPromptBundle(evalAgent, configuredModel);
  return { systemPrompt, agentConfig };
}

export function getKnownEvalSystemPrompts(): KnownEvalSystemPrompts {
  try {
    const def = loadEvalAgentDefinition();
    return knownPromptsFromSystem(def.system);
  } catch {
    return {};
  }
}

export function matchesStaticEvalPrompt(text: string, known: KnownEvalSystemPrompts): boolean {
  const trimmed = text.trim();
  if (!trimmed) return false;
  if (known.fullSystem && trimmed === known.fullSystem) return true;
  if (known.bodyWithoutDirective && trimmed === known.bodyWithoutDirective) return true;
  if (trimmed.startsWith(AUTOGATE_PROMPT_MARKER)) return true;
  return false;
}

export function stripPromptPrefixFromText(
  text: string,
  known: KnownEvalSystemPrompts,
): { strippedText: string; extractedSystemPrompt?: string } {
  if (known.fullSystem && text.startsWith(known.fullSystem)) {
    const remainder = text.slice(known.fullSystem.length).replace(/^\s+/, "");
    return {
      strippedText: remainder,
      extractedSystemPrompt: known.fullSystem,
    };
  }
  if (known.bodyWithoutDirective && text.startsWith(known.bodyWithoutDirective)) {
    let remainder = text.slice(known.bodyWithoutDirective.length).replace(/^\s+/, "");
    let extracted = known.bodyWithoutDirective;
    if (remainder.startsWith(PASSIVE_EVALUATOR_DIRECTIVE)) {
      extracted = `${known.bodyWithoutDirective}\n\n${PASSIVE_EVALUATOR_DIRECTIVE}`;
      remainder = remainder.slice(PASSIVE_EVALUATOR_DIRECTIVE.length).replace(/^\s+/, "");
    }
    return {
      strippedText: remainder,
      extractedSystemPrompt: extracted,
    };
  }
  if (text.startsWith(AUTOGATE_PROMPT_MARKER)) {
    const boundaryIdx = text.indexOf("\n\n## Environment Trust Boundaries:");
    if (boundaryIdx > 0) {
      const prefix = text.slice(0, boundaryIdx).trim();
      const remainder = text.slice(boundaryIdx).replace(/^\s+/, "");
      return {
        strippedText: remainder,
        extractedSystemPrompt: prefix,
      };
    }
  }
  return { strippedText: text };
}

function stripPartsList(
  parts: readonly unknown[],
  known: KnownEvalSystemPrompts,
  onExtracted: (sp: string) => void,
): { modified: boolean; parts: unknown[] } {
  let modified = false;
  const nextParts = parts.map((part) => {
    if (!isRecord(part) || part.type !== "text" || typeof part.text !== "string") {
      return part;
    }
    const res = stripPromptPrefixFromText(part.text, known);
    if (res.extractedSystemPrompt) {
      onExtracted(res.extractedSystemPrompt);
      modified = true;
      return { ...part, text: res.strippedText };
    }
    return part;
  });
  return { modified, parts: nextParts };
}

export function extractAndStripSystemPrompt(
  messages: readonly Record<string, unknown>[],
  known: KnownEvalSystemPrompts,
): { systemPrompt?: string; sanitizedMessages: Record<string, unknown>[] } {
  let extractedSystemPrompt: string | undefined;
  const captureSystem = (sp: string) => {
    if (!extractedSystemPrompt) {
      extractedSystemPrompt = sp;
    }
  };
  const sanitizedMessages: Record<string, unknown>[] = [];

  for (const msg of messages) {
    const clone: Record<string, unknown> = { ...msg };
    const msgRole = getMessageRole(clone);

    if (typeof clone.system === "string" && clone.system.trim().length > 0) {
      captureSystem(clone.system.trim());
      delete clone.system;
    }

    if (msgRole === "system" && typeof clone.text === "string") {
      if (matchesStaticEvalPrompt(clone.text, known)) {
        captureSystem(clone.text.trim());
        continue;
      }
    }

    if (msgRole === "user") {
      if (typeof clone.text === "string") {
        const res = stripPromptPrefixFromText(clone.text, known);
        if (res.extractedSystemPrompt) {
          captureSystem(res.extractedSystemPrompt);
          clone.text = res.strippedText;
        }
      }
      if (typeof clone.content === "string") {
        const res = stripPromptPrefixFromText(clone.content, known);
        if (res.extractedSystemPrompt) {
          captureSystem(res.extractedSystemPrompt);
          clone.content = res.strippedText;
        }
      } else if (Array.isArray(clone.content)) {
        const res = stripPartsList(clone.content, known, captureSystem);
        if (res.modified) {
          clone.content = res.parts;
        }
      }
      if (Array.isArray(clone.parts)) {
        const res = stripPartsList(clone.parts, known, captureSystem);
        if (res.modified) {
          clone.parts = res.parts;
        }
      }
    }

    sanitizedMessages.push(clone);
  }

  return {
    ...(extractedSystemPrompt ? { systemPrompt: extractedSystemPrompt } : {}),
    sanitizedMessages,
  };
}
