import type {
  ClassifierVerdict,
  ClassifierResult,
  RiskLevel,
  UserAuthorization,
  EnvironmentConfig,
  BuildClassifierPromptInput,
  GateAction,
  PermissionEventData,
} from "./types";
import { loadEvalAgentDefinition, PASSIVE_EVALUATOR_DIRECTIVE } from "./agent";
import {
  probeTargetContext,
  isShellActionName,
  isPatternCoveredByText,
  maxBacktickRun,
  sanitizeCodeFenceLanguage,
} from "./prober";

export { PASSIVE_EVALUATOR_DIRECTIVE };

function resolveEffectiveTrustBoundaries(
  environment: EnvironmentConfig | undefined,
  workspaceRoot: string,
): {
  trustedDomains: string[];
  trustedRemotes: string[];
  trustedPaths: string[];
  effectiveEnv: EnvironmentConfig;
} {
  const env = environment ?? {};
  const trustedDomains =
    env.trustedDomains && env.trustedDomains.length > 0 ? env.trustedDomains : [];
  const trustedRemotes =
    env.trustedGitRemotes && env.trustedGitRemotes.length > 0 ? env.trustedGitRemotes : ["origin"];
  const trustedPaths =
    env.trustedPaths && env.trustedPaths.length > 0
      ? env.trustedPaths
      : ["~/Projects", workspaceRoot];

  return {
    trustedDomains,
    trustedRemotes,
    trustedPaths,
    effectiveEnv: { ...env, trustedPaths },
  };
}

function projectArrayWithAntiShadowing(
  rawArray: unknown[],
  cmd: string | undefined,
  target: string | undefined,
  meta: Record<string, unknown> | undefined,
): Record<string, unknown> {
  const rawItems = rawArray.filter(
    (item): item is string => typeof item === "string" && item.trim().length > 0,
  );
  const rawJoined = rawItems.join(" ").trim();
  const metaCmd =
    typeof meta?.command === "string" && meta.command.trim()
      ? meta.command.trim()
      : typeof meta?.cmd === "string" && meta.cmd.trim()
        ? meta.cmd.trim()
        : undefined;
  const candidateCmd = metaCmd ?? (cmd && cmd !== rawJoined ? cmd : undefined);

  let effectiveCommand: string | undefined;
  if (candidateCmd) {
    const allowWildcard = rawArray.length <= 1;
    const uncovered = rawItems.filter(
      (item) => !isPatternCoveredByText(item, candidateCmd, { allowWildcard, mode: "shell" }),
    );
    effectiveCommand =
      uncovered.length > 0 ? `${candidateCmd} ; ${uncovered.join(" ; ")}` : candidateCmd;
  }

  const effectiveTarget = rawArray.length <= 1 ? target : undefined;

  return {
    ...(effectiveCommand ? { command: effectiveCommand } : {}),
    ...(effectiveTarget ? { path: effectiveTarget } : {}),
    patterns: rawArray,
    ...(meta ? { metadata: meta } : {}),
  };
}

function extractMetaFallbacks(meta: Record<string, unknown> | undefined): {
  metaCmd: string | undefined;
  metaTarget: string | undefined;
} {
  const metaCmd =
    typeof meta?.command === "string" && meta.command.trim()
      ? meta.command.trim()
      : typeof meta?.cmd === "string" && meta.cmd.trim()
        ? meta.cmd.trim()
        : undefined;
  const metaTarget =
    typeof meta?.filepath === "string" && meta.filepath.trim()
      ? meta.filepath.trim()
      : typeof meta?.path === "string" && meta.path.trim()
        ? meta.path.trim()
        : typeof meta?.file === "string" && meta.file.trim()
          ? meta.file.trim()
          : undefined;
  return { metaCmd, metaTarget };
}

export function resolveClassifierActionArgs(action: GateAction): unknown {
  const meta =
    action.metadata && typeof action.metadata === "object" && !Array.isArray(action.metadata)
      ? action.metadata
      : undefined;
  const { metaCmd, metaTarget } = extractMetaFallbacks(meta);

  const cmd =
    (typeof action.commandString === "string"
      ? action.commandString.trim() || undefined
      : undefined) ?? metaCmd;
  const target =
    (typeof action.targetPath === "string" ? action.targetPath.trim() || undefined : undefined) ??
    metaTarget;
  const actionPatterns = Array.isArray(action.patterns)
    ? action.patterns.filter((p): p is string => typeof p === "string" && p.trim().length > 0)
    : undefined;
  const hasActionPatterns = Boolean(actionPatterns && actionPatterns.length > 0);

  const raw = action.rawArgs;

  if (Array.isArray(raw)) {
    const rawStrSet = new Set(
      raw.filter((item): item is string => typeof item === "string").map((s) => s.trim()),
    );
    const mergedArray =
      hasActionPatterns && actionPatterns!.some((p) => !rawStrSet.has(p.trim()))
        ? [...raw, ...actionPatterns!.filter((p) => !rawStrSet.has(p.trim()))]
        : raw;
    return projectArrayWithAntiShadowing(mergedArray, cmd, target, meta);
  }

  if (typeof raw === "object" && raw !== null) {
    const obj = raw as Record<string, unknown>;
    const hasCmdField =
      (typeof obj.command === "string" && obj.command.trim().length > 0) ||
      (Array.isArray(obj.command) && obj.command.length > 0) ||
      (typeof obj.cmd === "string" && obj.cmd.trim().length > 0) ||
      (Array.isArray(obj.cmd) && obj.cmd.length > 0) ||
      (typeof obj.code === "string" && obj.code.trim().length > 0) ||
      (typeof obj.script === "string" && obj.script.trim().length > 0);

    const hasTargetField =
      (typeof obj.path === "string" && obj.path.trim().length > 0) ||
      (typeof obj.file === "string" && obj.file.trim().length > 0) ||
      (typeof obj.filePath === "string" && obj.filePath.trim().length > 0) ||
      (typeof obj.filepath === "string" && obj.filepath.trim().length > 0);

    const objPatterns = Array.isArray(obj.patterns)
      ? obj.patterns.filter((p): p is string => typeof p === "string" && p.trim().length > 0)
      : [];
    const mergedPatterns = hasActionPatterns
      ? Array.from(new Set([...objPatterns, ...actionPatterns!]))
      : objPatterns;
    const needPatternsBackfill = hasActionPatterns && mergedPatterns.length > objPatterns.length;

    const needCmdBackfill = Boolean(cmd && !hasCmdField);
    const needTargetBackfill = Boolean(target && !hasTargetField);

    if (!needCmdBackfill && !needTargetBackfill && !needPatternsBackfill) {
      return raw;
    }

    let backfilledCmd = cmd;
    if (needCmdBackfill && cmd && mergedPatterns.length > 0) {
      const allowWildcard = mergedPatterns.length <= 1;
      const uncovered = mergedPatterns.filter(
        (p) => !isPatternCoveredByText(p, cmd, { allowWildcard, mode: "shell" }),
      );
      if (uncovered.length > 0) {
        backfilledCmd = `${cmd} ; ${uncovered.join(" ; ")}`;
      }
    }

    return {
      ...obj,
      ...(needCmdBackfill ? { command: backfilledCmd } : {}),
      ...(needTargetBackfill ? { path: target } : {}),
      ...(needPatternsBackfill ? { patterns: mergedPatterns } : {}),
    };
  }

  if (typeof raw === "string") {
    const rawTrimmed = raw.trim();
    const cmdAddsContext = Boolean(cmd && cmd !== rawTrimmed);
    const targetAddsContext = Boolean(target && target !== rawTrimmed);
    const patternsAddContext = Boolean(
      hasActionPatterns &&
      !(actionPatterns!.length === 1 && actionPatterns![0].trim() === rawTrimmed),
    );

    if (!cmdAddsContext && !targetAddsContext && !patternsAddContext) {
      return raw;
    }

    if (isShellActionName(action.toolName)) {
      let effectiveCommand = raw;
      if (cmdAddsContext && cmd) {
        const covered = isPatternCoveredByText(rawTrimmed, cmd, {
          allowWildcard: true,
          mode: "shell",
        });
        effectiveCommand = covered ? cmd : `${cmd} ; ${rawTrimmed}`;
      }
      const combinedPatterns = patternsAddContext
        ? Array.from(new Set([rawTrimmed, ...actionPatterns!]))
        : cmdAddsContext
          ? [rawTrimmed]
          : undefined;
      return {
        command: effectiveCommand,
        ...(targetAddsContext ? { path: target } : {}),
        ...(combinedPatterns ? { patterns: combinedPatterns } : {}),
        ...(meta ? { metadata: meta } : {}),
      };
    }

    return {
      path: target ?? raw,
      ...(cmdAddsContext ? { command: cmd } : {}),
      ...(patternsAddContext ? { patterns: actionPatterns } : {}),
      ...(meta ? { metadata: meta } : {}),
    };
  }

  if (raw === undefined || raw === null) {
    if (hasActionPatterns) {
      return projectArrayWithAntiShadowing(actionPatterns!, cmd, target, meta);
    }
    if (!cmd && !target && !meta) {
      return {};
    }
    return {
      ...(cmd ? { command: cmd } : {}),
      ...(target ? { path: target } : {}),
      ...(meta ? { metadata: meta } : {}),
    };
  }

  return raw;
}

export function resolveRequestActionArgs(
  request?: PermissionEventData,
  actionArgs?: unknown,
): unknown {
  if (actionArgs !== undefined) {
    return actionArgs;
  }
  if (!request) {
    return {};
  }

  const nonEmptyStrings = (val: unknown): string[] | undefined => {
    if (!Array.isArray(val)) return undefined;
    const items = val.filter(
      (item): item is string => typeof item === "string" && item.trim().length > 0,
    );
    return items.length > 0 ? items : undefined;
  };

  const resources = nonEmptyStrings(request.resources);
  const patterns = nonEmptyStrings(request.patterns);
  const meta =
    request.metadata && typeof request.metadata === "object" && !Array.isArray(request.metadata)
      ? request.metadata
      : undefined;

  const commandString =
    typeof request.commandString === "string" && request.commandString.trim()
      ? request.commandString
      : typeof meta?.command === "string" && meta.command.trim()
        ? meta.command
        : typeof meta?.cmd === "string" && meta.cmd.trim()
          ? meta.cmd
          : (resources?.join(" ") ?? patterns?.join(" "));

  const targetPath =
    typeof request.targetPath === "string" && request.targetPath.trim()
      ? request.targetPath
      : typeof meta?.filepath === "string" && meta.filepath.trim()
        ? meta.filepath
        : typeof meta?.path === "string" && meta.path.trim()
          ? meta.path
          : typeof meta?.file === "string" && meta.file.trim()
            ? meta.file
            : undefined;

  return resolveClassifierActionArgs({
    id: request.id || "request",
    harness: request.harness || "generic",
    sessionID: request.sessionID || "",
    toolName: request.action || request.permission || request.toolName || "permission",
    commandString,
    targetPath,
    patterns,
    rawArgs: resources ?? patterns ?? meta,
    workspaceRoot: request.directory || meta?.directory || process.cwd(),
    userPrompt: "",
    metadata: meta,
  });
}

export function formatUserTranscript(userPrompt?: string): string {
  if (!userPrompt || !userPrompt.trim()) {
    return "*(No conversation transcript available)*";
  }
  return userPrompt.trim();
}

export function isRiskLevel(val: unknown): val is RiskLevel {
  return (
    typeof val === "string" &&
    (val === "LOW" || val === "MEDIUM" || val === "HIGH" || val === "CRITICAL")
  );
}

export function isUserAuthorization(val: unknown): val is UserAuthorization {
  return (
    typeof val === "string" &&
    (val === "NONE" || val === "LOW" || val === "MEDIUM" || val === "HIGH")
  );
}

export function isClassifierVerdict(val: unknown): val is ClassifierVerdict {
  return typeof val === "string" && (val === "ALLOW" || val === "BLOCK" || val === "UNSURE");
}

export function formatActionDetails(actionName: string, actionArgs: unknown): string {
  if (!actionArgs) return "";

  const actionLower = (actionName || "").trim().toLowerCase();
  const isShellAction = isShellActionName(actionName);

  let commandStr: string | null = null;
  let directory: string | null = null;
  let pathStr: string | null = null;

  if (typeof actionArgs === "string") {
    commandStr = actionArgs;
    pathStr = actionArgs;
  } else if (Array.isArray(actionArgs)) {
    const items = actionArgs.filter(
      (a): a is string => typeof a === "string" && a.trim().length > 0,
    );
    if (items.length > 0) {
      commandStr = items.join(isShellAction ? " ; " : ", ");
      pathStr = items.join(", ");
    }
  } else if (typeof actionArgs === "object" && actionArgs !== null) {
    const obj = actionArgs as Record<string, unknown>;
    if (typeof obj.command === "string") {
      commandStr = obj.command;
    } else if (Array.isArray(obj.command)) {
      commandStr = obj.command.filter((a): a is string => typeof a === "string").join(" ");
    } else if (typeof obj.cmd === "string") {
      commandStr = obj.cmd;
    } else if (Array.isArray(obj.cmd)) {
      commandStr = obj.cmd.filter((a): a is string => typeof a === "string").join(" ");
    } else if (typeof obj.script === "string") {
      commandStr = obj.script;
    } else if (typeof obj.code === "string") {
      commandStr = obj.code;
    }

    if (typeof obj.path === "string" && obj.path.trim()) {
      pathStr = obj.path.trim();
    } else if (typeof obj.filePath === "string" && obj.filePath.trim()) {
      pathStr = obj.filePath.trim();
    } else if (typeof obj.filepath === "string" && obj.filepath.trim()) {
      pathStr = obj.filepath.trim();
    } else if (typeof obj.file === "string" && obj.file.trim()) {
      pathStr = obj.file.trim();
    }

    if (Array.isArray(obj.patterns)) {
      const patternItems = obj.patterns.filter(
        (p): p is string => typeof p === "string" && p.trim().length > 0,
      );
      if (patternItems.length > 0) {
        const shellJoined = patternItems.join(" ; ");
        const fsJoined = patternItems.join(", ");
        const allowWildcard = patternItems.length === 1;
        if (!commandStr) {
          commandStr = isShellAction ? shellJoined : fsJoined;
        } else {
          const uncovered = patternItems.filter(
            (p) => !isPatternCoveredByText(p, commandStr!, { allowWildcard, mode: "shell" }),
          );
          if (uncovered.length > 0) {
            commandStr = `${commandStr} ; ${uncovered.join(" ; ")}`;
          }
        }
        if (!pathStr) {
          pathStr = fsJoined;
        } else {
          const uncoveredPath = patternItems.filter(
            (p) => !isPatternCoveredByText(p, pathStr!, { allowWildcard: false, mode: "fs" }),
          );
          if (uncoveredPath.length > 0) {
            pathStr = `${pathStr}, ${uncoveredPath.join(", ")}`;
          }
        }
      }
    }

    const meta =
      typeof obj.metadata === "object" && obj.metadata !== null
        ? (obj.metadata as Record<string, unknown>)
        : undefined;

    if (!pathStr && typeof meta?.filepath === "string" && meta.filepath.trim()) {
      pathStr = meta.filepath.trim();
    }
    if (typeof obj.directory === "string") {
      directory = obj.directory;
    } else if (typeof meta?.directory === "string") {
      directory = meta.directory;
    }
  }

  if (actionLower === "external_directory") {
    const target =
      pathStr ||
      directory ||
      commandStr ||
      (typeof actionArgs === "object" ? JSON.stringify(actionArgs) : String(actionArgs));
    return `- **Requested External Directory**: \`${target.trim()}\``;
  }

  if (
    actionLower.startsWith("fs:") ||
    actionLower === "read" ||
    actionLower === "edit" ||
    actionLower === "write"
  ) {
    const target =
      pathStr ||
      commandStr ||
      directory ||
      (typeof actionArgs === "object" ? JSON.stringify(actionArgs) : String(actionArgs));
    const files =
      typeof actionArgs === "object" &&
      actionArgs !== null &&
      Array.isArray((actionArgs as Record<string, unknown>).files)
        ? ((actionArgs as Record<string, unknown>).files as Array<Record<string, unknown>>)
        : undefined;
    const allFilePaths = files
      ? Array.from(
          new Set(
            files
              .map((entry) => (typeof entry?.file === "string" ? entry.file.trim() : ""))
              .filter((f) => f.length > 0),
          ),
        )
      : [];
    const targetDisplay = allFilePaths.length > 1 ? allFilePaths.join(", ") : target.trim();
    let details = `- **Target Path / Patterns**: \`${targetDisplay}\``;
    if (directory && directory !== target.trim()) {
      details += `\n- **Target Directory**: \`${directory}\``;
    }
    if (files && files.length > 0) {
      const MAX_BEFORE_BYTES = 2048;
      const MAX_EDIT_DETAILS_BYTES = 20480;
      const formattedFiles = files.map((entry) => {
        if (!entry || typeof entry !== "object") return entry;
        const { before, after, patch, ...rest } = entry;
        const cappedBefore =
          typeof before === "string" && Buffer.byteLength(before, "utf8") > MAX_BEFORE_BYTES
            ? truncateUtf8Bytes(before, MAX_BEFORE_BYTES)
            : before;
        return {
          ...rest,
          ...(after !== undefined ? { after } : {}),
          ...(patch !== undefined ? { patch } : {}),
          ...(cappedBefore !== undefined ? { before: cappedBefore } : {}),
        };
      });
      const serialized = JSON.stringify(formattedFiles, null, 2);
      const isTruncated = Buffer.byteLength(serialized, "utf8") > MAX_EDIT_DETAILS_BYTES;
      const editBody = isTruncated
        ? truncateUtf8Bytes(serialized, MAX_EDIT_DETAILS_BYTES)
        : serialized;
      details += `\n- **Edit Details**${isTruncated ? " *(truncated; inspect carefully)*" : ""}:\n\`\`\`json\n${editBody}\n\`\`\``;
    }
    return details;
  }

  if (actionLower === "eval") {
    const isObj = typeof actionArgs === "object" && actionArgs !== null;
    const argObj = isObj ? (actionArgs as Record<string, unknown>) : undefined;
    const rawLang =
      typeof argObj?.language === "string"
        ? argObj.language
        : typeof argObj?.lang === "string"
          ? argObj.lang
          : "javascript";
    const lang = sanitizeCodeFenceLanguage(rawLang);
    const code = commandStr || (typeof argObj?.code === "string" ? argObj.code : "");
    if (code) {
      const fence = "`".repeat(Math.max(3, maxBacktickRun(code) + 1));
      return `- **Eval Code (${lang})**:\n${fence}${lang}\n${code.trim()}\n${fence}`;
    }
  }

  if (isShellAction) {
    if (commandStr) {
      const fence = "`".repeat(Math.max(3, maxBacktickRun(commandStr) + 1));
      let details = `- **Command**:\n${fence}bash\n${commandStr.trim()}\n${fence}`;
      if (directory) {
        details += `\n- **Target Directory**: \`${directory}\``;
      }
      return details;
    }
  }

  return `- **Action Arguments**:\n\`\`\`json\n${JSON.stringify(actionArgs, null, 2)}\n\`\`\``;
}

export function stripOrchestratorMetaRules(text: string): string {
  return text
    .replace(/<skill-instruction>[\s\S]*?<\/skill-instruction>/gi, "")
    .replace(/<command-instruction>[\s\S]*?<\/command-instruction>/gi, "")
    .replace(/<session-context>[\s\S]*?<\/session-context>/gi, "")
    .replace(/<orchestrator-rule>[\s\S]*?<\/orchestrator-rule>/gi, "")
    .replace(/<system-directive>[\s\S]*?<\/system-directive>/gi, "")
    .replace(
      /<[a-zA-Z0-9_-]+-(?:instruction|directive|rule)>[\s\S]*?<\/[a-zA-Z0-9_-]+-(?:instruction|directive|rule)>/gi,
      "",
    )
    .replace(/<!--[\s\S]*?-->/g, "")
    .replace(/<[^>]+>/g, "")
    .trim();
}

export function sanitizeUserPrompt(rawPrompt?: string): string {
  if (!rawPrompt) return "";
  let prompt = rawPrompt.trim();
  if (/<auto-slash-command[^>]*>/i.test(prompt) || prompt.includes("<auto-slash-command>")) {
    const reqMatch = prompt.match(/<user-request>([\s\S]*?)<\/user-request>/i);
    let req = reqMatch && reqMatch[1] ? stripOrchestratorMetaRules(reqMatch[1]) : "";
    if (req.length > 0) {
      return `Execute /start-work: ${req}`;
    }
    const planMatch = prompt.match(/(?:\*\*Plan\*\*|Plan):\s*([^\n\r]+)/i);
    if (planMatch && planMatch[1]) {
      const plan = stripOrchestratorMetaRules(planMatch[1].trim().replace(/^["'`]|["'`]$/g, ""));
      if (plan.length > 0) {
        return `Execute plan: ${plan}`;
      }
    }
    const cleaned = stripOrchestratorMetaRules(prompt);
    return cleaned || "Execute slash command";
  }
  if (prompt.includes("## Environment Trust Boundaries:") || prompt.includes("## Context:")) {
    const match = prompt.match(
      /(?:Conversation Transcript[^\n]*|User's Recent Intent[^\n]*):?\s*(?:>\s*|"?)([\s\S]*?)(?:### Proposed Action|- \*\*Proposed Action|$)/i,
    );
    if (match && match[1]) {
      prompt = match[1].replace(/\\n/g, "\n").replace(/\\"/g, '"').trim();
      if (prompt.includes("## Environment Trust Boundaries:")) {
        return sanitizeUserPrompt(prompt);
      }
      return prompt;
    }
    return "";
  }
  return prompt;
}

function extractFlagPayloads(
  cmd: string,
  runnerRegexSource: string,
  flagRegexSource: string,
): string[] {
  const results: string[] = [];
  const pattern = new RegExp(
    `(?:^|[\\s;&|(])(?:[A-Za-z0-9_./~-]*\\/)?${runnerRegexSource}(?:\\s+(?:-[a-zA-Z]+|--[a-zA-Z0-9-]+))*\\s+${flagRegexSource}\\s+(?:"((?:\\\\.|[^"\\\\])+)"|'([^']+)')`,
    "gi",
  );
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(cmd)) !== null) {
    const rawPayload =
      match[1] !== undefined ? match[1].replace(/\\(["\\])/g, "$1") : (match[2] ?? "");
    if (rawPayload.trim()) {
      results.push(rawPayload.trim());
    }
  }
  return results;
}

function formatDeobfuscatedEntry(label: string, payload: string): string {
  if (payload.includes("\n") || payload.includes("\r") || payload.includes("```")) {
    const fence = "`".repeat(Math.max(3, maxBacktickRun(payload) + 1));
    return `${label}:\n${fence}text\n${payload}\n${fence}`;
  }
  return `${label}: "${payload}"`;
}

/**
 * De-obfuscates command wrappers, sub-shells, base64 payloads, and script flags
 * so the classifier inspects real-world impact rather than the outer wrapper.
 */
export function deobfuscatePayload(actionName: string, actionArgs: unknown): string | null {
  if (!actionArgs) return null;

  let cmd = "";
  if (typeof actionArgs === "string") {
    cmd = actionArgs;
  } else if (Array.isArray(actionArgs)) {
    cmd = actionArgs.filter((a): a is string => typeof a === "string").join(" ; ");
  } else if (typeof actionArgs === "object") {
    const obj = actionArgs as Record<string, unknown>;
    if (typeof obj.command === "string") {
      cmd = obj.command;
    } else if (Array.isArray(obj.command)) {
      cmd = obj.command.filter((a): a is string => typeof a === "string").join(" ");
    } else if (typeof obj.cmd === "string") {
      cmd = obj.cmd;
    } else if (Array.isArray(obj.cmd)) {
      cmd = obj.cmd.filter((a): a is string => typeof a === "string").join(" ");
    } else if (typeof obj.script === "string") {
      cmd = obj.script;
    } else if (typeof obj.code === "string") {
      cmd = obj.code;
    }

    if (Array.isArray(obj.patterns)) {
      const patternItems = obj.patterns.filter(
        (p): p is string => typeof p === "string" && p.trim().length > 0,
      );
      if (patternItems.length > 0) {
        const allowWildcard = patternItems.length === 1;
        if (!cmd) {
          cmd = patternItems.join(" ; ");
        } else {
          const uncovered = patternItems.filter(
            (p) => !isPatternCoveredByText(p, cmd, { allowWildcard, mode: "shell" }),
          );
          if (uncovered.length > 0) {
            cmd = `${cmd} ; ${uncovered.join(" ; ")}`;
          }
        }
      }
    }
  }

  if (!cmd.trim()) return null;

  const findings: string[] = [];

  // 1. Detect base64 encoded pipes (e.g. echo "..." | base64 -d | sh)
  const b64PipeMatch = cmd.match(
    /echo\s+["']?([A-Za-z0-9+/=]{4,})["']?\s*\|\s*(?:base64\s+(?:-d|--decode))\s*\|\s*(?:ba|z|da|k|tc)?sh/i,
  );
  if (b64PipeMatch && b64PipeMatch[1]) {
    try {
      const decoded = Buffer.from(b64PipeMatch[1], "base64").toString("utf8");
      findings.push(formatDeobfuscatedEntry("Decoded base64 shell pipeline", decoded.trim()));
    } catch {}
  }

  // 2. Detect Python base64 exec (e.g. exec(base64.b64decode('...')))
  const pyB64Match = cmd.match(/b64decode\s*\(\s*["']([A-Za-z0-9+/=]{4,})["']\s*\)/i);
  if (pyB64Match && pyB64Match[1]) {
    try {
      const decoded = Buffer.from(pyB64Match[1], "base64").toString("utf8");
      findings.push(formatDeobfuscatedEntry("Decoded Python base64 exec payload", decoded.trim()));
    } catch {}
  }

  // 3. Detect wrapper sub-shells: (bash|sh|zsh) -c / -lc / -cl / -l -c "..."
  for (const payload of extractFlagPayloads(cmd, "(?:ba|z|da|k|tc)?sh", "-[a-zA-Z]*c[a-zA-Z]*")) {
    findings.push(formatDeobfuscatedEntry("Unpacked inner sub-shell command", payload));
  }

  // 4. Detect Python inline commands: python3? -c "..."
  for (const payload of extractFlagPayloads(
    cmd,
    "python[23]?(?:\\.\\d+)?",
    "-[a-zA-Z]*c[a-zA-Z]*",
  )) {
    findings.push(formatDeobfuscatedEntry("Unpacked Python inline script", payload));
  }

  // 5. Detect Node/Bun inline eval: (node|bun) (-e|--eval|-p|--print) "..."
  for (const payload of extractFlagPayloads(cmd, "(?:node|bun)", "(?:-e|--eval|-p|--print)")) {
    findings.push(formatDeobfuscatedEntry("Unpacked Node/Bun inline script", payload));
  }

  // 6. Detect piped remote executions: curl/wget ... | bash/sh/python
  const pipeExecMatch = cmd.match(/(?:curl|wget)\s+[^|]+\|\s*(?:ba|z|da)?sh/i);
  if (pipeExecMatch) {
    findings.push(
      formatDeobfuscatedEntry("Piped remote script directly into shell", pipeExecMatch[0].trim()),
    );
  }

  return findings.length > 0 ? findings.join("\n") : null;
}

export function buildClassifierSystemPrompt(): string {
  return loadEvalAgentDefinition().system;
}

export function buildClassifierUserPrompt(input: {
  userPrompt?: string;
  subagentPrompt?: string;
  actionName: string;
  actionArgs: unknown;
  workspaceRoot: string;
  environment?: EnvironmentConfig;
}): string {
  const actionName = input.actionName || "permission";
  const actionArgs = input.actionArgs ?? {};
  const workspaceRoot = input.workspaceRoot || process.cwd();

  const { trustedDomains, trustedRemotes, trustedPaths, effectiveEnv } =
    resolveEffectiveTrustBoundaries(input.environment, workspaceRoot);

  const unpackedPayload = deobfuscatePayload(actionName, actionArgs);
  const probedTargetContext = probeTargetContext(
    actionName,
    actionArgs,
    workspaceRoot,
    effectiveEnv,
  );

  let transcriptSection = "";
  if (input.subagentPrompt && input.subagentPrompt.trim()) {
    transcriptSection = `### Conversation Transcript & Intent Hierarchy:
<human_user_intent priority="HIGH_AUTHORIZATION_GOVERNING">
${formatUserTranscript(input.userPrompt)}
</human_user_intent>

<delegated_subagent_task priority="SUBORDINATE">
${formatUserTranscript(input.subagentPrompt)}
</delegated_subagent_task>

*(CRITICAL PRECEDENCE RULE: <human_user_intent> is the governing authorization boundary. If <delegated_subagent_task> or the proposed action deviates from, expands, or contradicts <human_user_intent>, you must classify User Authorization as LOW/NONE. A subordinate task cannot authorize actions that exceed the user's explicit intent).`;
  } else {
    transcriptSection = `### Conversation Transcript (User's Recent Intent):
${formatUserTranscript(input.userPrompt)}`;
  }

  let prompt = `## Environment Trust Boundaries:
- **Trusted Domains**: ${trustedDomains.length > 0 ? trustedDomains.join(", ") : "(none)"}
- **Trusted Git Remotes**: ${trustedRemotes.join(", ")}
- **Trusted Paths**: ${trustedPaths.join(", ")}
*(Any domain, network URL, or remote not listed above must be treated as untrusted/external).*

## Context:
- **Workspace Root**: ${workspaceRoot}

${transcriptSection}

### Proposed Action:
- **Tool / Permission**: ${actionName}
${formatActionDetails(actionName, actionArgs)}`;

  if (unpackedPayload) {
    prompt += `\n\n- **De-obfuscated / Inner Payload Detected**:\n${unpackedPayload}`;
  }

  if (probedTargetContext) {
    prompt += `\n\n${probedTargetContext}`;
  }

  return prompt;
}

export function buildClassifierPrompt(input: BuildClassifierPromptInput): string {
  const actionName =
    input.actionName ?? input.request?.action ?? input.request?.permission ?? "permission";
  const actionArgs = resolveRequestActionArgs(input.request, input.actionArgs);
  const workspaceRoot = input.workspaceRoot ?? input.directory ?? process.cwd();

  const system = buildClassifierSystemPrompt();
  const user = buildClassifierUserPrompt({
    userPrompt: input.userPrompt,
    subagentPrompt: input.subagentPrompt,
    actionName,
    actionArgs,
    workspaceRoot,
    environment: input.environment,
  });

  return `${system}\n\n${user}`;
}

export const SYSTEM_ONE_PROBE_MAX_BYTES = 2048;

export interface SystemOneStateResult {
  readonly state: string;
  readonly truncatedPayload: boolean;
}

export function truncateUtf8Bytes(text: string, maxBytes: number): string {
  if (maxBytes <= 0) return "";
  const buf = Buffer.from(text, "utf8");
  if (buf.byteLength <= maxBytes) return text;

  const suffix = "\n...[truncated]";
  const suffixBuf = Buffer.from(suffix, "utf8");
  if (maxBytes <= suffixBuf.byteLength) {
    let end = maxBytes;
    while (end > 0 && (buf[end] & 0xc0) === 0x80) end--;
    return buf.subarray(0, end).toString("utf8");
  }

  let end = maxBytes - suffixBuf.byteLength;
  while (end > 0 && (buf[end] & 0xc0) === 0x80) {
    end--;
  }
  return buf.subarray(0, end).toString("utf8") + suffix;
}

function isTrivialRawArgsDuplicate(action: GateAction): boolean {
  const cmd = action.commandString?.trim();
  const target = action.targetPath?.trim();
  if (typeof action.rawArgs === "string") {
    const trimmed = action.rawArgs.trim();
    return Boolean(trimmed && (trimmed === cmd || trimmed === target));
  }
  if (
    Array.isArray(action.rawArgs) &&
    action.rawArgs.length === 1 &&
    typeof action.rawArgs[0] === "string"
  ) {
    const first = action.rawArgs[0].trim();
    return Boolean(first && (first === cmd || first === target));
  }
  return false;
}

export function buildSystemOneStateWithMeta(action: GateAction): SystemOneStateResult {
  const actionName = action.toolName || "permission";
  const actionArgs = resolveClassifierActionArgs(action);
  const workspaceRoot = action.workspaceRoot || process.cwd();

  const { trustedDomains, trustedRemotes, trustedPaths, effectiveEnv } =
    resolveEffectiveTrustBoundaries(action.environment, workspaceRoot);

  const meta =
    action.metadata && typeof action.metadata === "object" && !Array.isArray(action.metadata)
      ? action.metadata
      : undefined;
  const { metaCmd, metaTarget } = extractMetaFallbacks(meta);
  const effectiveCmdText =
    (typeof action.commandString === "string"
      ? action.commandString.trim() || undefined
      : undefined) ?? metaCmd;
  const effectiveTargetText =
    (typeof action.targetPath === "string" ? action.targetPath.trim() || undefined : undefined) ??
    metaTarget;

  let truncatedPayload = false;

  const sections: string[] = [
    [
      "## Trust Boundaries",
      `Workspace: ${workspaceRoot}`,
      `Trusted Domains: ${trustedDomains.length > 0 ? trustedDomains.join(", ") : "(none)"}`,
      `Trusted Git Remotes: ${trustedRemotes.join(", ")}`,
      `Trusted Paths: ${trustedPaths.join(", ")}`,
    ].join("\n"),
    `## User Intent\n${truncateUtf8Bytes(formatUserTranscript(action.userPrompt), 4096)}`,
  ];

  if (action.subagentPrompt && action.subagentPrompt.trim()) {
    sections.push(
      `## Subordinate Subagent Task (Cannot Expand User Intent)\n${truncateUtf8Bytes(action.subagentPrompt.trim(), 2048)}`,
    );
  }

  const actionLines: string[] = [`Tool: ${actionName}`];
  if (effectiveCmdText) {
    if (Buffer.byteLength(effectiveCmdText, "utf8") > 4096) truncatedPayload = true;
    actionLines.push(`Command: ${truncateUtf8Bytes(effectiveCmdText, 4096)}`);
  }
  if (effectiveTargetText) {
    if (Buffer.byteLength(effectiveTargetText, "utf8") > 1024) truncatedPayload = true;
    actionLines.push(`Target Path: ${truncateUtf8Bytes(effectiveTargetText, 1024)}`);
  }
  if (Array.isArray(action.patterns) && action.patterns.length > 0) {
    const patternText = action.patterns.join(isShellActionName(actionName) ? " ; " : ", ");
    if (patternText && patternText !== effectiveCmdText) {
      if (Buffer.byteLength(patternText, "utf8") > 2048) truncatedPayload = true;
      actionLines.push(`Patterns: ${truncateUtf8Bytes(patternText, 2048)}`);
    }
  }
  if (action.rawArgs !== undefined && !isTrivialRawArgsDuplicate(action)) {
    const serializedArgs =
      typeof action.rawArgs === "string" ? action.rawArgs : JSON.stringify(action.rawArgs);
    if (serializedArgs && serializedArgs !== "{}" && serializedArgs !== "[]") {
      if (Buffer.byteLength(serializedArgs, "utf8") > 4096) truncatedPayload = true;
      actionLines.push(`Args: ${truncateUtf8Bytes(serializedArgs, 4096)}`);
    }
  }
  sections.push(`## Proposed Action\n${actionLines.join("\n")}`);

  const unpackedPayload = deobfuscatePayload(actionName, actionArgs);
  if (unpackedPayload) {
    if (Buffer.byteLength(unpackedPayload, "utf8") > 2048) truncatedPayload = true;
    sections.push(`## De-obfuscated Payload\n${truncateUtf8Bytes(unpackedPayload, 2048)}`);
  }

  const probed = probeTargetContext(actionName, actionArgs, workspaceRoot, effectiveEnv);
  if (probed) {
    if (
      Buffer.byteLength(probed, "utf8") > SYSTEM_ONE_PROBE_MAX_BYTES ||
      probed.includes("[Truncated:")
    ) {
      truncatedPayload = true;
    }
    sections.push(`## Probe Excerpt\n${truncateUtf8Bytes(probed, SYSTEM_ONE_PROBE_MAX_BYTES)}`);
  }

  return {
    state: sections.join("\n\n"),
    truncatedPayload,
  };
}

export function buildSystemOneState(action: GateAction): string {
  return buildSystemOneStateWithMeta(action).state;
}

export function parseVerdict(rawContent: string): ClassifierResult {
  if (!rawContent || typeof rawContent !== "string") {
    return { verdict: "UNSURE", reason: "Empty or invalid classifier output" };
  }

  const extractAndParse = (text: string): ClassifierResult | null => {
    try {
      const parsed = JSON.parse(text);
      if (typeof parsed !== "object" || parsed === null) return null;

      const verdictRaw = String(parsed.verdict ?? parsed.decision ?? "")
        .toUpperCase()
        .trim();
      const reason = typeof parsed.reason === "string" ? parsed.reason : undefined;

      const riskRaw = String(parsed.risk_level ?? "")
        .toUpperCase()
        .trim();
      const authRaw = String(parsed.user_authorization ?? "")
        .toUpperCase()
        .trim();
      const risk_level = isRiskLevel(riskRaw) ? riskRaw : undefined;
      const user_authorization = isUserAuthorization(authRaw) ? authRaw : undefined;

      if (isClassifierVerdict(verdictRaw)) {
        return {
          verdict: verdictRaw,
          risk_level,
          user_authorization,
          reason: reason || "",
        };
      }
    } catch {
      // not valid JSON
    }
    return null;
  };

  // 1. Direct JSON parse
  const trimmed = rawContent.trim();
  const directResult = extractAndParse(trimmed);
  if (directResult) return directResult;

  // 2. Markdown code fence extraction
  let jsonCandidate = trimmed;
  const jsonMatch = trimmed.match(/```(?:json)?\s*([\s\S]*?)\s*```/i);
  if (jsonMatch && jsonMatch[1]) {
    jsonCandidate = jsonMatch[1].trim();
    const fenceResult = extractAndParse(jsonCandidate);
    if (fenceResult) return fenceResult;
  }

  // 3. Extract substring between first '{' and last '}'
  const firstBrace = jsonCandidate.indexOf("{");
  const lastBrace = jsonCandidate.lastIndexOf("}");
  if (firstBrace !== -1 && lastBrace !== -1 && lastBrace > firstBrace) {
    const braceResult = extractAndParse(jsonCandidate.slice(firstBrace, lastBrace + 1));
    if (braceResult) return braceResult;
  }

  if (jsonCandidate !== trimmed) {
    const origFirstBrace = trimmed.indexOf("{");
    const origLastBrace = trimmed.lastIndexOf("}");
    if (origFirstBrace !== -1 && origLastBrace !== -1 && origLastBrace > origFirstBrace) {
      const origBraceResult = extractAndParse(trimmed.slice(origFirstBrace, origLastBrace + 1));
      if (origBraceResult) return origBraceResult;
    }
  }

  return {
    verdict: "UNSURE",
    reason: "Classifier response did not contain a valid structured verdict",
  };
}
