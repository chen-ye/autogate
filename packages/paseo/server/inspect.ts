import type { GateAction } from "@autogate/core";

export const TRUNCATION_LIMIT = 4096;
export const TRUNCATION_SUFFIX = "... [truncated]";

/**
 * Safely slices a UTF-8 buffer to at most `maxBytes` without cutting in the middle
 * of a multi-byte UTF-8 sequence.
 */
function sliceUtf8Safe(buf: Buffer, maxBytes: number): string {
  if (buf.length <= maxBytes) {
    return buf.toString("utf-8");
  }

  let end = maxBytes;
  // If we landed in the middle of a UTF-8 continuation byte (10xxxxxx), walk backwards
  while (end > 0 && (buf[end] & 0xc0) === 0x80) {
    end--;
  }

  // Now buf[end] is either an ASCII byte or a leading byte of a multi-byte character
  if (end > 0) {
    const lead = buf[end];
    let expectedLength = 1;
    if ((lead & 0xe0) === 0xc0) expectedLength = 2;
    else if ((lead & 0xf0) === 0xe0) expectedLength = 3;
    else if ((lead & 0xf8) === 0xf0) expectedLength = 4;

    if (end + expectedLength > maxBytes) {
      // The character would be cut off, exclude it
      return buf.subarray(0, end).toString("utf-8");
    }
  }

  return buf.subarray(0, maxBytes).toString("utf-8");
}

/**
 * Truncates large strings exceeding `maxBytes` (default 4096 bytes / 4KB)
 * appending `... [truncated]` to guard against Ntfy broker payload drops.
 */
export function truncate(str: string, maxBytes = TRUNCATION_LIMIT): string {
  if (typeof str !== "string") {
    return str;
  }

  const buf = Buffer.from(str, "utf-8");
  if (buf.byteLength <= maxBytes) {
    return str;
  }

  const sliced = sliceUtf8Safe(buf, maxBytes);
  return sliced + TRUNCATION_SUFFIX;
}

function hasLargeString(obj: unknown, maxBytes = TRUNCATION_LIMIT): boolean {
  if (typeof obj === "string") {
    return Buffer.byteLength(obj, "utf-8") > maxBytes;
  }
  if (Array.isArray(obj)) {
    return obj.some((item) => hasLargeString(item, maxBytes));
  }
  if (obj !== null && typeof obj === "object") {
    return Object.values(obj).some((val) => hasLargeString(val, maxBytes));
  }
  return false;
}

function truncateValue(val: unknown, maxBytes = TRUNCATION_LIMIT): unknown {
  if (typeof val === "string") {
    return truncate(val, maxBytes);
  }
  if (Array.isArray(val)) {
    return val.map((item) => truncateValue(item, maxBytes));
  }
  if (val !== null && typeof val === "object") {
    const copy: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(val)) {
      copy[k] = truncateValue(v, maxBytes);
    }
    return copy;
  }
  return val;
}

/**
 * Convenience helper matching Paseo's official example helper pattern
 * for extracting shell commands from permission requests.
 */
export function shellCommand(request: unknown): string | null {
  if (!request || typeof request !== "object") {
    return null;
  }
  const reqObj = request as Record<string, unknown>;
  const input = reqObj.input ?? reqObj.args ?? request;
  if (!input) {
    return null;
  }

  if (typeof input === "string") {
    const trimmed = input.trim();
    if (trimmed.startsWith("{") && trimmed.endsWith("}")) {
      try {
        const parsed: unknown = JSON.parse(trimmed);
        if (parsed && typeof parsed === "object") {
          const p = parsed as Record<string, unknown>;
          if (typeof p.command === "string") return p.command;
          if (typeof p.cmd === "string") return p.cmd;
          if (typeof p.code === "string") return p.code;
          if (typeof p.script === "string") return p.script;
        }
      } catch {}
    }
    return input;
  }

  if (typeof input === "object" && input !== null) {
    const inObj = input as Record<string, unknown>;
    if (typeof inObj.command === "string") {
      return inObj.command;
    }
    if (typeof inObj.cmd === "string") {
      return inObj.cmd;
    }
    if (typeof inObj.code === "string") {
      return inObj.code;
    }
    if (typeof inObj.script === "string") {
      return inObj.script;
    }
  }

  if (typeof reqObj.command === "string") {
    return reqObj.command;
  }
  if (typeof reqObj.cmd === "string") {
    return reqObj.cmd;
  }
  if (typeof reqObj.code === "string") {
    return reqObj.code;
  }
  if (typeof reqObj.script === "string") {
    return reqObj.script;
  }

  return null;
}

function extractToolName(request: unknown): string {
  if (!request || typeof request !== "object") {
    return "";
  }
  const r = request as Record<string, unknown>;
  if (typeof r.name === "string" && r.name) {
    return r.name;
  }
  if (typeof r.toolName === "string" && r.toolName) {
    return r.toolName;
  }
  if (typeof r.tool === "string" && r.tool) {
    return r.tool;
  }
  if (typeof r.kind === "string" && r.kind) {
    return r.kind;
  }
  if (typeof r.type === "string" && r.type) {
    return r.type;
  }
  return "";
}

function extractTargetPath(args: unknown, request: unknown): string | undefined {
  let path: string | undefined = undefined;

  if (args && typeof args === "object") {
    const a = args as Record<string, unknown>;
    if (typeof a.path === "string") {
      path = a.path;
    } else if (typeof a.filepath === "string") {
      path = a.filepath;
    } else if (typeof a.filePath === "string") {
      path = a.filePath;
    } else if (typeof a.file === "string") {
      path = a.file;
    }
  }

  if (!path && request && typeof request === "object") {
    const r = request as Record<string, unknown>;
    if (typeof r.path === "string") {
      path = r.path;
    } else if (typeof r.filepath === "string") {
      path = r.filepath;
    } else if (typeof r.filePath === "string") {
      path = r.filePath;
    } else if (typeof r.file === "string") {
      path = r.file;
    } else if (typeof r.targetPath === "string") {
      path = r.targetPath;
    }
  }

  if (path !== undefined) {
    return truncate(path);
  }
  return undefined;
}

function extractCommandString(args: unknown, request: unknown): string | undefined {
  let command: string | undefined = undefined;

  if (args && typeof args === "object") {
    const a = args as Record<string, unknown>;
    if (typeof a.command === "string") {
      command = a.command;
    } else if (typeof a.cmd === "string") {
      command = a.cmd;
    } else if (typeof a.code === "string") {
      command = a.code;
    } else if (typeof a.script === "string") {
      command = a.script;
    }
  }

  if (!command && typeof args === "string") {
    command = args;
  }

  if (!command) {
    const sc = shellCommand(request);
    if (sc !== null) {
      command = sc;
    }
  }

  if (command !== undefined) {
    return truncate(command);
  }
  return undefined;
}

/**
 * Extracts a normalized GateAction payload from a Paseo agent permission request event.
 */
export function extractActionFromRequest(event: {
  agent?: unknown;
  request?: unknown;
  userPrompt?: string;
}): GateAction {
  const request =
    event?.request && typeof event.request === "object"
      ? (event.request as Record<string, unknown>)
      : undefined;
  const agent =
    event?.agent && typeof event.agent === "object"
      ? (event.agent as Record<string, unknown>)
      : undefined;

  let rawArgs: unknown = undefined;
  if (request) {
    rawArgs = request.input ?? request.args ?? request.params ?? request.detail ?? request;
  } else if (event?.request !== undefined) {
    rawArgs = event.request;
  }

  // Parses shell commands from tool arguments (args.command, args.cmd, args.code, args.script)
  const commandString = extractCommandString(rawArgs, request);

  // Extracts targetPath from file operations (args.path, args.filepath, args.file)
  const targetPath = extractTargetPath(rawArgs, request);

  // Formats clean GateAction payload
  const id =
    typeof request?.id === "string" ? request.id : request?.id != null ? String(request.id) : "";
  const sessionID =
    typeof agent?.id === "string" ? agent.id : agent?.id != null ? String(agent.id) : "";
  const toolName = extractToolName(request);
  const workspaceRoot = typeof agent?.cwd === "string" && agent.cwd ? agent.cwd : process.cwd();

  // Truncation Guard: Truncate large stringified arguments to 4096 bytes (4KB)
  if (typeof rawArgs === "string") {
    rawArgs = truncate(rawArgs);
  } else if (hasLargeString(rawArgs)) {
    rawArgs = truncateValue(rawArgs);
  }

  const userPrompt =
    typeof agent?.userPrompt === "string"
      ? agent.userPrompt
      : typeof request?.userPrompt === "string"
        ? request.userPrompt
        : typeof event?.userPrompt === "string"
          ? event.userPrompt
          : "";

  const action: GateAction = {
    id,
    harness: "paseo",
    sessionID,
    toolName,
    commandString,
    targetPath,
    rawArgs,
    workspaceRoot,
    userPrompt,
  };

  if (request?.metadata && typeof request.metadata === "object") {
    action.metadata = request.metadata as Record<string, unknown>;
  }
  if (request?.signal instanceof AbortSignal) {
    action.signal = request.signal;
  }

  return action;
}
