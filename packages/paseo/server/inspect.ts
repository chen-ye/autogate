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
export function shellCommand(request: any): string | null {
  if (!request || typeof request !== "object") {
    return null;
  }

  const input = request.input ?? request.args ?? request;
  if (!input) {
    return null;
  }

  if (typeof input === "string") {
    const trimmed = input.trim();
    if (trimmed.startsWith("{") && trimmed.endsWith("}")) {
      try {
        const parsed = JSON.parse(trimmed);
        if (parsed && typeof parsed === "object") {
          if (typeof parsed.command === "string") return parsed.command;
          if (typeof parsed.cmd === "string") return parsed.cmd;
          if (typeof parsed.code === "string") return parsed.code;
          if (typeof parsed.script === "string") return parsed.script;
        }
      } catch {}
    }
    return input;
  }

  if (typeof input === "object") {
    if (typeof input.command === "string") {
      return input.command;
    }
    if (typeof input.cmd === "string") {
      return input.cmd;
    }
    if (typeof input.code === "string") {
      return input.code;
    }
    if (typeof input.script === "string") {
      return input.script;
    }
  }

  if (typeof request.command === "string") {
    return request.command;
  }
  if (typeof request.cmd === "string") {
    return request.cmd;
  }
  if (typeof request.code === "string") {
    return request.code;
  }
  if (typeof request.script === "string") {
    return request.script;
  }

  return null;
}

function extractToolName(request: any): string {
  if (!request || typeof request !== "object") {
    return "";
  }
  if (typeof request.name === "string" && request.name) {
    return request.name;
  }
  if (typeof request.toolName === "string" && request.toolName) {
    return request.toolName;
  }
  if (typeof request.tool === "string" && request.tool) {
    return request.tool;
  }
  if (typeof request.kind === "string" && request.kind) {
    return request.kind;
  }
  if (typeof request.type === "string" && request.type) {
    return request.type;
  }
  return "";
}

function extractTargetPath(args: any, request: any): string | undefined {
  let path: string | undefined = undefined;

  if (args && typeof args === "object") {
    if (typeof args.path === "string") {
      path = args.path;
    } else if (typeof args.filepath === "string") {
      path = args.filepath;
    } else if (typeof args.filePath === "string") {
      path = args.filePath;
    } else if (typeof args.file === "string") {
      path = args.file;
    }
  }

  if (!path && request && typeof request === "object") {
    if (typeof request.path === "string") {
      path = request.path;
    } else if (typeof request.filepath === "string") {
      path = request.filepath;
    } else if (typeof request.filePath === "string") {
      path = request.filePath;
    } else if (typeof request.file === "string") {
      path = request.file;
    } else if (typeof request.targetPath === "string") {
      path = request.targetPath;
    }
  }

  if (path !== undefined) {
    return truncate(path);
  }
  return undefined;
}

function extractCommandString(args: any, request: any): string | undefined {
  let command: string | undefined = undefined;

  if (args && typeof args === "object") {
    if (typeof args.command === "string") {
      command = args.command;
    } else if (typeof args.cmd === "string") {
      command = args.cmd;
    } else if (typeof args.code === "string") {
      command = args.code;
    } else if (typeof args.script === "string") {
      command = args.script;
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
export function extractActionFromRequest(event: { agent?: any; request?: any }): GateAction {
  const request = event?.request;
  const agent = event?.agent;

  let rawArgs: unknown = undefined;
  if (request && typeof request === "object") {
    rawArgs = request.input ?? request.args ?? request.params ?? request.detail ?? request;
  } else if (request !== undefined) {
    rawArgs = request;
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
        : typeof (event as any)?.userPrompt === "string"
          ? (event as any).userPrompt
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
    action.metadata = request.metadata;
  }
  if (request?.signal instanceof AbortSignal) {
    action.signal = request.signal;
  }

  return action;
}
