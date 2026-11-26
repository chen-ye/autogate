import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import type { EnvironmentConfig, GateAction, PermissionEventData } from "@autogate/core";

export function resolveWorkspaceDirectory(val: unknown): string | undefined {
  if (typeof val === "string" && val.trim().length > 0) {
    return val.trim();
  }
  if (val && typeof val === "object") {
    const obj = val as Record<string, unknown>;
    if (typeof obj.directory === "string" && obj.directory.trim().length > 0) {
      return obj.directory.trim();
    }
  }
  return undefined;
}

export function isEventForWorkspace(event: unknown, workspaceDir?: unknown): boolean {
  const wsDirStr = resolveWorkspaceDirectory(workspaceDir);
  if (!wsDirStr) return true;
  if (!event || typeof event !== "object") return true;

  const ev = event as Record<string, unknown>;
  const normalizedWs = path.resolve(wsDirStr);

  if (ev.location && typeof ev.location === "object") {
    const locDir = resolveWorkspaceDirectory(ev.location);
    if (locDir) {
      const resolvedLoc = path.resolve(locDir);
      return resolvedLoc === normalizedWs || normalizedWs.startsWith(resolvedLoc + path.sep);
    }
  }

  const eventData = (ev.data || ev.properties) as Record<string, unknown> | undefined;
  const meta = eventData?.metadata as Record<string, unknown> | undefined;
  const dataDir =
    resolveWorkspaceDirectory(meta?.directory) ?? resolveWorkspaceDirectory(eventData?.directory);

  if (!dataDir) {
    return true;
  }

  const resolvedDataDir = path.resolve(dataDir);
  return resolvedDataDir === normalizedWs || resolvedDataDir.startsWith(normalizedWs + path.sep);
}

export function resolveServerPassword(configDir?: string): string {
  const envPassword = process.env.OPENCODE_SERVER_PASSWORD || process.env.OPENCODE_PASSWORD;

  const explicitDir = configDir || process.env.OPENCODE_CONFIG_DIR;
  if (explicitDir && explicitDir.trim().length > 0) {
    try {
      const serviceJsonPath = path.join(explicitDir.trim(), "service.json");
      if (fs.existsSync(serviceJsonPath)) {
        const raw = fs.readFileSync(serviceJsonPath, "utf8");
        const parsed = JSON.parse(raw);
        if (typeof parsed?.password === "string" && parsed.password.trim().length > 0) {
          return parsed.password.trim();
        }
      }
    } catch {
      // Fall back to env vars if service.json is unreadable
    }
    if (envPassword && envPassword.trim().length > 0) {
      return envPassword.trim();
    }
    return "";
  }

  const candidateDirs: string[] = [];
  if (process.env.XDG_STATE_HOME && process.env.XDG_STATE_HOME.trim().length > 0) {
    candidateDirs.push(path.join(process.env.XDG_STATE_HOME.trim(), "opencode"));
  }
  if (process.env.XDG_CONFIG_HOME && process.env.XDG_CONFIG_HOME.trim().length > 0) {
    candidateDirs.push(path.join(process.env.XDG_CONFIG_HOME.trim(), "opencode"));
  }
  candidateDirs.push(path.join(os.homedir(), ".local", "state", "opencode"));
  candidateDirs.push(path.join(os.homedir(), ".config", "opencode"));

  for (const dir of candidateDirs) {
    try {
      const serviceJsonPath = path.join(dir, "service.json");
      if (fs.existsSync(serviceJsonPath)) {
        const raw = fs.readFileSync(serviceJsonPath, "utf8");
        const parsed = JSON.parse(raw);
        if (typeof parsed?.password === "string" && parsed.password.trim().length > 0) {
          return parsed.password.trim();
        }
      }
    } catch {
      // Ignore unreadable or malformed service.json while scanning candidates
    }
  }

  if (envPassword && envPassword.trim().length > 0) {
    return envPassword.trim();
  }

  return "";
}

export function resolveCurrentProcessServiceUrl(configDir?: string): string | undefined {
  const candidateDirs: string[] = [];
  const explicitDir = configDir || process.env.OPENCODE_CONFIG_DIR;
  if (explicitDir && explicitDir.trim().length > 0) {
    candidateDirs.push(explicitDir.trim());
  } else {
    if (process.env.XDG_STATE_HOME && process.env.XDG_STATE_HOME.trim().length > 0) {
      candidateDirs.push(path.join(process.env.XDG_STATE_HOME.trim(), "opencode"));
    }
    if (process.env.XDG_CONFIG_HOME && process.env.XDG_CONFIG_HOME.trim().length > 0) {
      candidateDirs.push(path.join(process.env.XDG_CONFIG_HOME.trim(), "opencode"));
    }
    candidateDirs.push(path.join(os.homedir(), ".local", "state", "opencode"));
    candidateDirs.push(path.join(os.homedir(), ".config", "opencode"));
  }

  for (const dir of candidateDirs) {
    try {
      const serviceJsonPath = path.join(dir, "service.json");
      if (!fs.existsSync(serviceJsonPath)) continue;
      const raw = fs.readFileSync(serviceJsonPath, "utf8");
      const parsed = JSON.parse(raw) as { pid?: unknown; url?: unknown };
      if (
        parsed?.pid === process.pid &&
        typeof parsed.url === "string" &&
        parsed.url.trim().length > 0
      ) {
        return parsed.url.trim().replace(/\/+$/, "");
      }
    } catch {
      // Ignore unreadable or malformed service.json while scanning candidates
    }
  }

  return undefined;
}

export function buildOpenCodeGateAction(
  request: PermissionEventData,
  context: {
    workspaceRoot: string;
    userPrompt: string;
    subagentPrompt?: string;
    environment?: EnvironmentConfig;
    signal?: AbortSignal;
  },
): GateAction {
  const nonEmptyStringList = (val: unknown): string[] | undefined => {
    if (!Array.isArray(val)) return undefined;
    const strings = val.filter(
      (item): item is string => typeof item === "string" && item.trim().length > 0,
    );
    return strings.length > 0 ? strings : undefined;
  };
  const isSoleWildcardPlaceholder = (list: string[] | undefined): boolean =>
    Boolean(list && list.length === 1 && list[0].trim() === "*");

  const rawResources = nonEmptyStringList(request.resources);
  const rawPatterns = nonEmptyStringList(request.patterns);
  const metaFiles = Array.isArray(request.metadata?.files)
    ? (request.metadata.files as Array<Record<string, unknown>>)
    : undefined;
  const hasMcpInput =
    Boolean(request.metadata) &&
    typeof request.metadata === "object" &&
    "input" in request.metadata! &&
    request.metadata!.input !== undefined;
  const hasStructuredMeta = hasMcpInput || Boolean(metaFiles && metaFiles.length > 0);

  const resources =
    hasStructuredMeta && isSoleWildcardPlaceholder(rawResources) ? undefined : rawResources;
  const patterns =
    hasStructuredMeta && isSoleWildcardPlaceholder(rawPatterns) ? undefined : rawPatterns;

  const toolName = request.action || request.permission || request.source?.type || "permission";

  const commandString =
    typeof request.metadata?.command === "string" && request.metadata.command.trim().length > 0
      ? request.metadata.command
      : typeof request.metadata?.cmd === "string" && request.metadata.cmd.trim().length > 0
        ? request.metadata.cmd
        : (resources?.join(" ") ?? patterns?.join(" "));

  const metaFilePaths = (metaFiles ?? [])
    .map((entry) => (typeof entry?.file === "string" ? entry.file.trim() : ""))
    .filter((f) => f.length > 0);
  const firstMetaFile = metaFilePaths[0];
  const isFileTool = toolName === "read" || toolName === "edit" || toolName === "write";

  const targetPath =
    typeof request.metadata?.filepath === "string" && request.metadata.filepath.trim().length > 0
      ? request.metadata.filepath
      : typeof request.metadata?.path === "string" && request.metadata.path.trim().length > 0
        ? request.metadata.path
        : typeof request.metadata?.file === "string" && request.metadata.file.trim().length > 0
          ? request.metadata.file
          : (firstMetaFile ?? (isFileTool ? (resources?.[0] ?? patterns?.[0]) : undefined));

  const allEditPaths =
    metaFiles && metaFiles.length > 0
      ? Array.from(new Set([...(resources ?? []), ...(patterns ?? []), ...metaFilePaths]))
      : [];
  const effectivePatterns = patterns ?? (allEditPaths.length > 1 ? allEditPaths : undefined);

  const rawArgs =
    metaFiles && metaFiles.length > 0
      ? { ...(targetPath ? { path: targetPath } : {}), files: metaFiles }
      : hasMcpInput
        ? resources || patterns
          ? { resources: resources ?? patterns, input: request.metadata!.input }
          : request.metadata!.input
        : (resources ?? patterns ?? request.metadata);

  const sessionID = (request.sessionID as string) || "";
  const signal = context.signal ?? (request as { signal?: AbortSignal }).signal;
  return {
    id: (request.id as string) || Math.random().toString(36).slice(2),
    harness: (request.harness as string) || "opencode",
    sessionID,
    toolName,
    commandString,
    targetPath,
    ...(effectivePatterns ? { patterns: effectivePatterns } : {}),
    rawArgs,
    workspaceRoot: (request.metadata?.directory as string) || context.workspaceRoot,
    userPrompt: context.userPrompt,
    subagentPrompt: context.subagentPrompt,
    environment: context.environment,
    metadata: request.metadata,
    ...(signal ? { signal } : {}),
  };
}
