import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { fileURLToPath } from "url";
import { tool, type Hooks, type PluginInput } from "@opencode-ai/plugin";
import type { UserMessage, Part } from "@opencode-ai/sdk";
import {
  loadConfig,
  NtfyAdapter,
  AutoGateCoreEngine,
  recordEscalationIntent,
  isClassifierVerdict,
  isRiskLevel,
  isUserAuthorization,
  type HarnessAdapter,
  type PermissionEventData,
  type GateAction,
  type AutoGateConfig,
  type ClassifierVerdict,
  type RiskLevel,
  type UserAuthorization,
} from "@autogate/core";
import {
  OpenCodeSessionEvaluator,
  isEvaluationSession,
  recordEvaluationVerdict,
  evaluationSessions,
} from "./evaluator.js";
import { OpenCodePromptResolver } from "./prompt-resolver.js";
import type { OpenCodeSessionClient, OpenCodeEvent, OpenCodePluginInput } from "./types.js";

export function isEventForWorkspace(event: unknown, workspaceDir?: string): boolean {
  if (!workspaceDir) return true;
  if (!event || typeof event !== "object") return true;

  const ev = event as Record<string, unknown>;
  const normalizedWs = path.resolve(workspaceDir);

  // 1. Authoritative workspace directory in OpenCode v2 events
  if (
    ev.location &&
    typeof ev.location === "object" &&
    typeof (ev.location as Record<string, unknown>).directory === "string"
  ) {
    const locDir = (ev.location as Record<string, unknown>).directory as string;
    if (locDir.trim().length > 0) {
      return path.resolve(locDir) === normalizedWs;
    }
  }

  // 2. Fall back to event data directory metadata
  const eventData = (ev.properties || ev.data) as Record<string, unknown> | undefined;
  const meta = eventData?.metadata as Record<string, unknown> | undefined;
  const dataDir =
    typeof meta?.directory === "string"
      ? meta.directory
      : typeof eventData?.directory === "string"
        ? eventData.directory
        : undefined;

  if (!dataDir) {
    return true;
  }

  const resolvedDataDir = path.resolve(dataDir);
  return resolvedDataDir === normalizedWs || resolvedDataDir.startsWith(normalizedWs + path.sep);
}

export {
  OpenCodeSessionEvaluator,
  isEvaluationSession,
  recordEvaluationVerdict,
  evaluationSessions,
};
export * from "./types.js";
export * from "./prompt-resolver.js";

export function ensureAgentInstalled(): void {
  try {
    const homeDir = os.homedir();
    const agentsDir = path.join(homeDir, ".config", "opencode", "agents");
    const targetFile = path.join(agentsDir, "auto-gate-eval.md");
    const __dirname = path.dirname(fileURLToPath(import.meta.url));
    const pluginAgentFile = path.resolve(__dirname, "../../core/agents/auto-gate-eval.md");

    if (!fs.existsSync(pluginAgentFile)) {
      return;
    }

    if (!fs.existsSync(agentsDir)) {
      fs.mkdirSync(agentsDir, { recursive: true });
    }

    try {
      const stats = fs.lstatSync(targetFile);
      if (stats.isSymbolicLink()) {
        const currentLink = fs.readlinkSync(targetFile);
        if (path.resolve(path.dirname(targetFile), currentLink) === pluginAgentFile) {
          return;
        }
        fs.unlinkSync(targetFile);
      } else {
        fs.unlinkSync(targetFile);
      }
    } catch (e: unknown) {
      if (e && typeof e === "object" && "code" in e && (e as { code?: string }).code !== "ENOENT") {
        return;
      }
    }

    fs.symlinkSync(pluginAgentFile, targetFile);
  } catch {
    // Non-fatal if filesystem is readonly or symlink fails in test harnesses
  }
}

export function resolveServerPassword(configDir?: string): string {
  const envPassword = process.env.OPENCODE_SERVER_PASSWORD || process.env.OPENCODE_PASSWORD;
  if (envPassword && envPassword.trim().length > 0) {
    return envPassword.trim();
  }

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
    } catch {}
    return "";
  }

  const candidateDirs: string[] = [];
  if (process.env.XDG_CONFIG_HOME && process.env.XDG_CONFIG_HOME.trim().length > 0) {
    candidateDirs.push(path.join(process.env.XDG_CONFIG_HOME.trim(), "opencode"));
    candidateDirs.push(path.join(process.env.XDG_CONFIG_HOME.trim(), "opencode2"));
  }
  candidateDirs.push(path.join(os.homedir(), ".config", "opencode"));
  candidateDirs.push(path.join(os.homedir(), ".config", "opencode2"));

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
    } catch {}
  }

  return "";
}

export class OpenCodeHarnessAdapter implements HarnessAdapter {
  readonly name = "opencode-harness";
  private engine: AutoGateCoreEngine;
  private promptResolver: OpenCodePromptResolver;
  private stopListener?: () => void;
  private ctx: PluginInput;
  private config: AutoGateConfig;
  readonly serverUrl: string;

  constructor(ctx: PluginInput, options?: Record<string, unknown>) {
    this.ctx = ctx;
    ensureAgentInstalled();
    const config = loadConfig(options);
    this.config = config;
    const serverUrl = config.opencode?.serverUrl || config.serverUrl || "http://localhost:4096";
    this.serverUrl = serverUrl;
    config.serverUrl = serverUrl;
    const adapter = new NtfyAdapter({
      server: config.ntfyServer,
      topic: config.ntfyTopic,
      token: config.ntfyToken,
    });

    const workspaceRoot = ctx.directory || ctx.worktree || process.cwd();

    const client = (ctx.client ?? ctx) as unknown as OpenCodeSessionClient;
    this.promptResolver = new OpenCodePromptResolver(client);
    this.engine = new AutoGateCoreEngine({
      config,
      adapter,
      evaluator: new OpenCodeSessionEvaluator(client, config),
      workspaceRoot,
      remoteReviewEnabled: true,
    });
  }

  async start(): Promise<void> {
    this.stopListener = await this.engine.start();
  }

  async dispose(): Promise<void> {
    await this.engine.stop();
    if (this.stopListener) {
      this.stopListener();
      this.stopListener = undefined;
    }
  }

  getEngine(): AutoGateCoreEngine {
    return this.engine;
  }

  async handlePermissionAsked(request: PermissionEventData): Promise<void> {
    const workspaceRoot = this.ctx.directory || this.ctx.worktree || process.cwd();
    const requestDir = (request?.metadata?.directory || request?.directory) as string | undefined;
    if (requestDir && (this.ctx.directory || this.ctx.worktree)) {
      const explicitWs = this.ctx.directory || this.ctx.worktree;
      const normalizedReq = path.resolve(requestDir);
      const normalizedWs = path.resolve(explicitWs);
      if (normalizedReq !== normalizedWs && !normalizedReq.startsWith(normalizedWs + path.sep)) {
        return;
      }
    }
    const commandString =
      typeof request.metadata?.command === "string"
        ? request.metadata.command
        : Array.isArray(request.resources) && typeof request.resources[0] === "string"
          ? request.resources[0]
          : undefined;

    const toolName = request.permission || request.action || request.source?.type || "permission";

    const sessionID = (request.sessionID as string) || "";
    const resolvedPrompts = await this.promptResolver.resolveSessionPrompts(
      sessionID,
      undefined,
      this.engine.getUserPrompt(sessionID),
    );

    const parentID = this.promptResolver.getParentSessionID(sessionID);
    if (parentID) {
      this.engine.setSessionParent(sessionID, parentID);
    }
    if (resolvedPrompts.userPrompt) {
      this.engine.setUserPrompt(sessionID, resolvedPrompts.userPrompt);
    }

    const action: GateAction = {
      id: (request.id as string) || Math.random().toString(36).slice(2),
      harness: (request.harness as string) || "opencode",
      sessionID,
      toolName,
      commandString,
      targetPath:
        typeof request.metadata?.filepath === "string" ? request.metadata.filepath : undefined,
      rawArgs: request.patterns || request.resources || request.metadata,
      workspaceRoot: (request.metadata?.directory as string) || workspaceRoot,
      userPrompt: resolvedPrompts.userPrompt,
      subagentPrompt: resolvedPrompts.subagentPrompt,
      environment: this.config.environment,
      metadata: request.metadata,
    };
    const decision = await this.engine.evaluate(action);
    const replyVal = decision.reply || (decision.verdict === "ALLOW" ? "once" : "reject");
    const targetDir = (request.metadata?.directory as string) || workspaceRoot;
    await this.replyPermission(
      request.id as string,
      replyVal,
      sessionID,
      decision.reason,
      targetDir,
    );
  }

  private async replyPermission(
    requestID: string,
    reply: "once" | "always" | "reject",
    sessionID?: string,
    message?: string,
    directory?: string,
  ): Promise<void> {
    const ctxAny = this.ctx as unknown as {
      permission?: { reply?(opts: unknown): Promise<unknown> };
      configDir?: string;
    };
    if (ctxAny.permission && typeof ctxAny.permission.reply === "function") {
      try {
        await ctxAny.permission.reply({
          path: { requestID },
          body: {
            reply,
            decision: reply,
            message,
          },
          query: directory ? { directory } : undefined,
        });
        return;
      } catch {}
    }

    const serverUrl = this.serverUrl || "http://localhost:4096";
    const password = resolveServerPassword(
      typeof ctxAny.configDir === "string" ? ctxAny.configDir : undefined,
    );
    const authHeader = "Basic " + Buffer.from(`opencode:${password}`).toString("base64");
    const workspaceRoot = this.ctx.directory || this.ctx.worktree;
    const targetDir = directory || workspaceRoot;
    const urls = [
      sessionID
        ? `${serverUrl}/api/session/${encodeURIComponent(sessionID)}/permission/${encodeURIComponent(requestID)}/reply`
        : undefined,
      sessionID
        ? `${serverUrl}/session/${encodeURIComponent(sessionID)}/permission/${encodeURIComponent(requestID)}/reply`
        : undefined,
      `${serverUrl}/api/permission/${encodeURIComponent(requestID)}/reply`,
      `${serverUrl}/permission/${encodeURIComponent(requestID)}/reply`,
    ].filter(Boolean) as string[];
    for (const u of urls) {
      const fullUrl = `${u}${targetDir ? `?directory=${encodeURIComponent(targetDir)}` : ""}`;
      try {
        const res = await fetch(fullUrl, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: authHeader,
          },
          body: JSON.stringify({ decision: reply, message }),
          signal: AbortSignal.timeout(5000),
        });
        if (res.ok && !res.headers.get("content-type")?.includes("text/html")) {
          return;
        }
      } catch {}
    }

    const client = this.ctx.client as unknown as OpenCodeSessionClient | undefined;
    if (!client) return;
    if (typeof client.postSessionIdPermissionsPermissionId === "function" && sessionID) {
      try {
        const res = await client.postSessionIdPermissionsPermissionId({
          path: { id: sessionID, permissionID: requestID },
          body: { response: reply },
          query: targetDir ? { directory: targetDir } : undefined,
        });
        if (!res?.error && res?.response?.ok !== false) return;
      } catch {}
    }
    if (typeof client.permission?.reply === "function") {
      try {
        const res = await client.permission.reply({
          path: { requestID },
          body: { reply, message },
          query: targetDir ? { directory: targetDir } : undefined,
        });
        if (!res?.error && res?.response?.ok !== false) return;
      } catch {}
    }
  }

  async handlePermissionReplied(data: {
    requestID?: string;
    id?: string;
    reply?: string;
  }): Promise<void> {
    this.engine.handlePermissionReplied(data);
  }

  clearTurnCache(sessionID: string): void {
    this.engine.clearTurnCache(sessionID);
  }
}

export async function AutoGatePlugin(
  ctx: PluginInput,
  options?: Record<string, unknown>,
): Promise<Hooks> {
  const adapter = new OpenCodeHarnessAdapter(ctx, options);
  const engine = adapter.getEngine();
  await adapter.start();

  const config = loadConfig(options);
  console.log(
    `AutoGate Plugin initialized (model: ${config.classifierModel}, topic: ${config.ntfyTopic})`,
  );
  try {
    await ctx.client.app.log({
      body: {
        service: "auto-gate",
        level: "info",
        message: `AutoGate Plugin initialized (model: ${config.classifierModel}, topic: ${config.ntfyTopic})`,
      },
    });
  } catch {}

  const hooks: Hooks = {
    tool: {
      classify_result: tool({
        description:
          "Report the security classification result for the agent action (internal evaluation tool)",
        args: {
          risk_level: tool.schema.enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
          user_authorization: tool.schema.enum(["NONE", "LOW", "MEDIUM", "HIGH"]),
          verdict: tool.schema.enum(["ALLOW", "BLOCK", "UNSURE"]),
          reason: tool.schema.string(),
        },
        async execute(args: Record<string, unknown>, context: { sessionID?: string }) {
          if (!context.sessionID || !isEvaluationSession(context.sessionID)) {
            throw new Error(
              "classify_result is an internal security tool reserved exclusively for AutoGate evaluation sessions.",
            );
          }
          const verdictStr = typeof args.verdict === "string" ? args.verdict : "UNSURE";
          const riskStr = typeof args.risk_level === "string" ? args.risk_level : undefined;
          const authStr =
            typeof args.user_authorization === "string" ? args.user_authorization : undefined;
          const reasonStr = typeof args.reason === "string" ? args.reason : "";
          recordEvaluationVerdict(context.sessionID, {
            verdict: isClassifierVerdict(verdictStr) ? verdictStr : "UNSURE",
            risk_level: isRiskLevel(riskStr) ? riskStr : undefined,
            user_authorization: isUserAuthorization(authStr) ? authStr : undefined,
            reason: reasonStr,
          });
          const client = ctx.client as unknown as OpenCodeSessionClient | undefined;
          client?.session?.abort?.({ path: { id: context.sessionID } }).catch(() => {});
          return {
            output: JSON.stringify(args),
          };
        },
      }),
      escalate_permission: tool({
        description:
          "Request human manual verification for a blocked or high-risk action when safe automated transformations cannot satisfy the goal.",
        args: {
          action: tool.schema
            .string()
            .describe(
              "The command or target path requiring human approval (e.g. '/etc/hosts' or 'rm -rf dist')",
            ),
          reason: tool.schema
            .string()
            .describe(
              "Why the safe alternative or automated transform cannot be used and human review is required",
            ),
        },
        async execute(args: Record<string, unknown>, context: { sessionID?: string }) {
          const actionStr = typeof args.action === "string" ? args.action : "";
          const reasonStr = typeof args.reason === "string" ? args.reason : "";
          if (context.sessionID) {
            recordEscalationIntent(context.sessionID, actionStr, reasonStr);
          }
          return {
            output: `Manual verification intent registered for '${actionStr}'. Please re-issue your tool call now; it will be forwarded directly to the user's phone for manual approval.`,
          };
        },
      }),
    },

    dispose: async () => {
      await adapter.dispose();
    },

    "chat.message": async (
      input: { sessionID: string; messageID?: string },
      output: { message?: UserMessage; parts?: Part[] },
    ) => {
      if (!output || !Array.isArray(output.parts)) return;
      if (output.message && output.message.role && output.message.role !== "user") return;

      const textParts = output.parts
        .filter(
          (p): p is Part & { type: "text"; text: string } =>
            p !== null && typeof p === "object" && p.type === "text" && typeof p.text === "string",
        )
        .map((p) => p.text)
        .join("\n")
        .trim();

      if (input?.sessionID && isEvaluationSession(input.sessionID)) return;
      if (
        textParts.includes("## Environment Trust Boundaries:") ||
        textParts.includes("## Context:") ||
        textParts.includes("### Conversation Transcript") ||
        textParts.startsWith("[auto-gate-eval]")
      ) {
        return;
      }
      if (textParts && input?.sessionID) {
        engine.setUserPrompt(input.sessionID, textParts);
      } else if (textParts) {
        engine.setUserPrompt(textParts);
      }

      const trimmed = textParts.trim().toLowerCase();
      if (trimmed.startsWith("/automode") || trimmed.startsWith("automode")) {
        const parts = trimmed.split(/\s+/);
        const arg = parts[1] || "";
        if (arg === "off" || arg === "disable" || arg === "false" || arg === "0") {
          engine.setEnabled(false);
        } else if (arg === "on" || arg === "enable" || arg === "true" || arg === "1") {
          engine.setEnabled(true);
        } else if (arg === "toggle") {
          engine.setEnabled(!engine.isEnabled());
        }
      }
    },

    event: async (input: { event: unknown }) => {
      const event = input.event as OpenCodeEvent | undefined;
      if (!event || !event.type) return;

      const workspaceDir = ctx.directory || ctx.worktree;
      if (workspaceDir && !isEventForWorkspace(event, workspaceDir)) {
        return;
      }

      if (event.type === "permission.asked" || event.type === "permission.v2.asked") {
        const eventData = (event.properties || event.data) as PermissionEventData | undefined;
        if (eventData) {
          await adapter.handlePermissionAsked(eventData);
        }
      } else if (event.type === "permission.replied" || event.type === "permission.v2.replied") {
        const eventData = (event.properties || event.data) as
          | { requestID?: string; id?: string; reply?: string }
          | undefined;
        if (eventData) {
          await adapter.handlePermissionReplied(eventData);
        }
      } else if (
        event.type === "session.idle" ||
        (event.type === "session.status" &&
          ((event.properties as Record<string, unknown> | undefined)?.status === "idle" ||
            event.data?.status === "idle"))
      ) {
        const sessionID =
          (event.properties as Record<string, unknown> | undefined)?.sessionID ||
          event.data?.sessionID;
        if (typeof sessionID === "string") {
          adapter.clearTurnCache(sessionID);
        }
      }
    },

    "command.execute.before": async (
      input: { command: string; sessionID: string; arguments: string },
      output: { parts: Part[] },
    ) => {
      if (input.command === "automode" || input.command === "auto-mode") {
        const arg = (input.arguments || "").trim().toLowerCase();

        let msg = "";
        if (arg === "off" || arg === "disable" || arg === "false" || arg === "0") {
          engine.setEnabled(false);
          msg = "Auto Mode is now DISABLED (all requests route to ntfy).";
        } else if (arg === "on" || arg === "enable" || arg === "true" || arg === "1") {
          engine.setEnabled(true);
          msg = "Auto Mode is now ENABLED (classifier active).";
        } else if (arg === "status" || !arg) {
          const status = engine.isEnabled()
            ? "ENABLED (classifier active)"
            : "DISABLED (routing to remote)";
          msg = `Auto Mode status: ${status}`;
        } else {
          const nextState = !engine.isEnabled();
          engine.setEnabled(nextState);
          msg = `Auto Mode toggled to: ${nextState ? "ENABLED" : "DISABLED"}`;
        }

        output.parts = [
          {
            id: `part-${Date.now()}`,
            sessionID: input.sessionID,
            messageID: `msg-${Date.now()}`,
            type: "text",
            text: `[SYSTEM DIRECTIVE]: The user executed /automode. Output ONLY this exact single line and nothing else:\n[auto-gate] ${msg}`,
          } as unknown as Part,
        ];
      }
    },
  };

  return hooks;
}

export const plugin = {
  id: "auto-gate",
  async setup(ctx: OpenCodePluginInput) {
    const opts =
      typeof ctx.options === "object" && ctx.options !== null
        ? (ctx.options as Record<string, unknown>)
        : undefined;
    const adapter = new OpenCodeHarnessAdapter(ctx as unknown as PluginInput, opts);
    await adapter.start();

    const config = loadConfig(opts);
    console.log(
      `AutoGate Plugin initialized (model: ${config.classifierModel}, topic: ${config.ntfyTopic})`,
    );

    // Register tools via ctx.tool.transform if available
    if (ctx.tool && typeof ctx.tool.transform === "function") {
      await ctx.tool.transform((editor: { add(toolDef: unknown): void }) => {
        editor.add({
          name: "classify_result",
          options: { codemode: false },
          description:
            "Report the security classification result for the agent action (internal evaluation tool)",
          input: {
            type: "object",
            properties: {
              risk_level: { type: "string", enum: ["LOW", "MEDIUM", "HIGH", "CRITICAL"] },
              user_authorization: { type: "string", enum: ["NONE", "LOW", "MEDIUM", "HIGH"] },
              verdict: { type: "string", enum: ["ALLOW", "BLOCK", "UNSURE"] },
              reason: { type: "string" },
            },
            required: ["risk_level", "user_authorization", "verdict", "reason"],
          },
          async execute(args: Record<string, unknown>, context: { sessionID?: string }) {
            if (!context.sessionID || !isEvaluationSession(context.sessionID)) {
              throw new Error(
                "classify_result is an internal security tool reserved exclusively for AutoGate evaluation sessions.",
              );
            }
            const verdictStr = typeof args.verdict === "string" ? args.verdict : "UNSURE";
            const riskStr = typeof args.risk_level === "string" ? args.risk_level : undefined;
            const authStr =
              typeof args.user_authorization === "string" ? args.user_authorization : undefined;
            const reasonStr = typeof args.reason === "string" ? args.reason : "";
            recordEvaluationVerdict(context.sessionID, {
              verdict: isClassifierVerdict(verdictStr) ? verdictStr : "UNSURE",
              risk_level: isRiskLevel(riskStr) ? riskStr : undefined,
              user_authorization: isUserAuthorization(authStr) ? authStr : undefined,
              reason: reasonStr,
            });
            (
              ctx as unknown as { session?: { interrupt?: (id: string) => Promise<unknown> } }
            ).session
              ?.interrupt?.(context.sessionID)
              .catch(() => {});
            return {
              content: JSON.stringify(args),
            };
          },
        });

        editor.add({
          name: "escalate_permission",
          options: { codemode: false },
          description:
            "Request human manual verification for a blocked or high-risk action when safe automated transformations cannot satisfy the goal.",
          input: {
            type: "object",
            properties: {
              action: {
                type: "string",
                description:
                  "The command or target path requiring human approval (e.g. '/etc/hosts' or 'rm -rf dist')",
              },
              reason: {
                type: "string",
                description:
                  "Why the safe alternative or automated transform cannot be used and human review is required",
              },
            },
            required: ["action", "reason"],
          },
          async execute(args: Record<string, unknown>, context: { sessionID?: string }) {
            const actionStr = typeof args.action === "string" ? args.action : "";
            const reasonStr = typeof args.reason === "string" ? args.reason : "";
            if (context.sessionID) {
              recordEscalationIntent(context.sessionID, actionStr, reasonStr);
            }
            return {
              content: `Manual verification intent registered for '${actionStr}'. Please re-issue your tool call now; it will be forwarded directly to the user's phone for manual approval.`,
            };
          },
        });
      });
    }

    // Subscribe to events
    const eventObj = ctx.event as unknown as
      | { subscribe(opts?: { signal?: AbortSignal }): Promise<AsyncIterable<OpenCodeEvent>> }
      | undefined;
    if (eventObj && typeof eventObj.subscribe === "function") {
      const controller = new AbortController();
      const subscribeFn = eventObj.subscribe.bind(eventObj);
      (async () => {
        try {
          const stream = await subscribeFn({ signal: controller.signal });
          for await (const event of stream) {
            const workspaceDir = ctx.directory || ctx.worktree;
            if (workspaceDir && !isEventForWorkspace(event, workspaceDir)) {
              continue;
            }

            if (event.type === "permission.asked" || event.type === "permission.v2.asked") {
              const eventData = event.properties || event.data;
              if (eventData) {
                await adapter.handlePermissionAsked(eventData);
              }
            } else if (
              event.type === "permission.replied" ||
              event.type === "permission.v2.replied"
            ) {
              const eventData = event.properties || event.data;
              if (eventData) {
                await adapter.handlePermissionReplied(eventData);
              }
            } else if (
              event.type === "session.idle" ||
              (event.type === "session.status" &&
                (event.properties?.status === "idle" || event.data?.status === "idle"))
            ) {
              const sessionID = event.properties?.sessionID || event.data?.sessionID;
              if (typeof sessionID === "string" && sessionID.length > 0) {
                adapter.clearTurnCache(sessionID);
              }
            }
          }
        } catch {}
      })();
    }

    return async () => {
      await adapter.dispose();
    };
  },
  server: AutoGatePlugin,
};

export default plugin;
