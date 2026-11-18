import * as path from "path";
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
  buildClassifierSystemPrompt,
  type HarnessAdapter,
  type PermissionEventData,
  type GateAction,
  type GateEvaluator,
  type AutoGateConfig,
} from "@autogate/core";
import {
  OpenCodeV1SessionEvaluator,
  isEvaluationSession,
  recordEvaluationVerdict,
  evaluationSessions,
  logEvaluationDecision,
} from "./evaluator.js";
import { OpenCodeV1PromptResolver } from "./prompt-resolver.js";
import type { OpenCodeV1SessionClient, OpenCodeV1Event } from "./types.js";

export function resolveWorkspaceDirectory(val: unknown): string | undefined {
  if (typeof val === "string" && val.trim().length > 0) {
    return val.trim();
  }
  if (typeof val === "object" && val !== null) {
    const obj = val as Record<string, unknown>;
    if (typeof obj.directory === "string" && obj.directory.trim().length > 0) {
      return obj.directory.trim();
    }
    if (typeof obj.path === "string" && obj.path.trim().length > 0) {
      return obj.path.trim();
    }
  }
  return undefined;
}

export function isEventForWorkspace(event: unknown, workspaceDir?: unknown): boolean {
  const wsDir = resolveWorkspaceDirectory(workspaceDir);
  if (!wsDir) return true;
  const normalizedWs = path.resolve(wsDir);

  if (typeof event === "object" && event !== null) {
    const ev = event as Record<string, unknown>;
    const locDir = resolveWorkspaceDirectory(ev.location);
    if (locDir) {
      const resolvedLoc = path.resolve(locDir);
      return resolvedLoc === normalizedWs || normalizedWs.startsWith(resolvedLoc + path.sep);
    }
  }

  const evObj = typeof event === "object" && event !== null ? (event as OpenCodeV1Event) : {};
  const eventData = (evObj.properties || evObj.data) as Record<string, unknown> | undefined;
  const meta =
    eventData && typeof eventData.metadata === "object" && eventData.metadata !== null
      ? (eventData.metadata as Record<string, unknown>)
      : undefined;
  const dataDir =
    resolveWorkspaceDirectory(meta?.directory) ?? resolveWorkspaceDirectory(eventData?.directory);

  if (!dataDir) {
    return true;
  }

  const resolvedDataDir = path.resolve(dataDir);
  return resolvedDataDir === normalizedWs || resolvedDataDir.startsWith(normalizedWs + path.sep);
}

export {
  OpenCodeV1SessionEvaluator,
  isEvaluationSession,
  recordEvaluationVerdict,
  evaluationSessions,
};
export * from "./types.js";
export * from "./prompt-resolver.js";

export class OpenCodeV1HarnessAdapter implements HarnessAdapter {
  readonly name = "opencode1-harness";
  private engine: AutoGateCoreEngine;
  private promptResolver: OpenCodeV1PromptResolver;
  private stopListener?: () => void;
  private ctx: PluginInput;
  private config: AutoGateConfig;
  readonly serverUrl: string;

  constructor(ctx: PluginInput, options?: Record<string, unknown>) {
    this.ctx = ctx;
    const config = loadConfig(options);
    this.config = config;
    const serverUrl =
      config.opencode?.serverUrl ||
      (options?.serverUrl as string | undefined) ||
      process.env.OPENCODE_SERVER_URL ||
      "http://localhost:4097";
    this.serverUrl = serverUrl;
    config.serverUrl = serverUrl;
    const adapter = new NtfyAdapter({
      server: config.ntfyServer,
      topic: config.ntfyTopic,
      token: config.ntfyToken,
    });

    const workspaceRoot =
      resolveWorkspaceDirectory(ctx.directory) ??
      resolveWorkspaceDirectory(ctx.worktree) ??
      process.cwd();

    const client = ctx.client as unknown as OpenCodeV1SessionClient;
    this.promptResolver = new OpenCodeV1PromptResolver(client);
    const evaluator =
      (options?.evaluator as GateEvaluator | undefined) ??
      new OpenCodeV1SessionEvaluator(client, config);
    const remoteReviewEnabled =
      typeof options?.remoteReviewEnabled === "boolean"
        ? options.remoteReviewEnabled
        : config.reviewFallbackMode !== "native";
    this.engine = new AutoGateCoreEngine({
      config,
      adapter,
      evaluator,
      workspaceRoot,
      remoteReviewEnabled,
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
    const workspaceRoot =
      resolveWorkspaceDirectory(this.ctx.directory) ??
      resolveWorkspaceDirectory(this.ctx.worktree) ??
      process.cwd();
    const explicitWs =
      resolveWorkspaceDirectory(this.ctx.directory) ?? resolveWorkspaceDirectory(this.ctx.worktree);
    const requestDir =
      resolveWorkspaceDirectory(request?.metadata?.directory) ??
      resolveWorkspaceDirectory(request?.directory);
    if (requestDir && explicitWs) {
      const normalizedReq = path.resolve(requestDir);
      const normalizedWs = path.resolve(explicitWs);
      if (normalizedReq !== normalizedWs && !normalizedReq.startsWith(normalizedWs + path.sep)) {
        return;
      }
    }
    const nonEmptyStringList = (val: unknown): string[] | undefined => {
      if (!Array.isArray(val)) return undefined;
      const strings = val.filter(
        (item): item is string => typeof item === "string" && item.trim().length > 0,
      );
      return strings.length > 0 ? strings : undefined;
    };

    const resources = nonEmptyStringList(request.resources);
    const patterns = nonEmptyStringList(request.patterns);
    const commandString =
      typeof request.metadata?.command === "string" && request.metadata.command.trim().length > 0
        ? request.metadata.command
        : typeof request.metadata?.cmd === "string" && request.metadata.cmd.trim().length > 0
          ? request.metadata.cmd
          : (resources?.join(" ") ?? patterns?.join(" "));

    const targetPath =
      typeof request.metadata?.filepath === "string" && request.metadata.filepath.trim().length > 0
        ? request.metadata.filepath
        : typeof request.metadata?.path === "string" && request.metadata.path.trim().length > 0
          ? request.metadata.path
          : typeof request.metadata?.file === "string" && request.metadata.file.trim().length > 0
            ? request.metadata.file
            : undefined;

    const toolName = request.action || request.permission || "permission";

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

    const signal = (request as { signal?: AbortSignal }).signal;
    const action: GateAction = {
      id: (request.id as string) || Math.random().toString(36).slice(2),
      harness: (request.harness as string) || "opencode",
      sessionID,
      toolName,
      commandString,
      targetPath,
      ...(patterns ? { patterns } : {}),
      rawArgs: resources ?? patterns ?? request.metadata,
      workspaceRoot: (request.metadata?.directory as string) || workspaceRoot,
      userPrompt: resolvedPrompts.userPrompt,
      subagentPrompt: resolvedPrompts.subagentPrompt,
      environment: this.config.environment,
      metadata: request.metadata,
      ...(signal ? { signal } : {}),
    };
    const evalStartTime = Date.now();
    const decision = await this.engine.evaluate(action);
    const durationMs = Date.now() - evalStartTime;
    if (decision.cascade) {
      logEvaluationDecision(
        {
          timestamp: Date.now(),
          sessionID,
          toolName,
          commandString:
            commandString ?? JSON.stringify(request.patterns || request.metadata || {}),
          userPrompt: action.userPrompt,
          reasoning:
            (typeof decision.metadata?.reasoning === "string"
              ? decision.metadata.reasoning
              : undefined) ?? decision.reason,
          verdict: decision.verdict,
          risk_level: decision.riskLevel,
          user_authorization: decision.userAuthorization,
          durationMs,
          cascade: decision.cascade,
        },
        this.config.evalLogFile,
      );
    }
    if (decision.verdict === "UNSURE" && !decision.reply) {
      return;
    }
    const replyVal = decision.reply || (decision.verdict === "ALLOW" ? "once" : "reject");
    const targetDir = (request.metadata?.directory as string) || workspaceRoot;
    await this.replyPermission(request.id as string, replyVal, decision.reason, targetDir);
  }

  private async replyPermission(
    requestID: string,
    reply: "once" | "always" | "reject",
    message?: string,
    directory?: string,
  ): Promise<void> {
    const client = this.ctx.client as unknown as OpenCodeV1SessionClient | undefined;
    if (client?.permission && typeof client.permission.reply === "function") {
      await client.permission.reply({
        path: { requestID },
        body: {
          reply,
          ...(message ? { message } : {}),
        },
        ...(directory ? { query: { directory } } : {}),
      });
    }
  }

  async handlePermissionReplied(eventData: {
    requestID?: string;
    id?: string;
    reply?: string;
  }): Promise<void> {
    this.engine.handlePermissionReplied(eventData);
  }

  clearTurnCache(sessionID: string): void {
    this.engine.clearTurnCache(sessionID);
  }
}

export async function AutoGatePlugin(
  ctx: PluginInput,
  options?: Record<string, unknown>,
): Promise<Hooks> {
  const adapter = new OpenCodeV1HarnessAdapter(ctx, options);
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
    async config(configData: Record<string, unknown>) {
      if (configData && typeof configData === "object") {
        if (!configData.agent || typeof configData.agent !== "object") {
          configData.agent = {};
        }
        const agentMap = configData.agent as Record<string, unknown>;
        agentMap["auto-gate-eval"] = {
          name: "auto-gate-eval",
          description: "Autonomous security evaluation classifier for AutoGate",
          mode: "subagent",
          hidden: true,
          prompt: buildClassifierSystemPrompt(),
          steps: 3,
          model: config.classifierModel || "google/gemini-3.5-flash-lite",
          permission: {
            "*": "deny",
            classify_result: "allow",
          },
        };
      }
    },
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
          const client = ctx.client as unknown as OpenCodeV1SessionClient | undefined;
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
          const sessionID = typeof context.sessionID === "string" ? context.sessionID : "";
          if (!recordEscalationIntent(sessionID, actionStr, reasonStr)) {
            return {
              output:
                "Unable to register manual verification intent: both a valid sessionID and a non-empty action are required.",
            };
          }
          const delivery = adapter.getEngine().isRemoteReviewEnabled()
            ? "forwarded directly to the user's phone for manual approval"
            : "handled via the native harness prompt for manual approval";
          return {
            output: `Manual verification intent registered for '${actionStr.trim()}'. Please re-issue your tool call now; it will be ${delivery}.`,
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
      const event = input.event as OpenCodeV1Event | undefined;
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
  server: AutoGatePlugin,
};

export default plugin;
