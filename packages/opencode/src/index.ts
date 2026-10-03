import * as fs from "fs"
import * as path from "path"
import * as os from "os"
import { fileURLToPath } from "url"
import { tool, type Hooks, type PluginInput } from "@opencode-ai/plugin"
import type { UserMessage, Part } from "@opencode-ai/sdk"
import {
loadConfig,
NtfyAdapter,
AutoGateCoreEngine,
recordEscalationIntent,
type HarnessAdapter,
type PermissionEventData,
  type GateAction,
} from "@autogate/core"
import {
OpenCodeSessionEvaluator,
isEvaluationSession,
recordEvaluationVerdict,
evaluationSessions,
} from "./evaluator.js"

export function isEventForWorkspace(event: any, workspaceDir?: string): boolean {
  if (!workspaceDir) return true
  const normalizedWs = path.resolve(workspaceDir)

  // 1. Authoritative workspace directory in OpenCode v2 events
  if (typeof event?.location?.directory === "string" && event.location.directory.trim().length > 0) {
    return path.resolve(event.location.directory) === normalizedWs
  }

  // 2. Fall back to event data directory metadata
  const eventData = event?.properties || event?.data
  const dataDir =
    typeof eventData?.metadata?.directory === "string"
      ? eventData.metadata.directory
      : typeof eventData?.directory === "string"
      ? eventData.directory
      : undefined

  if (!dataDir) {
    return true
  }

  const resolvedDataDir = path.resolve(dataDir)
  return resolvedDataDir === normalizedWs || resolvedDataDir.startsWith(normalizedWs + path.sep)
}

export {
  OpenCodeSessionEvaluator,
  isEvaluationSession,
  recordEvaluationVerdict,
  evaluationSessions,
}

export function ensureAgentInstalled(): void {
  try {
    const homeDir = os.homedir()
    const agentsDir = path.join(homeDir, ".config", "opencode", "agents")
    const targetFile = path.join(agentsDir, "auto-gate-eval.md")
    const __dirname = path.dirname(fileURLToPath(import.meta.url))
    const pluginAgentFile = path.resolve(__dirname, "../../core/agents/auto-gate-eval.md")

    if (!fs.existsSync(pluginAgentFile)) {
      return
    }

    if (!fs.existsSync(agentsDir)) {
      fs.mkdirSync(agentsDir, { recursive: true })
    }

    try {
      const stats = fs.lstatSync(targetFile)
      if (stats.isSymbolicLink()) {
        const currentLink = fs.readlinkSync(targetFile)
        if (path.resolve(path.dirname(targetFile), currentLink) === pluginAgentFile) {
          return
        }
        fs.unlinkSync(targetFile)
      } else {
        fs.unlinkSync(targetFile)
      }
    } catch (e: any) {
      if (e?.code !== "ENOENT") {
        return
      }
    }

    fs.symlinkSync(pluginAgentFile, targetFile)
  } catch {
    // Non-fatal if filesystem is readonly or symlink fails in test harnesses
  }
}

export class OpenCodeHarnessAdapter implements HarnessAdapter {
  readonly name = "opencode-harness"
  private engine: AutoGateCoreEngine
  private stopListener?: () => void
  private ctx: PluginInput
  readonly serverUrl: string

  constructor(ctx: PluginInput, options?: Record<string, unknown>) {
    this.ctx = ctx
    ensureAgentInstalled()
    const config = loadConfig(options)
    const serverUrl = config.opencode?.serverUrl || config.serverUrl || "http://localhost:4096"
    this.serverUrl = serverUrl
    config.serverUrl = serverUrl
    const adapter = new NtfyAdapter({
      server: config.ntfyServer,
      topic: config.ntfyTopic,
      token: config.ntfyToken,
    })

    const workspaceRoot = ctx.directory || ctx.worktree || process.cwd()

    const client = ctx.client || (ctx as any)
    this.engine = new AutoGateCoreEngine({
      config,
      client,
      adapter,
      evaluator: new OpenCodeSessionEvaluator(client, config),
      workspaceRoot,
      remoteReviewEnabled: true,
    })
  }

  async start(): Promise<void> {
    this.stopListener = await this.engine.start()
  }

  async dispose(): Promise<void> {
    await this.engine.stop()
    if (this.stopListener) {
      this.stopListener()
      this.stopListener = undefined
    }
  }

  getEngine(): AutoGateCoreEngine {
    return this.engine
  }

  async handlePermissionAsked(request: PermissionEventData): Promise<void> {
    const workspaceRoot = this.ctx.directory || this.ctx.worktree || process.cwd()
    const requestDir = (request?.metadata?.directory || request?.directory) as string | undefined
    if (requestDir && (this.ctx.directory || this.ctx.worktree)) {
      const explicitWs = this.ctx.directory || this.ctx.worktree
      const normalizedReq = path.resolve(requestDir)
      const normalizedWs = path.resolve(explicitWs)
      if (normalizedReq !== normalizedWs && !normalizedReq.startsWith(normalizedWs + path.sep)) {
        return
      }
    }
    const commandString =
      typeof request.metadata?.command === "string"
        ? request.metadata.command
        : Array.isArray((request as any).resources) && typeof (request as any).resources[0] === "string"
        ? (request as any).resources[0]
        : undefined

    const toolName =
      request.permission ||
      (request as any).action ||
      (request as any).source?.type ||
      "permission"

    const action: GateAction = {
      id: request.id || Math.random().toString(36).slice(2),
      harness: request.harness || "opencode",
      sessionID: request.sessionID || "",
      toolName,
      commandString,
      targetPath: typeof request.metadata?.filepath === "string" ? request.metadata.filepath : undefined,
      rawArgs: request.patterns || (request as any).resources || request.metadata,
      workspaceRoot: (request.metadata?.directory as string) || workspaceRoot,
      userPrompt: this.engine.getUserPrompt(request.sessionID),
      environment: (this.engine as any).config?.environment,
      metadata: request.metadata,
    }
    const decision = await this.engine.evaluate(action)
    const replyVal = decision.reply || (decision.verdict === "ALLOW" ? "once" : "reject")
    const targetDir = (request.metadata?.directory as string) || workspaceRoot
    await this.replyPermission(request.id, replyVal, request.sessionID, decision.reason, targetDir)
  }

  private async replyPermission(
    requestID: string,
    reply: "once" | "always" | "reject",
    sessionID?: string,
    message?: string,
    directory?: string
  ): Promise<void> {
    const ctxAny = this.ctx as any
    if (ctxAny.permission && typeof ctxAny.permission.reply === "function") {
      try {
        await ctxAny.permission.reply({
          sessionID: sessionID || "",
          requestID,
          decision: reply,
          reply,
          message,
        })
        return
      } catch {}
    }

    const serverUrl = this.serverUrl || "http://localhost:4096"
    const password = process.env.OPENCODE_SERVER_PASSWORD || ""
    const authHeader = "Basic " + Buffer.from(`opencode:${password}`).toString("base64")
    const workspaceRoot = this.ctx.directory || this.ctx.worktree
    const targetDir = directory || workspaceRoot
    const urls = [
      sessionID ? `${serverUrl}/api/session/${encodeURIComponent(sessionID)}/permission/${encodeURIComponent(requestID)}/reply` : undefined,
      sessionID ? `${serverUrl}/session/${encodeURIComponent(sessionID)}/permission/${encodeURIComponent(requestID)}/reply` : undefined,
      `${serverUrl}/api/permission/${encodeURIComponent(requestID)}/reply`,
      `${serverUrl}/permission/${encodeURIComponent(requestID)}/reply`,
    ].filter(Boolean) as string[]
    for (const u of urls) {
      const fullUrl = `${u}${targetDir ? `?directory=${encodeURIComponent(targetDir)}` : ""}`
      try {
        const res = await fetch(fullUrl, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Authorization": authHeader,
          },
          body: JSON.stringify({ decision: reply, reply, message }),
          signal: AbortSignal.timeout(5000),
        })
        if (res.ok && !res.headers.get("content-type")?.includes("text/html")) {
          return
        }
      } catch {}
    }

    const client = this.ctx.client
    if (!client) return
    if (typeof client?.postSessionIdPermissionsPermissionId === "function" && sessionID) {
      try {
        const res = await client.postSessionIdPermissionsPermissionId({
          path: { id: sessionID, permissionID: requestID },
          body: { response: reply },
          query: targetDir ? { directory: targetDir } : undefined,
})
if (!res?.error && res?.response?.ok !== false) return
} catch {}
}
    if (typeof (client as any)?.permission?.reply === "function") {
      try {
        const res = await (client as any).permission.reply({
          path: { requestID },
          body: { reply, message },
          query: targetDir ? { directory: targetDir } : undefined,
        })
        if (!res?.error && res?.response?.ok !== false) return
      } catch {}
    }
  }

  async handlePermissionReplied(data: { requestID?: string; id?: string; reply?: string }): Promise<void> {
    this.engine.handlePermissionReplied(data)
  }

  clearTurnCache(sessionID: string): void {
    this.engine.clearTurnCache(sessionID)
  }
}

export async function AutoGatePlugin(
  ctx: PluginInput,
  options?: Record<string, unknown>
): Promise<Hooks> {
  const adapter = new OpenCodeHarnessAdapter(ctx, options)
  const engine = adapter.getEngine()
  await adapter.start()

  const config = loadConfig(options)
  console.log(`AutoGate Plugin initialized (model: ${config.classifierModel}, topic: ${config.ntfyTopic})`)
  try {
    await ctx.client.app.log({
      body: {
        service: "auto-gate",
        level: "info",
        message: `AutoGate Plugin initialized (model: ${config.classifierModel}, topic: ${config.ntfyTopic})`,
      },
    })
  } catch {}

  const hooks: Hooks = {
    tool: {
      classify_result: tool({
        description: "Report the security classification result for the agent action (internal evaluation tool)",
        args: {
          risk_level: tool.schema.enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
          user_authorization: tool.schema.enum(["NONE", "LOW", "MEDIUM", "HIGH"]),
          verdict: tool.schema.enum(["ALLOW", "BLOCK", "UNSURE"]),
          reason: tool.schema.string(),
        },
        async execute(args: any, context: any) {
          if (!isEvaluationSession(context.sessionID)) {
            throw new Error("classify_result is an internal security tool reserved exclusively for AutoGate evaluation sessions.")
          }
          recordEvaluationVerdict(context.sessionID, {
            verdict: args.verdict,
            risk_level: args.risk_level,
            user_authorization: args.user_authorization,
            reason: args.reason,
          })
          ctx.client?.session?.abort?.({ path: { id: context.sessionID } }).catch(() => {})
          return {
            output: JSON.stringify(args),
          }
        },
      }),
      escalate_permission: tool({
        description: "Request human manual verification for a blocked or high-risk action when safe automated transformations cannot satisfy the goal.",
        args: {
          action: tool.schema.string().describe("The command or target path requiring human approval (e.g. '/etc/hosts' or 'rm -rf dist')"),
          reason: tool.schema.string().describe("Why the safe alternative or automated transform cannot be used and human review is required"),
        },
        async execute(args: any, context: any) {
          recordEscalationIntent(context.sessionID, args.action, args.reason)
          return {
            output: `Manual verification intent registered for '${args.action}'. Please re-issue your tool call now; it will be forwarded directly to the user's phone for manual approval.`,
          }
        },
      }),
    },

    dispose: async () => {
      await adapter.dispose()
    },

    "chat.message": async (
      input: { sessionID: string; messageID?: string },
      output: { message?: UserMessage; parts?: Part[] }
    ) => {
      if (!output || !Array.isArray(output.parts)) return
      if (output.message && output.message.role && output.message.role !== "user") return

      const textParts = output.parts
        .filter((p): p is Part & { type: "text"; text: string } => p !== null && typeof p === "object" && p.type === "text" && typeof p.text === "string")
        .map((p) => p.text)
        .join("\n")
        .trim()

      if (input?.sessionID && isEvaluationSession(input.sessionID)) return
      if (
        textParts.includes("## Environment Trust Boundaries:") ||
        textParts.includes("## Context:") ||
        textParts.includes("### Conversation Transcript") ||
        textParts.startsWith("[auto-gate-eval]")
      ) {
        return
      }
      if (textParts && input?.sessionID) {
        engine.setUserPrompt(input.sessionID, textParts)
      } else if (textParts) {
        engine.setUserPrompt(textParts)
      }

      const trimmed = textParts.trim().toLowerCase()
      if (trimmed.startsWith("/automode") || trimmed.startsWith("automode")) {
        const parts = trimmed.split(/\s+/)
        const arg = parts[1] || ""
        if (arg === "off" || arg === "disable" || arg === "false" || arg === "0") {
          engine.setEnabled(false)
        } else if (arg === "on" || arg === "enable" || arg === "true" || arg === "1") {
          engine.setEnabled(true)
        } else if (arg === "toggle") {
          engine.setEnabled(!engine.isEnabled())
        }
      }
    },

    event: async (input: { event: any }) => {
      const { event } = input
      if (!event || !event.type) return

      const workspaceDir = ctx.directory || ctx.worktree
      if (workspaceDir && !isEventForWorkspace(event, workspaceDir)) {
        return
      }

      if (event.type === "permission.asked" || event.type === "permission.v2.asked") {
        const eventData = event.properties || event.data
        if (eventData) {
          await adapter.handlePermissionAsked(eventData)
        }
      } else if (event.type === "permission.replied" || event.type === "permission.v2.replied") {
        const eventData = event.properties || event.data
        if (eventData) {
          await adapter.handlePermissionReplied(eventData)
        }
      } else if (
        event.type === "session.idle" ||
        (event.type === "session.status" && (event.properties?.status === "idle" || event.data?.status === "idle"))
      ) {
        const sessionID = event.properties?.sessionID || event.data?.sessionID
        if (sessionID) {
          adapter.clearTurnCache(sessionID)
        }
      }
    },

    "command.execute.before": async (
      input: { command: string; sessionID: string; arguments: string },
      output: { parts: Part[] }
    ) => {
      if (input.command === "automode" || input.command === "auto-mode") {
        const arg = (input.arguments || "").trim().toLowerCase()

        let msg = ""
        if (arg === "off" || arg === "disable" || arg === "false" || arg === "0") {
          engine.setEnabled(false)
          msg = "Auto Mode is now DISABLED (all requests route to ntfy)."
        } else if (arg === "on" || arg === "enable" || arg === "true" || arg === "1") {
          engine.setEnabled(true)
          msg = "Auto Mode is now ENABLED (classifier active)."
        } else if (arg === "status" || !arg) {
          const status = engine.isEnabled() ? "ENABLED (classifier active)" : "DISABLED (routing to remote)"
          msg = `Auto Mode status: ${status}`
        } else {
          const nextState = !engine.isEnabled()
          engine.setEnabled(nextState)
          msg = `Auto Mode toggled to: ${nextState ? "ENABLED" : "DISABLED"}`
        }

        output.parts = [
          {
            type: "text",
            text: `[SYSTEM DIRECTIVE]: The user executed /automode. Output ONLY this exact single line and nothing else:\n[auto-gate] ${msg}`,
          } as Part,
        ]
      }
    },
  }

  return hooks
}

export const plugin = {
  id: "auto-gate",
  async setup(ctx: any) {
    const adapter = new OpenCodeHarnessAdapter(ctx, ctx.options)
    await adapter.start()

    const config = loadConfig(ctx.options)
    console.log(`AutoGate Plugin initialized (model: ${config.classifierModel}, topic: ${config.ntfyTopic})`)

    // Register tools via ctx.tool.transform if available
    if (ctx.tool && typeof ctx.tool.transform === "function") {
      await ctx.tool.transform((editor: any) => {
        editor.add({
          name: "classify_result",
          options: { codemode: false },
          description: "Report the security classification result for the agent action (internal evaluation tool)",
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
          async execute(args: any, context: any) {
            if (!isEvaluationSession(context.sessionID)) {
              throw new Error("classify_result is an internal security tool reserved exclusively for AutoGate evaluation sessions.")
            }
            recordEvaluationVerdict(context.sessionID, {
              verdict: args.verdict,
              risk_level: args.risk_level,
              user_authorization: args.user_authorization,
              reason: args.reason,
            })
            ctx.session?.interrupt?.(context.sessionID).catch(() => {})
            return {
              content: JSON.stringify(args),
            }
          },
        })

        editor.add({
          name: "escalate_permission",
          options: { codemode: false },
          description: "Request human manual verification for a blocked or high-risk action when safe automated transformations cannot satisfy the goal.",
          input: {
            type: "object",
            properties: {
              action: { type: "string", description: "The command or target path requiring human approval (e.g. '/etc/hosts' or 'rm -rf dist')" },
              reason: { type: "string", description: "Why the safe alternative or automated transform cannot be used and human review is required" },
            },
            required: ["action", "reason"],
          },
          async execute(args: any, context: any) {
            recordEscalationIntent(context.sessionID, args.action, args.reason)
            return {
              content: `Manual verification intent registered for '${args.action}'. Please re-issue your tool call now; it will be forwarded directly to the user's phone for manual approval.`,
            }
          },
        })
      })
    }

    // Subscribe to events
    if (ctx.event && typeof ctx.event.subscribe === "function") {
      const controller = new AbortController()
      ;(async () => {
        try {
          for await (const event of ctx.event.subscribe({ signal: controller.signal })) {
            const workspaceDir = ctx.directory || ctx.worktree
            if (workspaceDir && !isEventForWorkspace(event, workspaceDir)) {
              continue
            }

            if (event.type === "permission.asked" || event.type === "permission.v2.asked") {
              const eventData = event.properties || event.data
              if (eventData) {
                await adapter.handlePermissionAsked(eventData)
              }
            } else if (event.type === "permission.replied" || event.type === "permission.v2.replied") {
              const eventData = event.properties || event.data
              if (eventData) {
                await adapter.handlePermissionReplied(eventData)
              }
            } else if (
              event.type === "session.idle" ||
              (event.type === "session.status" && (event.properties?.status === "idle" || event.data?.status === "idle"))
            ) {
              const sessionID = event.properties?.sessionID || event.data?.sessionID
              if (sessionID) {
                adapter.clearTurnCache(sessionID)
              }
            }
          }
        } catch {}
      })()
    }

    return async () => {
      await adapter.dispose()
    }
  },
  server: AutoGatePlugin,
}

export default plugin
