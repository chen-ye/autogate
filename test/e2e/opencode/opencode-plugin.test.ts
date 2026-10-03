import { describe, it, expect, afterEach } from "bun:test"
import path from "node:path"
import os from "node:os"
import fs from "node:fs"
import { createMockOpenCodeClient, createMockPluginContext } from "./mock-opencode"
import { AutoGatePlugin, plugin as OpenCodePluginExport, isEvaluationSession, evaluationSessions, isEventForWorkspace } from "@autogate/opencode"
import {
  sharedRecentlyRejected,
  sharedExplicitEscalations,
} from "@autogate/core"

describe("AutoGate OpenCode Plugin Integration", () => {
  afterEach(() => {
    sharedRecentlyRejected.clear()
    sharedExplicitEscalations.clear()
    evaluationSessions.clear()
  })

  it("v2 plugin setup registers evaluate hook, prompt hook, command transform, and tool transform", async () => {
    const registeredHooks: any = {}
    const registeredTools: any[] = []
    const subscribedEvents: any[] = []

    const mockCtx = {
      client: {
        app: { log: async () => {} }
      },
      permission: {
        hook: (name: string, cb: any) => {
          registeredHooks[`permission.${name}`] = cb
        }
      },
      session: {
        hook: (name: string, cb: any) => {
          registeredHooks[`session.${name}`] = cb
        }
      },
      command: {
        transform: (cb: any) => {
          registeredHooks["command.transform"] = cb
        }
      },
      tool: {
        transform: (cb: any) => {
          registeredHooks["tool.transform"] = cb
          const editor = {
            add: (toolDef: any) => {
              registeredTools.push(toolDef)
            }
          }
          cb(editor)
        }
      },
      event: {
        subscribe: (opts: any) => {
          subscribedEvents.push(opts)
          return (async function* () {})()
        }
      },
      options: {}
    }

    const dispose = await OpenCodePluginExport.setup(mockCtx)
    expect(typeof registeredTools.some).toBe("function")
    expect(registeredTools.some((t) => t.name === "classify_result")).toBe(true)
    expect(registeredTools.some((t) => t.name === "escalate_permission")).toBe(true)

    if (typeof dispose === "function") {
      await dispose()
    }
  })

  it("Slash command: /automode toggles enabled status in memory", async () => {
    const { client } = createMockOpenCodeClient()
    const ctx = createMockPluginContext(client)
    const plugin = await AutoGatePlugin(ctx, { autoMode: true, ntfyServer: "https://ntfy.sh", ntfyTopic: "test-topic" })

    const outputOff: any = { parts: [] }
    await plugin["command.execute.before"]({ command: "automode", arguments: "off", sessionID: "sess-1" }, outputOff)
    expect(outputOff.parts[0].text).toContain("DISABLED")

    const outputOn: any = { parts: [] }
    await plugin["command.execute.before"]({ command: "automode", arguments: "on", sessionID: "sess-1" }, outputOn)
    expect(outputOn.parts[0].text).toContain("ENABLED")

    const outputStatus: any = { parts: [] }
    await plugin["command.execute.before"]({ command: "automode", arguments: "status", sessionID: "sess-1" }, outputStatus)
    expect(outputStatus.parts[0].text).toContain("ENABLED")

    if (plugin.dispose) {
      await plugin.dispose()
    }
  })

  it("Guarded Contextual classify_result Tool: session authorization enforcement and valid execution", async () => {
    const { client } = createMockOpenCodeClient()
    const pluginContext = createMockPluginContext(client, "/workspace")
    const hooks = await AutoGatePlugin(pluginContext, { ntfyServer: "https://ntfy.sh", ntfyTopic: "test-topic" })

    const classifyResultTool = hooks.tool?.classify_result
    expect(classifyResultTool).toBeDefined()

    // 1. Verify classify_result throws unauthorized error when called from arbitrary non-eval session
    const nonEvalContext = { sessionID: "general-user-session-123" }
    const validArgs = {
      risk_level: "HIGH" as const,
      user_authorization: "LOW" as const,
      verdict: "UNSURE" as const,
      reason: "Suspicious command",
    }

    expect(isEvaluationSession("general-user-session-123")).toBe(false)
    await expect(classifyResultTool!.execute(validArgs, nonEvalContext)).rejects.toThrow(
      "classify_result is an internal security tool reserved exclusively for AutoGate evaluation sessions."
    )

    // 2. Verify classify_result executes successfully when session is an active evaluation session
    const evalSessionID = "auto-gate-eval-session-456"
    evaluationSessions.add(evalSessionID)
    try {
      expect(isEvaluationSession(evalSessionID)).toBe(true)
      const result = await classifyResultTool!.execute(validArgs, { sessionID: evalSessionID })
      expect(result).toBeDefined()
      expect(result.output).toBeDefined()
      const parsedOutput = JSON.parse(result.output)
      expect(parsedOutput).toEqual(validArgs)
    } finally {
      evaluationSessions.delete(evalSessionID)
    }

    if (hooks.dispose) {
      await hooks.dispose()
    }
  })

  it("Explicit Escalation via escalate_permission Tool: one-shot intent registration", async () => {
    const { client } = createMockOpenCodeClient({
      classifierVerdict: "BLOCK",
      classifierReason: "Default classifier policy block",
    })
    const pluginContext = createMockPluginContext(client, "/workspace")
    const hooks = await AutoGatePlugin(pluginContext, { ntfyServer: "https://ntfy.sh", ntfyTopic: "test-topic" })

    const escalateTool = hooks.tool?.escalate_permission
    expect(escalateTool).toBeDefined()

    const sessionID = "sess-tool-esc"
    const toolExecRes = await escalateTool!.execute(
      { action: "/etc/hosts", reason: "verify network resolution" },
      { sessionID }
    )
    expect(toolExecRes.output).toContain("Manual verification intent registered for '/etc/hosts'")

    expect(sharedExplicitEscalations.has(sessionID)).toBe(true)
    expect(sharedExplicitEscalations.get(sessionID)?.action).toBe("/etc/hosts")
    expect(sharedExplicitEscalations.get(sessionID)?.reason).toBe("verify network resolution")

    if (hooks.dispose) {
      await hooks.dispose()
    }
  })
  it("JSONL audit logging and stateless generate.text support in classifier evaluation", async () => {
    const tmpLogFile = path.join(os.tmpdir(), `autogate-evals-${Date.now()}.jsonl`)
    let generateCalled = false
    const { client } = createMockOpenCodeClient()
    client.generate = {
      text: async (_opts: any) => {
        generateCalled = true
        return {
          text: JSON.stringify({ verdict: "ALLOW", risk_level: "LOW", user_authorization: "NONE", reason: "Safe read test" }),
          reasoning: "Checked patterns, confirmed safe read",
        }
      },
    }

    const pluginContext = createMockPluginContext(client, "/workspace")
    const hooks = await AutoGatePlugin(pluginContext, {
      ntfyServer: "https://ntfy.sh",
      ntfyTopic: "test-topic",
      evalLogFile: tmpLogFile,
    })

    // Trigger tool check via hooks.tool or direct classifyRequest test
    const { classifyRequest } = await import("@autogate/opencode/evaluator")
    const result = await classifyRequest({
      client,
      userPrompt: "Read package.json",
      actionName: "read",
      actionArgs: { file: "package.json" },
      workspaceRoot: "/workspace",
      config: { evalLogFile: tmpLogFile } as any,
    })

    expect(generateCalled).toBe(true)
    expect(result.verdict).toBe("ALLOW")

    // Verify JSONL log file written
    expect(fs.existsSync(tmpLogFile)).toBe(true)
    const logLines = fs.readFileSync(tmpLogFile, "utf8").trim().split("\n").filter(Boolean)
    expect(logLines.length).toBeGreaterThan(0)
    const lastEntry = JSON.parse(logLines[logLines.length - 1])
    expect(lastEntry.verdict).toBe("ALLOW")
    expect(lastEntry.toolName).toBe("read")
    expect(lastEntry.reasoning).toContain("Checked patterns")
    expect(typeof lastEntry.durationMs).toBe("number")

    try {
      fs.unlinkSync(tmpLogFile)
    } catch {}

    if (hooks.dispose) {
      await hooks.dispose()
    }
  })

  it("isEventForWorkspace: isolates events to the target workspace", () => {
    const ws = "/home/user/Projects/autogate"

    // 1. Authoritative event.location.directory match
    expect(isEventForWorkspace({ location: { directory: "/home/user/Projects/autogate" } }, ws)).toBe(true)

    // 2. Authoritative event.location.directory mismatch (different project)
    expect(isEventForWorkspace({ location: { directory: "/home/user/Projects/another-repo" } }, ws)).toBe(false)

    // 3. Parent workspace should not intercept child workspace event when location is explicit
    expect(isEventForWorkspace({ location: { directory: "/home/user/Projects/autogate" } }, "/home/user")).toBe(false)

    // 4. Fallback to eventData.metadata.directory matching workspace
    expect(isEventForWorkspace({ properties: { metadata: { directory: "/home/user/Projects/autogate" } } }, ws)).toBe(true)

    // 5. Fallback to eventData.metadata.directory matching subfolder
    expect(isEventForWorkspace({ properties: { metadata: { directory: "/home/user/Projects/autogate/packages/opencode" } } }, ws)).toBe(true)

    // 6. Fallback to eventData.metadata.directory from external project
    expect(isEventForWorkspace({ properties: { metadata: { directory: "/home/user/Projects/other-app" } } }, ws)).toBe(false)

    // 7. No workspace specified defaults to true
    expect(isEventForWorkspace({ location: { directory: "/foo" } }, undefined)).toBe(true)
  })

  it("OpenCode v2 plugin event subscription ignores events belonging to other workspaces", async () => {
    const foreignEvent = {
      type: "permission.asked",
      location: { directory: "/home/user/Projects/other-project" },
      properties: {
        id: "perm-other-1",
        sessionID: "ses-other-1",
        permission: "bash",
        patterns: ["ls"],
        metadata: { directory: "/home/user/Projects/other-project", command: "ls" },
      },
    }

    const localEvent = {
      type: "permission.asked",
      location: { directory: "/home/user/Projects/my-app" },
      properties: {
        id: "perm-local-1",
        sessionID: "ses-local-1",
        permission: "bash",
        patterns: ["echo local"],
        metadata: { directory: "/home/user/Projects/my-app", command: "echo local" },
      },
    }

    let handledCount = 0
    let lastHandledId: string | undefined

    const { client } = createMockOpenCodeClient({ classifierVerdict: "ALLOW" })
    const mockCtx = {
      directory: "/home/user/Projects/my-app",
      client,
      permission: {
        reply: async (args: any) => {
          handledCount++
          lastHandledId = args.requestID
        },
      },
      tool: {
        transform: () => {},
      },
      event: {
        subscribe: (_opts: any) => {
          return (async function* () {
            yield foreignEvent
            yield localEvent
          })()
        },
      },
      options: {},
    }

    const dispose = await OpenCodePluginExport.setup(mockCtx)
    // Give async event processing a tick
    await new Promise((r) => setTimeout(r, 100))

    // Foreign event should be skipped, local event should be handled
    expect(handledCount).toBe(1)
    expect(lastHandledId).toBe("perm-local-1")

    if (typeof dispose === "function") {
      await dispose()
    }
  })
})
