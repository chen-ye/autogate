import { describe, it, expect, beforeEach, afterEach, beforeAll, afterAll } from "bun:test"
import { MockNtfyServer } from "../mock-ntfy"
import { createMockOpenCodeClient, createMockPluginContext } from "./mock-opencode"
import {
  AutoGateCoreEngine,
  sharedRecentlyRejected,
  sharedExplicitEscalations,
  loadConfig,
  NtfyAdapter,
} from "@autogate/core"
import { AutoGatePlugin, ensureAgentInstalled, isEvaluationSession, evaluationSessions } from "@autogate/opencode"

describe("AutoGate OpenCode Plugin Integration", () => {
  let mockNtfy: MockNtfyServer

  beforeAll(async () => {
    mockNtfy = new MockNtfyServer(0)
  })

  afterAll(async () => {
    await mockNtfy.stop()
  })

  beforeEach(() => {
    mockNtfy.clearPublished()
  })

  afterEach(() => {
    sharedRecentlyRejected.clear()
    sharedExplicitEscalations.clear()
    evaluationSessions.clear()
  })

  it("Slash command: /automode toggles enabled status in memory", async () => {
    const { client } = createMockOpenCodeClient()
    const ctx = createMockPluginContext(client)
    const plugin = await AutoGatePlugin(ctx, { autoMode: true, ntfyServer: mockNtfy.url, ntfyTopic: "test-topic" })

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
    const hooks = await AutoGatePlugin(pluginContext, { ntfyServer: mockNtfy.url, ntfyTopic: "test-topic" })

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
    const hooks = await AutoGatePlugin(pluginContext, { ntfyServer: mockNtfy.url, ntfyTopic: "test-topic" })

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
})
