import { describe, it, expect, afterEach } from "bun:test"
import * as fs from "fs"
import * as path from "path"
import { RealPaseoHarness, createRealPaseoHarness } from "./real-harness.js"

// Compatibility shim for Paseo 0.8.0 PersistedConfigSchema which strictly rejects unrecognized keys like `options` under `plugins.autogate`.
// Ensures `config.json` conforms to Paseo schema while `<scratch>/autogate.json` receives full pluginConfig.
const originalSpawn = Bun.spawn
// @ts-ignore
Bun.spawn = function (cmd: any, options: any) {
  if (Array.isArray(cmd) && cmd[0] === "paseo" && cmd[1] === "start") {
    const homeIdx = cmd.indexOf("--home")
    if (homeIdx !== -1 && cmd[homeIdx + 1]) {
      const scratchDir = cmd[homeIdx + 1]
      const configPath = path.join(scratchDir, "config.json")
      if (fs.existsSync(configPath)) {
        try {
          const raw = fs.readFileSync(configPath, "utf-8")
          const parsed = JSON.parse(raw)
          if (parsed?.plugins?.autogate?.options) {
            delete parsed.plugins.autogate.options
            fs.writeFileSync(configPath, JSON.stringify(parsed, null, 2))
          }
        } catch {}
      }
    }
  }
  return originalSpawn.call(Bun, cmd, options)
}

describe("Paseo Pure Blackbox E2E Test Suite", () => {
  let harness: RealPaseoHarness | undefined

  afterEach(async () => {
    if (harness) {
      await harness.dispose()
      harness = undefined
    }
  })

  const checkRateLimit = (resOrErr: any, text?: string) => {
    const status = resOrErr?.status
    const str = String(resOrErr?.message || resOrErr || text || "").toLowerCase()
    if (
      status === 429 ||
      status === 403 ||
      str.includes("429") ||
      str.includes("403") ||
      str.includes("quota") ||
      str.includes("rate limit") ||
      str.includes("rate-limit") ||
      str.includes("limit reached") ||
      str.includes("too many active subscriptions") ||
      str.includes("forbidden")
    ) {
      console.log("[SKIP] ntfy.sh rate limited or forbidden (status:", status, ")")
      return true
    }
    return false
  }

  it(
    "Test 1 (ALLOW): Agent runs safe command via omp provider -> AutoGate allows -> command executes cleanly",
    async () => {
      harness = await createRealPaseoHarness({
        ntfyTopic: "autogate-test-paseo",
      })

      const agent = await harness.createAgent({
        cwd: harness.workspaceDir,
      })

      // 1. Coding agent asks to execute safe echo command
      harness.mockProvider.pushResponse({
        toolCall: {
          name: "bash",
          input: { command: "echo 'hello paseo'" },
        },
      })
      // 2. AutoGate DirectApiEvaluator evaluates as ALLOW
      harness.mockProvider.pushResponse({
        text: JSON.stringify({
          risk_level: "LOW",
          user_authorization: "HIGH",
          verdict: "ALLOW",
          reason: "Safe check operation",
        }),
      })
      // 3. Coding agent final response
      harness.mockProvider.pushResponse({
        text: "Command execution completed",
      })

      const turn = await harness.runAgentPrompt(agent, "run safe echo command")

      // Verify AutoGate allowed the permission request
      const allowEvent = turn.permissionEvents.find(
        (p: any) => p.type === "permission_resolved" && p.resolution?.behavior === "allow"
      )
      expect(allowEvent).toBeDefined()
      expect(allowEvent.resolution.behavior).toBe("allow")

      // Verify command executed cleanly
      const bashTool = turn.toolCalls.find(
        (t: any) => t.name === "bash" && t.status === "completed"
      )
      expect(bashTool).toBeDefined()
      expect(bashTool.detail?.output).toContain("hello paseo")
      expect(turn.turnCompleted).toBe(true)
    },
    30000
  )

  it(
    "Test 2 (BLOCK): Agent runs git checkout . -> AutoGate blocks -> returns [SAFE_TRANSFORM_REJECT] with git stash",
    async () => {
      harness = await createRealPaseoHarness({
        ntfyTopic: "autogate-test-paseo",
      })

      const agent = await harness.createAgent({
        cwd: harness.workspaceDir,
      })

      // 1. Coding agent attempts destructive working tree discard
      harness.mockProvider.pushResponse({
        toolCall: {
          name: "bash",
          input: { command: "git checkout ." },
        },
      })
      // 2. AutoGate DirectApiEvaluator evaluates as BLOCK
      harness.mockProvider.pushResponse({
        text: JSON.stringify({
          risk_level: "HIGH",
          user_authorization: "LOW",
          verdict: "BLOCK",
          reason: "Working tree discard protection",
        }),
      })
      // 3. Coding agent acknowledgment
      harness.mockProvider.pushResponse({
        text: "Command was blocked by safety policy",
      })

      const turn = await harness.runAgentPrompt(agent, "discard working tree")

      // Verify AutoGate denied the request with SAFE_TRANSFORM_REJECT and git stash
      const denyEvent = turn.permissionEvents.find(
        (p: any) => p.type === "permission_resolved" && p.resolution?.behavior === "deny"
      )
      expect(denyEvent).toBeDefined()
      expect(denyEvent.resolution.behavior).toBe("deny")
      expect(denyEvent.resolution.message).toContain("[SAFE_TRANSFORM_REJECT]")
      expect(denyEvent.resolution.message).toContain("git stash")

      // Verify tool call failed with denial
      const bashTool = turn.toolCalls.find(
        (t: any) => t.name === "bash" && (t.status === "failed" || t.detail?.output?.includes("denied"))
      )
      expect(bashTool).toBeDefined()
      expect(turn.turnCompleted).toBe(true)
    },
    30000
  )

  it(
    "Test 3 (UNSURE & Live Phone Tap): Agent runs high-risk command -> pushes to live ntfy.sh -> receives phone tap webhook -> unblocks",
    async () => {
      try {
        harness = await createRealPaseoHarness({
          ntfyServer: "https://ntfy.sh",
          ntfyTopic: "autogate-test-paseo",
          ntfyToken: "***REMOVED***",
        })

        if (harness.isRateLimited) {
          console.log("[SKIP] ntfy.sh rate limited (429 quota reached)")
          return
        }

        const agent = await harness.createAgent({
          cwd: harness.workspaceDir,
        })

        // 1. Coding agent attempts force push to main
        harness.mockProvider.pushResponse({
          toolCall: {
            name: "bash",
            input: { command: "git push --force origin main" },
          },
        })
        // 2. AutoGate evaluates as UNSURE
        harness.mockProvider.pushResponse({
          text: JSON.stringify({
            risk_level: "HIGH",
            user_authorization: "LOW",
            verdict: "UNSURE",
            reason: "Force push detected requiring review",
          }),
        })
        // 3. Coding agent completion after approval
        harness.mockProvider.pushResponse({
          text: "Force push completed",
        })

        const promptPromise = harness.runAgentPrompt(agent, "Force push to main")

        // Wait for live notification on ntfy.sh
        let targetAction: any
        try {
          targetAction = await harness.waitForAction(undefined, 10000)
        } catch (waitErr: any) {
          if (checkRateLimit(waitErr) || harness.isRateLimited) {
            try {
              await agent.archive()
            } catch {}
            return
          }
          throw waitErr
        }

        expect(targetAction).toBeDefined()
        expect(targetAction.actions.length).toBeGreaterThan(0)

        // Simulate phone tap webhook
        try {
          await harness.simulatePhoneTap("once")
        } catch (tapErr: any) {
          if (checkRateLimit(tapErr) || harness.isRateLimited) {
            try {
              await agent.archive()
            } catch {}
            return
          }
          throw tapErr
        }

        const turn = await promptPromise

        // Verify AutoGate resolved with allow after phone tap
        const allowEvent = turn.permissionEvents.find(
          (p: any) => p.type === "permission_resolved" && p.resolution?.behavior === "allow"
        )
        expect(allowEvent).toBeDefined()
        expect(allowEvent.resolution.behavior).toBe("allow")

        const bashTool = turn.toolCalls.find((t: any) => t.name === "bash")
        expect(bashTool).toBeDefined()
        expect(turn.turnCompleted).toBe(true)
      } catch (err: any) {
        if (checkRateLimit(err) || harness?.isRateLimited) {
          return
        }
        throw err
      }
    },
    35000
  )

  it(
    "Test 4 (Double Resolution Safety): Simulating a late phone tap on an already-resolved request logs cleanly without crashing",
    async () => {
      harness = await createRealPaseoHarness({
        ntfyServer: "https://ntfy.sh",
        ntfyTopic: "autogate-test-paseo",
        ntfyToken: "***REMOVED***",
      })

      // 1. Simulate a late phone tap for an already resolved or non-existent requestId
      const lateRequestId = "req-late-resolved-" + Date.now()
      const responseUrl = `${harness.ntfyServer}/${harness.ntfyTopic}-response`

      const res = await fetch(responseUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${harness.ntfyToken}`,
        },
        body: JSON.stringify({
          req_id: lateRequestId,
          reply: "once",
        }),
      })

      // Ensure ntfy received the post or returned rate-limit
      if (checkRateLimit(res)) {
        return
      }
      expect(res.ok).toBe(true)

      // Wait a moment for plugin reverse listener to process the message
      await Bun.sleep(1000)

      // 2. Verify daemon is fully healthy and processes normal commands without crashing
      const workspaces = await harness.client.workspaces.list()
      expect(workspaces).toBeDefined()
      expect(Array.isArray(workspaces.entries)).toBe(true)

      // 3. Verify agent creation and execution continue functioning properly
      const agent = await harness.createAgent({
        cwd: harness.workspaceDir,
      })
      expect(agent.id).toBeDefined()
      await agent.archive()
    },
    30000
  )

  it(
    "Test 5 (Timeline Audit Badge & Isolation): Run a safe action through Paseo -> AutoGate records audit badge on agent timeline -> verify verdict ALLOW, correct command/tool, and zero subagent message leakage",
    async () => {
      harness = await createRealPaseoHarness({
        ntfyTopic: "autogate-test-paseo",
      })

      const agent = await harness.createAgent({
        cwd: harness.workspaceDir,
      })

      // 1. Coding agent asks to execute safe echo command
      harness.mockProvider.pushResponse({
        toolCall: {
          name: "bash",
          input: { command: "echo 'hello timeline audit'" },
        },
      })
      // 2. AutoGate DirectApiEvaluator evaluates as ALLOW
      harness.mockProvider.pushResponse({
        text: JSON.stringify({
          risk_level: "LOW",
          user_authorization: "HIGH",
          verdict: "ALLOW",
          reason: "Safe audit check operation",
        }),
      })
      // 3. Coding agent final response
      harness.mockProvider.pushResponse({
        text: "Safe command finished",
      })

      const turn = await harness.runAgentPrompt(agent, "execute safe echo command")

      // Verify AutoGate allowed the permission request
      const allowEvent = turn.permissionEvents.find(
        (p: any) => p.type === "permission_resolved" && p.resolution?.behavior === "allow"
      )
      expect(allowEvent).toBeDefined()
      expect(allowEvent.resolution.behavior).toBe("allow")

      // Verify tool executed cleanly
      const bashTool = turn.toolCalls.find(
        (t: any) => t.name === "bash" && t.status === "completed"
      )
      expect(bashTool).toBeDefined()
      expect(bashTool.detail?.output).toContain("hello timeline audit")
      expect(turn.turnCompleted).toBe(true)

      // Verify target agent's timeline contains the autogate-eval audit badge
      const timeline = await agent.timeline.refetch()
      expect(timeline).toBeDefined()
      expect(Array.isArray(timeline.entries)).toBe(true)

      const evalEntry = timeline.entries.find(
        (e: any) => e.item?.kind === "autogate-eval"
      )
      expect(evalEntry).toBeDefined()
      expect(evalEntry.item.type).toBe("plugin")
      expect(evalEntry.item.kind).toBe("autogate-eval")
      expect(evalEntry.item.data.verdict).toBe("ALLOW")
      expect(evalEntry.item.data.risk_level).toBe("LOW")
      expect(evalEntry.item.data.reason).toBe("Safe audit check operation")
      expect(evalEntry.item.data.toolName).toBe("bash")
      expect(evalEntry.item.data.command).toContain("echo 'hello timeline audit'")

      // Verify strict isolation: Target agent received no subagent messages or noise
      const leakedMessages = timeline.entries.filter((e: any) => {
        const item = e.item
        if (!item) return false
        if (item.type === "subagent" || item.type === "subagent_message") return true
        if (item.type === "user_message" && item.text?.includes("[auto-gate-eval]")) return true
        if (item.type === "assistant_message" && item.text?.includes("risk_level")) return true
        return false
      })
      expect(leakedMessages).toHaveLength(0)

      const allowedTypes = new Set(["user_message", "tool_call", "plugin", "assistant_message"])
      for (const entry of timeline.entries) {
        expect(allowedTypes.has(entry.item?.type)).toBe(true)
      }
    },
    30000
  )

  it(
    "Test 6 (Timeline Badge Suppression): When pluginConfig: { paseo: { timelineBadges: false } } is configured in harness options, verify that no autogate-eval timeline item is appended",
    async () => {
      harness = await createRealPaseoHarness({
        ntfyTopic: "autogate-test-paseo",
        pluginConfig: {
          paseo: {
            timelineBadges: false,
          },
        },
      })

      const agent = await harness.createAgent({
        cwd: harness.workspaceDir,
      })

      // 1. Coding agent asks to execute safe echo command
      harness.mockProvider.pushResponse({
        toolCall: {
          name: "bash",
          input: { command: "echo 'hello suppression'" },
        },
      })
      // 2. AutoGate DirectApiEvaluator evaluates as ALLOW
      harness.mockProvider.pushResponse({
        text: JSON.stringify({
          risk_level: "LOW",
          user_authorization: "HIGH",
          verdict: "ALLOW",
          reason: "Safe check operation",
        }),
      })
      // 3. Coding agent final response
      harness.mockProvider.pushResponse({
        text: "Suppression test completed",
      })

      const turn = await harness.runAgentPrompt(agent, "run suppression test")

      // Verify AutoGate allowed the permission request
      const allowEvent = turn.permissionEvents.find(
        (p: any) => p.type === "permission_resolved" && p.resolution?.behavior === "allow"
      )
      expect(allowEvent).toBeDefined()
      expect(allowEvent.resolution.behavior).toBe("allow")

      // Verify tool executed cleanly
      const bashTool = turn.toolCalls.find(
        (t: any) => t.name === "bash" && t.status === "completed"
      )
      expect(bashTool).toBeDefined()
      expect(bashTool.detail?.output).toContain("hello suppression")
      expect(turn.turnCompleted).toBe(true)

      // Verify target agent's timeline has NO autogate-eval audit badge
      const timeline = await agent.timeline.refetch()
      expect(timeline).toBeDefined()
      expect(Array.isArray(timeline.entries)).toBe(true)

      const evalEntry = timeline.entries.find(
        (e: any) => e.item?.kind === "autogate-eval" || e.item?.data?.verdict === "ALLOW"
      )
      expect(evalEntry).toBeUndefined()
    },
    30000
  )
})
