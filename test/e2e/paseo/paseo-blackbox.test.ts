import { describe, it, expect, afterEach } from "bun:test"
import { RealPaseoHarness, createRealPaseoHarness } from "./real-harness.js"

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
})
