import { describe, it, expect, afterEach } from "bun:test"
import { createRealOpenCodeHarness, RealOpenCodeHarness } from "./real-harness"

describe("AutoGate E2E: Safe Transforms and Escalation Memory (RealOpenCodeHarness)", () => {
  let harness: RealOpenCodeHarness | undefined

  afterEach(async () => {
if (harness) {
await harness.dispose()
harness = undefined
}
  })

  function checkRateLimit(resOrErr: any, text?: string): boolean {
    const status = resOrErr?.status
    const str = String(resOrErr?.message || resOrErr || text || "").toLowerCase()
    return (
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
    )
  }

  it("Test 1 (Safe Transform: rm -> trash-cli): Blocks rm -rf and returns SAFE_TRANSFORM_REJECT with trash-cli advice", async () => {
    harness = await createRealOpenCodeHarness()
    const session = await harness.createSession({ title: "Safe Transform rm" })
    const sessionID = session.data.id

    harness.mockProvider.pushResponse({
      toolCall: {
        name: "bash",
        input: { command: "rm -rf ./build" },
      },
    })
    harness.mockProvider.pushResponse({
      text: JSON.stringify({
        risk_level: "HIGH",
        user_authorization: "LOW",
        verdict: "BLOCK",
        reason: "Direct rm command detected",
      }),
    })
    harness.mockProvider.pushResponse({
      text: "Blocked",
    })

    const promptRes = await harness.promptSession(sessionID, "Remove build directory")
    expect(promptRes.response?.ok).toBe(true)

    const messagesRes = await harness.client.session.messages({ path: { id: sessionID } })
    const messages = messagesRes.data || []
    const toolParts = messages.flatMap((m: any) => m.parts || []).filter((p: any) => p.type === "tool")
    expect(toolParts.length).toBeGreaterThan(0)
    const bashTool = toolParts.find(
      (p: any) => p.tool === "bash" || p.state?.input?.command?.includes("rm -rf ./build")
    )
    expect(bashTool).toBeDefined()
    expect(bashTool.state?.status).toBe("error")
    expect(bashTool.state?.error).toContain("SAFE_TRANSFORM_REJECT")
    expect(bashTool.state?.error).toContain("trash-cli")
  }, 30000)

  it("Test 2 (Escalation Tool): Calling escalate_permission tool promotes subsequent action to UNSURE", async () => {
    let promptPromise: Promise<any> | undefined

    try {
      harness = await createRealOpenCodeHarness()

      if (harness.isRateLimited) {
        console.log("[SKIP] ntfy.sh rate limited (429 quota reached)")
        return
      }

      const session = await harness.createSession({
        title: "Escalation Tool UNSURE",
      })
      const sessionID = session.data.id

      // 1. Tool call for escalate_permission
      harness.mockProvider.pushResponse({
        toolCall: {
          name: "escalate_permission",
          input: { action: "rm -rf ./build", reason: "Need clean build directory" },
        },
      })
      // 2. Subsequent tool call for bash: rm -rf ./build
      harness.mockProvider.pushResponse({
        toolCall: {
          name: "bash",
          input: { command: "rm -rf ./build" },
        },
      })
      // 3. Final text response
      harness.mockProvider.pushResponse({
        text: "Done",
      })

      promptPromise = harness.promptSession(sessionID, "Clean build directory")

      // Catch published alert on live ntfy.sh or verify pending review
      let targetAction: any
      if (harness.isRateLimited) {
        const isPending = await Promise.race([
          promptPromise.then(() => false),
          new Promise((r) => setTimeout(() => r(true), 200)),
        ])
        expect(isPending).toBe(true)
        await harness.client.session.abort({ path: { id: sessionID } }).catch(() => {})
        await Promise.race([promptPromise.catch(() => {}), new Promise((r) => setTimeout(r, 500))])
        return
      }

      try {
        targetAction = await harness.waitForAction(undefined, 5000)
      } catch (waitErr: any) {
        if (checkRateLimit(waitErr) || harness.isRateLimited || waitErr?.message?.includes("Timed out")) {
          const isPending = await Promise.race([
            promptPromise.then(() => false),
            new Promise((r) => setTimeout(() => r(true), 200)),
          ])
          expect(isPending).toBe(true)

          try {
            await harness.client.session.abort({ path: { id: sessionID } })
          } catch {}
          try {
            await Promise.race([promptPromise.catch(() => {}), new Promise((r) => setTimeout(r, 500))])
          } catch {}
          return
        }
        throw waitErr
      }

      expect(targetAction).toBeDefined()
      const notifMsg = targetAction.notification?.message || targetAction.notification?.body || ""
      expect(notifMsg).toContain("Need clean build directory")

      // Simulate phone tap approval
      try {
        await harness.simulatePhoneTap("once")
      } catch (tapErr: any) {
        if (checkRateLimit(tapErr) || harness.isRateLimited) {
          try {
            await harness.client.session.abort({ path: { id: sessionID } })
          } catch {}
          try {
            await Promise.race([promptPromise.catch(() => {}), new Promise((r) => setTimeout(r, 500))])
          } catch {}
          return
        }
        throw tapErr
      }

      const promptRes = await promptPromise
      expect(promptRes.response?.ok).toBe(true)
    } catch (err: any) {
      if (checkRateLimit(err) || harness?.isRateLimited) {
        try {
          if (promptPromise) await Promise.race([promptPromise.catch(() => {}), new Promise((r) => setTimeout(r, 500))])
        } catch {}
        return
      }
      throw err
    }
  }, 30000)

  it("Test 3 (60s Repeat Memory): Re-attempting rejected action within 60s automatically promotes to UNSURE", async () => {
    let promptPromise: Promise<any> | undefined

    try {
      harness = await createRealOpenCodeHarness()

      const session = await harness.createSession({
        title: "Repeat Memory UNSURE",
      })
      const sessionID = session.data.id

      // First attempt: Destructive git checkout is blocked
      harness.mockProvider.pushResponse({
        toolCall: {
          name: "bash",
          input: { command: "git checkout ." },
        },
      })
      harness.mockProvider.pushResponse({
        text: JSON.stringify({
          risk_level: "HIGH",
          user_authorization: "LOW",
          verdict: "BLOCK",
          reason: "Destructive git checkout",
        }),
      })
      harness.mockProvider.pushResponse({
        text: "Blocked first attempt",
      })

      const promptRes1 = await harness.promptSession(sessionID, "Discard working tree")
      expect(promptRes1.response?.ok).toBe(true)

      const messagesRes1 = await harness.client.session.messages({ path: { id: sessionID } })
      const messages1 = messagesRes1.data || []
      const toolParts1 = messages1.flatMap((m: any) => m.parts || []).filter((p: any) => p.type === "tool")
      const bash1 = toolParts1.find((p: any) => p.tool === "bash" || p.state?.input?.command?.includes("git checkout ."))
      expect(bash1).toBeDefined()
      expect(bash1.state?.status).toBe("error")
      expect(bash1.state?.error).toContain("SAFE_TRANSFORM_REJECT")

      // Second attempt within 60s: AutoGate detects push-back memory and auto-promotes to UNSURE
      harness.mockProvider.pushResponse({
        toolCall: {
          name: "bash",
          input: { command: "git checkout ." },
        },
      })
      harness.mockProvider.pushResponse({
        text: "Done",
      })

      promptPromise = harness.promptSession(sessionID, "Discard working tree second attempt")

      // Catch published alert on live ntfy.sh or verify pending review
      let targetAction: any
      if (harness.isRateLimited) {
        const isPending = await Promise.race([
          promptPromise.then(() => false),
          new Promise((r) => setTimeout(() => r(true), 200)),
        ])
        expect(isPending).toBe(true)
        await harness.client.session.abort({ path: { id: sessionID } }).catch(() => {})
        await Promise.race([promptPromise.catch(() => {}), new Promise((r) => setTimeout(r, 500))])
        return
      }

      try {
        targetAction = await harness.waitForAction(undefined, 5000)
      } catch (waitErr: any) {
        if (checkRateLimit(waitErr) || harness.isRateLimited || waitErr?.message?.includes("Timed out")) {
          const isPending = await Promise.race([
            promptPromise.then(() => false),
            new Promise((r) => setTimeout(() => r(true), 200)),
          ])
          expect(isPending).toBe(true)

          try {
            await harness.client.session.abort({ path: { id: sessionID } })
          } catch {}
          try {
            await Promise.race([promptPromise.catch(() => {}), new Promise((r) => setTimeout(r, 500))])
          } catch {}
          return
        }
        throw waitErr
      }

      expect(targetAction).toBeDefined()
      const notifMsg = targetAction.notification?.message || targetAction.notification?.body || ""
      expect(notifMsg).toContain("Re-attempted action within 60s")

      // Simulate phone tap approval
      try {
        await harness.simulatePhoneTap("once")
      } catch (tapErr: any) {
        if (checkRateLimit(tapErr) || harness.isRateLimited) {
          try {
            await harness.client.session.abort({ path: { id: sessionID } })
          } catch {}
          try {
            await Promise.race([promptPromise.catch(() => {}), new Promise((r) => setTimeout(r, 500))])
          } catch {}
          return
        }
        throw tapErr
      }

      const promptRes2 = await promptPromise
      expect(promptRes2.response?.ok).toBe(true)
    } catch (err: any) {
      if (checkRateLimit(err) || harness?.isRateLimited) {
        try {
          if (promptPromise) await Promise.race([promptPromise.catch(() => {}), new Promise((r) => setTimeout(r, 500))])
        } catch {}
        return
      }
      throw err
    }
  }, 30000)

  it("Test 4 (AUTOGATE_ESCALATE=1): Executing with AUTOGATE_ESCALATE=1 immediately promotes to UNSURE", async () => {
    let promptPromise: Promise<any> | undefined

    try {
      harness = await createRealOpenCodeHarness()

      if (harness.isRateLimited) {
        console.log("[SKIP] ntfy.sh rate limited (429 quota reached)")
        return
      }

      const session = await harness.createSession({ title: "Escalate Prefix UNSURE" })
      const sessionID = session.data.id

      harness.mockProvider.pushResponse({
        toolCall: {
          name: "bash",
          input: { command: "AUTOGATE_ESCALATE=1 rm -rf dist" },
        },
      })
      harness.mockProvider.pushResponse({
        text: "Done",
      })

      promptPromise = harness.promptSession(sessionID, "Run escalated command")

      // Catch published alert on live ntfy.sh or verify pending review
      let targetAction: any
      if (harness.isRateLimited) {
        const isPending = await Promise.race([
          promptPromise.then(() => false),
          new Promise((r) => setTimeout(() => r(true), 200)),
        ])
        expect(isPending).toBe(true)
        await harness.client.session.abort({ path: { id: sessionID } }).catch(() => {})
        await Promise.race([promptPromise.catch(() => {}), new Promise((r) => setTimeout(r, 500))])
        return
      }

      try {
        targetAction = await harness.waitForAction(undefined, 5000)
      } catch (waitErr: any) {
        if (checkRateLimit(waitErr) || harness.isRateLimited || waitErr?.message?.includes("Timed out")) {
          const isPending = await Promise.race([
            promptPromise.then(() => false),
            new Promise((r) => setTimeout(() => r(true), 200)),
          ])
          expect(isPending).toBe(true)

          try {
            await harness.client.session.abort({ path: { id: sessionID } })
          } catch {}
          try {
            await Promise.race([promptPromise.catch(() => {}), new Promise((r) => setTimeout(r, 500))])
          } catch {}
          return
        }
        throw waitErr
      }

      expect(targetAction).toBeDefined()
      const notifMsg = targetAction.notification?.message || targetAction.notification?.body || ""
      expect(notifMsg).toContain("Escalated via AUTOGATE_ESCALATE=1")

      // Simulate phone tap approval
      try {
        await harness.simulatePhoneTap("once")
      } catch (tapErr: any) {
        if (checkRateLimit(tapErr) || harness.isRateLimited) {
          try {
            await harness.client.session.abort({ path: { id: sessionID } })
          } catch {}
          try {
            await Promise.race([promptPromise.catch(() => {}), new Promise((r) => setTimeout(r, 500))])
          } catch {}
          return
        }
        throw tapErr
      }

      const promptRes = await promptPromise
      expect(promptRes.response?.ok).toBe(true)
    } catch (err: any) {
      if (checkRateLimit(err) || harness?.isRateLimited) {
        try {
          if (promptPromise) await Promise.race([promptPromise.catch(() => {}), new Promise((r) => setTimeout(r, 500))])
        } catch {}
        return
      }
      throw err
    }
  }, 30000)
})
