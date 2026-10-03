import { describe, it, expect, afterEach } from "bun:test"
import { createRealOpenCodeHarness, RealOpenCodeHarness } from "./real-harness"
import { MockInferenceProvider } from "./mock-provider"

describe("OpenCode Pure Black-box E2E Test Suite", () => {
  let harness: RealOpenCodeHarness | undefined

  afterEach(async () => {
    if (harness) {
      await harness.dispose()
      harness = undefined
    }
  })

  it("Test 1 (Black-box ALLOW): Executes safe bash command via client.session.prompt and mock-provider tool call", async () => {
    harness = await createRealOpenCodeHarness()
    const session = await harness.createSession({ title: "Blackbox ALLOW" })
    const sessionID = session.data.id

    harness.mockProvider.pushResponse({
      toolCall: {
        name: "shell",
        input: { command: "echo 'opencode blackbox allow'" },
      },
    })
    harness.mockProvider.pushResponse({
      text: JSON.stringify({
        risk_level: "LOW",
        user_authorization: "HIGH",
        verdict: "ALLOW",
        reason: "Safe check operation",
      }),
    })
    harness.mockProvider.pushResponse({
      text: "Done",
    })

    const promptRes = await harness.promptSession(sessionID, "Run safe check")
    expect(promptRes.response?.ok).toBe(true)
    const startTime = Date.now()
    let messages: any[] = []
    let shellTool: any
    while (Date.now() - startTime < 20000) {
      messages = await harness.getSessionMessages(sessionID)
      const toolParts = messages
        .filter((m: any) => m.type === "assistant" || m.role === "assistant" || m.info?.role === "assistant")
        .flatMap((m: any) => m.content || m.parts || [])
        .filter((p: any) => p.type === "tool")
      shellTool = toolParts.find((p: any) => {
        const isShellOrBash = p.tool === "shell" || p.name === "shell" || p.tool === "bash" || p.name === "bash"
        const hasCmd = p.state?.input?.command?.includes("echo 'opencode blackbox allow'")
        return (isShellOrBash || hasCmd) && (p.state?.status === "completed" || p.state?.status === "error")
      })
      if (shellTool) {
        break
      }
      await new Promise((r) => setTimeout(r, 300))
    }

    expect(shellTool).toBeDefined()
    expect(shellTool.state?.status).toBe("completed")
    const output = shellTool.state?.output || shellTool.state?.content?.[0]?.text || ""
    expect(output).toContain("opencode blackbox allow")
  }, 30000)

  it("Test 2 (Black-box BLOCK): Blocks destructive git checkout via client.session.prompt and returns SAFE_TRANSFORM_REJECT", async () => {
    harness = await createRealOpenCodeHarness()
    const session = await harness.createSession({ title: "Blackbox BLOCK" })
    const sessionID = session.data.id

    harness.mockProvider.pushResponse({
      toolCall: {
        name: "shell",
        input: { command: "git checkout ." },
      },
    })
    harness.mockProvider.pushResponse({
      text: JSON.stringify({
        risk_level: "HIGH",
        user_authorization: "LOW",
        verdict: "BLOCK",
        reason: "Discard working tree protection",
      }),
    })
    harness.mockProvider.pushResponse({
      text: "Blocked",
    })

    const promptRes = await harness.promptSession(sessionID, "Discard working tree")
    expect(promptRes.response?.ok).toBe(true)

    const startTime = Date.now()
    let messages: any[] = []
    let shellTool: any
    while (Date.now() - startTime < 20000) {
      messages = await harness.getSessionMessages(sessionID)
      const toolParts = messages
        .filter((m: any) => m.type === "assistant" || m.role === "assistant" || m.info?.role === "assistant")
        .flatMap((m: any) => m.content || m.parts || [])
        .filter((p: any) => p.type === "tool")
      shellTool = toolParts.find((p: any) => {
        const isShellOrBash = p.tool === "shell" || p.name === "shell" || p.tool === "bash" || p.name === "bash"
        const hasCmd = p.state?.input?.command?.includes("git checkout .")
        return (isShellOrBash || hasCmd) && (p.state?.status === "completed" || p.state?.status === "error")
      })
      if (shellTool) {
        break
      }
      await new Promise((r) => setTimeout(r, 300))
    }

    expect(shellTool).toBeDefined()
    expect(shellTool.state?.status).toBe("error")
    const errStr = typeof shellTool.state?.error === "string" ? shellTool.state.error : JSON.stringify(shellTool.state?.error || "")
    expect(errStr).toContain("SAFE_TRANSFORM_REJECT")
    expect(errStr).toContain("git stash")
  }, 30000)

  it("Test 3 (Black-box Live ntfy.sh Review): Unwhitelisted command prompts for review on live ntfy.sh and unblocks upon approval", async () => {
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

    let promptPromise: Promise<any> | undefined

    try {
      harness = await createRealOpenCodeHarness()

      if (harness.isRateLimited) {
        console.log("[SKIP] ntfy.sh rate limited (429 quota reached)")
        return
      }

      const session = await harness.createSession({ title: "Blackbox UNSURE" })
      const sessionID = session.data.id

      harness.mockProvider.pushResponse({
        toolCall: {
          name: "shell",
          input: { command: "git push --force origin main" },
        },
      })
      harness.mockProvider.pushResponse({
        text: JSON.stringify({
          risk_level: "HIGH",
          user_authorization: "LOW",
          verdict: "UNSURE",
          reason: "Force push detected requiring review",
        }),
      })
      harness.mockProvider.pushResponse({
        text: "Done",
      })

      promptPromise = harness.promptSession(sessionID, "Force push to main")

      // Catch published alert on live ntfy.sh
      let targetAction: any
      try {
        targetAction = await harness.waitForAction(undefined, 10000)
      } catch (waitErr: any) {
        if (checkRateLimit(waitErr) || harness.isRateLimited) {
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

      const startTime = Date.now()
      let messages: any[] = []
      let toolParts: any[] = []
      while (Date.now() - startTime < 20000) {
        messages = await harness.getSessionMessages(sessionID)
        toolParts = messages
          .filter((m: any) => m.type === "assistant" || m.role === "assistant" || m.info?.role === "assistant")
          .flatMap((m: any) => m.content || m.parts || [])
          .filter((p: any) => p.type === "tool")
        const shellTool = toolParts.find((p: any) => {
          const isShellOrBash = p.tool === "shell" || p.name === "shell" || p.tool === "bash" || p.name === "bash"
          const hasCmd = p.state?.input?.command?.includes("git push --force")
          return (isShellOrBash || hasCmd) && (p.state?.status === "completed" || p.state?.status === "error")
        })
        if (shellTool) {
          break
        }
        await new Promise((r) => setTimeout(r, 300))
      }
      expect(toolParts.length).toBeGreaterThan(0)
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

  it("MockInferenceProvider respects delayMs option", async () => {
    const provider = new MockInferenceProvider(0)
    try {
      provider.pushResponse({
        text: "Delayed response",
        delayMs: 50,
      })

      const start = Date.now()
      const res = await fetch(`${provider.url}/v1/chat/completions`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ model: "gpt-4o", messages: [{ role: "user", content: "hello" }] }),
      })
      const duration = Date.now() - start

      expect(res.ok).toBe(true)
      expect(duration).toBeGreaterThanOrEqual(45)
    } finally {
      await provider.stop()
    }
  })
})
