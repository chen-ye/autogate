import { describe, it, expect, afterEach } from "bun:test"
import { createAutoGateE2EHarness, OpenCodeE2EHarness } from "./harness"
import { MockInferenceProvider } from "./mock-provider"

describe("AutoGate E2E: Edge Conditions & Resilience", () => {
  let harness: OpenCodeE2EHarness | null = null
  let standaloneProvider: MockInferenceProvider | null = null

  afterEach(async () => {
    if (harness) {
      await harness.dispose()
      harness = null
    }
    if (standaloneProvider) {
      await standaloneProvider.stop()
      standaloneProvider = null
    }
  })

  describe("MockInferenceProvider: Empty Response Queue Behavior", () => {
    it("returns HTTP 500 with 'No mock responses queued' when queue is empty (OpenAI format)", async () => {
      standaloneProvider = new MockInferenceProvider(0)

      const res = await fetch(`${standaloneProvider.url}/v1/chat/completions`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          model: "gpt-4o",
          messages: [{ role: "user", content: "hello" }],
        }),
      })

      expect(res.status).toBe(500)
      const data = await res.json()
      expect(data).toEqual({ error: "No mock responses queued" })
      expect(standaloneProvider.getRequests().length).toBe(1)
    })

    it("returns HTTP 500 when queue is empty (Gemini format)", async () => {
      standaloneProvider = new MockInferenceProvider(0)

      const res = await fetch(`${standaloneProvider.url}/v1/models/gemini-2.5-flash:generateContent`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          contents: [{ parts: [{ text: "evaluate command" }] }],
        }),
      })

      expect(res.status).toBe(500)
      const data = await res.json()
      expect(data).toEqual({ error: "No mock responses queued" })
    })

    it("serves queued responses first, then returns HTTP 500 on subsequent requests", async () => {
      standaloneProvider = new MockInferenceProvider(0)

      standaloneProvider.pushResponse({
        text: JSON.stringify({ verdict: "ALLOW", reason: "First response" }),
      })

      // First call succeeds
      const res1 = await fetch(`${standaloneProvider.url}/v1/chat/completions`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ messages: [] }),
      })
      expect(res1.status).toBe(200)
      const data1 = await res1.json()
      expect(data1.choices[0].message.content).toContain("First response")

      // Second call fails with 500 because queue is now empty
      const res2 = await fetch(`${standaloneProvider.url}/v1/chat/completions`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ messages: [] }),
      })
      expect(res2.status).toBe(500)
      const data2 = await res2.json()
      expect(data2).toEqual({ error: "No mock responses queued" })
    })

    it("Harness falls back to default approval when MockInferenceProvider returns 500 (empty queue)", async () => {
      harness = await createAutoGateE2EHarness({
        workspaceDir: "/tmp/project-fallback",
      })

      // Note: do NOT push any response to harness.mockProvider so it returns 500
      const promptRes = await fetch(`http://localhost:${harness.server.port}/session/ses_test/prompt`, {
        method: "POST",
        headers: {
          Authorization: harness.authHeader,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          model: "gpt-4o",
          messages: [{ role: "user", content: "classify" }],
        }),
      })

      expect(promptRes.status).toBe(200)
      const promptData = await promptRes.json()
      expect(promptData.parts).toBeDefined()
      expect(promptData.parts[0].text).toContain("Default mock fallback approval")
      expect(promptData.parts[0].text).toContain("ALLOW")
    })
  })

  describe("OpenCodeE2EHarness: Basic Auth Failure & 401 Behavior", () => {
    it("rejects requests missing the Authorization header with HTTP 401", async () => {
      harness = await createAutoGateE2EHarness()
      const baseUrl = `http://localhost:${harness.server.port}`

      // GET /permission
      const resPerm = await fetch(`${baseUrl}/permission`)
      expect(resPerm.status).toBe(401)
      expect(await resPerm.text()).toBe("Unauthorized")

      // POST /session
      const resSess = await fetch(`${baseUrl}/session`, { method: "POST" })
      expect(resSess.status).toBe(401)

      // POST /permission/:id/reply
      const resReply = await fetch(`${baseUrl}/permission/test-1/reply`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ reply: "once" }),
      })
      expect(resReply.status).toBe(401)
    })

    it("rejects requests with incorrect password with HTTP 401", async () => {
      harness = await createAutoGateE2EHarness({
        serverPassword: "correct-secret-token-999",
      })
      const baseUrl = `http://localhost:${harness.server.port}`
      const badAuth = "Basic " + Buffer.from("opencode:wrong-password").toString("base64")

      const res = await fetch(`${baseUrl}/permission`, {
        headers: { Authorization: badAuth },
      })
      expect(res.status).toBe(401)
      expect(await res.text()).toBe("Unauthorized")
    })

    it("rejects requests with invalid Authorization scheme or malformed header with HTTP 401", async () => {
      harness = await createAutoGateE2EHarness()
      const baseUrl = `http://localhost:${harness.server.port}`

      // Bearer token instead of Basic
      const resBearer = await fetch(`${baseUrl}/permission`, {
        headers: { Authorization: "Bearer some-token" },
      })
      expect(resBearer.status).toBe(401)

      // Wrong username (admin instead of opencode)
      const resUser = await fetch(`${baseUrl}/permission`, {
        headers: {
          Authorization: "Basic " + Buffer.from(`admin:${harness.serverPassword}`).toString("base64"),
        },
      })
      expect(resUser.status).toBe(401)
    })

    it("accepts requests with exact configured Basic Auth credentials with HTTP 200", async () => {
      const customPassword = "my-custom-e2e-pass-42"
      harness = await createAutoGateE2EHarness({
        serverPassword: customPassword,
      })
      const baseUrl = `http://localhost:${harness.server.port}`
      const goodAuth = "Basic " + Buffer.from(`opencode:${customPassword}`).toString("base64")

      const res = await fetch(`${baseUrl}/permission`, {
        headers: { Authorization: goodAuth },
      })
      expect(res.status).toBe(200)
      const data = await res.json()
      expect(Array.isArray(data)).toBe(true)
    })
  })

  describe("Multi-Directory Routing Assertions (?directory=...)", () => {
    it("parses and records ?directory query param on reply endpoint", async () => {
      harness = await createAutoGateE2EHarness()
      const baseUrl = `http://localhost:${harness.server.port}`
      const auth = harness.authHeader

      const targetDir = "/opt/repo/service-a"
      const res = await fetch(`${baseUrl}/permission/req-dir-test-1/reply?directory=${encodeURIComponent(targetDir)}`, {
        method: "POST",
        headers: {
          Authorization: auth,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ reply: "once", message: "Approved for dir A" }),
      })

      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data.success).toBe(true)

      const replies = harness.getReceivedReplies()
      const recorded = replies.find((r) => r.id === "req-dir-test-1")
      expect(recorded).toBeDefined()
      expect(recorded?.directory).toBe(targetDir)
      expect(recorded?.reply).toBe("once")
      expect(recorded?.message).toBe("Approved for dir A")
    })

    it("handles special characters and spaces in directory paths correctly", async () => {
      harness = await createAutoGateE2EHarness()
      const baseUrl = `http://localhost:${harness.server.port}`
      const auth = harness.authHeader

      const spacedDir = "/Users/test/My Documents/Project (Beta)+Special"
      const res = await fetch(`${baseUrl}/permission/req-special-dir/reply?directory=${encodeURIComponent(spacedDir)}`, {
        method: "POST",
        headers: {
          Authorization: auth,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ reply: "always" }),
      })

      expect(res.status).toBe(200)
      const recorded = harness.getReceivedReplies().find((r) => r.id === "req-special-dir")
      expect(recorded).toBeDefined()
      expect(recorded?.directory).toBe(spacedDir)
      expect(recorded?.reply).toBe("always")
    })

    it("leaves directory undefined when query parameter is omitted", async () => {
      harness = await createAutoGateE2EHarness()
      const baseUrl = `http://localhost:${harness.server.port}`
      const auth = harness.authHeader

      const res = await fetch(`${baseUrl}/permission/req-no-dir/reply`, {
        method: "POST",
        headers: {
          Authorization: auth,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ reply: "reject" }),
      })

      expect(res.status).toBe(200)
      const recorded = harness.getReceivedReplies().find((r) => r.id === "req-no-dir")
      expect(recorded).toBeDefined()
      expect(recorded?.directory).toBeUndefined()
      expect(recorded?.reply).toBe("reject")
    })

    it("maintains strict multi-directory isolation across concurrent permission requests", async () => {
      harness = await createAutoGateE2EHarness({
        workspaceDir: "/workspace/root",
      })

      const dirAlpha = "/workspace/sub-alpha"
      const dirBeta = "/workspace/sub-beta"

      // Queue UNSURE responses so ntfy notification is triggered for both
      harness.mockProvider.pushResponse({
        text: JSON.stringify({
          verdict: "UNSURE",
          reason: "Needs review in Alpha",
        }),
      })
      harness.mockProvider.pushResponse({
        text: JSON.stringify({
          verdict: "UNSURE",
          reason: "Needs review in Beta",
        }),
      })

      // Ask Alpha
      await harness.simulatePermissionAsk({
        id: "req-multi-alpha",
        sessionID: "sess-alpha",
        permission: "bash",
        patterns: ["deploy alpha"],
        metadata: { directory: dirAlpha, command: "deploy alpha" },
      })

      // Ask Beta
      await harness.simulatePermissionAsk({
        id: "req-multi-beta",
        sessionID: "sess-beta",
        permission: "bash",
        patterns: ["deploy beta"],
        metadata: { directory: dirBeta, command: "deploy beta" },
      })

      // Simulate phone taps with respective responses (phone taps provide reply "once" / "always")
      await harness.simulatePhoneTap("req-multi-alpha", "once")
      await harness.simulatePhoneTap("req-multi-beta", "always")

      // Wait for resolutions
      const resAlpha = await harness.waitForResolution("req-multi-alpha", 4000)
      const resBeta = await harness.waitForResolution("req-multi-beta", 4000)

      expect(resAlpha.reply).toBe("once")
      expect(resAlpha.directory).toBe(dirAlpha)

      expect(resBeta.reply).toBe("always")
      expect(resBeta.directory).toBe(dirBeta)
      // Verify harness replies log confirms separation
      const replies = harness.getReceivedReplies()
      const replyAlpha = replies.find((r) => r.id === "req-multi-alpha")
      const replyBeta = replies.find((r) => r.id === "req-multi-beta")

      expect(replyAlpha).toBeDefined()
      expect(replyAlpha?.directory).toBe(dirAlpha)
      expect(replyBeta).toBeDefined()
      expect(replyBeta?.directory).toBe(dirBeta)
    })
  })
})
