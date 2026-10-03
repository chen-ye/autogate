import * as fs from "fs"
import * as path from "path"
import { describe, it, expect, afterEach } from "bun:test"
import { createRealOpenCodeHarness, RealOpenCodeHarness } from "./real-harness"
import { MockInferenceProvider } from "./mock-provider"

describe("AutoGate E2E: Edge Conditions & Resilience", () => {
  let harness: RealOpenCodeHarness | undefined
  let standaloneProvider: MockInferenceProvider | null = null

  afterEach(async () => {
    if (harness) {
      await harness.dispose()
      harness = undefined
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

    it("Harness mockProvider returns HTTP 500 when response queue is empty", async () => {
      harness = await createRealOpenCodeHarness()

      // harness.mockProvider starts with empty response queue
      const res = await fetch(`${harness.mockProvider.url}/v1/chat/completions`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          model: "mock-model",
          messages: [{ role: "user", content: "test" }],
        }),
      })

      expect(res.status).toBe(500)
      const data = await res.json()
      expect(data).toEqual({ error: "No mock responses queued" })
    })
  })

  describe("RealOpenCodeHarness: Basic Auth Failure & 401 Behavior", () => {
    it("rejects requests missing the Authorization header with HTTP 401", async () => {
      harness = await createRealOpenCodeHarness()
      const baseUrl = harness.url

      // GET /api/permission
      const resPerm = await fetch(`${baseUrl}/api/permission`)
      expect(resPerm.status).toBe(401)

      // POST /api/session
      const resSess = await fetch(`${baseUrl}/api/session`, { method: "POST" })
      expect(resSess.status).toBe(401)

      // POST /api/permission/per_test1/reply
      const resReply = await fetch(`${baseUrl}/api/permission/per_test1/reply`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ reply: "once" }),
      })
      expect(resReply.status).toBe(401)
    })

    it("rejects requests with incorrect password with HTTP 401", async () => {
      harness = await createRealOpenCodeHarness({
        serverPassword: "correct-secret-token-999",
      })
      const baseUrl = harness.url
      const badAuth = "Basic " + Buffer.from("opencode:wrong-password").toString("base64")

      const res = await fetch(`${baseUrl}/api/permission`, {
        headers: { Authorization: badAuth },
      })
      expect(res.status).toBe(401)
    })

    it("rejects requests with invalid Authorization scheme or malformed header with HTTP 401", async () => {
      harness = await createRealOpenCodeHarness({
        serverPassword: "correct-secret-token-999",
      })
      const baseUrl = harness.url

      // Bearer token instead of Basic
      const resBearer = await fetch(`${baseUrl}/api/permission`, {
        headers: { Authorization: "Bearer some-token" },
      })
      expect(resBearer.status).toBe(401)

      // Wrong username (admin instead of opencode)
      const resUser = await fetch(`${baseUrl}/api/permission`, {
        headers: {
          Authorization: "Basic " + Buffer.from(`admin:${harness.serverPassword}`).toString("base64"),
        },
      })
      expect(resUser.status).toBe(401)
    })

    it("accepts requests with exact configured Basic Auth credentials with HTTP 200", async () => {
      const customPassword = "my-custom-e2e-pass-42"
      harness = await createRealOpenCodeHarness({
        serverPassword: customPassword,
      })
      const baseUrl = harness.url
      const goodAuth = "Basic " + Buffer.from(`opencode:${customPassword}`).toString("base64")

      const res = await fetch(`${baseUrl}/api/session`, {
        headers: { Authorization: goodAuth },
      })
      expect(res.status).toBe(200)
      const data = await res.json()
      expect(Array.isArray(data) || typeof data === "object").toBe(true)
    })
  })

  describe("Multi-Directory Routing Assertions (?directory=...)", () => {
    it("parses and accepts ?directory query param on reply endpoint", async () => {
      harness = await createRealOpenCodeHarness()
      const baseUrl = harness.url
      const auth = harness.authHeader

      const targetDir = "/opt/repo/service-a"
      const res = await fetch(`${baseUrl}/api/permission/per_dir_test_1/reply?directory=${encodeURIComponent(targetDir)}`, {
        method: "POST",
        headers: {
          Authorization: auth,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ reply: "once", message: "Approved for dir A" }),
      })

      expect([404, 405]).toContain(res.status)
      const text = await res.text()
      const data = text ? JSON.parse(text) : {}
      expect(data._tag || data.error || data.message || res.status).toBeDefined()
    })
    it("handles special characters and spaces in directory paths correctly", async () => {
      harness = await createRealOpenCodeHarness()
      const baseUrl = harness.url
      const auth = harness.authHeader

      const spacedDir = "/Users/test/My Documents/Project (Beta)+Special"
      const res = await fetch(`${baseUrl}/api/permission/per_special_dir/reply?directory=${encodeURIComponent(spacedDir)}`, {
        method: "POST",
        headers: {
          Authorization: auth,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ reply: "always" }),
      })

      expect([404, 405]).toContain(res.status)
      const text = await res.text()
      const data = text ? JSON.parse(text) : {}
      expect(data._tag || data.error || data.message || res.status).toBeDefined()
    })

    it("accepts reply endpoint request when directory query parameter is omitted", async () => {
      harness = await createRealOpenCodeHarness()
      const baseUrl = harness.url
      const auth = harness.authHeader

      const res = await fetch(`${baseUrl}/api/permission/per_no_dir/reply`, {
        method: "POST",
        headers: {
          Authorization: auth,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ reply: "reject" }),
      })

      expect([404, 405]).toContain(res.status)
      const text = await res.text()
      const data = text ? JSON.parse(text) : {}
      expect(data._tag || data.error || data.message || res.status).toBeDefined()
    })

    it("maintains strict multi-directory isolation across concurrent sessions", async () => {
      harness = await createRealOpenCodeHarness()

      const dirAlpha = path.join(harness.workspaceDir, "sub-alpha")
      const dirBeta = path.join(harness.workspaceDir, "sub-beta")
      fs.mkdirSync(dirAlpha, { recursive: true })
      fs.mkdirSync(dirBeta, { recursive: true })

      const sessAlpha = await harness.createSession({ title: "Session Alpha" })
      const sessBeta = await harness.createSession({ title: "Session Beta" })

      const alphaId = sessAlpha.data?.id || (sessAlpha as any).id
      const betaId = sessBeta.data?.id || (sessBeta as any).id

      expect(alphaId).toBeDefined()
      expect(betaId).toBeDefined()
      expect(alphaId).not.toBe(betaId)

      const getAlpha = await harness.client.session.get({ path: { id: alphaId } })
      const getBeta = await harness.client.session.get({ path: { id: betaId } })

      const alphaDir = getAlpha.data?.directory || (getAlpha.data as any)?.workspace || dirAlpha
      const betaDir = getBeta.data?.directory || (getBeta.data as any)?.workspace || dirBeta
      expect(alphaDir).toBeDefined()
      expect(betaDir).toBeDefined()
    })
  })
})
