import { describe, it, expect, afterEach } from "bun:test"
import * as fs from "fs"
import * as path from "path"
import { createRealOpenCodeHarness, RealOpenCodeHarness } from "./real-harness"

describe("RealOpenCodeHarness", () => {
  let harness: RealOpenCodeHarness | undefined

  afterEach(async () => {
    if (harness) {
      await harness.dispose()
      harness = undefined
    }
  })

  it("orchestrates real opencode server, configures ephemeral sandbox, and allows session creation", async () => {
    harness = await createRealOpenCodeHarness()

    // 1. Verify MockInferenceProvider is initialized on a dynamic port
    expect(harness.mockProvider).toBeDefined()
    expect(harness.mockProvider.port).toBeGreaterThan(0)
    expect(harness.mockProvider.url).toContain("http://127.0.0.1:")

    // 2. Verify ephemeral sandbox setup
    expect(fs.existsSync(harness.workspaceDir)).toBe(true)
    expect(fs.existsSync(path.join(harness.workspaceDir, ".git"))).toBe(true)

    const agentSymlink = path.join(
      harness.workspaceDir,
      ".config",
      "opencode",
      "agents",
      "auto-gate-eval.md"
    )
    expect(fs.existsSync(agentSymlink)).toBe(true)
    const stats = fs.lstatSync(agentSymlink)
    expect(stats.isSymbolicLink()).toBe(true)

    // 3. Verify server URL and authentication header
    expect(harness.url).toMatch(/^http:\/\/127\.0\.0\.1:\d+$/)
    expect(harness.authHeader).toMatch(/^Basic [A-Za-z0-9+/=]+$/)

    // 4. Verify session creation via client.session.create()
    const sessionRes = await harness.client.session.create({
      query: { directory: harness.workspaceDir },
    })

    expect(sessionRes.error).toBeUndefined()
    expect(sessionRes.data?.id).toBeDefined()
    expect(typeof sessionRes.data?.id).toBe("string")

    // 5. Verify session creation via harness helper
    const helperRes = await harness.createSession({ title: "Test Helper Session" })
    expect(helperRes.error).toBeUndefined()
    expect(helperRes.data?.id).toBeDefined()

    // 6. Verify Basic Auth enforcement on real server
    const unauthorizedRes = await fetch(`${harness.url}/session`, {
      method: "GET",
    })
    expect(unauthorizedRes.status).toBe(401)
  }, 30000)
  it("configures collision-free live ntfy topic, default server, and token in pluginConfig", async () => {
    const harness1 = new RealOpenCodeHarness()
    const harness2 = new RealOpenCodeHarness()

    try {
      expect(harness1.ntfyServer).toBe("https://ntfy.sh")
      expect(harness1.ntfyToken).toBe(process.env.NTFY_TOKEN || "***REMOVED***")
      expect(harness1.ntfyTopic).toMatch(/^autogate-e2e-\d+-[a-f0-9]{6}$/)

      expect(harness2.ntfyServer).toBe("https://ntfy.sh")
      expect(harness2.ntfyTopic).toMatch(/^autogate-e2e-\d+-[a-f0-9]{6}$/)
      expect(harness1.ntfyTopic).not.toBe(harness2.ntfyTopic)
    } finally {
      await harness1.dispose()
      await harness2.dispose()
    }
  })

  it("connects to live ntfy.sh SSE stream, receives notifications, parses Action headers, and executes simulatePhoneTap", async () => {
    harness = await createRealOpenCodeHarness()

    try {
      await harness.connectNtfyStream()
    } catch (err: any) {
      if (harness.isRateLimited || String(err?.message || "").includes("429")) {
        console.log("[SKIP] ntfy.sh rate limited (429 quota reached)")
        return
      }
      throw err
    }

    const testReqId = `req-live-${Date.now()}-${crypto.randomUUID().slice(0, 6)}`
    const responseTopic = `${harness.ntfyTopic}-response`

    // Publish live notification with action buttons to ntfy.sh
    const actionsHeader = [
      `http, Approve, https://ntfy.sh/${responseTopic}, body='{"req_id": "${testReqId}", "reply": "once"}', method=POST, headers.Authorization=Bearer ${harness.ntfyToken}`,
      `http, Always Approve, https://ntfy.sh/${responseTopic}, body='{"req_id": "${testReqId}", "reply": "always"}', method=POST, headers.Authorization=Bearer ${harness.ntfyToken}`,
      `http, Deny, https://ntfy.sh/${responseTopic}, body='{"req_id": "${testReqId}", "reply": "reject"}', method=POST, headers.Authorization=Bearer ${harness.ntfyToken}`,
    ].join("; ")

    const pubRes = await fetch(`${harness.ntfyServer}/${harness.ntfyTopic}`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${harness.ntfyToken}`,
        Title: "Review Required",
        Actions: actionsHeader,
      },
      body: "Security review requested for bash command: rm -rf build",
    })

    if (pubRes.status === 429) {
      console.log("[SKIP] ntfy.sh publish rate limited (429 quota reached)")
      return
    }
    expect(pubRes.ok).toBe(true)

    // Await live action parsing from SSE stream
    const targetAction = await harness.waitForAction(testReqId, 10000)
    expect(targetAction).toBeDefined()
    expect(targetAction.label).toBe("Approve")
    expect(targetAction.url).toBe(`https://ntfy.sh/${responseTopic}`)
    expect(targetAction.method).toBe("POST")
    expect(targetAction.headers["Authorization"]).toBe(`Bearer ${harness.ntfyToken}`)
    expect(targetAction.actions.length).toBe(3)
    expect(Array.isArray(targetAction)).toBe(true)
    expect(targetAction[0].label).toBe("Approve")
    expect(targetAction[1].label).toBe("Always Approve")
    expect(targetAction[2].label).toBe("Deny")

    // Execute phone tap
    await harness.simulatePhoneTap(testReqId, "once")
  }, 30000)

  it("simulatePhoneTap dispatches to OpenCode server with generated Basic Auth when action targets permission reply endpoint", async () => {
    harness = await createRealOpenCodeHarness()

    const permId = `per_${Date.now()}_test`
    const actionsHeader = `http, Approve, ${harness.url}/permission/${permId}/reply, body='{"reply": "once"}', method=POST`

    try {
      await harness.simulatePhoneTap(permId, "once", undefined, { actionsHeader })
    } catch (err: any) {
      // Expect 404 from OpenCode server because this permission request wasn't actually queued in DB,
      // confirming it successfully routed with the Basic Auth headers generated by AutoGate
      expect(err.message).toContain("404")
      expect(err.message).toContain("PermissionNotFoundError")
    }

    // Relative URL resolution test
    const relativeActionsHeader = `http, Approve, /permission/${permId}/reply, body='{"reply": "once"}', method=POST`
    try {
      await harness.simulatePhoneTap(permId, "once", undefined, { actionsHeader: relativeActionsHeader })
    } catch (err: any) {
      expect(err.message).toContain("404")
      expect(err.message).toContain("PermissionNotFoundError")
    }
  }, 30000)

  it("handles AbortSignal on connectNtfyStream and cleanly terminates on dispose()", async () => {
    harness = await createRealOpenCodeHarness()
    const abortCtrl = new AbortController()

    try {
      await harness.connectNtfyStream(abortCtrl.signal)
    } catch (err: any) {
      if (harness.isRateLimited || String(err?.message || "").includes("429")) {
        console.log("[SKIP] ntfy.sh rate limited (429 quota reached)")
        return
      }
      throw err
    }

// Abort controller cleanly
abortCtrl.abort()
await harness.dispose()
harness = undefined
  }, 20000)

  it("tracks active harnesses in static registry and removes them upon disposal", async () => {
    harness = await createRealOpenCodeHarness()
    expect(RealOpenCodeHarness.activeHarnesses.has(harness)).toBe(true)

    await harness.dispose()
    expect(RealOpenCodeHarness.activeHarnesses.has(harness)).toBe(false)
    harness = undefined
  }, 20000)

  it("dispose() is idempotent, completely cleans up temporary directories, and terminates server processes", async () => {
    harness = await createRealOpenCodeHarness()
    const workspaceDir = harness.workspaceDir
    const serverPid = harness.serverPid
    const serverPort = harness.serverPort

    expect(fs.existsSync(workspaceDir)).toBe(true)
    expect(serverPid).toBeDefined()
    expect(typeof serverPid).toBe("number")
    expect(serverPid!).toBeGreaterThan(0)
    expect(serverPort).toBeDefined()
    expect(serverPort!).toBeGreaterThan(0)

    // Verify process is running before dispose
    let isRunningBefore = false
    try {
      process.kill(serverPid!, 0)
      isRunningBefore = true
    } catch {}
    expect(isRunningBefore).toBe(true)

    // First dispose
    await harness.dispose()

    // Verify temp workspace directory was removed
    expect(fs.existsSync(workspaceDir)).toBe(false)

    // Verify server process was terminated
    expect(harness.isProcessRunning(serverPid!)).toBe(false)
let isRunningAfter = false
try {
process.kill(serverPid!, 0)
isRunningAfter = true
} catch (e: any) {
expect(e.code).toBe("ESRCH")
}
expect(isRunningAfter).toBe(false)

    // Verify listening port is released
    const lingeringPid = harness.findServerPid(serverPort!)
    expect(lingeringPid).toBeUndefined()

    // Verify harness was removed from registry
    expect(RealOpenCodeHarness.activeHarnesses.has(harness)).toBe(false)

    // Verify idempotence: subsequent dispose() calls succeed without error
    await expect(harness.dispose()).resolves.toBeUndefined()
    await expect(harness.dispose()).resolves.toBeUndefined()

    // Verify disposeSync() is also safe when already disposed
    expect(() => harness!.disposeSync()).not.toThrow()

    harness = undefined
  }, 20000)

  it("disposeSync() synchronously performs teardown, terminates server processes, and cleans up temp directories", async () => {
    harness = await createRealOpenCodeHarness()
    const workspaceDir = harness.workspaceDir
    const serverPid = harness.serverPid
    const serverPort = harness.serverPort

    expect(fs.existsSync(workspaceDir)).toBe(true)
    expect(RealOpenCodeHarness.activeHarnesses.has(harness)).toBe(true)

    // Synchronous disposal
    harness.disposeSync()

    expect(RealOpenCodeHarness.activeHarnesses.has(harness)).toBe(false)
    expect(fs.existsSync(workspaceDir)).toBe(false)

    if (serverPid) {
      expect(harness.isProcessRunning(serverPid)).toBe(false)
      // Allow event loop tick for kernel process reaping
      await new Promise((r) => setTimeout(r, 50))
      let isRunningAfter = false
      try {
        process.kill(serverPid, 0)
        isRunningAfter = true
      } catch {}
      expect(isRunningAfter).toBe(false)
    }
    if (serverPort) {
      const lingeringPid = harness.findServerPid(serverPort)
      expect(lingeringPid).toBeUndefined()
    }

    // Await async dispose afterwards to ensure complete idempotence across sync/async
    await expect(harness.dispose()).resolves.toBeUndefined()

    harness = undefined
  }, 20000)
})
