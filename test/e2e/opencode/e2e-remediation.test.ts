import { describe, it, expect, beforeEach, afterEach } from "bun:test"
import { createAutoGateE2EHarness, OpenCodeE2EHarness } from "./harness"

describe("AutoGate E2E: Safe Transforms and Escalation Memory", () => {
  let harness: OpenCodeE2EHarness

  afterEach(async () => {
    if (harness) {
      await harness.dispose()
    }
  })

  it("Test 1: Safe Transform: rm command receives [SAFE_TRANSFORM_REJECT] with trash-cli advice", async () => {
    harness = await createAutoGateE2EHarness()
    harness.mockProvider.pushResponse({
      text: JSON.stringify({
        verdict: "BLOCK",
        reason: "Direct rm command detected",
      }),
    })

    await harness.simulatePermissionAsk({
      id: "req-rm-1",
      sessionID: "sess-1",
      permission: "shell:run",
      patterns: ["rm -rf ./build"],
      metadata: { command: "rm -rf ./build" },
    })

    const resolution = await harness.waitForResolution("req-rm-1")
    expect(resolution.reply).toBe("reject")
    expect(resolution.message).toBeDefined()
    expect(resolution.message).toContain("[SAFE_TRANSFORM_REJECT]")
    expect(resolution.message).toContain("npx trash-cli")
  })

  it("Test 2: Escalation Tool: Calling escalate_permission tool promotes subsequent action to UNSURE", async () => {
    harness = await createAutoGateE2EHarness()
    
    // Call escalate_permission tool
    const toolExec = (harness.plugin.tool as any).escalate_permission.execute
    await toolExec(
      { action: "rm -rf ./build", reason: "Need clean build directory" },
      { sessionID: "sess-user-1" }
    )

    harness.mockProvider.pushResponse({
      text: JSON.stringify({
        verdict: "BLOCK",
        reason: "Direct rm command detected",
      }),
    })

    await harness.simulatePermissionAsk({
      id: "req-rm-2",
      sessionID: "sess-user-1",
      permission: "shell:run",
      patterns: ["rm -rf ./build"],
      metadata: { command: "rm -rf ./build" },
    })

    // Because escalation was triggered, AutoGate promotes action to UNSURE and publishes push notification to mockNtfy
    let reviewNotif: any
    for (let i = 0; i < 40; i++) {
      const published = harness.mockNtfy.getPublished("e2e-test-topic")
      reviewNotif = published.find((m) => m.title?.includes("[REVIEW]"))
      if (reviewNotif) break
      await new Promise((r) => setTimeout(r, 50))
    }
expect(reviewNotif).toBeDefined()
expect(reviewNotif?.body).toContain("Need clean build directory")
  })

  it("Test 3: 60s Repeat Memory: Re-attempting rejected action within 60s automatically promotes to UNSURE", async () => {
    harness = await createAutoGateE2EHarness()

    // First attempt gets rejected
    harness.mockProvider.pushResponse({
      text: JSON.stringify({
        verdict: "BLOCK",
        reason: "Destructive git checkout",
      }),
    })

    await harness.simulatePermissionAsk({
      id: "req-repeat-1",
      sessionID: "sess-1",
      permission: "shell:run",
      patterns: ["git checkout ."],
      metadata: { command: "git checkout ." },
    })

    const res1 = await harness.waitForResolution("req-repeat-1")
    expect(res1.reply).toBe("reject")

    // Second attempt within 60s should automatically promote to UNSURE (delegating to remote/ntfy)
    await harness.simulatePermissionAsk({
      id: "req-repeat-2",
      sessionID: "sess-1",
      permission: "shell:run",
      patterns: ["git checkout ."],
      metadata: { command: "git checkout ." },
    })

    let reviewNotif: any
    for (let i = 0; i < 40; i++) {
      const published = harness.mockNtfy.getPublished("e2e-test-topic")
      reviewNotif = published.find((m) => m.title?.includes("[REVIEW]"))
      if (reviewNotif) break
      await new Promise((r) => setTimeout(r, 50))
    }
expect(reviewNotif).toBeDefined()
expect(reviewNotif?.body).toContain("Re-attempted action within 60s")
  })

  it("Test 4: Shell Escalation: Executing with AUTOGATE_ESCALATE=1 immediately promotes to UNSURE", async () => {
    harness = await createAutoGateE2EHarness()

    harness.mockProvider.pushResponse({
      text: JSON.stringify({
        verdict: "BLOCK",
        reason: "Destructive rm command",
      }),
    })

    await harness.simulatePermissionAsk({
      id: "req-esc-1",
      sessionID: "sess-1",
      permission: "shell:run",
      patterns: ["AUTOGATE_ESCALATE=1 rm -rf dist"],
      metadata: { command: "AUTOGATE_ESCALATE=1 rm -rf dist" },
    })

    let reviewNotif: any
    for (let i = 0; i < 40; i++) {
      const published = harness.mockNtfy.getPublished("e2e-test-topic")
      reviewNotif = published.find((m) => m.title?.includes("[REVIEW]"))
      if (reviewNotif) break
      await new Promise((r) => setTimeout(r, 50))
    }
expect(reviewNotif).toBeDefined()
expect(reviewNotif?.body).toContain("Escalated via AUTOGATE_ESCALATE=1")
  })
})
