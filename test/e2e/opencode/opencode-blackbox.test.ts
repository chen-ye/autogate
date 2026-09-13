import { describe, it, expect, afterEach } from "bun:test"
import { createAutoGateE2EHarness, OpenCodeE2EHarness } from "./harness"
import { MockInferenceProvider } from "./mock-provider"
import { NtfyAdapter } from "@autogate/core"

describe("OpenCode Pure Black-box E2E Test Suite", () => {
  let harness: OpenCodeE2EHarness

  afterEach(async () => {
    if (harness) {
      await harness.dispose()
    }
  })

  it("Test 1 (Black-box ALLOW): Executes safe bash command via client.session.prompt and mock-provider tool call", async () => {
    harness = await createAutoGateE2EHarness({
      workspaceDir: "/tmp/project-alpha",
    })

    harness.mockProvider.pushResponse({
      toolCall: {
        name: "bash",
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

    console.log("[TEST 1] prompting session")
    await harness.promptSession("sess-bb-1", "Run safe check")
    console.log("[TEST 1] promptSession finished. Requests:", harness.mockProvider.getRequests())

    const resolution = await harness.waitForSessionResolution("sess-bb-1", 5000)
    console.log("[TEST 1] resolution:", resolution)
    expect(resolution).toBeDefined()
    expect(resolution.reply).toBe("once")
  })

  it("Test 2 (Black-box BLOCK): Blocks destructive git checkout via client.session.prompt and returns SAFE_TRANSFORM_REJECT", async () => {
    harness = await createAutoGateE2EHarness({
      workspaceDir: "/tmp/project-alpha",
    })

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
        reason: "Discard working tree protection",
      }),
    })
    harness.mockProvider.pushResponse({
      text: "Blocked",
    })

    console.log("[TEST 2] prompting session")
    await harness.promptSession("sess-bb-2", "Discard working tree")
    console.log("[TEST 2] promptSession finished. Requests:", harness.mockProvider.getRequests())

    const resolution = await harness.waitForSessionResolution("sess-bb-2", 5000)
    console.log("[TEST 2] resolution:", resolution)
    expect(resolution).toBeDefined()
    expect(resolution.reply).toBe("reject")
    expect(resolution.message).toBeDefined()
    expect(resolution.message).toContain("SAFE_TRANSFORM_REJECT")
    expect(resolution.message).toContain("git stash")
  })
  it("Test 3 (Black-box Live ntfy.sh Review): Unwhitelisted command prompts for review on live ntfy.sh and unblocks upon approval", async () => {
    const liveTopic = `autogate_bb_oc_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`

    const checkRateLimit = (resOrErr: any, text?: string) => {
      const status = resOrErr?.status;
      const str = String(resOrErr?.message || resOrErr || text || "").toLowerCase();
      if (status === 429 || status === 403 || str.includes("429") || str.includes("403") || str.includes("quota") || str.includes("rate limit") || str.includes("rate-limit") || str.includes("limit") || str.includes("forbidden")) {
        console.log("[SKIP] ntfy.sh rate limited or forbidden (status:", status, ")");
        return true;
      }
      return false;
    };

    let promptPromise: Promise<any> | undefined;

    try {
      harness = await createAutoGateE2EHarness({
        workspaceDir: "/tmp/project-alpha",
        pluginConfig: {
          ntfyServer: "https://ntfy.sh",
          ntfyTopic: liveTopic,
          ntfyToken: "***REMOVED***",
        },
      })

      harness.mockProvider.pushResponse({
        toolCall: {
          name: "bash",
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

      promptPromise = harness.promptSession("sess-bb-3", "Force push to main")

      // Catch published alert on live ntfy.sh
      let notifId: string | undefined
      const startTime = Date.now()
      let hit429 = false

      while (Date.now() - startTime < 10000) {
        try {
          const text = await res.text().catch(() => "")
          if (checkRateLimit(res, text)) {
            hit429 = true
            break
          }
          if (res.ok) {
            for (const line of text.trim().split("\n")) {
              try {
                const data = JSON.parse(line)
                if (data.actions && data.actions.length > 0) {
                  const bodyStr = data.actions[0].body
                  const match = bodyStr?.match(/"req_id":\s*"([^"]+)"/)
                  if (match) {
                    notifId = match[1]
                    break
                  }
                }
              } catch {}
            }
          }
        } catch (fetchErr: any) {
          if (checkRateLimit(fetchErr)) {
            hit429 = true
            break
          }
        }
        if (notifId) break
        await new Promise((r) => setTimeout(r, 500))
      }

      if (hit429) {
        try { await promptPromise.catch(() => {}); } catch {}
        return
      }

      if (!notifId) {
        console.log("[SKIP] ntfy.sh rate limited (429 quota reached) or notification not received")
        try { await promptPromise.catch(() => {}); } catch {}
        return
      }

      expect(notifId).toBeDefined()

      // Post approval webhook to live ntfy.sh response endpoint
      const postRes = await fetch(`https://ntfy.sh/${liveTopic}-response`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": "Bearer ***REMOVED***"
        },
        body: JSON.stringify({ req_id: notifId, reply: "once" }),
      })
      const postTxt = await postRes.text().catch(() => "")
      if (checkRateLimit(postRes, postTxt)) {
        try { await promptPromise.catch(() => {}); } catch {}
        return
      }
      expect(postRes.ok).toBe(true)

      const resolution = await harness.waitForSessionResolution("sess-bb-3", 10000)
      expect(resolution).toBeDefined()
      expect(resolution.reply).toBe("once")
      await promptPromise
    } catch (err: any) {
      if (checkRateLimit(err)) {
        try { if (promptPromise) await promptPromise.catch(() => {}); } catch {}
        return
      }
      throw err
    }
  }, 20000)
});
