import { describe, it, expect, beforeEach } from "bun:test"
import { resolveShadowedApproval } from "../src/approval-bridge.ts"
import { registerShadowedEvalTool } from "../src/index.ts"
import { registerToolCallHook } from "../src/hook.ts"
import { formatActionDetails } from "@autogate/core"

describe("shadowed eval tool & approval support", () => {
  let store: Map<string, any>

  beforeEach(() => {
    store = new Map()
  })

  it("1. resolveShadowedApproval resolves code argument and toolCallId verdicts", () => {
    // Allow via toolCallId
    store.set("tool-1", { verdict: "ALLOW", policy: "allow" })
    expect(resolveShadowedApproval({ code: "print('test')", toolCallId: "tool-1" }, store)).toEqual({
      tier: "write",
      policy: "allow",
    })

    // Allow via code string
    store.set("print('hello')", { verdict: "ALLOW", policy: "allow" })
    expect(resolveShadowedApproval({ code: "print('hello')" }, store)).toEqual({
      tier: "write",
      policy: "allow",
    })

    // Deny verdict
    store.set("tool-deny", { verdict: "BLOCK", policy: "deny", reason: "Unsafe code" })
    expect(resolveShadowedApproval({ code: "import os; os.system('rm -rf /')", toolCallId: "tool-deny" }, store)).toEqual({
      tier: "exec",
      policy: "deny",
      override: true,
      reason: "Unsafe code",
    })

    // Prompt verdict
    store.set("tool-prompt", { verdict: "UNSURE", policy: "prompt", reason: "Needs review" })
    expect(resolveShadowedApproval({ code: "eval('bad')", toolCallId: "tool-prompt" }, store)).toEqual({
      tier: "exec",
      policy: "prompt",
      override: true,
      reason: "Needs review",
    })

    // No record defaults to write
    expect(resolveShadowedApproval({ code: "print('unknown')" }, store)).toEqual({
      tier: "write",
    })
  })

  it("2. registerShadowedEvalTool registers 'eval' tool with approval function and delegates to ctx.invokeTool", async () => {
    const registeredTools: any[] = []
    const mockPi = {
      registerTool(tool: any) {
        registeredTools.push(tool)
      },
    }

    const mockEngine = {
      isEnabled: () => true,
    }

    registerShadowedEvalTool(mockPi, mockEngine as any)

    expect(registeredTools.length).toBe(1)
    const evalTool = registeredTools[0]
    expect(evalTool.name).toBe("eval")
    expect(typeof evalTool.approval).toBe("function")
    expect(typeof evalTool.execute).toBe("function")

    // Test execution delegation
    let invoked = false
    const mockCtx = {
      invokeTool: async (params: any, options: any) => {
        invoked = true
        expect(params).toEqual({ code: "2 + 2", language: "py" })
        return { result: "4" }
      },
    }

    const result = await evalTool.execute("call-123", { code: "2 + 2", language: "py" }, null, null, mockCtx)
    expect(invoked).toBe(true)
    expect(result).toEqual({ result: "4" })

    // Test missing invokeTool error
    await expect(
      evalTool.execute("call-123", { code: "2 + 2" }, null, null, {})
    ).rejects.toThrow("ctx.invokeTool is unavailable for shadowed eval delegation")
  })

  it("3. formatActionDetails produces fenced code block for eval action", () => {
    const formatted = formatActionDetails("eval", { code: "print('hello world')", language: "py" })
    expect(formatted).toContain("```py")
    expect(formatted).toContain("print('hello world')")
    expect(formatted).toContain("- **Eval Code (py)**:")
  })

  it("4. tool_call hook extracts event.input.code into action payload", async () => {
    const listeners = new Map<string, Function>()
    const mockPi = {
      on(event: string, cb: Function) {
        listeners.set(event, cb)
      },
    }

    let evaluatedAction: any = null
    const testStore = new Map()
    const mockEngine = {
      isEnabled: () => true,
      getUserPrompt: () => "user instruction",
      evaluate: async (action: any) => {
        evaluatedAction = action
        return { verdict: "ALLOW" }
      },
    }

    registerToolCallHook(mockPi, mockEngine as any, testStore)

    const toolCallHandler = listeners.get("tool_call")
    expect(typeof toolCallHandler).toBe("function")

    await toolCallHandler(
      {
        toolCallId: "eval-call-1",
        toolName: "eval",
        input: { code: "import math; math.pi", language: "py" },
      },
      { sessionID: "ses-test" }
    )

    expect(evaluatedAction).not.toBeNull()
    expect(evaluatedAction.toolName).toBe("eval")
    expect(evaluatedAction.commandString).toBe("import math; math.pi")
    expect(evaluatedAction.rawArgs).toEqual({ code: "import math; math.pi", language: "py" })
    expect(evaluatedAction.sessionID).toBe("ses-test")
    expect(evaluatedAction.userPrompt).toBe("user instruction")
  })
})
