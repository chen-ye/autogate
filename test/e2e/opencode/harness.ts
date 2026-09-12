import { MockNtfyServer } from "../mock-ntfy"
import { MockInferenceProvider } from "./mock-provider"
import { AutoGatePlugin } from "@autogate/opencode"
import { createOpencodeClient } from "@opencode-ai/sdk"
import type { Hooks, PluginInput } from "@opencode-ai/plugin"
import type { PermissionEventData } from "@autogate/core"

export interface HarnessOptions {
  workspaceDir?: string
  serverPassword?: string
  pluginConfig?: Record<string, unknown>
  ntfyToken?: string
  mockNtfy?: MockNtfyServer
}

export interface ParsedNtfyAction {
  action: string
  label: string
  url: string
  method: string
  headers: Record<string, string>
  body?: string
  clear?: boolean
}

export function splitOutsideQuotes(input: string, delimiter: string): string[] {
  const results: string[] = []
  let current = ""
  let inQuote: string | null = null
  for (let i = 0; i < input.length; i++) {
    const char = input[i]
    if ((char === "'" || char === '"') && (i === 0 || input[i - 1] !== "\\")) {
      if (!inQuote) {
        inQuote = char
      } else if (inQuote === char) {
        inQuote = null
      }
    }
    if (char === delimiter && !inQuote) {
      results.push(current.trim())
      current = ""
    } else {
      current += char
    }
  }
  if (current.trim()) {
    results.push(current.trim())
  }
  return results
}

export function parseNtfyActions(actionsHeader: string): ParsedNtfyAction[] {
  const rawActions = splitOutsideQuotes(actionsHeader, ";")
  const parsed: ParsedNtfyAction[] = []

  for (const rawAction of rawActions) {
    const parts = splitOutsideQuotes(rawAction, ",")
    if (parts.length < 3) continue

    const action = parts[0]
    const label = parts[1]
    const url = parts[2]
    const actionHeaders: Record<string, string> = {}
    let method = "POST"
    let body: string | undefined
    let clear: boolean | undefined

    for (let i = 3; i < parts.length; i++) {
      const part = parts[i]
      const eqIdx = part.indexOf("=")
      if (eqIdx === -1) continue

      const key = part.slice(0, eqIdx).trim()
      let val = part.slice(eqIdx + 1).trim()
      if ((val.startsWith("'") && val.endsWith("'")) || (val.startsWith('"') && val.endsWith('"'))) {
        val = val.slice(1, -1)
      }

      if (key === "method") {
        method = val.toUpperCase()
      } else if (key === "body") {
        body = val
      } else if (key === "clear") {
        clear = val.toLowerCase() === "true"
      } else if (key.startsWith("headers.")) {
        const headerName = key.slice("headers.".length).trim()
        actionHeaders[headerName] = val
      }
    }

    parsed.push({
      action,
      label,
      url,
      method,
      headers: actionHeaders,
      body,
      clear,
    })
  }

  return parsed
}

export interface ReceivedReply {
  id: string
  sessionID?: string
  reply: "once" | "always" | "reject"
  directory?: string
  message?: string
  headers: Record<string, string>
  body: Record<string, unknown>
}
export class OpenCodeE2EHarness {
  public mockNtfy: MockNtfyServer
  public mockProvider: MockInferenceProvider
  public server: ReturnType<typeof Bun.serve>
  public plugin!: Hooks
  public workspaceDir: string
  private receivedReplies: ReceivedReply[] = []
  private pendingResolutions = new Map<string, (val: { reply: string; directory?: string; message?: string }) => void>()
  private pendingPermissions = new Map<string, PermissionEventData>()
  public serverPassword: string
  public authHeader: string
  private ntfyTopic: string
  private ntfyToken?: string
  private ntfyServer?: string

  constructor(options?: HarnessOptions) {
    this.serverPassword = options?.serverPassword || process.env.OPENCODE_SERVER_PASSWORD || crypto.randomUUID()
    process.env.OPENCODE_SERVER_PASSWORD = this.serverPassword
this.workspaceDir = options?.workspaceDir || "/tmp/project-alpha"
    const pluginCfg = options?.pluginConfig || {}
    this.ntfyTopic = (pluginCfg.ntfyTopic as string) || "e2e-test-topic"
    this.ntfyToken = options?.ntfyToken ?? (pluginCfg.ntfyToken as string | undefined)
    this.mockNtfy = options?.mockNtfy ?? new MockNtfyServer(0, this.ntfyToken)
    this.mockProvider = new MockInferenceProvider(0)
    this.authHeader = "Basic " + Buffer.from(`opencode:${this.serverPassword}`).toString("base64")
    const authHeader = this.authHeader

    // Start in-process OpenCode HTTP server on port 0
    this.server = Bun.serve({
      port: 0,
      fetch: async (req) => {
        const url = new URL(req.url)
        const path = url.pathname
        const method = req.method
        console.log("[HARNESS ALL REQUESTS]:", method, path)
        // Validate Basic Auth
        const auth = req.headers.get("authorization")
if (!auth || auth !== this.authHeader) {
          console.log("[HARNESS] 401 Unauthorized for path:", path, "auth received:", auth, "expected:", this.authHeader)
          return new Response("Unauthorized", {
            status: 401,
            headers: { "Content-Type": "text/plain" },
          })
        }

        const headers: Record<string, string> = {}
        req.headers.forEach((val, key) => {
          headers[key] = val
        })

        // 1.5 POST /session/:id/permissions/:permissionID
        const permMatch = path.match(/^\/session\/([^/]+)\/permissions\/([^/]+)$/)
        if (method === "POST" && permMatch) {
          const sessionID = decodeURIComponent(permMatch[1]!)
          const id = decodeURIComponent(permMatch[2]!)
          const directory = url.searchParams.get("directory") || undefined
          let body: Record<string, unknown> = {}
          try {
            body = await req.json()
          } catch {}

          const rawReply = body?.response || body?.reply || "reject"
          const replyVal = (rawReply === "once" || rawReply === "always" || rawReply === "reject" ? rawReply : "once") as any
          const messageVal = body?.message as string | undefined

          const reqObj = this.pendingPermissions.get(id)
          const reqSessionID = reqObj?.sessionID || undefined
          console.log("[HARNESS DEBUG] perm/permissionID reply received for id:", id, "reqObj:", reqObj, "reqSessionID:", reqSessionID, "all pending:", Array.from(this.pendingPermissions.keys()))

          this.receivedReplies.push({
            id,
            sessionID: reqSessionID,
            reply: replyVal,
            directory,
            message: messageVal,
            headers,
            body,
          })
          const resolver = this.pendingResolutions.get(id)
          if (resolver) {
            resolver({ reply: replyVal, directory, message: messageVal })
            this.pendingResolutions.delete(id)
          }
          this.pendingPermissions.delete(id)

          return new Response(JSON.stringify({ success: true }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          })
        }

        // 1. POST /permission/:id/reply
        const replyMatch = path.match(/^\/permission\/([^/]+)\/reply$/)
if (method === "POST" && replyMatch) {
          const id = decodeURIComponent(replyMatch[1]!)
          const directory = url.searchParams.get("directory") || undefined
          let body: Record<string, unknown> = {}
          try {
            body = await req.json()
          } catch (err) {
            try {
              body = JSON.parse(await req.text())
            } catch (err2) {
              console.debug("[Harness] Failed to parse reply body as JSON:", err2)
            }
          }

          const replyVal = (body?.reply as any) || "reject"
          const messageVal = (body?.message || body?.response || body?.reason) as string | undefined
          const reqObj = this.pendingPermissions.get(id)
          const reqSessionID = reqObj?.sessionID || undefined
          console.log("[HARNESS DEBUG] permission/reply received for id:", id, "reqObj:", reqObj, "reqSessionID:", reqSessionID, "all pending:", Array.from(this.pendingPermissions.keys()))

          this.receivedReplies.push({
            id,
            sessionID: reqSessionID,
            reply: replyVal,
            directory,
            message: messageVal,
            headers,
            body,
          })
          const resolver = this.pendingResolutions.get(id)
          if (resolver) {
            resolver({ reply: replyVal, directory, message: messageVal })
            this.pendingResolutions.delete(id)
          }
          this.pendingPermissions.delete(id)

          return new Response(JSON.stringify({ success: true }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          })
        }

        // 2. GET /permission
        if (method === "GET" && path === "/permission") {
          return new Response(JSON.stringify(Array.from(this.pendingPermissions.values())), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          })
        }

// 3. POST /session
if (method === "POST" && path === "/session") {
const sessionID = `ses_eval_${Date.now()}_${Math.random().toString(36).slice(2)}`
return new Response(JSON.stringify({ id: sessionID, data: { id: sessionID } }), {
status: 200,
headers: { "Content-Type": "application/json" },
})
        }

        // 3.5 GET /session/:id or /session/:id/messages
        const sessGetMatch = path.match(/^\/session\/([^/]+)(\/messages)?$/)
        if (method === "GET" && sessGetMatch) {
          const sessionID = decodeURIComponent(sessGetMatch[1]!)
          if (sessGetMatch[2]) {
            return new Response(JSON.stringify({ data: [], messages: [] }), {
              status: 200,
              headers: { "Content-Type": "application/json" },
            })
          }
          return new Response(JSON.stringify({ data: { id: sessionID, parentID: null, title: "Session" } }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          })
        }

        // 4.1 PATCH or POST /session/:id (session archive/update)
        if ((method === "PATCH" || method === "POST") && /^\/session\/[^/]+$/.test(path)) {
          return new Response(JSON.stringify({ data: { success: true } }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          })
        }

        // 4. DELETE /session/:id
        if (method === "DELETE" && /^\/session\/[^/]+$/.test(path)) {
          return new Response(JSON.stringify({ data: { success: true } }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          })
        }

        // 5. POST /session/:id/prompt or message
        console.log("[HARNESS] method before prompt/message:", JSON.stringify(method), "path:", JSON.stringify(path))
        console.log("[HARNESS] regex test:", /^\/session\/[^/]+\/(prompt|message)$/.test(path))
        if (method === "POST" && /^\/session\/[^/]+\/(prompt|message)$/.test(path)) {
          const sessionMatch = path.match(/^\/session\/([^/]+)\/(prompt|message)$/)
          const sessionID = sessionMatch ? decodeURIComponent(sessionMatch[1]!) : "sess-default"
          const parts: Array<Record<string, unknown>> = []
          try {
            let providerRes: Response
            try {
              providerRes = await this.mockProvider.handleRequest(
                new Request(`${this.mockProvider.url}/v1/chat/completions`, {
                  method: "POST",
                  headers: { "Content-Type": "application/json" },
                }),
                { model: "gpt-4o", messages: [{ role: "user", content: "prompt" }] }
              )
            } catch (innerErr: any) {
              console.error("[HARNESS] handleRequest threw message:", innerErr?.message, "stack:", innerErr?.stack)
              throw innerErr
            }
            console.log("[Harness] providerRes status:", providerRes.status, "ok:", providerRes.ok)
if (providerRes.ok) {
              const providerJson = await providerRes.json()
              console.log("[HARNESS] providerJson:", JSON.stringify(providerJson))
              const message = providerJson?.choices?.[0]?.message
              const content = message?.content ?? JSON.stringify(providerJson)
              const toolCalls = message?.tool_calls
              console.log("[HARNESS] toolCalls:", toolCalls)
              if (toolCalls && toolCalls.length > 0) {
                for (const tc of toolCalls) {
                  let args = tc.function.arguments
                  try {
                    args = JSON.parse(args)
                  } catch (err) {
                    console.debug("[Harness] Failed to parse tool call arguments as JSON:", err)
                  }
                  parts.push({
                    type: "tool",
                    tool: tc.function.name,
                    state: { input: args },
                  })

                  const cmd = typeof args === "object" && args !== null && "command" in args ? (args as any).command : JSON.stringify(args)
                  const permId = `req_${Date.now()}_${Math.random().toString(36).slice(2)}`
                  this.pendingPermissions.set(permId, {
                    id: permId,
                    sessionID,
                    permission: tc.function.name,
                    patterns: [cmd],
                    metadata: { command: cmd, directory: this.workspaceDir },
                    always: [],
                  })
                  console.log("[HARNESS] scheduling simulatePermissionAsk for permId:", permId)
                  setTimeout(() => {
                    this.simulatePermissionAsk({
                      id: permId,
                      sessionID,
                      permission: tc.function.name,
                      patterns: [cmd],
                      metadata: { command: cmd, directory: this.workspaceDir },
                    }).catch((err) => {
                      console.error("[Harness] simulatePermissionAsk background error:", err)
                    })
                  }, 50)
                }
              } else {
                parts.push({
                  type: "text",
                  text: content,
                })
              }
            }
          } catch (err: any) {
            console.error("[HARNESS] CRITICAL Provider fetch exception:", err?.message, "stack:", err?.stack)
          }

          if (parts.length === 0) {
            parts.push({
              type: "text",
              text: JSON.stringify({ verdict: "ALLOW", reason: "Default mock fallback approval" }),
            })
          }
          const respObj = {
            id: "msg_" + Date.now(),
            parts,
            data: { parts },
          }

          return new Response(JSON.stringify(respObj), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          })
        }

        // 6. POST /app/log or POST /log
        if (method === "POST" && (path === "/app/log" || path === "/log")) {
          return new Response(JSON.stringify({ success: true }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          })
        }

        return new Response("Not Found", { status: 404 })
      },
    })

    const serverUrl = `http://127.0.0.1:${this.server.port}`
    this.client = createOpencodeClient({
      baseUrl: serverUrl,
      headers: { Authorization: authHeader },
    })
  }

  public async init(options?: HarnessOptions): Promise<void> {
    process.env.GEMINI_BASE_URL = this.mockProvider.url
    process.env.GEMINI_API_KEY = "test-key"
    const workspaceDir = options?.workspaceDir || "/tmp/project-alpha"
    const pluginConfig = {
      ntfyServer: this.mockNtfy.url,
      ntfyTopic: this.ntfyTopic,
      ...(this.ntfyToken ? { ntfyToken: this.ntfyToken } : {}),
      serverUrl: `http://127.0.0.1:${this.server.port}`,
      classifierModel: "mock/eval-model",
      classifierFallback: "UNSURE",
      environment: "desktop",
      autoMode: true,
...(options?.pluginConfig || {}),
    }
    if (options?.pluginConfig?.ntfyServer) {
this.ntfyServer = options.pluginConfig.ntfyServer as string
} else {
this.ntfyServer = this.mockNtfy.url
}

    const pluginInput: PluginInput = {
      client: this.client,
      directory: workspaceDir,
      worktree: workspaceDir,
    }

    console.log("[INIT] mockNtfy.url:", this.mockNtfy.url, "pluginConfig.ntfyServer:", pluginConfig.ntfyServer)
    this.plugin = await AutoGatePlugin(pluginInput, pluginConfig)
  }
public async simulatePermissionAsk(request: Partial<PermissionEventData>): Promise<void> {
    console.log("[HARNESS] simulatePermissionAsk called with:", request)
    const id = request.id || `req_${Date.now()}_${Math.random().toString(36).slice(2)}`
const req: PermissionEventData = {
id,
sessionID: request.sessionID || "sess-1",
permission: request.permission || "shell:run",
patterns: request.patterns || ["ls"],
metadata: request.metadata || {},
always: request.always || [],
...request,
}

    this.pendingPermissions.set(id, req)

    if (!this.pendingResolutions.has(id)) {
      new Promise<{ reply: string; directory?: string; message?: string }>((resolve) => {
        this.pendingResolutions.set(id, resolve)
      })
    }

    if (this.plugin && typeof this.plugin.event === "function") {
      this.plugin.event({
        event: {
          type: "permission.asked",
          data: req,
          properties: req,
        },
      }).catch((err) => {
        console.error("[SIMULATE] permission asked event error:", err)
      })
    }
  }

  public async simulatePhoneTap(
    requestId: string,
    reply: "once" | "always" | "reject",
    message?: string,
    options?: { actionsHeader?: string }
  ): Promise<void> {
    let actionsHeader = options?.actionsHeader
    let parsedActions: ParsedNtfyAction[] = []

    if (actionsHeader) {
      parsedActions = parseNtfyActions(actionsHeader)
    } else {
      // 1. Poll MockNtfyServer for published messages with Actions
      const startTime = Date.now()
      while (Date.now() - startTime < 4000) {
        const published = this.mockNtfy.getPublished()
        console.log("[SIMULATE PHONE TAP] polling for requestId:", requestId, "published count:", published.length, "messages:", JSON.stringify(published))
        const notif = published.find(
          (m) =>
            m.headers["x-sequence-id"] === requestId ||
            (m.actions && m.actions.includes(`"req_id": "${requestId}"`)) ||
            (m.body && m.body.includes(requestId))
        )
        if (notif?.actions) {
          actionsHeader = Array.isArray(notif.actions) ? notif.actions.join("; ") : notif.actions
          parsedActions = parseNtfyActions(actionsHeader)
          break
        }
        await new Promise((r) => setTimeout(r, 50))
      }

      // 2. If not found in mockNtfy and ntfyServer is remote, query the remote topic
      if (parsedActions.length === 0 && this.ntfyServer && !this.ntfyServer.includes("localhost")) {
        const pollUrl = `${this.ntfyServer}/${this.ntfyTopic}/json?poll=1`
        const pollHeaders: Record<string, string> = {}
        if (this.ntfyToken) {
          pollHeaders["Authorization"] = `Bearer ${this.ntfyToken}`
        }
        try {
          const pollRes = await fetch(pollUrl, { headers: pollHeaders })
          if (pollRes.ok) {
            const pollText = await pollRes.text()
            const lines = pollText.trim().split("\n")
            for (const line of lines) {
              try {
                const data = JSON.parse(line)
                if (data.actions && Array.isArray(data.actions)) {
                  const hasReq = data.actions.some(
                    (a: any) => typeof a.body === "string" && a.body.includes(requestId)
                  )
                  if (hasReq) {
                    parsedActions = data.actions.map((a: any) => ({
                      action: a.action || "http",
                      label: a.label,
                      url: a.url,
                      method: (a.method || "POST").toUpperCase(),
                      headers: a.headers || {},
                      body: typeof a.body === "string" ? a.body : JSON.stringify(a.body),
                    }))
                    break
                  }
                }
              } catch {}
            }
          }
        } catch {}
      }
    }

    if (parsedActions.length === 0) {
      throw new Error(`Could not find published notification with Actions for request ID "${requestId}"`)
    }

    // Find matching action for requested reply
    const targetAction = parsedActions.find((a) => {
      if (a.body) {
        try {
          const parsedBody = JSON.parse(a.body)
          if (parsedBody.req_id === requestId && parsedBody.reply === reply) {
            return true
          }
        } catch {}
      }
      const labelUpper = (a.label || "").toUpperCase()
      if (reply === "always" && labelUpper.includes("ALWAYS")) return true
      if (reply === "once" && labelUpper.includes("APPROVE") && !labelUpper.includes("ALWAYS")) return true
      if (reply === "reject" && (labelUpper.includes("DENY") || labelUpper.includes("REJECT"))) return true
    })

    if (!targetAction) {
      throw new Error(
        `Could not find matching action for reply "${reply}" and request ID "${requestId}" in actions: ${JSON.stringify(parsedActions)}`
      )
    }

    let bodyToSend = targetAction.body || JSON.stringify({ req_id: requestId, reply })
    if (message) {
      try {
        const parsed = JSON.parse(bodyToSend)
        parsed.message = message
        bodyToSend = JSON.stringify(parsed)
      } catch {
        bodyToSend = JSON.stringify({ req_id: requestId, reply, message })
      }
    }

    const requestHeaders: Record<string, string> = {
      "Content-Type": "application/json",
      ...targetAction.headers,
    }

    const res = await fetch(targetAction.url, {
      method: targetAction.method || "POST",
      headers: requestHeaders,
      body: bodyToSend,
    })

    if (!res.ok) {
      const errText = await res.text()
      throw new Error(`simulatePhoneTap HTTP request failed: ${res.status} ${res.statusText} - ${errText}`)
    }
  }

  public async waitForResolution(
    requestId: string,
    timeoutMs = 5000
  ): Promise<{ reply: string; directory?: string; message?: string }> {
    const existing = this.receivedReplies.find((r) => r.id === requestId)
    if (existing) {
      return { reply: existing.reply, directory: existing.directory, message: existing.message }
    }

    let resolver = this.pendingResolutions.get(requestId)
    let promise: Promise<{ reply: string; directory?: string; message?: string }>
    if (!resolver) {
      promise = new Promise<{ reply: string; directory?: string; message?: string }>((resolve) => {
        this.pendingResolutions.set(requestId, resolve)
      })
    } else {
      promise = new Promise<{ reply: string; directory?: string; message?: string }>((resolve) => {
        this.pendingResolutions.set(requestId, resolve)
      })
    }

    let timerId: any | undefined
    const timeoutPromise = new Promise<{ reply: string; directory?: string; message?: string }>((_, reject) => {
      timerId = setTimeout(() => reject(new Error(`Timeout waiting for resolution of request ${requestId}`)), timeoutMs)
    })

    try {
      return await Promise.race([promise, timeoutPromise])
    } finally {
      if (timerId) {
        clearTimeout(timerId)
      }
    }
  }
  public async promptSession(sessionID: string, userText: string): Promise<any> {
    return await this.client.session.prompt({
      path: { id: sessionID },
      body: {
        parts: [{ type: "text", text: userText }],
      },
    })
  }

  public async waitForSessionResolution(sessionID: string, timeoutMs = 5000): Promise<{ id: string; reply: string; directory?: string; message?: string }> {
    const existing = this.receivedReplies.find((r) => r.sessionID === sessionID)
    if (existing) {
      return existing
    }

    const startTime = Date.now()
    while (Date.now() - startTime < timeoutMs) {
      const found = this.receivedReplies.find((r) => r.sessionID === sessionID)
      if (found) {
        return found
      }
      await new Promise((r) => setTimeout(r, 50))
    }
    throw new Error(`Timeout waiting for resolution of session ${sessionID}`)
  }

  public getReceivedReplies(): ReceivedReply[] {
    return this.receivedReplies
  }

  public async dispose(): Promise<void> {
    if (this.plugin && typeof this.plugin.dispose === "function") {
      await this.plugin.dispose()
    }
    await this.mockNtfy.stop()
    await this.mockProvider.stop()
    await this.server.stop(true)
  }
}

export async function createAutoGateE2EHarness(options?: HarnessOptions): Promise<OpenCodeE2EHarness> {
  const harness = new OpenCodeE2EHarness(options)
  await harness.init(options)
  return harness
}
