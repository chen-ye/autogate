import * as fs from "fs"
import * as path from "path"
import * as os from "os"
import * as crypto from "crypto"
import { execSync } from "child_process"
import { fileURLToPath } from "url"
import {
  createOpencodeServer,
  createOpencodeClient,
  type OpencodeClient,
} from "@opencode-ai/sdk"
import { MockInferenceProvider } from "./mock-provider"

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

export class TargetActionDetails extends Array<ParsedNtfyAction> implements ParsedNtfyAction {
  public readonly action: string
  public readonly label: string
  public readonly url: string
  public readonly method: string
  public readonly headers: Record<string, string>
  public readonly body?: string
  public readonly clear?: boolean
  public readonly actions: ParsedNtfyAction[]
  public readonly notification?: any

  constructor(actions: ParsedNtfyAction[], notification?: any) {
    super(...actions)
    this.actions = actions
    this.notification = notification
    const primary = actions[0] || {
      action: "http",
      label: "",
      url: "",
      method: "POST",
      headers: {},
      body: undefined,
      clear: false,
    }
    this.action = primary.action
    this.label = primary.label
    this.url = primary.url
    this.method = primary.method
    this.headers = primary.headers
    this.body = primary.body
    this.clear = primary.clear
  }
}

export interface RealHarnessOptions {
workspaceDir?: string
serverPassword?: string
pluginConfig?: Record<string, unknown>
opencodeConfig?: Record<string, unknown>
  timeout?: number
  ntfyServer?: string
  ntfyToken?: string
  ntfyTopic?: string
  serverPort?: number
}

export class RealOpenCodeHarness {
  public static readonly activeHarnesses: Set<RealOpenCodeHarness> = new Set()
  private static exitHooksRegistered: boolean = false

  public static registerExitHooks(): void {
    if (this.exitHooksRegistered) return
    this.exitHooksRegistered = true

    const cleanupAll = () => {
      for (const harness of Array.from(this.activeHarnesses)) {
        try {
          harness.disposeSync()
        } catch {}
      }
    }

    process.on("exit", () => {
      cleanupAll()
    })

    process.on("SIGINT", () => {
      cleanupAll()
    })

    process.on("SIGTERM", () => {
      cleanupAll()
    })
  }

  public readonly mockProvider: MockInferenceProvider
  public server!: { url: string; close(): void }
  public client!: OpencodeClient
  public readonly serverPassword: string
  public readonly authHeader: string
  public readonly workspaceDir: string
  public url!: string
  public isRateLimited: boolean = false
  public readonly ntfyServer: string
  public readonly ntfyToken: string
  public readonly ntfyTopic: string
  public serverPid?: number
  public serverPort?: number
  private readonly isTemporaryWorkspace: boolean
  private readonly savedEnv: Record<string, string | undefined>
  private ntfyStreamController?: AbortController
  private ntfyStreamReader?: ReadableStreamDefaultReader<Uint8Array>
  private ntfyStreamConnected: boolean = false
  private receivedNotifications: any[] = []
  private receivedActions: ParsedNtfyAction[] = []
private actionWaiters: Array<{
    requestId?: string
resolve: (actions: TargetActionDetails) => void
reject: (err: Error) => void
timer: NodeJS.Timeout
}> = []
  private disposed: boolean = false
  private disposePromise?: Promise<void>
  constructor(options?: RealHarnessOptions) {
    RealOpenCodeHarness.registerExitHooks()
    RealOpenCodeHarness.activeHarnesses.add(this)
this.mockProvider = new MockInferenceProvider(0)
    this.serverPassword = options?.serverPassword || crypto.randomUUID()
    this.authHeader =
      "Basic " + Buffer.from(`opencode:${this.serverPassword}`).toString("base64")

    this.ntfyServer =
      options?.ntfyServer ||
      (options?.pluginConfig?.ntfyServer as string) ||
      "https://ntfy.sh"
    this.ntfyToken =
      options?.ntfyToken ||
      (options?.pluginConfig?.ntfyToken as string) ||
      process.env.NTFY_TOKEN ||
      "***REMOVED***"
    this.ntfyTopic =
      options?.ntfyTopic ||
      (options?.pluginConfig?.ntfyTopic as string) ||
      `autogate-e2e-${Date.now()}-${crypto.randomUUID().slice(0, 6)}`
    if (options?.workspaceDir) {
      this.workspaceDir = options.workspaceDir
      this.isTemporaryWorkspace = false
    } else {
      this.workspaceDir = fs.mkdtempSync(path.join(os.tmpdir(), "autogate-e2e-"))
      this.isTemporaryWorkspace = true
    }

    this.savedEnv = {
      OPENCODE_SERVER_PASSWORD: process.env.OPENCODE_SERVER_PASSWORD,
      OPENCODE_CONFIG_CONTENT: process.env.OPENCODE_CONFIG_CONTENT,
      XDG_CONFIG_HOME: process.env.XDG_CONFIG_HOME,
      XDG_DATA_HOME: process.env.XDG_DATA_HOME,
      XDG_STATE_HOME: process.env.XDG_STATE_HOME,
      XDG_CACHE_HOME: process.env.XDG_CACHE_HOME,
    }
  }

  public async init(options?: RealHarnessOptions): Promise<void> {
    // 1. Initialize git repository in ephemeral directory
    if (!fs.existsSync(this.workspaceDir)) {
      fs.mkdirSync(this.workspaceDir, { recursive: true })
    }

    try {
      execSync("git init", { cwd: this.workspaceDir, stdio: "ignore" })
      execSync("git config user.email test@autogate.test", {
        cwd: this.workspaceDir,
        stdio: "ignore",
      })
      execSync("git config user.name Test", {
        cwd: this.workspaceDir,
        stdio: "ignore",
      })
    } catch {
      // Non-fatal if git is already initialized
    }

    // 2. Set up .config/opencode/agents/ and symlink auto-gate-eval.md
    const agentsDir = path.join(this.workspaceDir, ".config", "opencode", "agents")
    if (!fs.existsSync(agentsDir)) {
      fs.mkdirSync(agentsDir, { recursive: true })
    }

    const targetFile = path.join(agentsDir, "auto-gate-eval.md")
    const __dirname = path.dirname(fileURLToPath(import.meta.url))
    const candidatePaths = [
      path.resolve(process.cwd(), "packages/core/agents/auto-gate-eval.md"),
      path.resolve(__dirname, "../../../packages/core/agents/auto-gate-eval.md"),
      path.resolve(__dirname, "../../core/agents/auto-gate-eval.md"),
    ]
    const pluginAgentFile = candidatePaths.find((p) => fs.existsSync(p))

    if (pluginAgentFile) {
      try {
        const stats = fs.lstatSync(targetFile)
        if (stats.isSymbolicLink() || stats.isFile()) {
          fs.unlinkSync(targetFile)
        }
      } catch (e: any) {
        if (e?.code !== "ENOENT") {
          // ignore
        }
      }
      try {
        fs.symlinkSync(pluginAgentFile, targetFile)
      } catch {
        // Non-fatal if symlink creation fails
      }
    }

    // 3. Prepare OpenCode configuration
    // 3. Prepare OpenCode configuration and allocate dynamic port
    const allocatedPort =
      options?.serverPort ??
      (await (async () => {
        const dummy = Bun.serve({ port: 0, fetch: () => new Response("") })
        const p = dummy.port
        dummy.stop(true)
        return p
      })())
    this.serverPort = allocatedPort
    this.url = `http://127.0.0.1:${allocatedPort}`

    const pluginPath = path.resolve(process.cwd(), "packages/opencode/src/index.ts")
    const pluginConfig = {
      ntfyServer: this.ntfyServer,
      ntfyTopic: this.ntfyTopic,
      ntfyToken: this.ntfyToken,
      serverUrl: this.url,
      classifierModel: "mock-provider/mock-model",
      autoMode: true,
      ...(options?.pluginConfig || {}),
    }
    const pluginEntry = [[pluginPath, pluginConfig]]
    const opencodeConfig = {
      plugin: pluginEntry,
      db: ":memory:",
      model: "mock-provider/mock-model",
      permission: {
        "*": "ask",
      },
      provider: {
        "mock-provider": {
          npm: "@ai-sdk/openai-compatible",
          name: "Mock Provider",
          options: {
            baseURL: `${this.mockProvider.url}/v1`,
            apiKey: "mock-api-key",
          },
          models: {
            "mock-model": {
              name: "Mock Model",
            },
          },
        },
      },
      ...(options?.opencodeConfig || {}),
    }

    // 4. Inject environment variables
    process.env.SERVER_URL = this.url
    process.env.OPENCODE_SERVER_PASSWORD = this.serverPassword
    process.env.OPENCODE_CONFIG_CONTENT = JSON.stringify(opencodeConfig)
    process.env.XDG_CONFIG_HOME = path.join(this.workspaceDir, ".config")
    process.env.XDG_DATA_HOME = path.join(this.workspaceDir, ".local", "share")
    process.env.XDG_STATE_HOME = path.join(this.workspaceDir, ".local", "state")
    process.env.XDG_CACHE_HOME = path.join(this.workspaceDir, ".cache")

    // 5. Spawn real opencode serve binary via @opencode-ai/sdk
    this.server = await createOpencodeServer({
      port: allocatedPort,
      config: opencodeConfig as any,
      timeout: options?.timeout ?? 20000,
    })
    this.url = this.server.url
    try {
      const urlObj = new URL(this.server.url)
      this.serverPort = parseInt(urlObj.port, 10)
      this.serverPid = this.findServerPid(this.serverPort)
    } catch {}
    // 6. Instantiate typed client with Basic Auth
    this.client = createOpencodeClient({
      baseUrl: this.server.url,
      headers: {
        Authorization: this.authHeader,
      },
      directory: this.workspaceDir,
    })
  }

  public async connectNtfyStream(signal?: AbortSignal): Promise<void> {
    if (this.ntfyStreamConnected && this.ntfyStreamController && !this.ntfyStreamController.signal.aborted) {
      return
    }

    this.ntfyStreamController = new AbortController()
    const compositeSignal = signal
      ? AbortSignal.any([this.ntfyStreamController.signal, signal])
      : this.ntfyStreamController.signal

    const streamUrl = `${this.ntfyServer}/${this.ntfyTopic}/json`
    const headers: Record<string, string> = {
      Accept: "application/x-ndjson, text/event-stream, application/json",
    }
    if (this.ntfyToken) {
      headers["Authorization"] = `Bearer ${this.ntfyToken}`
    }

    const res = await fetch(streamUrl, {
      headers,
      signal: compositeSignal,
    })

if (!res.ok) {
      const errText = await res.text().catch(() => "")
      if (res.status === 429 || errText.includes("429") || errText.includes("limit reached")) {
        this.isRateLimited = true
      }
throw new Error(
`Failed to connect to ntfy stream at ${streamUrl}: ${res.status} ${res.statusText} - ${errText}`
)
}

    if (!res.body) {
      throw new Error(`No response body from ntfy stream at ${streamUrl}`)
    }

this.ntfyStreamConnected = true
    const reader = res.body.getReader()
    this.ntfyStreamReader = reader

    let resolveOpen!: () => void
    const openPromise = new Promise<void>((resolve) => {
      resolveOpen = resolve
    })

    ;(async () => {
      const decoder = new TextDecoder()
      let buffer = ""
      try {
        while (!compositeSignal.aborted) {
          const { value, done } = await reader.read()
          if (done) break
          buffer += decoder.decode(value, { stream: true })
          const lines = buffer.split("\n")
          buffer = lines.pop() || ""

          for (const line of lines) {
            const trimmed = line.trim()
            if (!trimmed) continue
            let dataStr = trimmed
            if (trimmed.startsWith("data:")) {
              dataStr = trimmed.slice(5).trim()
            }
            try {
              const data = JSON.parse(dataStr)
              if (data.event === "open") {
                resolveOpen()
              }
              this.handleIncomingNtfyMessage(data)
            } catch {
              // ignore unparseable line
            }
          }
        }
      } catch {
        // Stream closed or aborted
      } finally {
this.ntfyStreamConnected = false
try {
reader.releaseLock()
        } catch {}
        if (this.ntfyStreamReader === reader) {
          this.ntfyStreamReader = undefined
      }
      }
    })()

    const openTimeout = setTimeout(() => resolveOpen(), 2000)
    await openPromise.finally(() => clearTimeout(openTimeout))
  }

  private extractActions(data: any): ParsedNtfyAction[] {
    if (!data) return []
    if (Array.isArray(data.actions)) {
      if (data.actions.length === 0) return []
      if (typeof data.actions[0] === "string") {
        return parseNtfyActions(data.actions.join("; "))
      }
      return data.actions.map((a: any) => ({
        action: a.action || "http",
        label: a.label,
        url: a.url,
        method: (a.method || "POST").toUpperCase(),
        headers: a.headers || {},
        body: typeof a.body === "string" ? a.body : JSON.stringify(a.body),
        clear: a.clear,
      }))
    }
    if (typeof data.actions === "string") {
      return parseNtfyActions(data.actions)
    }
    return []
  }

  private handleIncomingNtfyMessage(data: any): void {
    if (!data) return
    this.receivedNotifications.push(data)
    const actions = this.extractActions(data)
    for (const a of actions) {
      this.receivedActions.push(a)
    }

    for (let i = this.actionWaiters.length - 1; i >= 0; i--) {
      const waiter = this.actionWaiters[i]
      const matchingActions = waiter.requestId
        ? this.findActionsForRequestId(waiter.requestId)
        : actions.length > 0
        ? actions
        : this.receivedActions
      if (matchingActions.length > 0) {
        clearTimeout(waiter.timer)
        this.actionWaiters.splice(i, 1)
        waiter.resolve(new TargetActionDetails(matchingActions, data))
      }
    }
  }

  private findActionsForRequestId(requestId: string): ParsedNtfyAction[] {
    for (const notif of this.receivedNotifications) {
      const notifActions = this.extractActions(notif)
      if (notifActions.length === 0) continue

      const hasMatch =
        notifActions.some((a) => {
          if (a.body) {
            try {
              const parsed = JSON.parse(a.body)
              if (parsed.req_id === requestId || parsed.reqID === requestId || parsed.id === requestId) {
                return true
              }
            } catch {}
            if (a.body.includes(requestId)) return true
          }
          if (a.url && a.url.includes(requestId)) return true
          return false
        }) ||
        notif.id === requestId ||
        notif["x-sequence-id"] === requestId ||
        (typeof notif.message === "string" && notif.message.includes(requestId))

      if (hasMatch) {
        return notifActions
      }
    }

    return this.receivedActions.filter((a) => {
      if (a.body) {
        try {
          const parsed = JSON.parse(a.body)
          if (parsed.req_id === requestId || parsed.reqID === requestId || parsed.id === requestId) {
            return true
          }
        } catch {}
        if (a.body.includes(requestId)) return true
      }
      if (a.url && a.url.includes(requestId)) return true
      return false
    })
  }

  public async waitForAction(
    requestIdOrTimeout?: string | number,
    timeoutMs: number = 10000
  ): Promise<TargetActionDetails> {
    const requestId = typeof requestIdOrTimeout === "string" ? requestIdOrTimeout : undefined
    const timeout = typeof requestIdOrTimeout === "number" ? requestIdOrTimeout : timeoutMs

    if (requestId) {
      const existing = this.findActionsForRequestId(requestId)
      if (existing.length > 0) {
        return new TargetActionDetails(existing)
      }
    } else if (this.receivedActions.length > 0) {
      return new TargetActionDetails(this.receivedActions, this.receivedNotifications[0])
    }

    if (!this.ntfyStreamConnected && !this.isRateLimited) {
      try {
        await this.connectNtfyStream()
      } catch (err: any) {
        if (this.isRateLimited || String(err?.message || "").includes("429")) {
          this.isRateLimited = true
          throw err
        }
      }
    }

    return new Promise<TargetActionDetails>((resolve, reject) => {
      const timer = setTimeout(() => {
        const idx = this.actionWaiters.findIndex((w) => w.requestId === requestId && w.resolve === resolve)
        if (idx !== -1) {
          this.actionWaiters.splice(idx, 1)
        }
        reject(
          new Error(
            `Timed out after ${timeout}ms waiting for action${requestId ? ` for request ID "${requestId}"` : ""} on topic "${this.ntfyTopic}"`
          )
        )
      }, timeout)

      this.actionWaiters.push({ requestId, resolve, reject, timer })
    })
  }

  public async simulatePhoneTap(
    replyOrRequestId: string = "once",
    replyArg?: "once" | "always" | "reject",
    message?: string,
    options?: { actionsHeader?: string; timeoutMs?: number }
  ): Promise<void> {
    const isReplyOnly =
      (replyOrRequestId === "once" || replyOrRequestId === "always" || replyOrRequestId === "reject") &&
      replyArg === undefined
    const reply: "once" | "always" | "reject" = isReplyOnly ? (replyOrRequestId as any) : replyArg || "once"
    let requestId: string | undefined = isReplyOnly ? undefined : replyOrRequestId

    let actions: ParsedNtfyAction[] = []

    if (options?.actionsHeader) {
      actions = parseNtfyActions(options.actionsHeader)
    } else if (requestId) {
      actions = this.findActionsForRequestId(requestId)
      if (actions.length === 0) {
        try {
          const targetDetails = await this.waitForAction(requestId, options?.timeoutMs ?? 5000)
          actions = targetDetails.actions
        } catch {}
      }
    } else {
      if (this.receivedActions.length > 0) {
        actions = this.receivedActions
      } else {
        try {
          const targetDetails = await this.waitForAction(undefined, options?.timeoutMs ?? 5000)
          actions = targetDetails.actions
        } catch {}
      }
    }

    if (actions.length === 0) {
      throw new Error(
        `Could not find published notification with Actions${requestId ? ` for request ID "${requestId}"` : ""} on topic "${this.ntfyTopic}"`
      )
    }

    const targetAction = actions.find((a) => {
      if (a.body) {
        try {
          const parsed = typeof a.body === "string" ? JSON.parse(a.body) : a.body
          if (
            requestId &&
            (parsed.req_id === requestId || parsed.reqID === requestId || parsed.id === requestId) &&
            parsed.reply === reply
          ) {
            return true
          }
          if (!requestId && parsed.reply === reply) {
            return true
          }
        } catch {}
      }
      const labelUpper = (a.label || "").toUpperCase()
      if (reply === "always" && labelUpper.includes("ALWAYS")) return true
      if (reply === "once" && labelUpper.includes("APPROVE") && !labelUpper.includes("ALWAYS")) return true
      if (reply === "reject" && (labelUpper.includes("DENY") || labelUpper.includes("REJECT"))) return true
      return false
    })

    if (!targetAction) {
      throw new Error(
        `Could not find matching action for reply "${reply}"${requestId ? ` and request ID "${requestId}"` : ""} in actions: ${JSON.stringify(actions)}`
      )
    }

    if (!requestId && targetAction.body) {
      try {
        const parsed = typeof targetAction.body === "string" ? JSON.parse(targetAction.body) : targetAction.body
        requestId = parsed.req_id || parsed.reqID || parsed.id
      } catch {}
    }

    let bodyToSend = targetAction.body || JSON.stringify({ req_id: requestId, reply })
    if (message) {
      try {
        const parsed = typeof bodyToSend === "string" ? JSON.parse(bodyToSend) : Object.assign({}, bodyToSend)
        parsed.message = message
        bodyToSend = JSON.stringify(parsed)
      } catch {
        bodyToSend = JSON.stringify({ req_id: requestId, reply, message })
      }
    }

    let targetUrl = targetAction.url
    if (targetUrl.startsWith("/")) {
      targetUrl = `${this.url}${targetUrl}`
    }

    const requestHeaders: Record<string, string> = {
      "Content-Type": "application/json",
      ...(targetAction.headers || {}),
    }

    if (targetUrl.includes("/permission/") && !requestHeaders["Authorization"]) {
      requestHeaders["Authorization"] = this.authHeader
    }

    const res = await fetch(targetUrl, {
      method: targetAction.method || "POST",
      headers: requestHeaders,
      body: bodyToSend,
    })

    if (!res.ok) {
      const errText = await res.text().catch(() => "")
      throw new Error(
        `simulatePhoneTap HTTP request failed: ${res.status} ${res.statusText} - ${errText}`
      )
    }
  }

  public async createSession(options?: { title?: string }): Promise<any> {
    return await this.client.session.create({
      body: { title: options?.title || "Test Session" },
      query: { directory: this.workspaceDir },
    })
  }

  public async promptSession(
    sessionID: string,
    userText: string,
    options?: {
      agent?: string
      model?: { providerID: string; modelID: string }
    }
  ): Promise<any> {
    if (!this.ntfyStreamConnected && !this.isRateLimited) {
      try {
        await this.connectNtfyStream()
      } catch (err: any) {
        if (this.isRateLimited || String(err?.message || "").includes("429")) {
          this.isRateLimited = true
        } else {
          throw err
        }
      }
    }
return await this.client.session.prompt({
path: { id: sessionID },
query: { directory: this.workspaceDir },
body: {
parts: [{ type: "text", text: userText }],
agent: options?.agent,
model: options?.model,
},
})
}

  public findServerPid(port: number): number | undefined {
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        const out = execSync(`lsof -i :${port} -sTCP:LISTEN -t`, {
          encoding: "utf8",
          stdio: ["ignore", "pipe", "ignore"],
        }).trim()
        if (out) {
          const pid = parseInt(out.split("\n")[0], 10)
          if (!isNaN(pid) && pid > 0) return pid
        }
      } catch {}

      try {
        const out = execSync(`ss -tlpn sport = :${port}`, {
          encoding: "utf8",
          stdio: ["ignore", "pipe", "ignore"],
        }).trim()
        const match = out.match(/pid=(\d+)/)
        if (match) {
          const pid = parseInt(match[1], 10)
          if (!isNaN(pid) && pid > 0) return pid
        }
      } catch {}

      try {
        const out = execSync(`pgrep -P ${process.pid}`, {
          encoding: "utf8",
          stdio: ["ignore", "pipe", "ignore"],
        }).trim()
        if (out) {
          const pids = out.split(/\s+/).map((p: string) => parseInt(p, 10))
          for (const p of pids) {
            if (!isNaN(p) && p > 0) {
              try {
                const cmd = execSync(`ps -p ${p} -o args=`, {
                  encoding: "utf8",
                  stdio: ["ignore", "pipe", "ignore"],
                }).trim()
                if (cmd.includes("opencode") && (cmd.includes(`--port=${port}`) || cmd.includes("--port=0"))) {
                  return p
                }
              } catch {}
            }
          }
        }
      } catch {}

if (attempt < 2) {
try {
execSync("sleep 0.02")
} catch {}
}
    }
    return undefined
  }
  public isProcessRunning(pid?: number): boolean {
    if (!pid || pid <= 0) return false
    try {
      const stat = execSync(`ps -p ${pid} -o stat=`, {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "ignore"],
      }).trim()
      return Boolean(stat && !stat.startsWith("Z"))
    } catch {
      return false
    }
  }
  private isSafeToKill(pid?: number): boolean {
    if (!pid || pid <= 1 || pid === process.pid) return false
    try {
      const cmd = execSync(`ps -p ${pid} -o args=`, {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "ignore"],
      }).trim()
      return !cmd.includes("opencode web")
    } catch {
      return false
    }
  }
  private getProcessTree(pid: number): number[] {
    const descendants: number[] = []
    const visited = new Set<number>()

    const collect = (parentPid: number) => {
      if (visited.has(parentPid)) return
      visited.add(parentPid)

      try {
        const pgrepOut = execSync(`pgrep -P ${parentPid}`, {
          encoding: "utf8",
          stdio: ["ignore", "pipe", "ignore"],
        }).trim()
        if (pgrepOut) {
          const childPids = pgrepOut
            .split(/\s+/)
            .map((p: string) => parseInt(p, 10))
            .filter((p: number) => !isNaN(p) && p > 0 && p !== process.pid && this.isSafeToKill(p))
          for (const childPid of childPids) {
            descendants.push(childPid)
            collect(childPid)
          }
        }
      } catch {}
    }

    collect(pid)
    return descendants
  }

  private terminateProcessTree(rootPid: number | undefined): void {
    if (!rootPid || !this.isSafeToKill(rootPid)) {
      return
    }

    try {
      const cmd = execSync(`ps -p ${rootPid} -o args=`, {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "ignore"],
      }).trim()
      if (!cmd.includes("opencode") || cmd.includes("opencode web")) {
        return
      }
    } catch {
      // Process already terminated
      return
    }

    const descendants = this.getProcessTree(rootPid)

    try {
      const pgidOut = execSync(`ps -o pgid= -p ${rootPid}`, {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "ignore"],
      }).trim()
      const pgid = parseInt(pgidOut, 10)
      const myPgid = typeof (process as any).getpgrp === "function" ? (process as any).getpgrp() : process.pid
      if (pgid === rootPid && pgid !== myPgid && pgid !== process.pid && pgid > 1) {
        try {
          process.kill(-pgid, "SIGTERM")
        } catch {}
      }
    } catch {}

    for (const p of descendants) {
      if (this.isSafeToKill(p)) {
        try {
          process.kill(p, "SIGTERM")
        } catch {}
      }
    }

    try {
      process.kill(rootPid, "SIGTERM")
    } catch {}

    try {
      execSync("sleep 0.05")
    } catch {}

    for (const p of [...descendants, rootPid]) {
      if (this.isSafeToKill(p)) {
        try {
          process.kill(p, 0)
          process.kill(p, "SIGKILL")
        } catch {}
      }
    }
  }

  public disposeSync(): void {
    if (this.disposed) return
    this.disposed = true
    RealOpenCodeHarness.activeHarnesses.delete(this)

    // 1. Abort SSE stream controller and release any stream reader locks
    if (this.ntfyStreamController) {
      try {
        this.ntfyStreamController.abort()
      } catch {}
      this.ntfyStreamController = undefined
    }

    if (this.ntfyStreamReader) {
      try {
        this.ntfyStreamReader.cancel().catch(() => {})
      } catch {}
      try {
        this.ntfyStreamReader.releaseLock()
      } catch {}
      this.ntfyStreamReader = undefined
    }
    this.ntfyStreamConnected = false

    for (const waiter of this.actionWaiters) {
      clearTimeout(waiter.timer)
      waiter.reject(new Error("RealOpenCodeHarness disposed"))
    }
    this.actionWaiters = []

    // 2. Stop MockInferenceProvider
    try {
      (this.mockProvider as any)?.server?.stop(true)
    } catch {}

    // 3. Call server.close() from @opencode-ai/sdk
    try {
      this.server?.close()
    } catch {}

    // 4. Ensure child process group is terminated so no background opencode serve processes remain
    this.terminateProcessTree(this.serverPid)

    if (this.serverPort && this.serverPort !== 4096) {
      const lingering = this.findServerPid(this.serverPort)
      if (lingering && lingering !== process.pid) {
        try {
          const cmd = execSync(`ps -p ${lingering} -o args=`, {
            encoding: "utf8",
            stdio: ["ignore", "pipe", "ignore"],
          }).trim()
          if (cmd.includes("opencode") && !cmd.includes("opencode web")) {
            process.kill(lingering, "SIGKILL")
          }
        } catch {}
      }
    }

    // 5. Restore environment variables
    for (const [key, value] of Object.entries(this.savedEnv)) {
      if (value === undefined) {
        delete process.env[key]
      } else {
        process.env[key] = value
      }
    }

    // 6. Clean up temporary /tmp/autogate-e2e-... directory
    if (this.isTemporaryWorkspace && this.workspaceDir && fs.existsSync(this.workspaceDir)) {
      try {
        fs.rmSync(this.workspaceDir, { recursive: true, force: true })
      } catch {}
    }
  }

  public async dispose(): Promise<void> {
    if (this.disposed) return
    if (this.disposePromise) return this.disposePromise

    this.disposePromise = (async () => {
      this.disposed = true
      RealOpenCodeHarness.activeHarnesses.delete(this)

      // 1. Abort SSE stream controller and release any stream reader locks
      if (this.ntfyStreamController) {
        try {
          this.ntfyStreamController.abort()
        } catch {}
        this.ntfyStreamController = undefined
      }

      if (this.ntfyStreamReader) {
        try {
          await this.ntfyStreamReader.cancel()
        } catch {}
        try {
          this.ntfyStreamReader.releaseLock()
        } catch {}
        this.ntfyStreamReader = undefined
      }
      this.ntfyStreamConnected = false

      for (const waiter of this.actionWaiters) {
        clearTimeout(waiter.timer)
        waiter.reject(new Error("RealOpenCodeHarness disposed"))
      }
      this.actionWaiters = []

      // 2. Stop MockInferenceProvider
      try {
        await this.mockProvider?.stop()
      } catch {}

      // 3. Call server.close() from @opencode-ai/sdk
      try {
        this.server?.close()
      } catch {}

      // 4. Ensure child process group is terminated so no background opencode serve processes remain
      this.terminateProcessTree(this.serverPid)

if (this.serverPort && this.serverPort !== 4096) {
const lingering = this.findServerPid(this.serverPort)
if (lingering && lingering !== process.pid) {
try {
const cmd = execSync(`ps -p ${lingering} -o args=`, {
encoding: "utf8",
stdio: ["ignore", "pipe", "ignore"],
}).trim()
if (cmd.includes("opencode") && !cmd.includes("opencode web")) {
process.kill(lingering, "SIGKILL")
}
} catch {}
}
      }

      if (this.serverPid) {
        for (let i = 0; i < 20; i++) {
          try {
            process.kill(this.serverPid, 0)
            await new Promise((r) => setTimeout(r, 25))
          } catch {
            break
          }
        }
      }

      // 5. Restore environment variables
      for (const [key, value] of Object.entries(this.savedEnv)) {
        if (value === undefined) {
          delete process.env[key]
        } else {
          process.env[key] = value
        }
      }

      // 6. Clean up temporary /tmp/autogate-e2e-... directory
      if (this.isTemporaryWorkspace && this.workspaceDir && fs.existsSync(this.workspaceDir)) {
        try {
          fs.rmSync(this.workspaceDir, { recursive: true, force: true })
        } catch {}
      }
    })()

    return this.disposePromise
  }
}

export async function createRealOpenCodeHarness(
  options?: RealHarnessOptions
): Promise<RealOpenCodeHarness> {
  const harness = new RealOpenCodeHarness(options)
  await harness.init(options)
  return harness
}
