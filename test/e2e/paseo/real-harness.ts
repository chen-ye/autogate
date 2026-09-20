import * as fs from "fs"
import * as path from "path"
import * as os from "os"
import * as crypto from "crypto"
import { execSync } from "child_process"
import { createPaseoClient, type PaseoClient } from "@getpaseo/client"
import { MockInferenceProvider } from "../opencode/mock-provider"
import {
  parseNtfyActions,
  splitOutsideQuotes,
  TargetActionDetails,
  type ParsedNtfyAction,
} from "../opencode/real-harness"

export {
  parseNtfyActions,
  splitOutsideQuotes,
  TargetActionDetails,
  type ParsedNtfyAction,
}

export interface RealPaseoHarnessOptions {
  workspaceDir?: string
  scratchDir?: string
  pluginPath?: string
  timeout?: number
  ntfyServer?: string
  ntfyToken?: string
  ntfyTopic?: string
  pluginConfig?: Record<string, unknown>
  paseoConfig?: Record<string, unknown>
  env?: Record<string, string | undefined>
}

export class RealPaseoHarness {
  public static readonly activeHarnesses: Set<RealPaseoHarness> = new Set()
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

  public readonly scratchDir: string
  public readonly workspaceDir: string
  public readonly mockProvider: MockInferenceProvider
  public client!: PaseoClient
  public listenUrl!: string
  public listenHost!: string
  public port!: number
  public readonly ntfyServer: string
  public readonly ntfyToken: string
  public readonly ntfyTopic: string
  public daemonProcess?: any
  public supervisorPid?: number
  public workerPid?: number
  public isRateLimited: boolean = false

  private readonly isTemporaryWorkspace: boolean
  private readonly isTemporaryScratch: boolean
  private readonly pluginPath: string
  private readonly timeout: number
  private readonly savedEnv: Record<string, string | undefined>
  private disposed: boolean = false
  private disposePromise?: Promise<void>

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

  constructor(options?: RealPaseoHarnessOptions) {
    RealPaseoHarness.registerExitHooks()
    RealPaseoHarness.activeHarnesses.add(this)

    if (options?.scratchDir) {
      this.scratchDir = options.scratchDir
      this.isTemporaryScratch = false
    } else {
      this.scratchDir = fs.mkdtempSync(path.join(os.tmpdir(), "autogate-paseo-e2e-"))
      this.isTemporaryScratch = true
    }

    if (options?.workspaceDir) {
      this.workspaceDir = options.workspaceDir
      this.isTemporaryWorkspace = false
    } else {
      this.workspaceDir = fs.mkdtempSync(path.join(os.tmpdir(), "autogate-paseo-ws-"))
      this.isTemporaryWorkspace = true
    }

    this.pluginPath = options?.pluginPath ?? path.resolve(process.cwd(), "packages/paseo")
    this.timeout = options?.timeout ?? 20000

    this.ntfyServer = options?.ntfyServer ?? "https://ntfy.sh"
    this.ntfyToken =
      options?.ntfyToken ??
      process.env.NTFY_TOKEN ??
      "***REMOVED***"
    this.ntfyTopic = options?.ntfyTopic ?? "autogate-test-paseo"

    this.mockProvider = new MockInferenceProvider(0)

    this.savedEnv = {
      PASEO_VOICE_MODE_ENABLED: process.env.PASEO_VOICE_MODE_ENABLED,
      PASEO_DICTATION_ENABLED: process.env.PASEO_DICTATION_ENABLED,
      NTFY_SERVER: process.env.NTFY_SERVER,
      NTFY_TOPIC: process.env.NTFY_TOPIC,
      NTFY_TOKEN: process.env.NTFY_TOKEN,
      AUTOGATE_NTFY_SERVER: process.env.AUTOGATE_NTFY_SERVER,
      AUTOGATE_NTFY_TOPIC: process.env.AUTOGATE_NTFY_TOPIC,
      AUTOGATE_NTFY_TOKEN: process.env.AUTOGATE_NTFY_TOKEN,
      AUTOGATE_CONFIG: process.env.AUTOGATE_CONFIG,
      AUTOGATE_EVALUATOR_BASE_URL: process.env.AUTOGATE_EVALUATOR_BASE_URL,
    }
  }

  public async start(options?: RealPaseoHarnessOptions): Promise<void> {
    // 1. Ensure ephemeral directories exist and git workspace initialized
    if (!fs.existsSync(this.scratchDir)) {
      fs.mkdirSync(this.scratchDir, { recursive: true })
    }
    if (!fs.existsSync(this.workspaceDir)) {
      fs.mkdirSync(this.workspaceDir, { recursive: true })
    }

    try {
      if (!fs.existsSync(path.join(this.workspaceDir, ".git"))) {
        execSync("git init", { cwd: this.workspaceDir, stdio: "ignore" })
        execSync("git config user.email test@autogate.test", {
          cwd: this.workspaceDir,
          stdio: "ignore",
        })
        execSync("git config user.name Test", {
          cwd: this.workspaceDir,
          stdio: "ignore",
        })
      }
    } catch {}

    const ompConfigDir = path.join(this.scratchDir, "omp-config")
    const ompAgentDir = path.join(this.scratchDir, "omp-agent")
    const xdgConfigDir = path.join(this.scratchDir, "xdg-config")
    const xdgDataDir = path.join(this.scratchDir, "xdg-data")
    const xdgStateDir = path.join(this.scratchDir, "xdg-state")
    const xdgCacheDir = path.join(this.scratchDir, "xdg-cache")

    for (const dir of [
      ompConfigDir,
      ompAgentDir,
      xdgConfigDir,
      xdgDataDir,
      xdgStateDir,
      xdgCacheDir,
    ]) {
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true })
      }
    }

    const modelsYml = `providers:
  mock-provider:
    baseUrl: ${this.mockProvider.url}/v1
    apiKey: test-key
    api: openai-completions
    models:
      - id: mock-model
        name: Mock Model
        reasoning: false
        input: [text]
`
    fs.writeFileSync(path.join(ompAgentDir, "models.yml"), modelsYml)
    fs.writeFileSync(path.join(ompConfigDir, "models.yml"), modelsYml)

    // 2. Pre-seed <scratch>/config.json
    const config = {
      pluginsEnabled: true,
      plugins: {
        autogate: {
          source: "directory",
          path: this.pluginPath,
          enabled: true,
          ...(options?.pluginConfig ? { options: options.pluginConfig } : {}),
        },
      },
      features: {
        voiceMode: { enabled: false },
        dictation: { enabled: false },
      },
      agents: {
        providers: {
          omp: {
            enabled: true,
            models: [
              {
                id: "mock-provider/mock-model",
                label: "Mock Model",
                isDefault: true,
              },
            ],
            env: {
              OPENAI_BASE_URL: `${this.mockProvider.url}/v1`,
              OPENAI_API_KEY: "test-key",
              PI_CONFIG_DIR: ompConfigDir,
              PI_CODING_AGENT_DIR: ompAgentDir,
              XDG_CONFIG_HOME: xdgConfigDir,
              XDG_DATA_HOME: xdgDataDir,
              XDG_STATE_HOME: xdgStateDir,
              XDG_CACHE_HOME: xdgCacheDir,
            },
          },
          opencode: {
            env: {
              OPENCODE_CONFIG_CONTENT: JSON.stringify({
                provider: {
                  "mock-provider": {
                    npm: "@ai-sdk/openai-compatible",
                    options: {
                      baseURL: `${this.mockProvider.url}/v1`,
                      apiKey: "test-key",
                    },
                    models: {
                      "mock-model": { name: "Mock Model" },
                    },
                  },
                },
              }),
              OPENCODE_SERVER_PASSWORD: "test-password",
            },
          },
        },
      },
      ...(options?.paseoConfig || {}),
    }

    fs.writeFileSync(
      path.join(this.scratchDir, "config.json"),
      JSON.stringify(config, null, 2)
    )

    // Pre-seed <scratch>/autogate.json
    const autogateConfig = {
      ntfyServer: this.ntfyServer,
      ntfyTopic: this.ntfyTopic,
      ntfyToken: this.ntfyToken,
      evaluatorBaseUrl: this.mockProvider.url,
      autoMode: true,
      ...(options?.pluginConfig || {}),
    }
    fs.writeFileSync(
      path.join(this.scratchDir, "autogate.json"),
      JSON.stringify(autogateConfig, null, 2)
    )

    // 3. Spawn paseo start with --port 0 and suppressed speech runtimes
    const spawnEnv = {
      ...process.env,
      PASEO_VOICE_MODE_ENABLED: "false",
      PASEO_DICTATION_ENABLED: "false",
      NTFY_SERVER: this.ntfyServer,
      NTFY_TOPIC: this.ntfyTopic,
      NTFY_TOKEN: this.ntfyToken,
      AUTOGATE_NTFY_SERVER: this.ntfyServer,
      AUTOGATE_NTFY_TOPIC: this.ntfyTopic,
      AUTOGATE_NTFY_TOKEN: this.ntfyToken,
      AUTOGATE_CONFIG: path.join(this.scratchDir, "autogate.json"),
      AUTOGATE_EVALUATOR_BASE_URL: this.mockProvider.url,
      ...(options?.env || {}),
    }

    this.daemonProcess = Bun.spawn(
      [
        "paseo",
        "start",
        "--home",
        this.scratchDir,
        "--port",
        "0",
        "--foreground",
        "--no-relay",
        "--no-mcp",
        "--no-web-ui",
        "--no-inject-mcp",
      ],
      {
        env: spawnEnv,
        stdout: "pipe",
        stderr: "pipe",
      }
    )

    // 4. Poll <scratch>/paseo.pid every 25ms to extract dynamic bound port
    const { port, listen, pid } = await this.waitForReadiness(this.timeout)
    this.port = port
    this.listenHost = listen
    this.listenUrl = `ws://${listen}/ws`
    if (pid) {
      this.supervisorPid = pid
    } else if (this.daemonProcess?.pid) {
      this.supervisorPid = this.daemonProcess.pid
    }

    // Try detecting worker PID
    this.findWorkerPid()

    // 5. Connect @getpaseo/client
    this.client = createPaseoClient({
      url: this.listenUrl,
      logger: {
        debug: () => {},
        info: () => {},
        warn: () => {},
        error: (obj: any, msg?: string) => {
          if (String(obj?.err || msg || "").includes("Daemon client closed")) return
          console.error(msg, obj)
        },
      },
    })
    await this.client.connect()
  }

  private async waitForReadiness(
    timeoutMs: number
  ): Promise<{ port: number; listen: string; pid?: number }> {
    const deadline = Date.now() + timeoutMs
    const pidFile = path.join(this.scratchDir, "paseo.pid")

    while (Date.now() < deadline) {
      if (fs.existsSync(pidFile)) {
        try {
          const raw = fs.readFileSync(pidFile, "utf-8")
          const parsed = JSON.parse(raw)
          if (parsed.listen && typeof parsed.listen === "string") {
            const match = parsed.listen.match(/:(\d+)$/)
            if (match) {
              return {
                port: parseInt(match[1], 10),
                listen: parsed.listen,
                pid: typeof parsed.pid === "number" ? parsed.pid : undefined,
              }
            }
          }
        } catch {}
      }
      await Bun.sleep(25)
    }
    throw new Error(
      `Timed out waiting for Paseo daemon readiness after ${timeoutMs}ms in ${this.scratchDir}`
    )
  }

  public findWorkerPid(): number | undefined {
    if (this.workerPid && this.isProcessRunning(this.workerPid)) {
      return this.workerPid
    }
    const candidateParents = [this.supervisorPid, this.daemonProcess?.pid].filter(
      Boolean
    ) as number[]

    for (const parent of candidateParents) {
      try {
        const out = execSync(`pgrep -P ${parent}`, {
          encoding: "utf8",
          stdio: ["ignore", "pipe", "ignore"],
        }).trim()
        if (out) {
          const pids = out
            .split(/\s+/)
            .map((p) => parseInt(p, 10))
            .filter((p) => !isNaN(p) && p > 0)
          if (pids.length > 0) {
            this.workerPid = pids[0]
            return this.workerPid
          }
        }
      } catch {}
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

  public findPortPid(port: number): number | undefined {
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

    return undefined
  }

  private isSafeToKill(pid?: number): boolean {
    if (!pid || pid <= 1 || pid === process.pid) return false
    return true
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
            .filter(
              (p: number) => !isNaN(p) && p > 0 && p !== process.pid && this.isSafeToKill(p)
            )
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

    const descendants = this.getProcessTree(rootPid)

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

  public async connectNtfyStream(signal?: AbortSignal): Promise<void> {
    if (
      this.ntfyStreamConnected &&
      this.ntfyStreamController &&
      !this.ntfyStreamController.signal.aborted
    ) {
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
      if (
        res.status === 429 ||
        errText.includes("429") ||
        errText.includes("limit reached")
      ) {
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
            } catch {}
          }
        }
      } catch {
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
              if (
                parsed.req_id === requestId ||
                parsed.reqID === requestId ||
                parsed.id === requestId
              ) {
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
          if (
            parsed.req_id === requestId ||
            parsed.reqID === requestId ||
            parsed.id === requestId
          ) {
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
    const requestId =
      typeof requestIdOrTimeout === "string" ? requestIdOrTimeout : undefined
    const timeout =
      typeof requestIdOrTimeout === "number" ? requestIdOrTimeout : timeoutMs

    if (requestId) {
      const existing = this.findActionsForRequestId(requestId)
      if (existing.length > 0) {
        return new TargetActionDetails(existing)
      }
    } else if (this.receivedActions.length > 0) {
      return new TargetActionDetails(
        this.receivedActions,
        this.receivedNotifications[0]
      )
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
        const idx = this.actionWaiters.findIndex(
          (w) => w.requestId === requestId && w.resolve === resolve
        )
        if (idx !== -1) {
          this.actionWaiters.splice(idx, 1)
        }
        reject(
          new Error(
            `Timed out after ${timeout}ms waiting for action${
              requestId ? ` for request ID "${requestId}"` : ""
            } on topic "${this.ntfyTopic}"`
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
      (replyOrRequestId === "once" ||
        replyOrRequestId === "always" ||
        replyOrRequestId === "reject") &&
      replyArg === undefined
    const reply: "once" | "always" | "reject" = isReplyOnly
      ? (replyOrRequestId as any)
      : replyArg || "once"
    let requestId: string | undefined = isReplyOnly ? undefined : replyOrRequestId

    let actions: ParsedNtfyAction[] = []

    if (options?.actionsHeader) {
      actions = parseNtfyActions(options.actionsHeader)
    } else if (requestId) {
      actions = this.findActionsForRequestId(requestId)
      if (actions.length === 0) {
        try {
          const targetDetails = await this.waitForAction(
            requestId,
            options?.timeoutMs ?? 5000
          )
          actions = targetDetails.actions
        } catch {}
      }
    } else {
      if (this.receivedActions.length > 0) {
        actions = this.receivedActions
      } else {
        try {
          const targetDetails = await this.waitForAction(
            undefined,
            options?.timeoutMs ?? 5000
          )
          actions = targetDetails.actions
        } catch {}
      }
    }

    if (actions.length === 0) {
      throw new Error(
        `Could not find published notification with Actions${
          requestId ? ` for request ID "${requestId}"` : ""
        } on topic "${this.ntfyTopic}"`
      )
    }

    const targetAction = actions.find((a) => {
      if (a.body) {
        try {
          const parsed = typeof a.body === "string" ? JSON.parse(a.body) : a.body
          if (
            requestId &&
            (parsed.req_id === requestId ||
              parsed.reqID === requestId ||
              parsed.id === requestId) &&
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
      if (
        reply === "once" &&
        labelUpper.includes("APPROVE") &&
        !labelUpper.includes("ALWAYS")
      )
        return true
      if (
        reply === "reject" &&
        (labelUpper.includes("DENY") || labelUpper.includes("REJECT"))
      )
        return true
      return false
    })

    if (!targetAction) {
      throw new Error(
        `Could not find matching action for reply "${reply}"${
          requestId ? ` and request ID "${requestId}"` : ""
        } in actions: ${JSON.stringify(actions)}`
      )
    }

    if (!requestId && targetAction.body) {
      try {
        const parsed =
          typeof targetAction.body === "string"
            ? JSON.parse(targetAction.body)
            : targetAction.body
        requestId = parsed.req_id || parsed.reqID || parsed.id
      } catch {}
    }

    let bodyToSend =
      targetAction.body || JSON.stringify({ req_id: requestId, reply })
    if (message) {
      try {
        const parsed =
          typeof bodyToSend === "string"
            ? JSON.parse(bodyToSend)
            : Object.assign({}, bodyToSend)
        parsed.message = message
        bodyToSend = JSON.stringify(parsed)
      } catch {
        bodyToSend = JSON.stringify({ req_id: requestId, reply, message })
      }
    }

    const targetUrl = targetAction.url
    const requestHeaders: Record<string, string> = {
      "Content-Type": "application/json",
      ...(targetAction.headers || {}),
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

  public async createAgent(options?: {
    cwd?: string
    provider?: string
    modeId?: string
    title?: string
  }) {
    return this.client.agents.create({
      cwd: options?.cwd ?? this.workspaceDir,
      config: {
        provider: options?.provider ?? "omp/mock-provider/mock-model",
        modeId: (options?.modeId as any) ?? "ask",
      },
      title: options?.title,
    })
  }

  public async runAgentPrompt(
    agent: any,
    prompt: string,
    options?: { timeoutMs?: number }
  ): Promise<{
    events: any[]
    turnCompleted: boolean
    toolCalls: any[]
    permissionEvents: any[]
  }> {
    const timeoutMs = options?.timeoutMs ?? 20000
    const events: any[] = []
    const toolCalls: any[] = []
    const permissionEvents: any[] = []

    let resolveDone!: () => void
    const donePromise = new Promise<void>((resolve) => {
      resolveDone = resolve
    })

    const unsub = agent.timeline.subscribe((event: any) => {
      events.push(event)
      const evType = event?.event?.type
      if (evType === "permission_requested" || evType === "permission_resolved") {
        permissionEvents.push(event.event)
      }
      if (evType === "timeline") {
        const item = event.event?.item
        if (item?.type === "tool_call") {
          toolCalls.push(item)
        }
      }
      if (evType === "turn_completed" || evType === "turn_failed" || evType === "turn_canceled") {
        setTimeout(() => resolveDone(), 150)
      }
    })

    const timer = setTimeout(() => resolveDone(), timeoutMs)
    try {
      await agent.send(prompt)
      await donePromise
    } finally {
      clearTimeout(timer)
      unsub()
    }

    const turnCompleted = events.some(
      (e) => e?.event?.type === "turn_completed" || e?.event?.type === "turn_failed"
    )

    return {
      events,
      turnCompleted,
      toolCalls,
      permissionEvents,
    }
  }

  public disposeSync(): void {
    if (this.disposed) return
    this.disposed = true
    RealPaseoHarness.activeHarnesses.delete(this)

    // 1. Abort SSE stream
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
      waiter.reject(new Error("RealPaseoHarness disposed"))
    }
    this.actionWaiters = []

    // 2. Stop mock inference provider
    try {
      (this.mockProvider as any)?.server?.stop(true)
    } catch {}

    // 3. Graceful daemon stop via CLI
    try {
      execSync(
        `paseo daemon stop --home "${this.scratchDir}" --timeout 5 --force --json`,
        { stdio: "ignore" }
      )
    } catch {}

    // 4. Force termination of process tree
    if (this.supervisorPid) {
      this.terminateProcessTree(this.supervisorPid)
    }
    if (this.daemonProcess?.pid) {
      this.terminateProcessTree(this.daemonProcess.pid)
    }
    if (this.workerPid) {
      this.terminateProcessTree(this.workerPid)
    }

    if (this.port) {
      const lingering = this.findPortPid(this.port)
      if (lingering && lingering !== process.pid) {
        try {
          process.kill(lingering, "SIGKILL")
        } catch {}
      }
    }

    // 5. Restore environment
    for (const [key, val] of Object.entries(this.savedEnv)) {
      if (val === undefined) {
        delete process.env[key]
      } else {
        process.env[key] = val
      }
    }

    // 6. Clean scratch directories
    if (this.isTemporaryScratch && fs.existsSync(this.scratchDir)) {
      try {
        fs.rmSync(this.scratchDir, { recursive: true, force: true })
      } catch {}
    }
    if (this.isTemporaryWorkspace && fs.existsSync(this.workspaceDir)) {
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
      RealPaseoHarness.activeHarnesses.delete(this)

      // 1. Close SDK client
      try {
        await this.client?.close()
      } catch {}

      // 2. Abort SSE stream
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
        waiter.reject(new Error("RealPaseoHarness disposed"))
      }
      this.actionWaiters = []

      // 3. Graceful daemon stop via CLI
      try {
        execSync(
          `paseo daemon stop --home "${this.scratchDir}" --timeout 5 --force --json`,
          { stdio: "ignore" }
        )
      } catch {}

      // 4. Force termination of process tree
      if (this.supervisorPid) {
        this.terminateProcessTree(this.supervisorPid)
      }
      if (this.daemonProcess?.pid) {
        this.terminateProcessTree(this.daemonProcess.pid)
      }
      if (this.workerPid) {
        this.terminateProcessTree(this.workerPid)
      }

      if (this.port) {
        const lingering = this.findPortPid(this.port)
        if (lingering && lingering !== process.pid) {
          try {
            process.kill(lingering, "SIGKILL")
          } catch {}
        }
      }

      // 5. Stop mock provider
      try {
        await this.mockProvider.stop()
      } catch {}

      // 6. Restore environment
      for (const [key, val] of Object.entries(this.savedEnv)) {
        if (val === undefined) {
          delete process.env[key]
        } else {
          process.env[key] = val
        }
      }

      // 7. Clean scratch directories
      if (this.isTemporaryScratch && fs.existsSync(this.scratchDir)) {
        try {
          fs.rmSync(this.scratchDir, { recursive: true, force: true })
        } catch {}
      }
      if (this.isTemporaryWorkspace && fs.existsSync(this.workspaceDir)) {
        try {
          fs.rmSync(this.workspaceDir, { recursive: true, force: true })
        } catch {}
      }
    })()

    return this.disposePromise
  }
}

export const PaseoBlackboxHarness = RealPaseoHarness

export async function createRealPaseoHarness(
  options?: RealPaseoHarnessOptions
): Promise<RealPaseoHarness> {
  const harness = new RealPaseoHarness(options)
  await harness.start(options)
  return harness
}
