import type { AutoGateConfig } from "./config"
import type {
  RemoteAdapter,
  NotificationPayload,
  NotificationAction,
  ApprovalResponse,
  PermissionEventData,
  RiskLevel,
  UserAuthorization
} from "./types"
import { classifyRequest, sanitizeUserPrompt } from "./classifier"
import { formatNotificationTitle, formatNotificationBody } from "./formatters"

export const sharedRecentlyRejected = new Map<string, { timestamp: number; reason: string }>()
export const sharedExplicitEscalations = new Map<string, { timestamp: number; action: string; reason: string }>()

export function sweepExpiredState(now = Date.now()): void {
  for (const [k, v] of sharedRecentlyRejected.entries()) {
    if (now - v.timestamp > 60000) sharedRecentlyRejected.delete(k)
  }
  for (const [k, v] of sharedExplicitEscalations.entries()) {
    if (now - v.timestamp > 60000) sharedExplicitEscalations.delete(k)
  }
}

export function recordEscalationIntent(sessionID: string, action: string, reason: string): void {
  sweepExpiredState()
  sharedExplicitEscalations.set(sessionID, {
    timestamp: Date.now(),
    action: action.trim(),
    reason: reason.trim(),
  })
}

export function getActionKey(request: PermissionEventData): string {
  const patterns = Array.isArray(request.patterns) ? request.patterns.join(",") : ""
  return `${request.sessionID || ""}:${request.permission}:${patterns}`
}

function matchesAction(entryAction: string, request: PermissionEventData, commandString: string): boolean {
  const normEntry = entryAction.trim().replace(/^["']|["']$/g, "").toLowerCase()
  if (!normEntry) return false

  // 1. Command string comparison
  const normCmd = commandString.trim().toLowerCase()
  if (normCmd) {
    if (normCmd === normEntry || normCmd.includes(normEntry) || normEntry.includes(normCmd)) {
      return true
    }
  }

  // 2. Patterns comparison
  if (Array.isArray(request.patterns)) {
    for (const pat of request.patterns) {
      const normPat = String(pat).trim().replace(/^["']|["']$/g, "").toLowerCase()
      if (normPat) {
        if (normPat === normEntry || normPat.includes(normEntry) || normEntry.includes(normPat)) {
          return true
        }
      }
    }
  }

  // 3. Metadata filepath/path comparison
  const filepath =
    (typeof request.metadata?.filepath === "string" ? request.metadata.filepath : "") ||
    (typeof request.metadata?.path === "string" ? request.metadata.path : "") ||
    (typeof request.metadata?.file === "string" ? request.metadata.file : "")

  if (filepath) {
    const normFp = filepath.trim().replace(/^["']|["']$/g, "").toLowerCase()
    if (normFp === normEntry || normFp.includes(normEntry) || normEntry.includes(normFp)) {
      return true
    }
  }

  return false
}

export function checkAndConsumeEscalation(request: PermissionEventData, parentSessionID?: string): string | null {
  sweepExpiredState()

  // 1. Checks if request.permission === "bash" and command string includes AUTOGATE_ESCALATE=1
  const commandString =
    (typeof request.metadata?.command === "string" ? request.metadata.command : "") ||
    (typeof request.metadata?.cmd === "string" ? request.metadata.cmd : "") ||
    (Array.isArray(request.patterns) ? request.patterns.join(" ") : "")

  const isBash = request.permission === "bash" || request.permission === "shell:run"
  if (isBash && commandString.includes("AUTOGATE_ESCALATE=1")) {
    return "Escalated via AUTOGATE_ESCALATE=1 environment variable"
  }

  // 2. Checks sharedExplicitEscalations
  const sessionCandidates = [request.sessionID, parentSessionID].filter(Boolean) as string[]
  for (const sid of sessionCandidates) {
    const entry = sharedExplicitEscalations.get(sid)
    if (entry) {
      if (Date.now() - entry.timestamp > 60000) {
        sharedExplicitEscalations.delete(sid)
      } else if (matchesAction(entry.action, request, commandString)) {
        sharedExplicitEscalations.delete(sid)
        return entry.reason || "Manual review requested via escalate_permission tool"
      }
    }
  }

  // 3. Checks sharedRecentlyRejected
  const actionKey = getActionKey(request)
  const rejectedEntry = sharedRecentlyRejected.get(actionKey)
  if (rejectedEntry) {
    if (Date.now() - rejectedEntry.timestamp < 60000) {
      sharedRecentlyRejected.delete(actionKey)
      return rejectedEntry.reason
        ? `Re-attempted action within 60s after push-back: ${rejectedEntry.reason}`
        : "Re-attempted action within 60s of automated rejection"
    } else {
      sharedRecentlyRejected.delete(actionKey)
    }
  }

  // Check parent session action key if parentSessionID is provided
  if (parentSessionID && parentSessionID !== request.sessionID) {
    const parentPatterns = Array.isArray(request.patterns) ? request.patterns.join(",") : ""
    const parentActionKey = `${parentSessionID}:${request.permission}:${parentPatterns}`
    const parentRejected = sharedRecentlyRejected.get(parentActionKey)
    if (parentRejected) {
      if (Date.now() - parentRejected.timestamp < 60000) {
        sharedRecentlyRejected.delete(parentActionKey)
        return parentRejected.reason
          ? `Re-attempted action within 60s after push-back: ${parentRejected.reason}`
          : "Re-attempted action within 60s of automated rejection"
      } else {
        sharedRecentlyRejected.delete(parentActionKey)
      }
    }
  }

  return null
}

export function isTransformableAction(request: PermissionEventData, commandString?: string): boolean {
  const cmd = (
    commandString ||
    (typeof request.metadata?.command === "string" ? request.metadata.command : "") ||
    (typeof request.metadata?.cmd === "string" ? request.metadata.cmd : "") ||
    (Array.isArray(request.patterns) ? request.patterns.join(" ") : "")
  ).trim()

  if (!cmd) return false

  // Catastrophic root deletion is not transformable (cannot trash root)
  if (/^rm\s+(-[a-zA-Z]*r[a-zA-Z]*\s+)?\/(\s|$)/.test(cmd) || cmd === "rm -rf /" || cmd === "rm -rf /*") {
    return false
  }

  // Check if command contains rm, git restore, or git checkout (without stash)
  const hasRm = cmd.includes("rm ") || /^rm(\s+|$)/i.test(cmd)
  const hasGitRestore = cmd.includes("git restore") && !cmd.includes("stash")
  const hasGitCheckout = cmd.includes("git checkout") && !cmd.includes("stash")

  return hasRm || hasGitRestore || hasGitCheckout
}

export class AutoGateEngine {
  private client: any
  private config: AutoGateConfig
  private remoteAdapter: RemoteAdapter
  private enabled: boolean
  private userPrompt: string = ""
  private userPrompts = new Map<string, string>()
  private sessionParentCache = new Map<string, string>()
  private consecutiveBlocks: number = 0
  private consecutiveBlockThreshold: number
  private inFlightRequests = new Map<string, { abort: AbortController; sessionID?: string; directory?: string }>()
  private turnDecisionCache = new Map<string, Set<string>>()
  private workspaceRoot?: string
  private stopRemoteListen?: () => void

  constructor(
    clientOrParams: any,
    config?: AutoGateConfig,
    remoteAdapter?: RemoteAdapter
  ) {
    if (clientOrParams && typeof clientOrParams === "object" && !Array.isArray(clientOrParams) && "config" in clientOrParams && "client" in clientOrParams) {
      this.client = clientOrParams.client
      this.config = clientOrParams.config
      this.remoteAdapter = clientOrParams.adapter ?? clientOrParams.remoteAdapter!
    } else {
      this.client = clientOrParams
      this.config = config!
      this.remoteAdapter = remoteAdapter!
    }
    this.workspaceRoot = clientOrParams?.workspaceRoot || (this.config as any)?.workspaceRoot
    this.enabled = this.config.autoMode
    this.consecutiveBlockThreshold = this.config.consecutiveBlockThreshold ?? 3
  }

  public setUserPrompt(prompt: string): void
  public setUserPrompt(sessionID: string, prompt: string): void
  public setUserPrompt(promptOrSession: string, promptText?: string): void {
    const text = typeof promptText === "string" ? promptText : promptOrSession
    const isSlashCommand = /<auto-slash-command[^>]*>/i.test(text)
    if (
      text.includes("## Environment Trust Boundaries:") ||
      text.includes("## Context:") ||
      text.includes("### Conversation Transcript") ||
      text.startsWith("[auto-gate-eval]") ||
      text.includes("[SYSTEM DIRECTIVE:") ||
      text.includes("[restore checkpointed") ||
      (text.includes("<!-- OMO_INTERNAL") && !isSlashCommand)
    ) {
      return
    }
    const sanitizedText = sanitizeUserPrompt(text)
    if (typeof promptText === "string") {
      this.userPrompts.set(promptOrSession, sanitizedText)
      if (this.sessionParentCache.has(promptOrSession)) {
        return
      }
      if (this.client?.session?.get) {
        this.client.session.get({ path: { id: promptOrSession } }).then((res: any) => {
          const data = res?.data ?? res
          if (data?.parentID) {
            this.sessionParentCache.set(promptOrSession, data.parentID)
          } else {
            this.userPrompt = sanitizedText
          }
        }).catch(() => {
          if (!this.userPrompt) this.userPrompt = sanitizedText
        })
      } else {
        if (!this.userPrompt) {
          this.userPrompt = sanitizedText
        }
      }
    } else {
      this.userPrompt = sanitizedText
    }
  }
 
  private async fetchLatestUserMessage(sessionID: string): Promise<string> {
    if (!this.client?.session?.messages) return ""
    try {
      const res = await this.client.session.messages({ path: { id: sessionID } })
      const messages = res?.data ?? res
      if (Array.isArray(messages) && messages.length > 0) {
        for (let i = messages.length - 1; i >= 0; i--) {
          const m = messages[i]
          const role = m?.info?.role ?? m?.role
          if (role === "user") {
            const parts = m.parts || m.content || []
            let text = ""
            if (typeof parts === "string") {
              text = parts
            } else if (Array.isArray(parts)) {
              text = parts
                .filter((p: any) => p && (typeof p === "string" || p.type === "text" || typeof p.text === "string"))
                .map((p: any) => (typeof p === "string" ? p : p.text || ""))
                .join("\n")
            } else if (m.content && typeof m.content === "string") {
              text = m.content
            }
            if (text) {
              const isSlashCmd = /<auto-slash-command[^>]*>/i.test(text)
              if (
                text.includes("[SYSTEM DIRECTIVE:") ||
                text.includes("[restore checkpointed") ||
                (text.includes("<!-- OMO_INTERNAL") && !isSlashCmd) ||
                text.includes("[auto-gate-eval]") ||
                text.includes("## Environment Trust Boundaries:") ||
                text.includes("## Context:") ||
                text.includes("### Conversation Transcript")
              ) {
                continue
              }
              const reqMatch = text.match(/<user-request>([\s\S]*?)<\/user-request>/i)
              if (reqMatch && reqMatch[1]) {
                text = reqMatch[1].trim()
              } else {
                const slashMatch = text.match(/<auto-slash-command[^>]*>([\s\S]*?)<\/auto-slash-command>/i)
                if (slashMatch && slashMatch[1]) {
                  const innerReq = slashMatch[1].match(/<user-request>([\s\S]*?)<\/user-request>/i)
                  if (innerReq && innerReq[1]) {
                    text = innerReq[1].trim()
                  } else {
                    text = slashMatch[1].trim()
                  }
                }
              }
              return text.trim()
            }
          }
        }
      }
    } catch {}
    return ""
  }
 
  public async resolveSessionPrompts(sessionID?: string): Promise<{ userPrompt: string; subagentPrompt?: string }> {
    if (!sessionID) {
      return { userPrompt: this.userPrompt || "" }
    }

    let parentID: string | undefined = undefined
    let sessionTitle: string | undefined = undefined

    try {
      if (this.sessionParentCache.has(sessionID)) {
        parentID = this.sessionParentCache.get(sessionID)
      }
      if (this.client?.session?.get) {
        const sessionRes = await this.client.session.get({ path: { id: sessionID } })
        const data = sessionRes?.data ?? sessionRes
        if (data?.parentID) {
          parentID = data.parentID
          this.sessionParentCache.set(sessionID, data.parentID)
        }
        sessionTitle = data?.title
      }
    } catch {}

    if (!parentID) {
      const userPrompt =
        this.userPrompts.get(sessionID) ||
        (await this.fetchLatestUserMessage(sessionID)) ||
        this.userPrompt ||
        ""
      return { userPrompt }
    }

    const rawSubagentText = this.userPrompts.get(sessionID) || (await this.fetchLatestUserMessage(sessionID)) || ""
    let subagentPrompt = rawSubagentText
    const cleanTitle = sessionTitle?.trim()
    if (cleanTitle) {
      if (subagentPrompt) {
        if (!subagentPrompt.includes(cleanTitle)) {
          subagentPrompt = `[Subagent: ${cleanTitle}]\n${subagentPrompt}`
        }
      } else {
        subagentPrompt = `[Subagent: ${cleanTitle}]`
      }
    }

    let rootSessionID = sessionID
    const visited = new Set<string>([sessionID])
    let iterID: string | undefined = parentID

    while (iterID && !visited.has(iterID)) {
      visited.add(iterID)
      try {
        let parentData: any = null
        if (this.client?.session?.get) {
          const res = await this.client.session.get({ path: { id: iterID } })
          parentData = res?.data ?? res
        }
        rootSessionID = iterID
        let nextParentID: string | undefined = undefined
        if (parentData && typeof parentData === "object") {
          nextParentID = parentData.parentID || undefined
        } else {
          nextParentID = this.sessionParentCache.get(iterID)
        }
        if (nextParentID) {
          this.sessionParentCache.set(iterID, nextParentID)
          iterID = nextParentID
        } else {
          break
        }
      } catch {
        break
      }
    }

    const rootUserPrompt = this.userPrompts.get(rootSessionID) || (await this.fetchLatestUserMessage(rootSessionID)) || this.userPrompt || ""
    return {
      userPrompt: rootUserPrompt,
      subagentPrompt: subagentPrompt || undefined,
    }
  }

  public getUserPrompt(sessionID?: string): string {
    if (sessionID && this.userPrompts.has(sessionID)) {
      return this.userPrompts.get(sessionID)!
    }
    if (sessionID && this.sessionParentCache.has(sessionID)) {
      let curr: string | undefined = sessionID
      const visited = new Set<string>([sessionID])
      while (curr && this.sessionParentCache.has(curr)) {
        const parentID: string | undefined = this.sessionParentCache.get(curr)
        if (!parentID || visited.has(parentID)) break
        visited.add(parentID)
        if (this.userPrompts.has(parentID)) {
          return this.userPrompts.get(parentID)!
        }
        curr = parentID
      }
    }
    if (sessionID) {
      return ""
    }
    return this.userPrompt
  }

  public setEnabled(enabled: boolean): void {
    this.enabled = enabled
  }

  public isEnabled(): boolean {
    return this.enabled
  }

  public getConsecutiveBlocks(): number {
    return this.consecutiveBlocks
  }

  public resetConsecutiveBlocks(): void {
    this.consecutiveBlocks = 0
  }
  public clearTurnCache(sessionID: string): void {
    this.turnDecisionCache.delete(sessionID)
  }
  public checkAndConsumeEscalation(request: PermissionEventData): string | null {
    const parentSessionID = request.sessionID ? this.sessionParentCache.get(request.sessionID) : undefined
    return checkAndConsumeEscalation(request, parentSessionID)
  }

  public recordEscalationIntent(sessionID: string, action: string, reason: string): void {
    recordEscalationIntent(sessionID, action, reason)
  }


  public async start(): Promise<(() => void) | undefined> {
    if (this.stopRemoteListen) {
      this.stopRemoteListen()
    }
    this.stopRemoteListen = await this.remoteAdapter.listen(async (resp) => {
      await this.handleRemoteResponse(resp)
    })
    return this.stopRemoteListen
  }

  public async stop(): Promise<void> {
    if (this.stopRemoteListen) {
      this.stopRemoteListen()
      this.stopRemoteListen = undefined
    }
    for (const entry of this.inFlightRequests.values()) {
      entry.abort.abort()
    }
    this.inFlightRequests.clear()
    this.turnDecisionCache.clear()
    sharedRecentlyRejected.clear()
    sharedExplicitEscalations.clear()
  }

  public async handlePermissionAsked(request: PermissionEventData): Promise<void> {
    if (!this.isEnabled()) {
      await this.delegateToRemote(request, "AutoMode is disabled")
      return
    }

    const threshold = this.consecutiveBlockThreshold
    if (this.consecutiveBlocks >= threshold) {
      await this.delegateToRemote(
        request,
        `Circuit breaker tripped: consecutive blocks (${this.consecutiveBlocks}) reached threshold (${threshold}).`,
        true
      )
      return
    }

    const { userPrompt: rawUserPrompt, subagentPrompt: rawSubagentPrompt } = await this.resolveSessionPrompts(request.sessionID)
    const userPrompt = sanitizeUserPrompt(rawUserPrompt)
    const subagentPrompt = rawSubagentPrompt ? sanitizeUserPrompt(rawSubagentPrompt) : undefined
    const escalationReason = this.checkAndConsumeEscalation(request)
    if (escalationReason) {
      await this.delegateToRemote(request, escalationReason)
      return
    }

    const commandString =
      (typeof request.metadata?.command === "string" ? request.metadata.command : "") ||
      (typeof request.metadata?.cmd === "string" ? request.metadata.cmd : "") ||
      (Array.isArray(request.patterns) ? request.patterns.join(" ") : "")
    const sid = request.sessionID || ""
    const actionKey = `${request.permission}:${commandString}`

    if (this.turnDecisionCache.get(sid)?.has(actionKey)) {
      const targetDir = (request.metadata?.directory as string) || this.workspaceRoot
      await this.replyPermission(request.id, "once", request.sessionID, undefined, targetDir)
      return
    }


    let verdictResult
    try {
      verdictResult = await classifyRequest({
        client: this.client,
        userPrompt,
        subagentPrompt,
        actionName: request.permission,
        actionArgs: {
          patterns: request.patterns,
          metadata: request.metadata,
          always: request.always,
        },
        workspaceRoot:
          typeof request.metadata?.directory === "string" ? request.metadata.directory : process.cwd(),
        model: this.config.classifierModel,
        environment: this.config.environment,
        config: this.config,
      })
    } catch (err) {
      verdictResult = { verdict: "UNSURE", reason: `Classifier error: ${err}` }
    }

    if (verdictResult.verdict === "ALLOW") {
      let sessionCache = this.turnDecisionCache.get(sid)
      if (!sessionCache) {
        sessionCache = new Set()
        this.turnDecisionCache.set(sid, sessionCache)
      }
      sessionCache.add(actionKey)
      this.resetConsecutiveBlocks()
      if (this.config.notifyOnVerdict !== false) {
        this.sendInformationalNotification(
          request,
          "ALLOW",
          verdictResult.reason,
          verdictResult.risk_level,
          verdictResult.user_authorization
        ).catch(() => {})
      }
      const targetDir = (request.metadata?.directory as string) || this.workspaceRoot
      await this.replyPermission(request.id, "once", request.sessionID, undefined, targetDir)
      return
    }

    if (verdictResult.verdict === "BLOCK") {
      this.consecutiveBlocks++
      const baseReason = verdictResult.reason ?? "Blocked by AutoGate classifier policy"
      const actionKey = getActionKey(request)
      sweepExpiredState()

      const commandString =
        (typeof request.metadata?.command === "string" ? request.metadata.command : "") ||
        (typeof request.metadata?.cmd === "string" ? request.metadata.cmd : "") ||
        (Array.isArray(request.patterns) ? request.patterns.join(" ") : "")

      let message = baseReason
      if (isTransformableAction(request, commandString)) {
        message = `[SAFE_TRANSFORM_REJECT]: ${baseReason}. Safe alternative: use 'npx trash-cli' instead of permanent 'rm', or 'git stash' before checkout/restore. To insist on manual review, call 'escalate_permission' tool, use AUTOGATE_ESCALATE=1 (for shell), or re-issue the exact action within 60s.`
      }

      sharedRecentlyRejected.set(actionKey, {
        timestamp: Date.now(),
        reason: message,
      })

      if (this.config.notifyOnVerdict !== false) {
        this.sendInformationalNotification(
          request,
          "BLOCK",
          message,
          verdictResult.risk_level,
          verdictResult.user_authorization
        ).catch(() => {})
      }
      const targetDir = (request.metadata?.directory as string) || this.workspaceRoot
      await this.replyPermission(request.id, "reject", request.sessionID, message, targetDir)
      return
    }

    // UNSURE
    await this.delegateToRemote(
      request,
      verdictResult.reason,
      false,
      verdictResult.risk_level,
      verdictResult.user_authorization
    )
  }

  public handlePermissionReplied(data: { requestID?: string; id?: string; reply?: string }): void {
    const reqID = data.requestID ?? data.id
    if (!reqID) return

    const entry = this.inFlightRequests.get(reqID)
    if (entry) {
      entry.abort.abort()
      this.inFlightRequests.delete(reqID)
      this.remoteAdapter
        .updateStatus(reqID, "✅ Answered in Terminal", "Permission request was answered locally in the terminal.")
        .catch(() => {})
    }
  }

  public async handleRemoteResponse(resp: ApprovalResponse): Promise<void> {
    const reqID = resp.req_id ?? (resp as any).id
    if (!reqID) return

    const entry = this.inFlightRequests.get(reqID)
    const sessionID = entry?.sessionID
    const directory = entry?.directory
    if (entry) {
      entry.abort.abort()
      this.inFlightRequests.delete(reqID)
    }

    if (resp.reply === "once" || resp.reply === "always") {
      this.resetConsecutiveBlocks()
    }

    try {
      await this.remoteAdapter.updateStatus(
        reqID,
        `✅ Answered Remotely (${resp.reply})`,
        `Permission request was answered remotely via ${resp.source ?? "ntfy"}.`
      )
    } catch {
      // Ignore update status failure
    }

    const replyVal = resp.reply === "always" ? "always" : resp.reply === "reject" ? "reject" : "once"
    await this.replyPermission(reqID, replyVal, sessionID, undefined, directory)
  }

  public async delegateToRemote(
    request: PermissionEventData,
    verdictReason?: string,
    isCircuitBreaker?: boolean,
    riskLevel?: RiskLevel,
    userAuth?: UserAuthorization
  ): Promise<void> {
    const payload: NotificationPayload = {
      id: request.id,
      title: formatNotificationTitle(isCircuitBreaker ? "CIRCUIT BREAKER" : "REVIEW", request.permission),
      message: formatNotificationBody({
        target: request.patterns,
        reason: verdictReason,
        warning: isCircuitBreaker
          ? `Consecutive block threshold (${this.consecutiveBlocks} >= ${this.config.consecutiveBlockThreshold ?? 3}) reached.`
          : undefined,
        risk_level: riskLevel,
        user_authorization: userAuth,
      }),
      priority: isCircuitBreaker ? "urgent" : "high",
      tags: isCircuitBreaker ? ["rotating_light", "warning", "lock"] : ["lock", "robot"],
      actions: [
        { id: "approve-once", label: "Approve", reply: "once" },
        { id: "approve-always", label: "Always Approve", reply: "always" },
        { id: "deny", label: "Deny", reply: "reject" },
      ],
    }

    const abortController = new AbortController()
    this.inFlightRequests.set(request.id, {
      abort: abortController,
      sessionID: request.sessionID,
      directory: (request.metadata?.directory as string) || this.workspaceRoot,
    })

    try {
      await this.remoteAdapter.publish(payload, abortController.signal)
    } catch (err: unknown) {
      if (abortController.signal.aborted || (err instanceof Error && err.name === "AbortError")) {
        return
      }
      console.error("Failed to publish notification to remote adapter:", err)
    }
  }

  private async sendInformationalNotification(
    request: PermissionEventData,
    verdict: "ALLOW" | "BLOCK",
    reason?: string,
    riskLevel?: RiskLevel,
    userAuth?: UserAuthorization
  ): Promise<void> {
    const payload: NotificationPayload = {
      id: request.id,
      title: formatNotificationTitle(verdict, request.permission),
      message: formatNotificationBody({
        target: request.patterns,
        reason,
        risk_level: riskLevel,
        user_authorization: userAuth,
      }),
      priority: verdict === "ALLOW" ? "low" : "default",
      tags: verdict === "ALLOW" ? ["white_check_mark"] : ["octagonal_sign"],
      actions: undefined,
    }

    try {
      await this.remoteAdapter.publish(payload, AbortSignal.timeout(5000))
    } catch (err) {
      console.error(`Failed to publish informational ${verdict} notification:`, err)
    }
  }

  private async replyPermission(
    requestID: string,
    reply: "once" | "always" | "reject",
    sessionID?: string,
    message?: string,
    directory?: string
  ): Promise<void> {
    const serverUrl = (this.config as any)?.serverUrl || "http://localhost:4096"
    const password = process.env.OPENCODE_SERVER_PASSWORD || ""
    const authHeader = "Basic " + Buffer.from(`opencode:${password}`).toString("base64")
    const targetDir = directory || (this.workspaceRoot ? this.workspaceRoot : undefined)
    const url = `${serverUrl}/permission/${encodeURIComponent(requestID)}/reply${targetDir ? `?directory=${encodeURIComponent(targetDir)}` : ""}`

    // 1. Direct HTTP fetch with directory routing and Basic Auth
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": authHeader,
        },
        body: JSON.stringify({ reply, message }),
        signal: AbortSignal.timeout(5000),
      })
      if (res.ok && !res.headers.get("content-type")?.includes("text/html")) {
        return
      }
    } catch (err) {}

    // 2. Try postSessionIdPermissionsPermissionId
    if (typeof this.client?.postSessionIdPermissionsPermissionId === "function" && sessionID) {
      try {
        const res = await this.client.postSessionIdPermissionsPermissionId({
          path: { id: sessionID, permissionID: requestID },
          body: { response: reply },
          query: targetDir ? { directory: targetDir } : undefined,
        })
        if (!res?.error && res?.response?.ok !== false) {
          return
        }
      } catch (err) {}
    }

    // 3. Try client.permission.reply (mock client / v2 SDK)
    if (typeof this.client?.permission?.reply === "function") {
      try {
        const res = await this.client.permission.reply({
          path: { requestID },
          body: { reply, message },
          query: targetDir ? { directory: targetDir } : undefined,
        })
        if (!res?.error && res?.response?.ok !== false) {
          return
        }
      } catch (err) {}

      try {
        await this.client.permission.reply({
          requestID,
          reply,
          message,
        })
        return
      } catch (err) {
        try {
          await this.client.permission.reply({
            sessionID,
            permissionID: requestID,
            response: reply,
          })
          return
        } catch {}
      }
    }

    // 4. Try client._client.post fallback
    if (typeof this.client?._client?.post === "function") {
      try {
        const res = await this.client._client.post({
          url: `/permission/${encodeURIComponent(requestID)}/reply${targetDir ? `?directory=${encodeURIComponent(targetDir)}` : ""}`,
          body: { reply, message },
        })
        if (!res?.error && res?.response?.ok !== false) {
          return
        }
      } catch (err) {}
    }

    if (typeof this.client?._client?.post === "function" && sessionID) {
      try {
        const res = await this.client._client.post({
          url: `/session/${encodeURIComponent(sessionID)}/permissions/${encodeURIComponent(requestID)}${targetDir ? `?directory=${encodeURIComponent(targetDir)}` : ""}`,
          body: { response: reply },
        })
        if (!res?.error && res?.response?.ok !== false) {
          return
        }
      } catch (err) {}
    }
    console.error(`Failed to reply to permission ${requestID}: no compatible client method found`)
  }
}
