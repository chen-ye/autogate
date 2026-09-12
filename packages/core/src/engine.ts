import type { AutoGateConfig } from "./config"
import type {
  NotifierAdapter,
  ReviewRequest,
  ReviewResponse,
  GateAction,
  GateDecision,
  GateEvaluator,
  ClassifierResult,
  RiskLevel,
  UserAuthorization,
  PermissionEventData,
} from "./types"
import { sanitizeUserPrompt } from "./classifier"
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

export function getActionKey(request: PermissionEventData | GateAction): string {
  const perm = (request as any).permission ?? (request as any).toolName ?? ""
  const patterns = Array.isArray((request as any).patterns)
    ? (request as any).patterns.join(",")
    : (request as any).commandString || (request as any).targetPath || ""
  const sessionID = (request as any).sessionID || ""
  return `${sessionID}:${perm}:${patterns}`
}

function matchesAction(entryAction: string, request: PermissionEventData, commandString: string): boolean {
  const normEntry = entryAction.trim().replace(/^["']|["']$/g, "").toLowerCase()
  if (!normEntry) return false

  const normCmd = commandString.trim().toLowerCase()
  if (normCmd) {
    if (normCmd === normEntry || normCmd.includes(normEntry) || normEntry.includes(normCmd)) {
      return true
    }
  }

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

export function checkAndConsumeEscalation(request: PermissionEventData | GateAction, parentSessionID?: string): string | null {
  sweepExpiredState()

  const perm = (request as any).permission ?? (request as any).toolName ?? ""
  const commandString =
    (request as any).commandString ||
    (typeof request.metadata?.command === "string" ? request.metadata.command : "") ||
    (typeof request.metadata?.cmd === "string" ? request.metadata.cmd : "") ||
    (Array.isArray((request as any).patterns) ? (request as any).patterns.join(" ") : "") ||
    (typeof (request as any).targetPath === "string" ? (request as any).targetPath : "")

  const isBash = perm === "bash" || perm === "shell:run"
  if (isBash && commandString.includes("AUTOGATE_ESCALATE=1")) {
    return "Escalated via AUTOGATE_ESCALATE=1 environment variable"
  }

  const sessionCandidates = [(request as any).sessionID, parentSessionID].filter(Boolean) as string[]
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

  if (parentSessionID && parentSessionID !== (request as any).sessionID) {
    const parentPatterns = Array.isArray((request as any).patterns) ? (request as any).patterns.join(",") : commandString
    const parentActionKey = `${parentSessionID}:${perm}:${parentPatterns}`
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

export function isTransformableAction(request: PermissionEventData | GateAction, commandString?: string): boolean {
  const cmd = (
    commandString ||
    (request as any).commandString ||
    (typeof request.metadata?.command === "string" ? request.metadata.command : "") ||
    (typeof request.metadata?.cmd === "string" ? request.metadata.cmd : "") ||
    (Array.isArray((request as any).patterns) ? (request as any).patterns.join(" ") : "") ||
    (Array.isArray((request as any).metadata?.patterns) ? ((request as any).metadata.patterns as any[]).join(" ") : "")
  ).trim()

  if (!cmd) return false

  if (/^rm\s+(-[a-zA-Z]*r[a-zA-Z]*\s+)?\/(\s|$)/.test(cmd) || cmd === "rm -rf /" || cmd === "rm -rf /*") {
    return false
  }

  const hasRm = cmd.includes("rm ") || /^rm(\s+|$)/i.test(cmd)
  const hasGitRestore = cmd.includes("git restore") && !cmd.includes("stash")
  const hasGitCheckout = cmd.includes("git checkout") && !cmd.includes("stash")

  return hasRm || hasGitRestore || hasGitCheckout
}

export class DefaultGateEvaluator implements GateEvaluator {
  readonly name = "default-classifier"
  constructor(private client?: any, private config?: AutoGateConfig) {}
  async evaluate(action: GateAction): Promise<ClassifierResult> {
    return { verdict: "UNSURE", reason: "No evaluator configured on engine" }
  }
}

function createDummyAdapter(): NotifierAdapter {
  return {
    name: "dummy",
    async publish() {},
    async listen() { return () => {} },
    async updateStatus() {},
  }
}

export interface AutoGateEngineOptions {
  config: AutoGateConfig
  adapter?: NotifierAdapter
  evaluator?: GateEvaluator
  workspaceRoot?: string
  client?: any
}

export class AutoGateCoreEngine {
  private config: AutoGateConfig
  private remoteAdapter: NotifierAdapter
  private evaluator: GateEvaluator
  private enabled: boolean
  private userPrompt: string = ""
  private userPrompts = new Map<string, string>()
  private sessionParentCache = new Map<string, string>()
  private consecutiveBlocks: number = 0
  private consecutiveBlockThreshold: number
  private inFlightRequests = new Map<string, { resolve: (decision: GateDecision) => void; reject: (err: Error) => void; abort: AbortController; sessionID?: string; directory?: string }>()
  private turnDecisionCache = new Map<string, Set<string>>()
  private workspaceRoot?: string
  private stopRemoteListen?: () => void
  private client?: any

  constructor(optionsOrClient?: AutoGateEngineOptions | any, config?: AutoGateConfig, remoteAdapter?: NotifierAdapter, evaluator?: GateEvaluator) {
    if (optionsOrClient && typeof optionsOrClient === "object" && !Array.isArray(optionsOrClient) && ("config" in optionsOrClient || "evaluator" in optionsOrClient || "adapter" in optionsOrClient)) {
      const opts = optionsOrClient as AutoGateEngineOptions
      this.config = opts.config
      this.remoteAdapter = opts.adapter ?? (opts as any).remoteAdapter ?? createDummyAdapter()
      this.evaluator = opts.evaluator ?? new DefaultGateEvaluator(opts.client, opts.config)
      this.workspaceRoot = opts.workspaceRoot ?? (opts.config as any)?.workspaceRoot
      this.client = opts.client
    } else {
      if (optionsOrClient && typeof optionsOrClient === "object" && "autoMode" in optionsOrClient) {
        this.config = optionsOrClient as AutoGateConfig
        this.remoteAdapter = (config as unknown as NotifierAdapter) ?? createDummyAdapter()
        this.evaluator = (remoteAdapter as unknown as GateEvaluator) ?? new DefaultGateEvaluator(undefined, this.config)
      } else {
        this.client = optionsOrClient
        this.config = config!
        this.remoteAdapter = remoteAdapter ?? createDummyAdapter()
        this.evaluator = evaluator ?? new DefaultGateEvaluator(this.client, this.config)
      }
    }
    this.workspaceRoot = this.workspaceRoot || (this.config as any)?.workspaceRoot
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

  public checkAndConsumeEscalation(request: PermissionEventData | GateAction): string | null {
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
      this.resolveReviewResponse(resp)
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

  public async evaluate(action: GateAction): Promise<GateDecision> {
    // 1. Checks disabled state -> requests review if disabled.
    if (!this.isEnabled()) {
      return this.requestReview(action, "AutoMode is disabled", false, undefined, undefined)
    }

    // 2. Checks circuit breaker (`consecutiveBlocks >= threshold`) -> requests review.
    const threshold = this.consecutiveBlockThreshold
    if (this.consecutiveBlocks >= threshold) {
      return this.requestReview(
        action,
        `Circuit breaker tripped: consecutive blocks (${this.consecutiveBlocks}) reached threshold (${threshold}).`,
        true
      )
    }

    // 3. Checks explicit escalation (`checkAndConsumeEscalation`) -> requests review.
    const parentSessionID = action.sessionID ? this.sessionParentCache.get(action.sessionID) : undefined
    const escalationReason = checkAndConsumeEscalation(action, parentSessionID)
    if (escalationReason) {
      return this.requestReview(action, escalationReason, false, undefined, undefined)
    }

    // 4. Checks turn decision cache -> returns cached ALLOW if found.
    const sid = action.sessionID || ""
    const commandString =
      action.commandString ||
      (typeof action.metadata?.command === "string" ? action.metadata.command : "") ||
      (Array.isArray(action.metadata?.patterns) ? (action.metadata.patterns as any[]).join(" ") : "") ||
      (Array.isArray(action.rawArgs) ? (action.rawArgs as any[]).join(" ") : "")
    const actionKey = `${action.toolName}:${commandString || action.targetPath || JSON.stringify(action.rawArgs || "")}`

    if (this.turnDecisionCache.get(sid)?.has(actionKey)) {
      return {
        verdict: "ALLOW",
        reason: "Cached turn decision",
        cached: true,
      }
    }

    // Resolve prompts if not already populated on action
    if (!action.userPrompt) {
      const resolved = await this.resolveSessionPrompts(action.sessionID)
      action.userPrompt = sanitizeUserPrompt(resolved.userPrompt)
      action.subagentPrompt = resolved.subagentPrompt ? sanitizeUserPrompt(resolved.subagentPrompt) : undefined
    }

    // 5. Calls `this.evaluator.evaluate(action)`.
    let verdictResult: ClassifierResult
    try {
      verdictResult = await this.evaluator.evaluate(action)
    } catch (err) {
      verdictResult = { verdict: "UNSURE", reason: `Classifier error: ${err}` }
    }

    // 6. On ALLOW: caches action, resets consecutive blocks, optional info notification, returns GateDecision.
    if (verdictResult.verdict === "ALLOW") {
      let sessionCache = this.turnDecisionCache.get(sid)
      if (!sessionCache) {
        sessionCache = new Set()
        this.turnDecisionCache.set(sid, sessionCache)
      }
      sessionCache.add(actionKey)
      this.resetConsecutiveBlocks()
      if (this.config.notifyOnVerdict !== false) {
        this.sendInformationalNotification(action, "ALLOW", verdictResult.reason, verdictResult.risk_level, verdictResult.user_authorization).catch(() => {})
      }
      return {
        verdict: "ALLOW",
        riskLevel: verdictResult.risk_level,
        userAuthorization: verdictResult.user_authorization,
        reason: verdictResult.reason || "Allowed by AutoGate classifier policy",
        cached: false,
      }
    }

    // 7. On BLOCK: increments consecutive blocks, checks `isTransformableAction`, records in `sharedRecentlyRejected`, optional info notification, returns GateDecision.
    if (verdictResult.verdict === "BLOCK") {
      this.consecutiveBlocks++
      const baseReason = verdictResult.reason ?? "Blocked by AutoGate classifier policy"
      const regActionKey = getActionKey(action)
      sweepExpiredState()

      let message = baseReason
      if (isTransformableAction(action, commandString)) {
        message = `[SAFE_TRANSFORM_REJECT]: ${baseReason}. Safe alternative: use 'npx trash-cli' instead of permanent 'rm', or 'git stash' before checkout/restore. To insist on manual review, call 'escalate_permission' tool, use AUTOGATE_ESCALATE=1 (for shell), or re-issue the exact action within 60s.`
      }

      sharedRecentlyRejected.set(regActionKey, {
        timestamp: Date.now(),
        reason: message,
      })

      if (this.config.notifyOnVerdict !== false) {
        this.sendInformationalNotification(action, "BLOCK", message, verdictResult.risk_level, verdictResult.user_authorization).catch(() => {})
      }

      return {
        verdict: "BLOCK",
        riskLevel: verdictResult.risk_level,
        userAuthorization: verdictResult.user_authorization,
        reason: message,
        safeTransformAlternative: isTransformableAction(action, commandString) ? message : undefined,
      }
    }

    // 8. On UNSURE: calls `requestReview(action, reason, isCircuitBreaker, riskLevel, userAuth)` and awaits in-flight resolver or timeout.
    return this.requestReview(
      action,
      verdictResult.reason,
      false,
      verdictResult.risk_level,
      verdictResult.user_authorization
    )
  }

  public async requestReview(
    action: GateAction,
    reason?: string,
    isCircuitBreaker?: boolean,
    riskLevel?: RiskLevel,
    userAuth?: UserAuthorization,
  ): Promise<GateDecision> {
    if (!this.stopRemoteListen) {
      await this.start();
    }
    const payload: ReviewRequest = {
      id: action.id,
      title: formatNotificationTitle(isCircuitBreaker ? "CIRCUIT BREAKER" : "REVIEW", action.toolName),
      message: formatNotificationBody({
        target: action.commandString
          ? [action.commandString]
          : action.targetPath
          ? [action.targetPath]
          : action.rawArgs
          ? [String(action.rawArgs)]
          : action.toolName,
        reason,
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
    const decisionPromise = new Promise<GateDecision>((resolve, reject) => {
      this.inFlightRequests.set(action.id, {
        resolve,
        reject,
        abort: abortController,
        sessionID: action.sessionID,
        directory: action.workspaceRoot || this.workspaceRoot,
      })
    })

    try {
      await this.remoteAdapter.publish(payload, abortController.signal)
    } catch (err: unknown) {
      if (abortController.signal.aborted || (err instanceof Error && err.name === "AbortError")) {
        return {
          verdict: "BLOCK",
          reason: "Review request aborted",
        }
      }
      console.error("Failed to publish notification to remote adapter:", err)
    }

    const timeoutMs = (this.config as any)?.reviewTimeout ?? 300000
    const timeoutPromise = new Promise<GateDecision>((resolve) => {
      setTimeout(() => {
        const entry = this.inFlightRequests.get(action.id)
        if (entry) {
          this.inFlightRequests.delete(action.id)
          entry.abort.abort()
          resolve({
            verdict: "BLOCK",
            reason: `Review request timed out after ${Math.round(timeoutMs / 1000)} seconds`,
          })
        }
      }, timeoutMs)
    })

    return Promise.race([decisionPromise, timeoutPromise])
  }

  public resolveReviewResponse(resp: ReviewResponse): void {
    const reqID = resp.req_id ?? (resp as any).id
    if (!reqID) return

    const entry = this.inFlightRequests.get(reqID)
    if (entry) {
      entry.abort.abort()
      this.inFlightRequests.delete(reqID)
      this.remoteAdapter
        .updateStatus(reqID, `✅ Answered Remotely (${resp.reply})`, `Permission request was answered remotely via ${resp.source ?? "ntfy"}.`)
        .catch(() => {})

      if (resp.reply === "once" || resp.reply === "always") {
        this.resetConsecutiveBlocks()
      }

      const verdict = resp.reply === "reject" ? "BLOCK" : "ALLOW"
      entry.resolve({
        verdict,
        reply: resp.reply,
        reason: `Answered remotely via ${resp.reply}`,
      })
    }
  }

  public async handlePermissionAsked(request: PermissionEventData): Promise<void> {
    const action: GateAction = {
      id: request.id || Math.random().toString(36).slice(2),
      harness: request.harness || "opencode",
      sessionID: request.sessionID || "",
      toolName: request.permission || "permission",
      commandString: typeof request.metadata?.command === "string" ? request.metadata.command : undefined,
      targetPath: typeof request.metadata?.filepath === "string" ? request.metadata.filepath : undefined,
      rawArgs: request.patterns || request.metadata,
      workspaceRoot: (request.metadata?.directory as string) || this.workspaceRoot || process.cwd(),
      userPrompt: this.getUserPrompt(request.sessionID),
      environment: this.config.environment,
      metadata: request.metadata,
    }
    const decision = await this.evaluate(action)
    if (this.client) {
      const replyVal = decision.reply || (decision.verdict === "ALLOW" ? "once" : "reject")
      const targetDir = (request.metadata?.directory as string) || this.workspaceRoot
      await this.replyPermissionLegacy(request.id, replyVal, request.sessionID, decision.reason, targetDir)
    }
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

  public async handleRemoteResponse(resp: ReviewResponse): Promise<void> {
    this.resolveReviewResponse(resp)
  }

  public async delegateToRemote(
    request: PermissionEventData,
    verdictReason?: string,
    isCircuitBreaker?: boolean,
    riskLevel?: RiskLevel,
    userAuth?: UserAuthorization
  ): Promise<GateDecision> {
    const action: GateAction = {
      id: request.id || Math.random().toString(36).slice(2),
      harness: request.harness || "opencode",
      sessionID: request.sessionID || "",
      toolName: request.permission || "permission",
      commandString: typeof request.metadata?.command === "string" ? request.metadata.command : undefined,
      targetPath: typeof request.metadata?.filepath === "string" ? request.metadata.filepath : undefined,
      rawArgs: request.patterns || request.metadata,
      workspaceRoot: (request.metadata?.directory as string) || this.workspaceRoot || process.cwd(),
      userPrompt: this.getUserPrompt(request.sessionID),
      environment: this.config.environment,
      metadata: request.metadata,
    }
    return this.requestReview(action, verdictReason, isCircuitBreaker, riskLevel, userAuth)
  }

  private async sendInformationalNotification(
    action: GateAction,
    verdict: "ALLOW" | "BLOCK",
    reason?: string,
    riskLevel?: RiskLevel,
    userAuth?: UserAuthorization
  ): Promise<void> {
    const payload: ReviewRequest = {
      id: action.id,
      title: formatNotificationTitle(verdict, action.toolName),
      message: formatNotificationBody({
        target: action.commandString
          ? [action.commandString]
          : action.targetPath
          ? [action.targetPath]
          : action.rawArgs
          ? [String(action.rawArgs)]
          : action.toolName,
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

  private async replyPermissionLegacy(
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

    if (!this.client) return
    if (typeof this.client?.postSessionIdPermissionsPermissionId === "function" && sessionID) {
      try {
        const res = await this.client.postSessionIdPermissionsPermissionId({
          path: { id: sessionID, permissionID: requestID },
          body: { response: reply },
          query: targetDir ? { directory: targetDir } : undefined,
        })
        if (!res?.error && res?.response?.ok !== false) return
      } catch {}
    }
    if (typeof this.client?.permission?.reply === "function") {
      try {
        const res = await this.client.permission.reply({
          path: { requestID },
          body: { reply, message },
          query: targetDir ? { directory: targetDir } : undefined,
        })
        if (!res?.error && res?.response?.ok !== false) return
      } catch {}
    }
  }
}

export const AutoGateEngine = AutoGateCoreEngine
