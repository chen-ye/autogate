import {
  AutoGateCoreEngine,
  NtfyAdapter,
  DirectApiEvaluator,
  loadConfig,
  formatNotificationTitle,
  formatNotificationBody,
  type ReviewRequest,
  type HarnessAdapter,
  type GateAction,
  type GateEvaluator,
  type NotifierAdapter,
  type ReviewResponse,
  type AutoGateConfig,
} from "@autogate/core";
import { extractActionFromRequest } from "./inspect.js";
import { PaseoNativeEvaluator } from "./evaluator.js";
import type {
  PaseoServer,
  PaseoClient,
  PaseoAgentInstance,
  PaseoPluginOptions,
  PaseoPermissionEvent,
} from "./types.js";

export interface PendingPermissionRequest {
  agentId: string;
  action: GateAction;
  agent?: PaseoAgentInstance;
}

export class PaseoHarnessAdapter implements HarnessAdapter {
  readonly name: string = "paseo";

  private server: PaseoServer;
  private options?: PaseoPluginOptions;
  private config: AutoGateConfig;
  private engine: AutoGateCoreEngine;
  private ntfyAdapter: NotifierAdapter;
  private pendingRequests: Map<string, PendingPermissionRequest> = new Map();
  private unregisterRequested?: () => void;
  private unregisterResolved?: () => void;
  private stopRemoteListen?: () => void;
  private isDisposed: boolean = false;
  private lastHookPaseo?: PaseoClient;

  constructor(server: PaseoServer, options?: PaseoPluginOptions) {
    this.server = server;
    this.options = options;

    const config = loadConfig(options);
    if (config.paseo?.notifyOnVerdict !== undefined) {
      config.notifyOnVerdict = config.paseo.notifyOnVerdict;
    }
    this.config = config;

    this.ntfyAdapter =
      (options?.adapter as NotifierAdapter) ??
      new NtfyAdapter({
        server: config.ntfyServer,
        topic: config.ntfyTopic,
        token: config.ntfyToken,
      });

    const directApiEvaluator = new DirectApiEvaluator({
      apiKey:
        (options?.apiKey as string) ||
        (options?.evaluatorApiKey as string) ||
        process.env.AUTOGATE_API_KEY ||
        process.env.GEMINI_API_KEY ||
        process.env.GOOGLE_API_KEY ||
        config.ntfyToken ||
        "test-key",
      baseUrl:
        (options?.baseUrl as string) ||
        (options?.evaluatorBaseUrl as string) ||
        process.env.AUTOGATE_EVALUATOR_BASE_URL ||
        process.env.AUTOGATE_INFERENCE_URL ||
        process.env.GEMINI_BASE_URL,
      model:
        (options?.classifierModel as string) || config.classifierModel || "gemini-3.5-flash-lite",
      timeoutMs: config.classifierTimeout,
    });

    const evaluator =
      (options?.evaluator as GateEvaluator | undefined) ??
      (config.paseo?.useDirectApi === true
        ? directApiEvaluator
        : new PaseoNativeEvaluator(() => this.getPaseoClient(), {
            fallbackEvaluator: directApiEvaluator,
            classifierTimeout: config.classifierTimeout,
            config,
            evaluatorProvider: config.paseo?.evaluatorProvider,
            ...(options as Record<string, unknown>),
          }));

    this.engine =
      (options?.engine as AutoGateCoreEngine) ??
      new AutoGateCoreEngine({
        config,
        adapter: this.ntfyAdapter,
        evaluator,
        remoteReviewEnabled: false,
        workspaceRoot: options?.workspaceRoot as string | undefined,
      });

    if (this.server && typeof this.server.on === "function") {
      const unregReq = this.server.on("agent.permission_requested", this.onPermissionRequested);
      if (typeof unregReq === "function") {
        this.unregisterRequested = unregReq;
      }

      const unregRes = this.server.on("agent.permission_resolved", this.onPermissionResolved);
      if (typeof unregRes === "function") {
        this.unregisterResolved = unregRes;
      }
    }

    this.startListening().catch(() => {});
  }

  private getPaseoClient(): PaseoClient | undefined {
    return this.lastHookPaseo || this.options?.paseo || this.options?.client || this.server?.paseo;
  }

  public getEngine(): AutoGateCoreEngine {
    return this.engine;
  }

  public getAdapter(): NotifierAdapter {
    return this.ntfyAdapter;
  }

  public getPendingRequests(): Map<string, PendingPermissionRequest> {
    return this.pendingRequests;
  }

  private async startListening(): Promise<void> {
    if (this.stopRemoteListen || this.isDisposed) {
      return;
    }
    if (this.ntfyAdapter && typeof this.ntfyAdapter.listen === "function") {
      try {
        const stop = await this.ntfyAdapter.listen(async (resp: ReviewResponse) => {
          await this.handleRemoteReply(resp);
        });
        if (this.isDisposed) {
          try {
            stop();
          } catch {}
        } else {
          this.stopRemoteListen = stop;
        }
      } catch {
        // Prevent unhandled async rejection if listen fails
      }
    }
  }

  public async start(): Promise<void> {
    await this.startListening();
  }

  public async handleRemoteReply(resp: ReviewResponse): Promise<void> {
    if (this.isDisposed) return;
    const reqObj = resp as unknown as {
      id?: string;
      requestId?: string;
      requestID?: string;
    };
    const requestId = resp.req_id || reqObj.id || reqObj.requestId || reqObj.requestID;
    if (!requestId) return;

    const pending = this.pendingRequests.get(requestId);
    if (!pending) {
      // If not found (already answered in Paseo UI): ignore safely.
      return;
    }

    this.pendingRequests.delete(requestId);

    try {
      this.engine.resolveReviewResponse(resp);
    } catch {}

    const reply = resp.reply;
    const behavior = reply === "reject" ? "deny" : "allow";
    const agent = pending.agent ?? this.getAgent(pending.agentId);

    if (agent && typeof agent.respondToPermission === "function") {
      try {
        await agent.respondToPermission({
          requestId,
          response: { behavior },
        });
      } catch {
        // Wrap agent.respondToPermission() calls in try/catch to handle cases where
        // the agent was deleted or request already answered.
      }
    }
  }

  public async handleRemoteResponse(resp: ReviewResponse): Promise<void> {
    await this.handleRemoteReply(resp);
  }

  private onPermissionRequested = async (event: unknown, context?: unknown): Promise<void> => {
    if (this.isDisposed) return;
    try {
      const ctx = context as { paseo?: PaseoClient } | undefined;
      if (ctx?.paseo) {
        this.lastHookPaseo = ctx.paseo;
      }

      const ev = event as PaseoPermissionEvent | undefined;
      const req = ev?.request;
      const requestId =
        (typeof req?.id === "string" ? req.id : undefined) ??
        (typeof ev?.requestId === "string" ? ev.requestId : undefined);
      if (!requestId) {
        return;
      }
      // Recursion guard: never evaluate permissions for the evaluator agent itself, and actively deny tool execution
      const agentObj = ev?.agent as
        | (PaseoAgentInstance & {
            labels?: Record<string, string>;
            title?: string;
            cwd?: string;
          })
        | undefined;
      if (
        agentObj?.labels?.["autogate.role"] === "evaluator" ||
        agentObj?.title?.startsWith("[auto-gate-eval]")
      ) {
        const agent = this.getAgent(agentObj?.id || agentObj?.agentId, event, context);
        if (
          agent &&
          typeof (agent as { respondToPermission?: unknown }).respondToPermission === "function"
        ) {
          try {
            await (
              agent as { respondToPermission(data: unknown): Promise<unknown> }
            ).respondToPermission({
              requestId,
              response: {
                behavior: "deny",
                message:
                  "AutoGate Security: Evaluator sessions are strictly forbidden from executing tools.",
              },
            });
          } catch {
            // Wrap agent.respondToPermission() calls in try/catch to handle cases where
            // the agent was deleted or request already answered.
          }
        }
        return;
      }

      const action = extractActionFromRequest(event as { agent?: unknown; request?: unknown });
      console.log("[AutoGate] onPermissionRequested for:", action.toolName, action.commandString);
      const agent = this.getAgent(agentObj?.id || agentObj?.agentId, event, context);
      const decision = await this.engine.evaluate(action);
      console.log("[AutoGate] decision verdict:", decision.verdict, decision.reason);

      if (this.config.paseo?.timelineBadges !== false) {
        try {
          const targetAgent =
            this.getAgent(agentObj?.id || action.sessionID, event, context) ?? agent;
          let timelineAgent = targetAgent;
          if (!timelineAgent?.timeline?.append) {
            const client = ctx?.paseo ?? this.getPaseoClient();
            const agentId = agentObj?.id || action.sessionID;
            if (agentId && typeof client?.agents?.ref === "function") {
              const refAgent = client.agents.ref(agentId);
              if (refAgent?.timeline?.append) {
                timelineAgent = refAgent;
              }
            }
          }
          if (typeof timelineAgent?.timeline?.append === "function") {
            const evalAgentId = decision.metadata?.evalAgentId;
            await timelineAgent.timeline.append({
              type: "plugin",
              id: "autogate-eval-" + action.id,
              kind: "autogate-eval",
              version: 1,
              data: {
                verdict: decision.verdict,
                risk_level: decision.riskLevel,
                reason: decision.reason,
                command: action.commandString,
                toolName: action.toolName,
                evalAgentId: typeof evalAgentId === "string" ? evalAgentId : undefined,
                ...(decision.cascade ? { cascade: decision.cascade } : {}),
              },
            });
          }
        } catch {
          // Wrapped in a try/catch so timeline append failures never disrupt permission resolution.
        }
      }
      if (decision.verdict === "ALLOW") {
        if (
          agent &&
          typeof (agent as { respondToPermission?: unknown }).respondToPermission === "function"
        ) {
          try {
            await (
              agent as { respondToPermission(data: unknown): Promise<unknown> }
            ).respondToPermission({
              requestId,
              response: { behavior: "allow" },
            });
          } catch {
            // Wrap agent.respondToPermission() calls in try/catch to handle cases where
            // the agent was deleted or request already answered.
          }
        }
      } else if (decision.verdict === "BLOCK") {
        if (
          agent &&
          typeof (agent as { respondToPermission?: unknown }).respondToPermission === "function"
        ) {
          try {
            await (
              agent as { respondToPermission(data: unknown): Promise<unknown> }
            ).respondToPermission({
              requestId,
              response: {
                behavior: "deny",
                message:
                  decision.safeTransformAlternative ||
                  decision.reason ||
                  "Action blocked by AutoGate",
              },
            });
          } catch {
            // Wrap agent.respondToPermission() calls in try/catch
          }
        }
      } else if (decision.verdict === "UNSURE") {
        const agentId = agentObj?.id ?? "";
        this.pendingRequests.set(requestId, {
          agentId,
          action,
          agent,
        });

        const payload: ReviewRequest = {
          id: requestId,
          title: formatNotificationTitle("REVIEW", action.toolName),
          message: formatNotificationBody({
            target: action.commandString
              ? [action.commandString]
              : action.targetPath
                ? [action.targetPath]
                : action.rawArgs
                  ? [String(action.rawArgs)]
                  : action.toolName,
            reason: decision.reason,
            risk_level: decision.riskLevel,
            user_authorization: decision.userAuthorization,
            cascade: decision.cascade,
          }),
          priority: "high",
          tags: ["lock", "robot"],
          actions: [
            { id: "approve-once", label: "Approve", reply: "once" },
            { id: "deny", label: "Deny", reply: "reject" },
          ],
        };

        if (this.ntfyAdapter && typeof this.ntfyAdapter.publish === "function") {
          try {
            this.ntfyAdapter.publish(payload).catch((err: unknown) => {
              console.error("[AutoGate] Failed to publish async Ntfy notification:", err);
            });
          } catch (publishErr) {
            console.error("[AutoGate] Synchronous publish error:", publishErr);
          }
        }
        // does NOT call respondToPermission
      }
    } catch {
      // Must NOT crash on unhandled async rejections
    }
  };

  private onPermissionResolved = async (event: unknown): Promise<void> => {
    if (this.isDisposed) return;
    try {
      const ev = event as
        | (PaseoPermissionEvent & {
            resolution?: { behavior?: string };
            request?: { id?: string };
          })
        | undefined;
      const requestId = ev?.requestId ?? ev?.request?.id ?? ev?.id;
      if (!requestId) return;

      const reply = ev?.resolution?.behavior === "allow" ? "once" : "reject";
      this.engine.handlePermissionReplied({
        id: requestId,
        requestID: requestId,
        reply,
      });

      this.pendingRequests.delete(requestId);
    } catch {
      // Must NOT crash on unhandled async rejections
    }
  };

  private getAgent(
    agentId?: string,
    event?: unknown,
    context?: unknown,
  ): PaseoAgentInstance | undefined {
    const ev = event as PaseoPermissionEvent | undefined;
    const ctx = context as { paseo?: PaseoClient } | undefined;
    if (
      ev?.agent &&
      typeof (ev.agent as { respondToPermission?: unknown }).respondToPermission === "function"
    ) {
      return ev.agent;
    }
    if (ctx?.paseo?.agents?.ref && agentId) {
      try {
        const agent = ctx.paseo.agents.ref(agentId);
        if (agent) return agent;
      } catch {}
    }
    if (this.lastHookPaseo?.agents?.ref && agentId) {
      try {
        const agent = this.lastHookPaseo.agents.ref(agentId);
        if (agent) return agent;
      } catch {}
    }
    if (this.server?.paseo?.agents?.ref && agentId) {
      try {
        const agent = this.server.paseo.agents.ref(agentId);
        if (agent) return agent;
      } catch {}
    }
    if (this.options?.paseo?.agents?.ref && agentId) {
      try {
        const agent = this.options.paseo.agents.ref(agentId);
        if (agent) return agent;
      } catch {}
    }
    if (ev?.agent) {
      return ev.agent;
    }
    return undefined;
  }

  public async dispose(): Promise<void> {
    this.isDisposed = true;
    this.lastHookPaseo = undefined;
    if (this.unregisterRequested) {
      try {
        this.unregisterRequested();
      } catch {}
      this.unregisterRequested = undefined;
    } else if (typeof this.server?.off === "function") {
      try {
        this.server.off("agent.permission_requested", this.onPermissionRequested);
      } catch {}
    }

    if (this.unregisterResolved) {
      try {
        this.unregisterResolved();
      } catch {}
      this.unregisterResolved = undefined;
    } else if (typeof this.server?.off === "function") {
      try {
        this.server.off("agent.permission_resolved", this.onPermissionResolved);
      } catch {}
    }

    if (this.stopRemoteListen) {
      try {
        this.stopRemoteListen();
      } catch {}
      this.stopRemoteListen = undefined;
    }

    try {
      await this.engine.stop();
    } catch {}

    this.pendingRequests.clear();
  }
}

export default PaseoHarnessAdapter;
