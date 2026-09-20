import {
  AutoGateCoreEngine,
  NtfyAdapter,
  DirectApiEvaluator,
  loadConfig,
  type HarnessAdapter,
  type GateAction,
  type GateEvaluator,
  type NotifierAdapter,
  type ReviewResponse,
} from "@autogate/core";
import { extractActionFromRequest } from "./inspect.js";

export interface PendingPermissionRequest {
  agentId: string;
  action: GateAction;
  agent?: any;
}

export class PaseoHarnessAdapter implements HarnessAdapter {
  readonly name: string = "paseo";

  private server: any;
  private engine: AutoGateCoreEngine;
  private ntfyAdapter: NotifierAdapter;
  private pendingRequests: Map<string, PendingPermissionRequest> = new Map();
  private unregisterRequested?: () => void;
  private unregisterResolved?: () => void;
  private stopRemoteListen?: () => void;
  private isDisposed: boolean = false;

  constructor(server: any, options?: Record<string, unknown>) {
    this.server = server;

    const config = loadConfig(options);
    if (config.paseo?.notifyOnVerdict !== undefined) {
      config.notifyOnVerdict = config.paseo.notifyOnVerdict;
    }

    this.ntfyAdapter =
      (options?.adapter as NotifierAdapter) ??
      new NtfyAdapter({
        server: config.ntfyServer,
        topic: config.ntfyTopic,
        token: config.ntfyToken,
      });

    const evaluator =
      (options?.evaluator as GateEvaluator | undefined) ??
      new DirectApiEvaluator({
        apiKey:
          (options?.apiKey as string) ||
          (options?.evaluatorApiKey as string) ||
          (config as any).apiKey ||
          process.env.AUTOGATE_API_KEY ||
          process.env.GEMINI_API_KEY ||
          process.env.GOOGLE_API_KEY ||
          config.ntfyToken ||
          "test-key",
        baseUrl:
          (options?.baseUrl as string) ||
          (options?.evaluatorBaseUrl as string) ||
          (config as any).evaluatorBaseUrl ||
          process.env.AUTOGATE_EVALUATOR_BASE_URL ||
          process.env.AUTOGATE_INFERENCE_URL ||
          process.env.GEMINI_BASE_URL,
        model:
          (options?.classifierModel as string) ||
          config.classifierModel ||
          "gemini-3.5-flash-lite",
        timeoutMs: config.classifierTimeout,
      });
    this.engine =
      (options?.engine as AutoGateCoreEngine) ??
      new AutoGateCoreEngine({
        config,
        adapter: this.ntfyAdapter,
        evaluator,
        remoteReviewEnabled: true,
        workspaceRoot: options?.workspaceRoot as string | undefined,
      });

    if (this.server && typeof this.server.on === "function") {
      const unregReq = this.server.on(
        "agent.permission_requested",
        this.onPermissionRequested
      );
      if (typeof unregReq === "function") {
        this.unregisterRequested = unregReq;
      }

      const unregRes = this.server.on(
        "agent.permission_resolved",
        this.onPermissionResolved
      );
      if (typeof unregRes === "function") {
        this.unregisterResolved = unregRes;
      }
    }

    this.startListening().catch(() => {});
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
        const stop = await this.ntfyAdapter.listen(
          async (resp: ReviewResponse) => {
            await this.handleRemoteReply(resp);
          }
        );
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
    const requestId =
      resp.req_id ??
      (resp as any).id ??
      (resp as any).requestId ??
      (resp as any).requestID;
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

  private onPermissionRequested = async (
    event: any,
    context?: any
  ): Promise<void> => {
    if (this.isDisposed) return;
    try {
      const requestId = event?.request?.id ?? event?.requestId;
      if (!requestId) {
        return;
      }

      const action = extractActionFromRequest(event);
      const agent = this.getAgent(event?.agent?.id, event, context);
      const decision = await this.engine.evaluate(action);

      if (decision.verdict === "ALLOW") {
        if (agent && typeof agent.respondToPermission === "function") {
          try {
            await agent.respondToPermission({
              requestId,
              response: { behavior: "allow" },
            });
          } catch {
            // Wrap agent.respondToPermission() calls in try/catch to handle cases where
            // the agent was deleted or request already answered.
          }
        }
      } else if (decision.verdict === "BLOCK") {
        if (agent && typeof agent.respondToPermission === "function") {
          try {
            await agent.respondToPermission({
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
        const agentId = event?.agent?.id ?? "";
        this.pendingRequests.set(requestId, {
          agentId,
          action,
          agent,
        });
        // does NOT call respondToPermission
      }
    } catch {
      // Must NOT crash on unhandled async rejections
    }
  };

  private onPermissionResolved = async (event: any): Promise<void> => {
    if (this.isDisposed) return;
    try {
      const requestId = event?.requestId ?? event?.request?.id ?? event?.id;
      if (!requestId) return;

      const reply = event?.resolution?.behavior === "allow" ? "once" : "reject";
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

  private getAgent(agentId?: string, event?: any, context?: any): any {
    if (event?.agent && typeof event.agent.respondToPermission === "function") {
      return event.agent;
    }
    if (context?.paseo?.agents?.ref && agentId) {
      try {
        const agent = context.paseo.agents.ref(agentId);
        if (agent) return agent;
      } catch {}
    }
    if (this.server?.paseo?.agents?.ref && agentId) {
      try {
        const agent = this.server.paseo.agents.ref(agentId);
        if (agent) return agent;
      } catch {}
    }
    if (this.server?.agents?.ref && agentId) {
      try {
        const agent = this.server.agents.ref(agentId);
        if (agent) return agent;
      } catch {}
    }
    if (typeof this.server?.getAgent === "function" && agentId) {
      try {
        const agent = this.server.getAgent(agentId);
        if (agent) return agent;
      } catch {}
    }
    if (event?.agent) {
      return event.agent;
    }
    return null;
  }

  public async dispose(): Promise<void> {
    this.isDisposed = true;
    if (this.unregisterRequested) {
      try {
        this.unregisterRequested();
      } catch {}
      this.unregisterRequested = undefined;
    } else if (typeof this.server?.off === "function") {
      try {
        this.server.off(
          "agent.permission_requested",
          this.onPermissionRequested
        );
      } catch {}
    }

    if (this.unregisterResolved) {
      try {
        this.unregisterResolved();
      } catch {}
      this.unregisterResolved = undefined;
    } else if (typeof this.server?.off === "function") {
      try {
        this.server.off(
          "agent.permission_resolved",
          this.onPermissionResolved
        );
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
