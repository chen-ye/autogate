import type { AutoGateConfig, ClassifyInput, PermissionEventData } from "@autogate/core";

export interface OpenCodeV1SessionClient {
  session: {
    create(options: {
      body?: {
        title?: string;
        directory?: string;
        agent?: string;
      };
      title?: string;
      directory?: string;
      agent?: string;
    }): Promise<{ data?: { id?: string }; id?: string }>;
    prompt(options: {
      path: { id?: string };
      agent?: string;
      body: {
        agent?: string;
        model?: {
          providerID: string;
          modelID: string;
        };
        tools?: Record<string, boolean>;
        system?: string;
        parts: Array<{ type: "text"; text: string }>;
      };
    }): Promise<{
      data?: { parts?: unknown[]; reasoning?: string; thinking?: string };
      parts?: unknown[];
      reasoning?: string;
      thinking?: string;
    }>;
    get(options: { path: { id?: string; sessionID?: string } }): Promise<{
      data?: { id?: string; parentID?: string; title?: string };
      id?: string;
      parentID?: string;
      title?: string;
    }>;
    messages(options: {
      path: { id?: string; sessionID?: string };
      query?: { limit?: number };
    }): Promise<{ data?: unknown[] } | unknown[]>;
    update?(options: {
      path: { id?: string; sessionID?: string };
      body: {
        title?: string;
        time?: { archived?: number };
      };
    }): Promise<unknown>;
    delete?(options: { path: { id?: string } }): Promise<unknown>;
    abort?(options: { path: { id?: string } }): Promise<unknown>;
  };
  app?: {
    log(options: { body: { service: string; level: string; message: string } }): Promise<unknown>;
    agents?(): Promise<{ data?: { name?: string }[] }>;
  };
  permission?: {
    reply(options: {
      path: { requestID: string; id?: string };
      body: {
        reply: "once" | "always" | "reject";
        message?: string;
      };
      query?: { directory?: string };
    }): Promise<{ error?: unknown; response?: { ok?: boolean } }>;
    list?(options: Record<string, unknown>): Promise<unknown>;
  };
  postSessionIdPermissionsPermissionId?(options: {
    path: { id: string; permissionID: string };
    body: { response: string };
    query?: { directory?: string };
  }): Promise<{ error?: unknown; response?: { ok?: boolean } }>;
  serverUrl?: string;
}

export interface OpenCodeV1ClassifyInput extends ClassifyInput {
  client?: OpenCodeV1SessionClient;
  config?: AutoGateConfig;
  signal?: AbortSignal;
  getEvalStore?: () => import("@autogate/core").AutoGateEvalStore | undefined;
}

export interface OpenCodeV1Event {
  type?: string;
  location?: { directory?: string };
  properties?: Record<string, unknown>;
  data?: {
    directory?: string;
    sessionID?: string;
    status?: string;
    request?: PermissionEventData;
    [key: string]: unknown;
  };
  [key: string]: unknown;
}
