import type { AutoGateConfig, ClassifyInput, PermissionEventData } from "@autogate/core";

export interface OpenCodeSessionClient {
  session: {
    create(options: {
      title?: string;
      agent?: string;
      location?: { directory?: string };
      directory?: string;
      body?: Record<string, unknown>;
    }): Promise<{ data?: { id?: string }; id?: string }>;
    prompt(options: Record<string, unknown>): Promise<{
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
      path?: { id?: string; sessionID?: string };
      sessionID?: string;
      query?: { limit?: number };
    }): Promise<{ data?: unknown[] } | unknown[]>;
    update?(options: Record<string, unknown>): Promise<unknown>;
    delete?(options: Record<string, unknown>): Promise<unknown>;
    abort?(options: { path: { id?: string } }): Promise<unknown>;
    wait?(options: { path: { id?: string; sessionID?: string } }): Promise<unknown>;
  };
  app?: {
    log(options: { body: { service: string; level: string; message: string } }): Promise<unknown>;
    agents?(): Promise<{ data?: { name?: string }[] }>;
  };
  generate?: {
    text?(options: Record<string, unknown>): Promise<{
      text?: string;
      content?: string;
      reasoning?: string;
      thinking?: string;
      metadata?: unknown;
    }>;
  };
  ctx?: {
    generate?: {
      text?(options: Record<string, unknown>): Promise<{
        text?: string;
        content?: string;
        reasoning?: string;
        thinking?: string;
        metadata?: unknown;
      }>;
    };
  };
  permission?: {
    reply(options: {
      path?: { requestID?: string; id?: string };
      body: {
        reply?: string;
        message?: string;
        decision?: string;
        response?: string;
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

export interface OpenCodeClassifyInput extends ClassifyInput {
  client?: OpenCodeSessionClient;
  config?: AutoGateConfig;
}

export interface OpenCodeEvent {
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

export interface OpenCodePluginInput {
  client?: OpenCodeSessionClient;
  directory?: string;
  worktree?: string;
  configDir?: string;
  serverUrl?: string;
  options?: Record<string, unknown>;
  permission?: {
    reply(options: {
      path?: { requestID?: string; id?: string };
      body: {
        reply?: string;
        message?: string;
        decision?: string;
        response?: string;
      };
      query?: { directory?: string };
    }): Promise<{ error?: unknown; response?: { ok?: boolean } }>;
  };
  event?: {
    subscribe?(options?: {
      directory?: string;
      signal?: AbortSignal;
    }): Promise<AsyncIterable<OpenCodeEvent>>;
  };
  tool?: {
    transform?(fn: (editor: { add(def: unknown): void }) => Promise<void> | void): Promise<void>;
  };
  session?: {
    interrupt?(sessionID: string): Promise<unknown>;
  };
  [key: string]: unknown;
}
