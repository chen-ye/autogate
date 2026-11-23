import type { AutoGateConfig, ClassifyInput, PermissionEventData } from "@autogate/core";

export interface OpenCodeSessionClient {
  session: {
    create(options: {
      title?: string;
      agent?: string;
      location?: { directory?: string };
    }): Promise<{ data?: { id?: string }; id?: string }>;
    prompt(options: { sessionID: string; text: string }): Promise<{
      data?: { parts?: unknown[]; reasoning?: string; thinking?: string };
      parts?: unknown[];
      reasoning?: string;
      thinking?: string;
    }>;
    get(options: { sessionID: string }): Promise<{
      data?: {
        id?: string;
        parentID?: string;
        title?: string;
        time?: { created?: number; updated?: number; archived?: number };
      };
      id?: string;
      parentID?: string;
      title?: string;
      time?: { created?: number; updated?: number; archived?: number };
    }>;
    list?(options?: {
      archived?: boolean;
      directory?: string;
      limit?: number;
      [key: string]: unknown;
    }): Promise<unknown>;
    context?(options: { sessionID: string }): Promise<{ data?: unknown[] } | unknown[]>;
    update?(options: { sessionID: string; title?: string; archived?: boolean }): Promise<unknown>;
    remove?(options: { sessionID: string }): Promise<unknown>;
    interrupt?(options: { sessionID: string; resume?: boolean }): Promise<unknown>;
    wait?(options: { sessionID: string }): Promise<unknown>;
  };
  agent?: {
    list?(): Promise<
      { data?: { id?: string; name?: string }[] } | { id?: string; name?: string }[]
    >;
    transform?(
      fn: (editor: {
        update: (id: string, fn: (draft: Record<string, unknown>) => void) => void;
      }) => Promise<void> | void,
    ): Promise<void>;
  };
  permission?: {
    reply(options: {
      sessionID: string;
      requestID: string;
      decision: "once" | "always" | "reject";
      message?: string;
    }): Promise<unknown>;
    list?(options?: Record<string, unknown>): Promise<unknown>;
  };
  serverUrl?: string;
}

export interface OpenCodeClassifyInput extends ClassifyInput {
  client?: OpenCodeSessionClient;
  config?: AutoGateConfig;
  signal?: AbortSignal;
  serverUrl?: string;
  configDir?: string;
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
  location?: unknown;
  configDir?: string;
  serverUrl?: string;
  options?: Record<string, unknown>;
  permission?: {
    reply(options: {
      sessionID: string;
      requestID: string;
      decision: "once" | "always" | "reject";
      message?: string;
    }): Promise<unknown>;
  };
  event?: {
    subscribe?(options?: {
      signal?: AbortSignal;
    }): Promise<AsyncIterable<OpenCodeEvent>> | AsyncIterable<OpenCodeEvent>;
  };
  agent?: {
    list?(): Promise<
      { data?: { id?: string; name?: string }[] } | { id?: string; name?: string }[]
    >;
    transform?(
      fn: (editor: {
        update: (id: string, fn: (draft: Record<string, unknown>) => void) => void;
      }) => Promise<void> | void,
    ): Promise<void>;
  };
  tool?: {
    transform?(fn: (editor: { add(def: unknown): void }) => Promise<void> | void): Promise<void>;
  };
  session?: OpenCodeSessionClient["session"];
  [key: string]: unknown;
}
