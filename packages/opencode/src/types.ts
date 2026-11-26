import type {
  AutoGateConfig,
  AutoGateEvalStore,
  ClassifyInput,
  ClassifierVerdict,
  EvalSessionCleanupMode,
  PermissionEventData,
  RiskLevel,
  S2SessionStatus,
  UserAuthorization,
} from "@autogate/core";

export interface OpenCodeSessionInfo {
  id?: string;
  parentID?: string;
  title?: string;
  agent?: string;
  model?: {
    id?: string;
    providerID?: string;
    variant?: string;
  };
  cost?: number;
  tokens?: {
    input?: number;
    output?: number;
    reasoning?: number;
    cache?: {
      read?: number;
      write?: number;
    };
  };
  outcome?: string;
  location?: {
    directory?: string;
    workspaceID?: string;
  };
  time?: {
    created?: number;
    updated?: number;
    idle?: number;
    viewed?: number;
    archived?: number;
  };
  [key: string]: unknown;
}

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
      data?: OpenCodeSessionInfo;
      id?: string;
      parentID?: string;
      title?: string;
      agent?: string;
      model?: OpenCodeSessionInfo["model"];
      cost?: number;
      tokens?: OpenCodeSessionInfo["tokens"];
      outcome?: string;
      location?: OpenCodeSessionInfo["location"];
      time?: OpenCodeSessionInfo["time"];
      [key: string]: unknown;
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

export interface S2SessionCapturedEvent {
  actionId?: string;
  targetSessionId?: string;
  s2SessionId: string;
  status: S2SessionStatus;
  timestamp: number;
  toolName: string;
  commandString: string;
  targetPath?: string;
  workspaceRoot: string;
  userPrompt: string;
  verdict: ClassifierVerdict;
  riskLevel?: RiskLevel;
  userAuthorization?: UserAuthorization;
  reasoning?: string;
  thinking?: string;
  durationMs: number;
  modelId?: string;
  modelProvider?: string;
  promptTokens?: number;
  outputTokens?: number;
  reasoningTokens?: number;
  cost?: number;
  attempts?: number;
  error?: string;
}

export interface OpenCodeClassifyInput extends ClassifyInput {
  client?: OpenCodeSessionClient;
  config?: AutoGateConfig;
  signal?: AbortSignal;
  serverUrl?: string;
  configDir?: string;
  evalDbFile?: string;
  getEvalDbFile?: () => string | undefined;
  evalSessionCleanup?: EvalSessionCleanupMode;
  getEvalSessionCleanup?: () => EvalSessionCleanupMode;
  evalStore?: AutoGateEvalStore;
  getEvalStore?: () => AutoGateEvalStore | undefined;
  targetSessionId?: string;
  actionId?: string;
  toolName?: string;
  commandString?: string;
  targetPath?: string;
  skipEvaluationRecord?: boolean;
  onS2SessionRecorded?: (event: S2SessionCapturedEvent) => void;
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
