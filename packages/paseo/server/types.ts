export interface PaseoTimelineBadge {
  text: string;
  variant?: string;
}

export interface PaseoTimelineItem {
  id?: string;
  type?: string;
  kind?: string;
  version?: number;
  title?: string;
  content?: string;
  badge?: PaseoTimelineBadge;
  data?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
  timestamp?: number;
  [key: string]: unknown;
}

export interface PaseoAgentInstance {
  id?: string;
  agentId?: string;
  timeline?: {
    append?(item: PaseoTimelineItem): Promise<unknown>;
  };
  send?(message: unknown): Promise<unknown>;
  waitFinish?(options?: {
    timeoutMs?: number;
  }): Promise<{ text?: string; content?: unknown; [key: string]: unknown }>;
  waitForFinish?(options?: {
    timeoutMs?: number;
  }): Promise<{ text?: string; content?: unknown; [key: string]: unknown }>;
  [key: string]: unknown;
}

export interface PaseoClient {
  agents?: {
    create?(options: Record<string, unknown>): Promise<PaseoAgentInstance>;
    ref?(agentId: string): PaseoAgentInstance | undefined;
    [key: string]: unknown;
  };
  metadataGeneration?: { providers?: unknown[] };
  daemonConfig?: { metadataGeneration?: { providers?: unknown[] } };
  config?: {
    metadataGeneration?: { providers?: unknown[] };
    get?(): Promise<{ config?: { metadataGeneration?: { providers?: unknown[] } } }>;
  };
  [key: string]: unknown;
}

export interface PaseoServer {
  on?(event: string, listener: (event: unknown, context?: unknown) => Promise<void> | void): void;
  off?(event: string, listener: unknown): void;
  respondToPermission?(data: {
    id?: string;
    requestId?: string;
    actionId?: string;
    decision: "allow" | "deny" | "escalate";
    feedback?: string;
    reason?: string;
    options?: Record<string, unknown>;
  }): Promise<unknown>;
  paseo?: PaseoClient;
  [key: string]: unknown;
}

export interface PaseoPermissionEvent {
  id?: string;
  requestId?: string;
  agentId?: string;
  agent?: PaseoAgentInstance;
  request?: Record<string, unknown>;
  userPrompt?: string;
  [key: string]: unknown;
}

export interface PaseoPluginOptions {
  paseo?: PaseoClient;
  client?: PaseoClient;
  apiKey?: string;
  evaluatorBaseUrl?: string;
  [key: string]: unknown;
}
