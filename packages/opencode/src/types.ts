import type { ClassifyInput } from "@autogate/core";

export interface OpenCodeSessionClient {
  session: {
    create(options: {
      title?: string;
      agent?: string;
      location?: { directory?: string };
      body?: Record<string, unknown>;
    }): Promise<{ data?: { id?: string }; id?: string }>;
    prompt(options: Record<string, unknown>): Promise<any>;
    get(options: { path: { id?: string; sessionID?: string } }): Promise<any>;
    messages(options: {
      path: { id?: string; sessionID?: string };
      query?: { limit?: number };
    }): Promise<any>;
    update?(options: Record<string, unknown>): Promise<any>;
    delete?(options: Record<string, unknown>): Promise<any>;
    abort?(options: Record<string, unknown>): Promise<any>;
  };
  permission?: {
    reply(options: Record<string, unknown>): Promise<any>;
    list?(options: Record<string, unknown>): Promise<any>;
  };
  generate?: {
    text?(options: Record<string, unknown>): Promise<any>;
  };
}

export interface OpenCodeClassifyInput extends ClassifyInput {
  client?: OpenCodeSessionClient | any;
}
