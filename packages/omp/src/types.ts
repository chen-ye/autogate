export interface OmpLogger {
  debug?(msg: string, data?: unknown): void;
  info?(msg: string, data?: unknown): void;
  warn?(msg: string, data?: unknown): void;
  error?(msg: string, data?: unknown): void;
}

export interface OmpEvaluatorOptions {
  model?: unknown;
  fallbackModel?: unknown;
  apiKey?: string;
  fallbackApiKey?: string;
  sessionId?: string;
  fallbackSessionId?: string;
  classifierTimeout?: number;
  evalDbFile?: string;
  getEvalStore?: () => import("@autogate/core").AutoGateEvalStore | undefined;
  suppressEvalLog?: boolean;
  getCtx?: () => unknown;
  logger?: OmpLogger;
}

export interface OmpContext {
  model?: unknown;
  session?: { id?: string };
  sessionId?: string;
  sessionManager?: { getSessionId?(): string };
  auth?: { getApiKey?(provider?: string): Promise<string | undefined> | string | undefined };
  [key: string]: unknown;
}
