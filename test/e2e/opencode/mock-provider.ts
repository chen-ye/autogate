export interface MockResponse {
  text?: string;
  content?: Array<Record<string, unknown>>;
  toolCall?: {
    name: string;
    input: Record<string, unknown> | string;
  };
  thinking?: string;
  reasoningTokens?: number;
  delayMs?: number;
  status?: number;
}

export interface RecordedRequest {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: unknown;
  timestamp: number;
}

export class MockInferenceProvider {
  private server: ReturnType<typeof Bun.serve>;
  private responseQueue: MockResponse[] = [];
  private requests: RecordedRequest[] = [];

  constructor(port = 0) {
    this.server = Bun.serve({
      hostname: "127.0.0.1",
      port,
      fetch: async (req) => {
        return this.handleRequest(req);
      },
    });
  }

  get port(): number {
    return this.server.port ?? 0;
  }

  get url(): string {
    return `http://127.0.0.1:${this.server.port}`;
  }

  get baseUrl(): string {
    return this.url;
  }

  public enqueueText(text: string): void {
    this.responseQueue.push({ text });
  }

  public enqueueToolCall(
    name: string,
    input: Record<string, unknown> | string,
    text?: string,
  ): void {
    this.responseQueue.push({ toolCall: { name, input }, text });
  }

  public enqueueResponse(response: MockResponse): void {
    this.responseQueue.push(response);
  }

  public pushResponse(response: MockResponse): void {
    this.responseQueue.push(response);
  }

  public getRecordedRequests(): RecordedRequest[] {
    return this.requests;
  }

  public clear(): void {
    this.requests = [];
    this.responseQueue = [];
  }

  public async close(): Promise<void> {
    await this.server.stop(true);
  }

  public async handleRequest(req: Request, preParsedBody?: unknown): Promise<Response> {
    const urlObj = new URL(req.url);
    const path = urlObj.pathname;
    const method = req.method;

    const headers: Record<string, string> = {};
    req.headers.forEach((val, key) => {
      headers[key] = val;
    });

    let body: unknown = preParsedBody ?? null;
    if (body === null && req.body) {
      try {
        const text = await req.text();
        if (text) {
          try {
            body = JSON.parse(text);
          } catch {
            body = text;
          }
        }
      } catch {}
    }
    this.requests.push({
      url: req.url,
      method,
      headers,
      body,
      timestamp: Date.now(),
    });
    if (method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
          "Access-Control-Allow-Headers": "*",
        },
      });
    }

    if (path === "/v1/models" || path === "/models") {
      return new Response(
        JSON.stringify({
          object: "list",
          data: [
            { id: "gpt-4o", object: "model" },
            { id: "gemini-2.5-flash-lite", object: "model" },
            { id: "gemini-3.5-flash-lite", object: "model" },
            { id: "mock-model", object: "model" },
          ],
        }),
        {
          status: 200,
          headers: { "Content-Type": "application/json" },
        },
      );
    }

    if (this.responseQueue.length === 0) {
      return new Response(JSON.stringify({ error: "No mock responses queued" }), {
        status: 500,
        headers: { "Content-Type": "application/json" },
      });
    }

    const mockRes = this.responseQueue.shift()!;
    if (mockRes.delayMs && mockRes.delayMs > 0) {
      await Bun.sleep(mockRes.delayMs);
    }
    const status = mockRes.status ?? 200;

    if (path.includes("generateContent")) {
      const isGeminiStreaming =
        path.includes("streamGenerateContent") ||
        (typeof body === "object" &&
          body !== null &&
          (body as Record<string, unknown>).stream === true);
      const parts: Array<Record<string, unknown>> = [];
      const requestedTools = (body as any)?.tools ?? (body as any)?.functionDeclarations;
      const hasClassifyTool =
        Array.isArray(requestedTools) &&
        requestedTools.some(
          (t: any) =>
            t?.name === "classify_result" ||
            t?.function?.name === "classify_result",
        );
      let asToolCall: { name: string; args: any } | null = null;
      if (mockRes.toolCall) {
        asToolCall = { name: mockRes.toolCall.name, args: mockRes.toolCall.input };
      } else if (
        hasClassifyTool &&
        typeof mockRes.text === "string" &&
        mockRes.text.includes('"verdict"')
      ) {
        try {
          const parsed = JSON.parse(mockRes.text);
          if (parsed && typeof parsed.verdict === "string") {
            asToolCall = { name: "classify_result", args: parsed };
          }
        } catch {}
      }

      if (asToolCall) {
        parts.push({
          functionCall: {
            name: asToolCall.name,
            args: asToolCall.args,
          },
        });
      } else {
        parts.push({
          text: mockRes.text ?? "",
        });
      }

      const geminiResp = {
        candidates: [
          {
            content: {
              parts,
              role: "model",
            },
            finishReason: "STOP",
            index: 0,
          },
        ],
        usageMetadata: {
          promptTokenCount: 10,
          candidatesTokenCount: 10,
          totalTokenCount: 20,
        },
      };

      if (isGeminiStreaming) {
        const stream = new ReadableStream({
          start(controller) {
            const encoder = new TextEncoder();
            controller.enqueue(encoder.encode(`data: ${JSON.stringify(geminiResp)}\n\n`));
            controller.close();
          },
        });
        return new Response(stream, {
          status,
          headers: {
            "Content-Type": "text/event-stream",
            "Cache-Control": "no-cache",
            Connection: "keep-alive",
          },
        });
      } else {
        return new Response(JSON.stringify(geminiResp), {
          status,
          headers: { "Content-Type": "application/json" },
        });
      }
    }

    const isStreaming =
      (typeof body === "object" &&
        body !== null &&
        (body as Record<string, unknown>).stream === true) ||
      path.includes("stream");
    const message: Record<string, unknown> = { role: "assistant" };
    const requestedToolsOpenAI = (body as any)?.tools;
    const hasClassifyToolOpenAI =
      Array.isArray(requestedToolsOpenAI) &&
      requestedToolsOpenAI.some(
        (t: any) =>
          t?.name === "classify_result" ||
          t?.function?.name === "classify_result",
      );
    let asToolCall: { name: string; args: any } | null = null;
    if (mockRes.toolCall) {
      asToolCall = { name: mockRes.toolCall.name, args: mockRes.toolCall.input };
    } else if (
      hasClassifyToolOpenAI &&
      typeof mockRes.text === "string" &&
      mockRes.text.includes('"verdict"')
    ) {
      try {
        const parsed = JSON.parse(mockRes.text);
        if (parsed && typeof parsed.verdict === "string") {
          asToolCall = { name: "classify_result", args: parsed };
        }
      } catch {}
    }

    if (mockRes.content) {
      message.content = mockRes.content;
    } else if (asToolCall) {
      message.content = mockRes.thinking
        ? [{ type: "thinking", thinking: mockRes.thinking }]
        : null;
    } else {
      message.content = mockRes.thinking
        ? [
            { type: "thinking", thinking: mockRes.thinking },
            { type: "text", text: mockRes.text ?? "" },
          ]
        : (mockRes.text ?? "");
    }
    if (asToolCall) {
      message.tool_calls = [
        {
          id: "call_1",
          type: "function",
          function: {
            name: asToolCall.name,
            arguments:
              typeof asToolCall.args === "string"
                ? asToolCall.args
                : JSON.stringify(asToolCall.args),
          },
        },
      ];
    }
    if (mockRes.thinking) {
      message.reasoning_content = mockRes.thinking;
      message.reasoning = mockRes.thinking;
      message.reasoningContent = mockRes.thinking;
    }

    if (isStreaming) {
      const chunkObj = {
        id: "chatcmpl-" + Math.random().toString(36).slice(2),
        object: "chat.completion.chunk",
        created: Math.floor(Date.now() / 1000),
        model: (body as any)?.model ?? "gpt-4o",
        choices: [
          {
            index: 0,
            delta: asToolCall
              ? {
                  role: "assistant",
                  tool_calls: [
                    {
                      index: 0,
                      id: "call_1",
                      type: "function",
                      function: {
                        name: asToolCall.name,
                        arguments:
                          typeof asToolCall.args === "string"
                            ? asToolCall.args
                            : JSON.stringify(asToolCall.args),
                      },
                    },
                  ],
                }
              : { role: "assistant", content: mockRes.text ?? "" },
            finish_reason: null,
          },
        ],
      };
      const doneChunk = {
        id: chunkObj.id,
        object: "chat.completion.chunk",
        created: chunkObj.created,
        model: chunkObj.model,
        choices: [
          {
            index: 0,
            delta: {},
            finish_reason: asToolCall ? "tool_calls" : "stop",
          },
        ],
      };
      const stream = new ReadableStream({
        start(controller) {
          const encoder = new TextEncoder();
          controller.enqueue(encoder.encode(`data: ${JSON.stringify(chunkObj)}\n\n`));
          controller.enqueue(encoder.encode(`data: ${JSON.stringify(doneChunk)}\n\n`));
          controller.enqueue(encoder.encode("data: [DONE]\n\n"));
          controller.close();
        },
      });
      return new Response(stream, {
        status,
        headers: {
          "Content-Type": "text/event-stream",
          "Cache-Control": "no-cache",
          Connection: "keep-alive",
        },
      });
    } else {
      const completionObj = {
        id: "chatcmpl-" + Math.random().toString(36).slice(2),
        object: "chat.completion",
        created: Math.floor(Date.now() / 1000),
        model: (body as any)?.model ?? "gpt-4o",
        choices: [
          {
            index: 0,
            message,
            finish_reason: mockRes.toolCall ? "tool_calls" : "stop",
          },
        ],
        usage: {
          prompt_tokens: 10,
          completion_tokens: 10,
          total_tokens: 20,
          ...(typeof mockRes.reasoningTokens === "number"
            ? {
                reasoning_tokens: mockRes.reasoningTokens,
                completion_tokens_details: { reasoning_tokens: mockRes.reasoningTokens },
              }
            : {}),
        },
        ...(typeof mockRes.reasoningTokens === "number"
          ? { reasoningTokens: mockRes.reasoningTokens }
          : {}),
      };
      return new Response(JSON.stringify(completionObj), {
        status,
        headers: { "Content-Type": "application/json" },
      });
    }
  }

  public getNextResponse(): MockResponse | undefined {
    return this.responseQueue.shift();
  }

  getRequests(): RecordedRequest[] {
    return this.requests;
  }

  clearRequests(): void {
    this.requests = [];
  }

  async stop(): Promise<void> {
    await this.server.stop(true);
  }
}
