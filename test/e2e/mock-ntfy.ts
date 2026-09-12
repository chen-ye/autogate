export interface PublishedMessage {
  topic: string;
  title?: string;
  priority?: string;
  tags?: string[];
  actions?: string[];
  body: string;
  headers: Record<string, string>;
  timestamp: number;
}

export interface MockNtfyServerOptions {
  token?: string;
}

export class MockNtfyServer {
  private server: ReturnType<typeof Bun.serve>;
  private published: PublishedMessage[] = [];
  private sseClients = new Set<ReadableStreamDefaultController>();
  private token?: string;

  constructor(options?: MockNtfyServerOptions) {
    this.token = options?.token;
    this.server = Bun.serve({
      port: 0,
      fetch: (req) => this.handleRequest(req),
    });
  }

  get url(): string {
    return `http://localhost:${this.server.port}`;
  }

  get port(): number {
    return this.server.port;
  }

  getPublished(): PublishedMessage[] {
    return [...this.published];
  }

  clearPublished(): void {
    this.published = [];
  }

  async stop(): Promise<void> {
    for (const client of this.sseClients) {
      try {
        client.close();
      } catch {}
    }
    this.sseClients.clear();
    await this.server.stop(true);
  }

  simulateReply(req_id: string, reply: string): void {
    const payload = JSON.stringify({ req_id, reply });
    const sseData = `data: ${JSON.stringify({ event: "message", message: payload })}\n\n`;
    for (const client of this.sseClients) {
      try {
        client.enqueue(new TextEncoder().encode(sseData));
      } catch {}
    }
  }

  private async handleRequest(req: Request): Promise<Response> {
    const url = new URL(req.url);
    const pathname = url.pathname;

    if (this.token) {
      const auth = req.headers.get("Authorization");
      if (auth !== `Bearer ${this.token}`) {
        return new Response("Unauthorized", { status: 401 });
      }
    }

    if (pathname.endsWith("/json") || pathname.endsWith("/sse") || req.headers.get("Accept")?.includes("text/event-stream")) {
      const stream = new ReadableStream({
        start: (controller) => {
          this.sseClients.add(controller);
          controller.enqueue(new TextEncoder().encode(": connected\n\n"));
        },
        cancel: (controller) => {
          this.sseClients.delete(controller as any);
        },
      });

      return new Response(stream, {
        headers: {
          "Content-Type": "text/event-stream",
          "Cache-Control": "no-cache",
          "Connection": "keep-alive",
        },
      });
    }

    if (req.method === "POST" || req.method === "PUT") {
      const body = await req.text();
      const headers: Record<string, string> = {};
      req.headers.forEach((value, key) => {
        headers[key] = value;
      });

      const title = req.headers.get("Title") || undefined;
      const priority = req.headers.get("Priority") || undefined;
      const tagsHeader = req.headers.get("Tags");
      const tags = tagsHeader ? tagsHeader.split(",").map(t => t.trim()).filter(Boolean) : undefined;
      const actionsHeader = req.headers.get("Actions");
      const actions = actionsHeader ? actionsHeader.split(";").map(a => a.trim()).filter(Boolean) : undefined;
      
      const topic = pathname.replace(/^\//, "").replace(/\/json$/, "").replace(/\/sse$/, "");

      if (pathname.includes("-response")) {
        try {
          const json = JSON.parse(body);
          if (json.req_id && json.reply) {
            this.simulateReply(json.req_id, json.reply);
          }
        } catch {}
      }

      this.published.push({
        topic,
        title,
        priority,
        tags,
        actions,
        body,
        headers,
        timestamp: Date.now(),
      });

      return new Response(JSON.stringify({ success: true, id: req.headers.get("X-Sequence-ID") || crypto.randomUUID() }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }

    return new Response(JSON.stringify({ topic: pathname, messages: this.published }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  }
}
