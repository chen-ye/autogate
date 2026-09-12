import { Server } from "bun"

export interface PublishedMessage {
  topic: string
  title?: string
  priority?: string
  tags?: string[]
  actions?: string
  body: string
  headers: Record<string, string>
  timestamp: number
}

export class MockNtfyServer {
  private server: ReturnType<typeof Bun.serve>
  private published: PublishedMessage[] = []
  private clients = new Set<ReadableStreamDefaultController>()
  private token?: string

  constructor(portOrOpts: number | { port?: number; token?: string } = 0, token?: string) {
    let port = 0
    if (typeof portOrOpts === "object") {
      port = portOrOpts.port ?? 0
      this.token = portOrOpts.token
    } else {
      port = portOrOpts
      this.token = token
    }
    this.server = Bun.serve({
      hostname: "127.0.0.1",
      port,
      fetch: async (req) => {
        if (this.token) {
          const auth = req.headers.get("authorization")
          if (!auth || auth !== `Bearer ${this.token}`) {
            return new Response(JSON.stringify({ error: "Unauthorized" }), {
              status: 401,
              headers: { "Content-Type": "application/json" },
            })
          }
        }
        const url = new URL(req.url)
        const path = url.pathname

        if (req.method === "POST") {
          const topic = path.replace(/^\//, "")
          const body = await req.text()
          const headers: Record<string, string> = {}
          req.headers.forEach((val, key) => {
            headers[key] = val
          })

          const msg: PublishedMessage = {
            topic,
            title: headers["title"],
            priority: headers["priority"],
            tags: headers["tags"] ? headers["tags"].split(",") : undefined,
            actions: headers["actions"],
            body,
            headers,
            timestamp: Date.now(),
          }
          this.published.push(msg)

          if (topic.endsWith("-response") || topic.includes("response")) {
            this.broadcast(body)
          }

          return new Response(JSON.stringify({ success: true }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          })
        }

        if (req.method === "GET") {
          if (path.endsWith("/json") || path.includes("stream") || path.includes("json")) {
            const stream = new ReadableStream({
              start: (controller) => {
                this.clients.add(controller)
                controller.enqueue(new TextEncoder().encode(": connected\n\n"))
              },
              cancel: (controller) => {
                this.clients.delete(controller)
              },
            })

            return new Response(stream, {
              status: 200,
              headers: {
                "Content-Type": "text/event-stream",
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
              },
            })
          }
        }

        return new Response("Not Found", { status: 404 })
      },
    })
  }

  get url(): string {
    return `http://127.0.0.1:${this.server.port}`
  }

  get port(): number {
    return this.server.port
  }

  get token(): string | undefined {
    return this.token
  }

  getPublished(topic?: string): PublishedMessage[] {
    if (!topic) return this.published
    return this.published.filter((m) => m.topic === topic || m.topic === `${topic}-response`)
  }

  clearPublished(): void {
    this.published = []
  }

  simulateReply(req_id: string, reply: "once" | "always" | "reject", topic = "opencode-auto-gate"): void {
    this.triggerAction(req_id, reply, topic)
  }

  triggerAction(req_id: string, reply: "once" | "always" | "reject", topic = "opencode-auto-gate"): void {
    const data = JSON.stringify({ req_id, reply })
    this.broadcast(data)
  }

  private broadcast(data: string): void {
    const message = `data: ${JSON.stringify({ event: "message", message: data })}\n\n`
    const encoded = new TextEncoder().encode(message)
    for (const client of this.clients) {
      try {
        client.enqueue(encoded)
      } catch {
        this.clients.delete(client)
      }
    }
  }

  async stop(): Promise<void> {
    for (const client of this.clients) {
      try {
        client.close()
      } catch {}
    }
    this.clients.clear()
    await this.server.stop(true)
  }
}
