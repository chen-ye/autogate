import type { RemoteAdapter, NotificationPayload, ApprovalResponse } from "../types";
import { formatStatusBody } from "../formatters";

export interface NtfyAdapterOptions {
  server?: string;
  topic?: string;
  token?: string;
}

export class NtfyAdapter implements RemoteAdapter {
  name = "ntfy";
  server: string;
  topic: string;
  token?: string;

  constructor(options?: NtfyAdapterOptions) {
    this.server = (options?.server || "https://ntfy.sh").replace(/\/$/, "");
    this.topic =
      options?.topic ||
      process.env.AUTOGATE_NTFY_TOPIC ||
      process.env.NTFY_TOPIC ||
      process.env.OPENCODE_NTFY_TOPIC ||
      "autogate";
    this.token = options?.token;
  }

  async publish(payload: NotificationPayload, signal?: AbortSignal): Promise<void> {
    const url = `${this.server}/${this.topic}`;
    console.log("[NTFY ADAPTER] server:", this.server, "topic:", this.topic, "url:", url);
    const headers: Record<string, string> = {
      Title: payload.title.replace(/[^\x20-\x7E]/g, "").trim() || "Notification",
      Priority: payload.priority ?? "urgent",
      "Content-Type": "text/plain; charset=utf-8",
    };

    if (this.token) {
      headers["Authorization"] = `Bearer ${this.token}`;
    }

    if (payload.tags && payload.tags.length > 0) {
      headers["Tags"] = payload.tags.join(",");
    }

    if (payload.actions && payload.actions.length > 0) {
      const authHeader = this.token ? `, headers.Authorization=Bearer ${this.token}` : "";
      const actionsStr = payload.actions
        .map(
          (a) =>
            `http, ${a.label}, ${this.server}/${this.topic}-response, body='{"req_id": "${payload.id}", "reply": "${a.reply}"}', method=POST${authHeader}`,
        )
        .join("; ");
      headers["Actions"] = actionsStr;

      if (payload.id) {
        const cleanId = payload.id.replace(/[^a-zA-Z0-9_-]/g, "_").slice(0, 64);
        if (cleanId.length > 0) {
          headers["X-Sequence-ID"] = cleanId;
        }
      }
    }

    const fetchSignal = signal
      ? AbortSignal.any([signal, AbortSignal.timeout(10000)])
      : AbortSignal.timeout(10000);
    const response = await fetch(url, {
      method: "POST",
      headers,
      body: payload.message,
      signal: fetchSignal,
    });

    if (!response.ok) {
      const text = await response.text();
      throw new Error(`Failed to publish ntfy notification: ${response.status} ${text}`);
    }
  }

  async listen(
    onResponse: (resp: ApprovalResponse) => Promise<void>,
    signal?: AbortSignal,
  ): Promise<() => void> {
    const url = `${this.server}/${this.topic}-response/json`;
    const controller = new AbortController();

    if (signal) {
      signal.addEventListener("abort", () => controller.abort(), { once: true });
    }

    const headers: Record<string, string> = {
      Accept: "text/event-stream",
    };
    if (this.token) {
      headers["Authorization"] = `Bearer ${this.token}`;
    }

    const run = async () => {
      while (!controller.signal.aborted) {
        let reader: any;
        try {
          const response = await fetch(url, {
            headers,
            signal: controller.signal,
          });

          if (!response.ok || !response.body) {
            // Wait before reconnecting if request was not successful
            await new Promise((resolve) => setTimeout(resolve, 1000));
            continue;
          }

          reader = response.body.getReader();
          const decoder = new TextDecoder();
          let buffer = "";

          while (!controller.signal.aborted) {
            const { value, done } = await reader.read();
            if (done) break;

            buffer += decoder.decode(value, { stream: true });
            const lines = buffer.split("\n");
            buffer = lines.pop() || "";

            for (const line of lines) {
              const trimmed = line.trim();
              if (!trimmed) continue;

              let dataStr = trimmed;
              if (trimmed.startsWith("data:")) {
                dataStr = trimmed.slice(5).trim();
              }

              try {
                const parsed = JSON.parse(dataStr);
                // Filter event type if present: only process 'message' events
                if (parsed.event && parsed.event !== "message") {
                  continue;
                }

                let msgContent = parsed.message ?? parsed.body ?? parsed;
                if (typeof msgContent === "string") {
                  try {
                    msgContent = JSON.parse(msgContent);
                  } catch {
                    // Not valid JSON string
                  }
                }

                if (msgContent && typeof msgContent === "object") {
                  const req_id = msgContent.req_id ?? msgContent.reqID ?? msgContent.id;
                  const reply = msgContent.reply;
                  if (req_id && (reply === "once" || reply === "always" || reply === "reject")) {
                    await onResponse({
                      req_id: String(req_id),
                      reply,
                      source: "ntfy",
                    });
                  }
                }
              } catch {
                // Ignore non-json lines
              }
            }
          }
        } catch (err: unknown) {
          if (controller.signal.aborted || (err instanceof Error && err.name === "AbortError")) {
            return;
          }
          // On unexpected network error or disconnect, wait briefly and reconnect
          await new Promise((resolve) => setTimeout(resolve, 1000));
        } finally {
          if (reader) {
            try {
              await reader.cancel();
            } catch {
              // Ignore cancellation errors
            }
          }
        }
      }
    };

    run();

    return () => {
      controller.abort();
    };
  }

  async updateStatus(id: string, status: string, details?: string): Promise<void> {
    const url = `${this.server}/${this.topic}`;
    const headers: Record<string, string> = {
      Title: status.replace(/[^\x20-\x7E]/g, "").trim() || "Status Update",
      Priority: "default",
      "X-Sequence-ID": id.replace(/[^a-zA-Z0-9_-]/g, "_"),
      "Content-Type": "text/plain; charset=utf-8",
      // No Actions header intentionally to clear action buttons
    };

    if (this.token) {
      headers["Authorization"] = `Bearer ${this.token}`;
    }

    const message = formatStatusBody(status, details);

    const response = await fetch(url, {
      method: "POST",
      headers,
      body: message,
      signal: AbortSignal.timeout(5000),
    });
    if (!response.ok) {
      const text = await response.text();
      throw new Error(`Failed to update ntfy status: ${response.status} ${text}`);
    }
  }
}
