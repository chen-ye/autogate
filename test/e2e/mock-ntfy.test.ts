import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { MockNtfyServer } from "./mock-ntfy";
import { NtfyAdapter } from "../../packages/core/src/remote/ntfy";

describe("MockNtfyServer", () => {
  let server: MockNtfyServer;

  beforeEach(() => {
    server = new MockNtfyServer();
  });

  afterEach(async () => {
    await server.stop();
  });

  it("captures published messages with correct metadata", async () => {
    const adapter = new NtfyAdapter({
      server: server.url,
      topic: "test-topic",
    });

    await adapter.publish({
      id: "req-123",
      harness: "opencode",
      sessionID: "ses-1",
      toolName: "bash",
      commandString: "echo hello",
      workspaceRoot: "/tmp",
      userPrompt: "test",
      title: "Test Alert",
      message: "Hello world message",
      priority: "urgent",
      tags: ["warning", "test"],
      actions: [
        { label: "Approve", reply: "once" },
      ],
    });

    const published = server.getPublished();
    expect(published.length).toBe(1);
    expect(published[0].topic).toBe("test-topic");
    expect(published[0].title).toBe("Test Alert");
    expect(published[0].priority).toBe("urgent");
    expect(published[0].tags).toEqual(["warning", "test"]);
    expect(published[0].body).toBe("Hello world message");
    expect(published[0].headers["x-sequence-id"]).toBe("req-123");
    expect(published[0].actions).toBeDefined();
    expect(typeof published[0].actions).toBe("string");

    server.clearPublished();
    expect(server.getPublished().length).toBe(0);
  });

  it("delivers simulated responses to listeners", async () => {
    const adapter = new NtfyAdapter({
      server: server.url,
      topic: "test-topic",
    });

    const responses: any[] = [];
    const unsubscribe = await adapter.listen(async (resp) => {
      responses.push(resp);
    });

    // Simulate reply after a short delay
    setTimeout(() => {
      server.simulateReply("req-456", "once");
    }, 50);

    // Wait for response to be received
    let attempts = 0;
    while (responses.length === 0 && attempts < 20) {
      await new Promise((r) => setTimeout(r, 50));
      attempts++;
    }

    unsubscribe();

    expect(responses.length).toBe(1);
    expect(responses[0]).toEqual({
      req_id: "req-456",
      reply: "once",
      source: "ntfy",
    });
  });

  it("validates bearer token authentication when configured", async () => {
    const authServer = new MockNtfyServer({ token: "secret-token" });
    const authUrl = authServer.url;

    const unauthAdapter = new NtfyAdapter({
      server: authUrl,
      topic: "secure-topic",
    });

    // Publishing without token should fail (401)
    let error: any;
    try {
      await unauthAdapter.publish({
        id: "req-sec",
        harness: "opencode",
        sessionID: "ses-1",
        toolName: "bash",
        commandString: "echo sec",
        workspaceRoot: "/tmp",
        userPrompt: "test",
        title: "Secure",
        message: "Secure msg",
      });
    } catch (err) {
      error = err;
    }
    expect(error).toBeDefined();

    // Publishing with token should succeed
    const authAdapter = new NtfyAdapter({
      server: authUrl,
      topic: "secure-topic",
      token: "secret-token",
    });

    await authAdapter.publish({
      id: "req-sec-2",
      harness: "opencode",
      sessionID: "ses-1",
      toolName: "bash",
      commandString: "echo sec",
      workspaceRoot: "/tmp",
      userPrompt: "test",
      title: "Secure",
      message: "Secure msg",
    });

    expect(authServer.getPublished().length).toBe(1);

    await authServer.stop();
  });
});
