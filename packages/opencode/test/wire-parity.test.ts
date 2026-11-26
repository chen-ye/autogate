import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import {
  buildClassifierUserPrompt,
  buildSystemOneStateWithMeta,
  loadConfig,
  resolveClassifierActionArgs,
  type GateAction,
  type GateEvaluator,
  type PermissionEventData,
} from "@autogate/core";
import {
  buildOpenCodeGateAction,
  formatOpenCodePromptHierarchy,
  OpenCodeHarnessAdapter,
} from "../src/index.js";
import {
  makeEditPermissionEvent,
  makeExternalDirectoryPermissionEvent,
  makeMcpPermissionEvent,
  makeReadPermissionEvent,
  makeShellPermissionEvent,
  projectOpenCodeBenchCase,
} from "../../../scripts/bench/opencode-v2-events.js";
import {
  createRealOpenCodeHarness,
  type RealOpenCodeHarness,
} from "../../../test/e2e/opencode/real-harness.js";

interface CapturedPermissionEvent {
  type: string;
  location?: { directory?: string };
  data: PermissionEventData;
}

function toClassifierPromptInput(action: GateAction) {
  return {
    userPrompt: action.userPrompt,
    subagentPrompt: action.subagentPrompt,
    actionName: action.toolName,
    actionArgs: resolveClassifierActionArgs(action),
    workspaceRoot: action.workspaceRoot,
    environment: action.environment,
  };
}

async function subscribeOpenCodeEvents(
  baseUrl: string,
  authHeader: string,
  signal: AbortSignal,
  onEvent: (ev: {
    type: string;
    location?: { directory?: string };
    data?: Record<string, unknown>;
  }) => void | Promise<void>,
): Promise<void> {
  const res = await fetch(`${baseUrl}/api/event`, {
    headers: {
      Accept: "text/event-stream",
      Authorization: authHeader,
    },
    signal,
  });
  if (!res.ok || !res.body) {
    throw new Error(`Failed to subscribe to /api/event: ${res.status} ${res.statusText}`);
  }

  const reader = res.body.getReader();
  const decoder = new TextDecoder();

  (async () => {
    let buffer = "";
    try {
      while (!signal.aborted) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const chunks = buffer.split("\n\n");
        buffer = chunks.pop() ?? "";
        for (const chunk of chunks) {
          const dataLines = chunk
            .split("\n")
            .filter((line) => line.startsWith("data:"))
            .map((line) => line.slice(5).trim());
          if (dataLines.length === 0) continue;
          const payloadText = dataLines.join("\n");
          try {
            const parsed = JSON.parse(payloadText) as Record<string, unknown>;
            const ev = (
              parsed.payload && typeof parsed.payload === "object" ? parsed.payload : parsed
            ) as {
              type?: string;
              location?: { directory?: string };
              data?: Record<string, unknown>;
            };
            if (typeof ev.type === "string") {
              await onEvent({ type: ev.type, location: ev.location, data: ev.data });
            }
          } catch {
            // ignore non-JSON keepalives
          }
        }
      }
    } catch {
      // stream aborted or closed
    } finally {
      try {
        reader.releaseLock();
      } catch {
        // Ignore if reader lock was already released on stream teardown
      }
    }
  })();
}

async function subscribePermissionEvents(
  baseUrl: string,
  authHeader: string,
  signal: AbortSignal,
  onPermissionAsked: (ev: CapturedPermissionEvent) => void | Promise<void>,
): Promise<void> {
  await subscribeOpenCodeEvents(baseUrl, authHeader, signal, async (ev) => {
    if (ev.type === "permission.asked" && ev.data) {
      await onPermissionAsked({
        type: ev.type,
        location: ev.location,
        data: ev.data as unknown as PermissionEventData,
      });
    }
  });
}

describe("@autogate/opencode wire parity with OpenCode 2.0.21", () => {
  const origEnv = { ...process.env };
  let harness: RealOpenCodeHarness | undefined;
  let externalDir: string | undefined;

  beforeEach(() => {
    delete process.env.OPENCODE_PASSWORD;
    delete process.env.OPENCODE_SERVER_PASSWORD;
    delete process.env.OPENCODE_CONFIG;
    delete process.env.OPENCODE_CONFIG_CONTENT;
    delete process.env.OPENCODE_CONFIG_DIR;
  });

  afterEach(async () => {
    if (harness) {
      await harness.dispose();
      harness = undefined;
    }
    if (externalDir && fs.existsSync(externalDir)) {
      fs.rmSync(externalDir, { recursive: true, force: true });
      externalDir = undefined;
    }
    process.env = { ...origEnv };
  });

  it("captures live permission.asked payloads for shell, read, edit, and external_directory and matches projected System 1 & System 2 prompts", async () => {
    harness = await createRealOpenCodeHarness({
      pluginConfig: {
        autoMode: false,
        reviewFallbackMode: "native",
        notifyOnVerdict: false,
      },
      opencodeConfig: {
        permissions: [
          { action: "shell", resource: "*", effect: "ask" },
          { action: "read", resource: "*", effect: "ask" },
          { action: "edit", resource: "*", effect: "ask" },
          { action: "external_directory", resource: "*", effect: "ask" },
        ],
      },
    });

    const sampleFile = path.join(harness.workspaceDir, "sample.txt");
    fs.writeFileSync(sampleFile, "line 1\nline 2\n", "utf8");

    externalDir = fs.mkdtempSync(path.join(os.tmpdir(), "autogate-wire-ext-"));
    const externalFile = path.join(externalDir, "outside.txt");
    fs.writeFileSync(externalFile, "external content\n", "utf8");

    const captured: CapturedPermissionEvent[] = [];
    const sseAbort = new AbortController();

    await subscribePermissionEvents(
      harness.url,
      harness.authHeader,
      sseAbort.signal,
      async (ev) => {
        captured.push(ev);
        const reqId = ev.data.id;
        const sesId = ev.data.sessionID;
        if (reqId && sesId) {
          await fetch(
            `${harness!.url}/api/session/${encodeURIComponent(sesId)}/permission/${encodeURIComponent(reqId)}/reply`,
            {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
                Authorization: harness!.authHeader,
              },
              body: JSON.stringify({ decision: "once" }),
            },
          );
        }
      },
    );

    try {
      const waitForEvents = async (minCount: number, timeoutMs = 15000) => {
        const start = Date.now();
        while (captured.length < minCount && Date.now() - start < timeoutMs) {
          await new Promise((r) => setTimeout(r, 100));
        }
        expect(captured.length).toBeGreaterThanOrEqual(minCount);
      };

      // 1. Shell tool call
      const shellPrompt = "Run echo wire-parity in the workspace";
      const s1 = await harness.createSession({ title: "Wire Shell" });
      harness.mockProvider.pushResponse({
        toolCall: { name: "shell", input: { command: "echo wire-parity" } },
      });
      harness.mockProvider.pushResponse({ text: "Shell complete" });
      await harness.promptSession(s1.data.id, shellPrompt);
      await waitForEvents(1);

      // 2. Read tool call
      const readPrompt = "Read sample.txt in the workspace";
      const s2 = await harness.createSession({ title: "Wire Read" });
      harness.mockProvider.pushResponse({
        toolCall: { name: "read", input: { path: sampleFile } },
      });
      harness.mockProvider.pushResponse({ text: "Read complete" });
      await harness.promptSession(s2.data.id, readPrompt);
      await waitForEvents(2);

      // 3. Edit tool call
      const editPrompt = "Edit sample.txt in the workspace";
      const s3 = await harness.createSession({ title: "Wire Edit" });
      harness.mockProvider.pushResponse({
        toolCall: {
          name: "edit",
          input: { path: sampleFile, oldString: "line 1", newString: "line 1 updated" },
        },
      });
      harness.mockProvider.pushResponse({ text: "Edit complete" });
      await harness.promptSession(s3.data.id, editPrompt);
      await waitForEvents(3);

      // 4. External directory via read outside workspace
      const extPrompt = "Read external file outside workspace";
      const s4 = await harness.createSession({ title: "Wire External" });
      harness.mockProvider.pushResponse({
        toolCall: { name: "read", input: { path: externalFile } },
      });
      harness.mockProvider.pushResponse({ text: "External read complete" });
      await harness.promptSession(s4.data.id, extPrompt);
      await waitForEvents(4);

      const shellLive = captured.find((c) => c.data.action === "shell")?.data;
      const readLive = captured.find((c) => c.data.action === "read")?.data;
      const editLive = captured.find((c) => c.data.action === "edit")?.data;
      const extLive = captured.find((c) => c.data.action === "external_directory")?.data;

      expect(shellLive).toBeDefined();
      expect(readLive).toBeDefined();
      expect(editLive).toBeDefined();
      expect(extLive).toBeDefined();

      // Verify exact OpenCode 2.0.21 wire shapes against opencode-v2-events.ts constructors
      const shellSynthetic = makeShellPermissionEvent({
        id: shellLive!.id,
        sessionID: shellLive!.sessionID,
        command: ["echo wire-parity"],
        save: ["echo *"],
      });
      expect(shellLive!.action).toBe(shellSynthetic.action);
      expect(shellLive!.resources).toEqual(shellSynthetic.resources);
      expect(shellLive!.save).toEqual(shellSynthetic.save);
      expect(shellLive!.metadata).toBeUndefined();

      const readSynthetic = makeReadPermissionEvent({
        id: readLive!.id,
        sessionID: readLive!.sessionID,
        filePath: "sample.txt",
      });
      expect(readLive!.action).toBe(readSynthetic.action);
      expect(readLive!.resources).toEqual(readSynthetic.resources);
      expect(readLive!.save).toEqual(readSynthetic.save);
      expect(readLive!.metadata).toBeUndefined();

      const editFiles = editLive!.metadata?.files as
        | Array<{
            file?: string;
            patch?: string;
            status?: string;
            additions?: number;
            deletions?: number;
          }>
        | undefined;
      expect(Array.isArray(editFiles)).toBe(true);
      expect(editFiles?.[0]?.file).toBe("sample.txt");

      const editSynthetic = makeEditPermissionEvent({
        id: editLive!.id,
        sessionID: editLive!.sessionID,
        filePath: "sample.txt",
        patch: editFiles?.[0]?.patch,
        status: editFiles?.[0]?.status,
        additions: editFiles?.[0]?.additions,
        deletions: editFiles?.[0]?.deletions,
      });
      expect(editLive!.action).toBe(editSynthetic.action);
      expect(editLive!.resources).toEqual(editSynthetic.resources);
      expect(editLive!.save).toEqual(editSynthetic.save);

      const extSynthetic = makeExternalDirectoryPermissionEvent({
        id: extLive!.id,
        sessionID: extLive!.sessionID,
        directory: `${externalDir}/*`,
      });
      expect(extLive!.action).toBe(extSynthetic.action);
      expect(extLive!.resources).toEqual(extSynthetic.resources);
      expect(extLive!.save).toEqual(extSynthetic.save);
      expect(extLive!.metadata).toBeUndefined();

      // Verify System 1 state & System 2 prompt parity between live wire events and projected bench cases
      const pairs: Array<{
        live: PermissionEventData;
        synthetic: PermissionEventData;
        prompt: string;
      }> = [
        { live: shellLive!, synthetic: shellSynthetic, prompt: shellPrompt },
        { live: readLive!, synthetic: readSynthetic, prompt: readPrompt },
        { live: editLive!, synthetic: editSynthetic, prompt: editPrompt },
        { live: extLive!, synthetic: extSynthetic, prompt: extPrompt },
      ];

      for (const pair of pairs) {
        const liveAction = buildOpenCodeGateAction(pair.live, {
          workspaceRoot: harness.workspaceDir,
          userPrompt: pair.prompt,
        });
        const projectedAction = projectOpenCodeBenchCase({
          event: pair.synthetic,
          userPrompt: pair.prompt,
          workspaceRoot: harness.workspaceDir,
        });

        const s1State = buildSystemOneStateWithMeta(liveAction);
        const s2Prompt = buildClassifierUserPrompt(toClassifierPromptInput(liveAction));
        expect(buildSystemOneStateWithMeta(projectedAction)).toEqual(s1State);
        expect(buildClassifierUserPrompt(toClassifierPromptInput(projectedAction))).toBe(s2Prompt);
        if (pair.live.action === "edit") {
          expect(s1State.state).toContain("line 1 updated");
          expect(s2Prompt).toContain("line 1 updated");
        }
      }
    } finally {
      sseAbort.abort();
    }
  }, 30000);

  it("projects MCP events and hierarchical subagent prompts with identical System 1 and System 2 output", () => {
    const workspaceRoot = "/tmp/wire-parity-ws";
    const mcpEvent = makeMcpPermissionEvent({
      id: "per_mcp_1",
      sessionID: "ses_mcp_1",
      tool: "github_create_issue",
      input: { repo: "chen-ye/autogate", title: "Parity check" },
    });

    expect(mcpEvent).toEqual({
      id: "per_mcp_1",
      sessionID: "ses_mcp_1",
      action: "github_create_issue",
      resources: ["*"],
      save: ["*"],
      metadata: { input: { repo: "chen-ye/autogate", title: "Parity check" } },
    });

    const projected = projectOpenCodeBenchCase({
      event: mcpEvent,
      userPrompt: "<user-request>File an issue for parity check</user-request>",
      subagentPrompt: "<auto-slash-command>Create the GitHub issue</auto-slash-command>",
      subagentTitle: "Issue Helper",
      workspaceRoot,
    });

    const formatted = formatOpenCodePromptHierarchy({
      userPrompt: "<user-request>File an issue for parity check</user-request>",
      subagentPrompt: "<auto-slash-command>Create the GitHub issue</auto-slash-command>",
      subagentTitle: "Issue Helper",
    });
    const direct = buildOpenCodeGateAction(mcpEvent, {
      workspaceRoot,
      userPrompt: formatted.userPrompt,
      subagentPrompt: formatted.subagentPrompt,
    });

    expect(projected).toEqual(direct);
    expect(projected.commandString).toBeUndefined();
    expect(projected.rawArgs).toEqual({ repo: "chen-ye/autogate", title: "Parity check" });
    expect(projected.userPrompt).toBe("File an issue for parity check");
    expect(projected.subagentPrompt).toBe("[Subagent: Issue Helper]\nCreate the GitHub issue");
    const s1Mcp = buildSystemOneStateWithMeta(projected);
    expect(s1Mcp).toEqual(buildSystemOneStateWithMeta(direct));
    expect(s1Mcp.state).toContain("Args:");
    expect(s1Mcp.state).toContain("chen-ye/autogate");
    expect(s1Mcp.state).toContain("Parity check");
    const s2Mcp = buildClassifierUserPrompt(toClassifierPromptInput(projected));
    expect(s2Mcp).toBe(buildClassifierUserPrompt(toClassifierPromptInput(direct)));
    expect(s2Mcp).toContain("chen-ye/autogate");
    expect(s2Mcp).toContain("Parity check");

    const editEvent = makeEditPermissionEvent({
      id: "per_edit_diff_1",
      sessionID: "ses_edit_1",
      filePath: "src/auth.ts",
      before: "const allow = false;",
      after: "const allow = true;",
    });
    const editProjected = projectOpenCodeBenchCase({
      event: editEvent,
      userPrompt: "Update auth check",
      workspaceRoot,
    });
    expect(editProjected.targetPath).toBe("src/auth.ts");
    const s1Edit = buildSystemOneStateWithMeta(editProjected);
    const s2Edit = buildClassifierUserPrompt(toClassifierPromptInput(editProjected));
    expect(s1Edit.state).toContain("const allow = false;");
    expect(s1Edit.state).toContain("const allow = true;");
    expect(s2Edit).toContain("const allow = false;");
    expect(s2Edit).toContain("const allow = true;");

    // Multi-resource wildcard ["src/safe.ts", "*"] must NOT strip "*"
    const multiWildcard = buildOpenCodeGateAction(
      {
        id: "per_mw_1",
        sessionID: "ses_mw_1",
        action: "read",
        resources: ["src/safe.ts", "*"],
      },
      { workspaceRoot, userPrompt: "Read safe file" },
    );
    expect(multiWildcard.commandString).toBe("src/safe.ts *");
    expect(multiWildcard.rawArgs).toEqual(["src/safe.ts", "*"]);

    // Non-wildcard resources + metadata.input preserves both
    const mcpWithRes = buildOpenCodeGateAction(
      {
        id: "per_mcp_res",
        sessionID: "ses_mcp_res",
        action: "custom_mcp",
        resources: ["repo-1"],
        metadata: { input: { action: "merge" } },
      },
      { workspaceRoot, userPrompt: "Inspect repo" },
    );
    expect(mcpWithRes.rawArgs).toEqual({ resources: ["repo-1"], input: { action: "merge" } });

    // Multi-file edit sets patterns[] for anti-piggybacking and large `before` does not crowd out `after`
    const hugeBefore = "x".repeat(5000);
    const multiEditAction = buildOpenCodeGateAction(
      {
        id: "per_me_1",
        sessionID: "ses_me_1",
        action: "edit",
        resources: ["src/safe.ts", ".env"],
        metadata: {
          files: [
            { file: "src/safe.ts", before: hugeBefore, after: "const safeAfter = true;" },
            { file: ".env", before: "A=1", after: "SECRET_EXFIL=1" },
          ],
        },
      },
      { workspaceRoot, userPrompt: "Update safe.ts" },
    );
    expect(multiEditAction.patterns).toEqual(["src/safe.ts", ".env"]);
    const s2MultiEdit = buildClassifierUserPrompt(toClassifierPromptInput(multiEditAction));
    expect(s2MultiEdit).toContain("src/safe.ts, .env");
    expect(s2MultiEdit).toContain("const safeAfter = true;");
    expect(s2MultiEdit).toContain("SECRET_EXFIL=1");
  });

  it("preserves directive text without recursive drop-filter or sanitization and guards against empty collapse", () => {
    const preserved = formatOpenCodePromptHierarchy({
      userPrompt: "[SYSTEM DIRECTIVE: keep] <!-- OMO_INTERNAL --> ## Context:",
      subagentTitle: "Worker",
    });
    expect(preserved.userPrompt).toBe("[SYSTEM DIRECTIVE: keep] <!-- OMO_INTERNAL --> ## Context:");
    expect(preserved.subagentPrompt).toBe("[Subagent: Worker]");

    expect(() =>
      projectOpenCodeBenchCase({
        event: makeShellPermissionEvent({ command: ["ls"] }),
        userPrompt: "<user-request>   </user-request>",
        workspaceRoot: "/tmp/ws",
      }),
    ).toThrow(/collapsed to empty string/);
  });

  it("matches OpenCodeHarnessAdapter.handlePermissionAsked GateAction construction verbatim", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "autogate-adapter-parity-"));
    delete process.env.AUTOGATE_CONFIG;
    process.env.XDG_CONFIG_HOME = path.join(tempDir, "xdg");
    fs.mkdirSync(path.join(process.env.XDG_CONFIG_HOME, "autogate"), { recursive: true });
    fs.writeFileSync(
      path.join(process.env.XDG_CONFIG_HOME, "autogate", "config.json"),
      JSON.stringify({ autoMode: true, reviewFallbackMode: "native" }),
      "utf8",
    );

    const evaluatedActions: GateAction[] = [];
    const mockEvaluator: GateEvaluator = {
      name: "capture-eval",
      async evaluate(action) {
        evaluatedActions.push(action);
        return { verdict: "ALLOW", reason: "ok" };
      },
    };

    const adapterOpts = {
      evaluator: mockEvaluator,
      ntfyServer: "http://127.0.0.1:59999",
      notifyOnVerdict: false,
      evalDbFile: path.join(tempDir, "evals.db"),
    };
    const expectedEnv = loadConfig(adapterOpts).environment;

    const adapter = new OpenCodeHarnessAdapter(
      {
        directory: tempDir,
        client: {
          session: {
            create: async () => ({ data: { id: "ses-par-eval" } }),
            prompt: async () => ({}),
            get: async () => ({ data: { id: "ses-par-1" } }),
            context: async () => [{ type: "user", text: "Check git status" }],
          },
          permission: { reply: async () => ({}) },
        },
        permission: { reply: async () => ({}) },
      },
      adapterOpts,
    );

    await adapter.start();
    try {
      const request = makeShellPermissionEvent({
        id: "per_par_1",
        sessionID: "ses-par-1",
        command: ["git status"],
      });

      await adapter.handlePermissionAsked(request);
      expect(evaluatedActions.length).toBe(1);

      const expectedAction = buildOpenCodeGateAction(request, {
        workspaceRoot: tempDir,
        userPrompt: "Check git status",
        environment: expectedEnv,
      });

      expect(evaluatedActions[0]?.signal).toBeInstanceOf(AbortSignal);
      expect(evaluatedActions[0]).toEqual({
        ...expectedAction,
        signal: evaluatedActions[0]?.signal,
      });
    } finally {
      await adapter.dispose();
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("handles PATCH /api/session/:id archiving cleanly on pinned 2.0.21 and verifies 2.1+ archive parity when supported", async () => {
    harness = await createRealOpenCodeHarness({
      pluginConfig: {
        autoMode: false,
        reviewFallbackMode: "native",
        notifyOnVerdict: false,
      },
    });

    const sseAbort = new AbortController();
    const lifecycleEvents: Array<{ type: string; sessionID?: unknown }> = [];
    await subscribeOpenCodeEvents(harness.url, harness.authHeader, sseAbort.signal, (ev) => {
      if (ev.type === "session.archived" || ev.type === "session.unarchived") {
        lifecycleEvents.push({ type: ev.type, sessionID: ev.data?.sessionID });
      }
    });

    try {
      const created = await harness.createSession({ title: "Archive Parity" });
      const sid = created.data.id;

      const patchArchive = await fetch(`${harness.url}/api/session/${encodeURIComponent(sid)}`, {
        method: "PATCH",
        headers: {
          "Content-Type": "application/json",
          Authorization: harness.authHeader,
        },
        body: JSON.stringify({ title: "[auto-gate-eval] bash -> ALLOW", archived: true }),
      });
      expect(patchArchive.status).toBe(204);

      const getRes = await fetch(`${harness.url}/api/session/${encodeURIComponent(sid)}`, {
        headers: { Authorization: harness.authHeader },
      });
      expect(getRes.ok).toBe(true);
      const getJson = (await getRes.json()) as {
        data?: { title?: string; time?: { archived?: number } };
        title?: string;
        time?: { archived?: number };
      };
      const sessionInfo = getJson.data ?? getJson;
      expect(sessionInfo.title).toBe("[auto-gate-eval] bash -> ALLOW");

      const supportsNativeArchive = typeof sessionInfo.time?.archived === "number";
      if (supportsNativeArchive) {
        const listRes = await fetch(`${harness.url}/api/session?archived=false`, {
          headers: { Authorization: harness.authHeader },
        });
        expect(listRes.ok).toBe(true);
        const listJson = (await listRes.json()) as { data?: Array<{ id?: string }> };
        expect((listJson.data ?? []).some((s) => s.id === sid)).toBe(false);

        const patchUnarchive = await fetch(
          `${harness.url}/api/session/${encodeURIComponent(sid)}`,
          {
            method: "PATCH",
            headers: {
              "Content-Type": "application/json",
              Authorization: harness.authHeader,
            },
            body: JSON.stringify({ archived: false }),
          },
        );
        expect(patchUnarchive.status).toBe(204);

        const waitStart = Date.now();
        while (lifecycleEvents.length < 2 && Date.now() - waitStart < 3000) {
          await new Promise((r) => setTimeout(r, 50));
        }
        expect(lifecycleEvents).toContainEqual({ type: "session.archived", sessionID: sid });
        expect(lifecycleEvents).toContainEqual({ type: "session.unarchived", sessionID: sid });
      }
    } finally {
      sseAbort.abort();
    }
  }, 20000);
});
