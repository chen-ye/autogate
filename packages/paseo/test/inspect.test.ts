import { describe, it } from "node:test";
import assert from "node:assert";
import {
  extractActionFromRequest,
  shellCommand,
  truncate,
  TRUNCATION_LIMIT,
  TRUNCATION_SUFFIX,
} from "../server/inspect";

describe("Paseo Permission Request Inspector", () => {
  describe("shellCommand", () => {
    it("extracts command from request.input.command", () => {
      const req = { input: { command: "ls -la" } };
      assert.strictEqual(shellCommand(req), "ls -la");
    });

    it("extracts cmd from request.input.cmd", () => {
      const req = { input: { cmd: "git status" } };
      assert.strictEqual(shellCommand(req), "git status");
    });

    it("extracts code from request.input.code", () => {
      const req = { input: { code: "console.log('hello')" } };
      assert.strictEqual(shellCommand(req), "console.log('hello')");
    });

    it("extracts script from request.input.script", () => {
      const req = { input: { script: "run.sh" } };
      assert.strictEqual(shellCommand(req), "run.sh");
    });

    it("extracts command from request.args fallback", () => {
      const req = { args: { command: "npm test" } };
      assert.strictEqual(shellCommand(req), "npm test");
    });

    it("extracts command when input is raw string", () => {
      const req = { input: "echo 123" };
      assert.strictEqual(shellCommand(req), "echo 123");
    });

    it("extracts command when input is stringified JSON", () => {
      const req = { input: JSON.stringify({ command: "whoami" }) };
      assert.strictEqual(shellCommand(req), "whoami");
    });

    it("returns null for non-command or missing input", () => {
      assert.strictEqual(shellCommand(null), null);
      assert.strictEqual(shellCommand(undefined), null);
      assert.strictEqual(shellCommand({}), null);
      assert.strictEqual(shellCommand({ input: null }), null);
      assert.strictEqual(shellCommand({ input: { path: "foo.txt" } }), null);
    });
  });

  describe("truncate", () => {
    it("preserves strings under the byte limit", () => {
      const small = "hello world";
      assert.strictEqual(truncate(small, 4096), small);
    });

    it("preserves strings exactly at the byte limit", () => {
      const exact = "a".repeat(4096);
      assert.strictEqual(truncate(exact, 4096), exact);
    });

    it("truncates strings exceeding 4096 bytes and appends suffix", () => {
      const large = "a".repeat(5000);
      const res = truncate(large, 4096);
      assert.strictEqual(res.startsWith("a".repeat(4096)), true);
      assert.strictEqual(res.endsWith(TRUNCATION_SUFFIX), true);
      assert.strictEqual(res, "a".repeat(4096) + TRUNCATION_SUFFIX);
    });

    it("safely handles multi-byte UTF-8 without cutting characters", () => {
      // '🚀' is 4 bytes in UTF-8
      const emoji = "🚀".repeat(1100); // 4400 bytes
      const res = truncate(emoji, 4096);
      assert.strictEqual(res.endsWith(TRUNCATION_SUFFIX), true);
      // Ensure no replacement character (\uFFFD) was introduced
      assert.strictEqual(res.includes("\uFFFD"), false);
    });
  });

  describe("extractActionFromRequest", () => {
    it("formats clean GateAction payload for shell command", () => {
      const event = {
        agent: {
          id: "agent-123",
          cwd: "/workspace/project",
        },
        request: {
          id: "req-456",
          name: "bash",
          kind: "tool",
          input: {
            command: "rm -rf node_modules",
          },
        },
      };

      const action = extractActionFromRequest(event);
      assert.deepStrictEqual(action, {
        id: "req-456",
        harness: "paseo",
        sessionID: "agent-123",
        toolName: "bash",
        commandString: "rm -rf node_modules",
        targetPath: undefined,
        rawArgs: { command: "rm -rf node_modules" },
        workspaceRoot: "/workspace/project",
        userPrompt: "",
      });
    });

    it("extracts targetPath from file operations (path, filepath, file)", () => {
      const eventPath = {
        agent: { id: "a1" },
        request: { id: "r1", name: "read_file", input: { path: "src/main.ts" } },
      };
      assert.strictEqual(extractActionFromRequest(eventPath).targetPath, "src/main.ts");

      const eventFilePath = {
        agent: { id: "a2" },
        request: { id: "r2", name: "write_file", input: { filepath: "/etc/config.json" } },
      };
      assert.strictEqual(extractActionFromRequest(eventFilePath).targetPath, "/etc/config.json");

      const eventFile = {
        agent: { id: "a3" },
        request: { id: "r3", name: "edit_file", input: { file: "package.json" } },
      };
      assert.strictEqual(extractActionFromRequest(eventFile).targetPath, "package.json");
    });

    it("falls back to request kind when tool name is missing", () => {
      const event = {
        agent: { id: "a1" },
        request: { id: "r1", kind: "question", input: { text: "Should I proceed?" } },
      };
      const action = extractActionFromRequest(event);
      assert.strictEqual(action.toolName, "question");
    });

    it("defaults workspaceRoot to process.cwd() when agent.cwd is missing", () => {
      const event = {
        agent: { id: "a1" },
        request: { id: "r1" },
      };
      const action = extractActionFromRequest(event);
      assert.strictEqual(action.workspaceRoot, process.cwd());
    });

    it("truncates large commands exceeding 4KB", () => {
      const largeCommand = "echo " + "x".repeat(5000);
      const event = {
        agent: { id: "a1" },
        request: {
          id: "r1",
          name: "bash",
          input: { command: largeCommand },
        },
      };

      const action = extractActionFromRequest(event);
      assert.ok(action.commandString);
      assert.strictEqual(action.commandString.endsWith("... [truncated]"), true);
      assert.strictEqual(action.commandString.startsWith(largeCommand.slice(0, 4096)), true);
    });

    it("truncates large stringified rawArgs exceeding 4KB", () => {
      const largePayload = "y".repeat(6000);
      const event = {
        agent: { id: "a1" },
        request: {
          id: "r1",
          name: "custom_tool",
          input: largePayload,
        },
      };

      const action = extractActionFromRequest(event);
      assert.strictEqual(typeof action.rawArgs, "string");
      assert.strictEqual((action.rawArgs as string).endsWith("... [truncated]"), true);
      assert.strictEqual((action.rawArgs as string).startsWith("y".repeat(4096)), true);
    });

    it("truncates large string properties inside rawArgs object exceeding 4KB", () => {
      const largeContent = "z".repeat(5000);
      const event = {
        agent: { id: "a1" },
        request: {
          id: "r1",
          name: "write_file",
          input: { path: "test.txt", content: largeContent },
        },
      };

      const action = extractActionFromRequest(event);
      const args = action.rawArgs as { path: string; content: string };
      assert.strictEqual(args.path, "test.txt");
      assert.strictEqual(args.content.endsWith("... [truncated]"), true);
      assert.strictEqual(args.content.startsWith("z".repeat(4096)), true);
    });

    it("does NOT crash on malformed, null, or missing request properties", () => {
      assert.doesNotThrow(() => extractActionFromRequest(null as any));
      assert.doesNotThrow(() => extractActionFromRequest(undefined as any));
      assert.doesNotThrow(() => extractActionFromRequest({} as any));
      assert.doesNotThrow(() => extractActionFromRequest({ agent: null, request: null }));
      assert.doesNotThrow(() =>
        extractActionFromRequest({
          agent: { id: undefined, cwd: null },
          request: { id: null, input: undefined },
        })
      );

      const nullAction = extractActionFromRequest(null as any);
      assert.strictEqual(nullAction.id, "");
      assert.strictEqual(nullAction.sessionID, "");
      assert.strictEqual(nullAction.harness, "paseo");
      assert.strictEqual(nullAction.toolName, "");
      assert.strictEqual(nullAction.commandString, undefined);
      assert.strictEqual(nullAction.targetPath, undefined);
      assert.strictEqual(nullAction.workspaceRoot, process.cwd());
    });
  });
});

