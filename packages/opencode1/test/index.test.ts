import { describe, it, expect } from "bun:test";
import type { PluginInput } from "@opencode-ai/plugin";
import { AutoGatePlugin, isEventForWorkspace } from "../src/index.js";

describe("@autogate/opencode1 runtime agent injection & workspace filter", () => {
  it("matches workspace correctly", () => {
    expect(isEventForWorkspace({}, undefined)).toBe(true);
    expect(
      isEventForWorkspace({ location: { directory: "/home/user/project" } }, "/home/user/project"),
    ).toBe(true);
    expect(
      isEventForWorkspace({ location: { directory: "/other/dir" } }, "/home/user/project"),
    ).toBe(false);
  });

  it("registers auto-gate-eval via config() hook in OpenCode v1 server plugin", async () => {
    const hooks = await AutoGatePlugin(
      { directory: "/tmp/test-ws-v1", client: {} } as unknown as PluginInput,
      {
        classifierModel: "google/gemini-3.5-flash-lite",
        ntfyServer: "http://127.0.0.1:59999",
      },
    );

    const hookMap = hooks as Record<string, unknown>;
    try {
      const configData: { agent?: Record<string, Record<string, unknown>> } = {};
      const configHook = hookMap.config as
        | ((cfg: Record<string, unknown>) => Promise<void>)
        | undefined;
      if (configHook) {
        await configHook(configData);
      }
      const evalAgent = configData.agent?.["auto-gate-eval"];
      expect(evalAgent).toBeDefined();
      expect(evalAgent?.mode).toBe("subagent");
      expect(evalAgent?.hidden).toBe(true);
      expect(typeof evalAgent?.prompt).toBe("string");
    } finally {
      const disposeHook = hookMap.dispose as (() => Promise<void>) | undefined;
      if (typeof disposeHook === "function") await disposeHook();
    }
  });
});
