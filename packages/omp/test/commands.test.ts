import { describe, it, expect, afterEach } from "bun:test";
import {
  AutoGateCoreEngine,
  sharedExplicitEscalations,
  sharedRecentlyRejected,
} from "../../core/src/index.js";
import { registerEscalatePermissionTool } from "../src/commands.js";

describe("@autogate/omp registerEscalatePermissionTool", () => {
  afterEach(() => {
    sharedExplicitEscalations.clear();
    sharedRecentlyRejected.clear();
  });

  it("resolves sessionID from ctx.sessionManager.getSessionId() and respects reviewFallbackMode", async () => {
    const engine = new AutoGateCoreEngine({
      config: { autoMode: true, reviewFallbackMode: "native", notifyOnVerdict: false },
    });

    let registeredTool:
      | {
          name: string;
          execute: (
            toolCallId: string,
            params: unknown,
            signal: AbortSignal,
            onUpdate: unknown,
            ctx: unknown,
          ) => Promise<{ output: string }>;
        }
      | undefined;

    registerEscalatePermissionTool(
      {
        registerTool(def: typeof registeredTool) {
          registeredTool = def;
        },
      },
      engine,
    );

    expect(registeredTool).toBeDefined();
    expect(registeredTool?.name).toBe("escalate_permission");

    const ac = new AbortController();
    const nativeRes = await registeredTool!.execute(
      "call-1",
      { action: "/etc/hosts", reason: "inspect network map" },
      ac.signal,
      undefined,
      { sessionManager: { getSessionId: () => "omp-ses-123" } },
    );

    expect(nativeRes.output).toContain("native harness prompt for manual approval");
    expect(sharedExplicitEscalations.get("omp-ses-123")).toHaveLength(1);
    expect(sharedExplicitEscalations.get("omp-ses-123")?.[0]?.action).toBe("/etc/hosts");

    engine.setFallbackMode("ntfy");
    const ntfyRes = await registeredTool!.execute(
      "call-2",
      { action: "rm -rf dist", reason: "clean build" },
      ac.signal,
      undefined,
      { sessionManager: { getSessionId: () => "omp-ses-123" } },
    );
    expect(ntfyRes.output).toContain("forwarded directly to the user's phone for manual approval");
    expect(sharedExplicitEscalations.get("omp-ses-123")).toHaveLength(2);

    const missingRes = await registeredTool!.execute(
      "call-3",
      { action: "/etc/hosts", reason: "missing session" },
      ac.signal,
      undefined,
      {},
    );
    expect(missingRes.output).toContain("Unable to register manual verification intent");
  });
});
