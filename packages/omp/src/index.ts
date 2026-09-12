  import {
  AutoGateCoreEngine,
  NtfyAdapter,
  DirectApiEvaluator,
  loadConfig,
  type HarnessAdapter,
  type GateAction,
  type GateDecision
} from "@autogate/core"
import { registerToolCallHook, verdictStore } from "./hook.ts"
import { resolveShadowedApproval } from "./approval-bridge.ts"
import { registerAutomodeCommand, registerEscalatePermissionTool } from "./commands.ts"
export class OmpHarnessAdapter implements HarnessAdapter {
  readonly name = "omp-harness"
  private engine: AutoGateCoreEngine

  constructor(pi: any, options?: Record<string, unknown>) {
    const config = loadConfig(options)
    const adapter = new NtfyAdapter({
      server: config.ntfyServer,
      topic: config.ntfyTopic,
      token: config.ntfyToken,
    })
    this.engine = new AutoGateCoreEngine({
      config,
      adapter,
      client: pi,
      evaluator: (options as any)?.evaluator,
    })
  }

  async start(): Promise<void> {
    await this.engine.start()
  }

  async dispose(): Promise<void> {
    await this.engine.stop()
  }

  getEngine(): AutoGateCoreEngine {
    return this.engine
  }
}

export function registerShadowedBashTool(pi: any, engine: AutoGateCoreEngine): void {
  const parameters = pi?.zod?.object
    ? pi.zod.object({
        command: pi.zod.string(),
        timeout: pi.zod.number().optional(),
        workdir: pi.zod.string().optional(),
      })
    : {
        type: "object",
        properties: {
          command: { type: "string" },
          timeout: { type: "number" },
          workdir: { type: "string" },
        },
        required: ["command"],
      };

  pi.registerTool({
    name: "bash",
    label: "Bash",
    description: "Execute a bash command in a persistent shell session",
    approval: (args: any) => resolveShadowedApproval(args),
    parameters,
    async execute(toolCallId: string, params: any, signal: AbortSignal, onUpdate: any, ctx: any) {
      if (!ctx?.invokeTool) {
        throw new Error("ctx.invokeTool is unavailable for shadowed bash delegation");
      }
      return await ctx.invokeTool(params, { signal, onUpdate });
    },
  });
}

export default function autoGateOmpExtension(pi: any, options?: Record<string, unknown>): void {
  pi.setLabel?.("AutoGate Security")
  const adapter = new OmpHarnessAdapter(pi, options)

  registerToolCallHook(pi, adapter.getEngine())
  registerAutomodeCommand(pi, adapter.getEngine())
  registerEscalatePermissionTool(pi, adapter.getEngine())
}
