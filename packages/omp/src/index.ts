import {
  AutoGateCoreEngine,
  NtfyAdapter,
  DirectApiEvaluator,
  type HarnessAdapter,
  type GateAction,
  type GateDecision
} from "../../core/src/index.ts"
import { registerToolCallHook, verdictStore } from "./hook.ts"
import { resolveShadowedApproval } from "./approval-bridge.ts"
import { registerAutomodeCommand, registerEscalatePermissionTool } from "./commands.ts"
export class OmpHarnessAdapter implements HarnessAdapter {
  readonly name = "omp-harness"
  private engine: AutoGateCoreEngine

  constructor(pi: any, options?: Record<string, unknown>) {
    this.engine = new AutoGateCoreEngine({
      config: { autoMode: true },
      client: pi,
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

export default function autoGateOmpExtension(pi: any): void {
  pi.setLabel?.("AutoGate Security")
  const adapter = new OmpHarnessAdapter(pi)
  adapter.start().catch(() => {})
  registerShadowedBashTool(pi, adapter.getEngine())
  registerToolCallHook(pi, adapter.getEngine())
  registerAutomodeCommand(pi, adapter.getEngine())
  registerEscalatePermissionTool(pi, adapter.getEngine())
}
