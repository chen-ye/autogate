import {
  AutoGateCoreEngine,
  NtfyAdapter,
  DirectApiEvaluator,
  type HarnessAdapter,
  type GateAction,
  type GateDecision
} from "../../core/src/index.ts"

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

export default function autoGateOmpExtension(pi: any): void {
  pi.setLabel?.("AutoGate Security")
  const adapter = new OmpHarnessAdapter(pi)
  adapter.start().catch(() => {})
}
