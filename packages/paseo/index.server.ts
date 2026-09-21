import { PaseoHarnessAdapter } from "./server/adapter.js";
import { extractActionFromRequest, shellCommand } from "./server/inspect.js";
import { PaseoNativeEvaluator, type PaseoNativeEvaluatorOptions } from "./server/evaluator.js";

/**
 * Daemon contribution entrypoint for Paseo.
 *
 * Adheres to the Paseo plugin server entrypoint contract:
 * `export default function contribute(server) { ... return () => cleanup }`
 *
 * Instantiates a new `PaseoHarnessAdapter(server)` and returns an async cleanup
 * function that calls `await adapter.dispose()`, cleanly unregistering event listeners,
 * stopping remote notification listeners, stopping the engine, and clearing pending states
 * without leaking timers or listeners on plugin reload or disable.
 */
export default function contribute(
  server: any,
  options?: Record<string, unknown>
): () => Promise<void> {
  const adapter = new PaseoHarnessAdapter(server, options);
  return async () => {
    await adapter.dispose();
  };
}

export {
  contribute,
  PaseoHarnessAdapter,
  PaseoNativeEvaluator,
  extractActionFromRequest,
  shellCommand,
  type PaseoNativeEvaluatorOptions,
};
