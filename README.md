# AutoGate

AutoGate intercepts tool calls and shell commands from AI coding agents before they run. It evaluates each action against your prompt and trust boundaries, runs safe commands without prompting, blocks destructive commands with safe alternatives, and sends ambiguous actions to both your host UI and your phone via ntfy.

AutoGate supports Paseo, OpenCode v1 and v2, and Oh My Pi.

---

## How it works

```text
                        +-------------------------------------+
                        |       AI Coding Agent or Host       |
                        |   Paseo, OpenCode v1/v2, Oh My Pi   |
                        +------------------+------------------+
                                           |
                                Tool or Action Request
                                           |
                                           v
                        +-------------------------------------+
                        |            Host Adapter             |
                        |  @autogate/paseo, opencode, omp...  |
                        +------------------+------------------+
                                           |
                                           v
                        +-------------------------------------+
                        |         AutoGate Core Engine        |
                        |  @autogate/core: Turn Cache,        |
                        |  Escalation Match, Target Prober,   |
                        |  De-obfuscation, Circuit Breaker    |
                        +------------------+------------------+
                                           |
          +--------------------------------+--------------------------------+
          |      Two-System Classifier (System 1 and System 2 Cascade)      |
          |                                                                 |
          |  When systemOne.enabled is true (otherwise System 2 directly):  |
          |   - race (default): run S1 and S2 in parallel, abort S2 if ok   |
          |   - cascade:        run S1 first, invoke S2 only on escalation  |
          |                                                                 |
          |  +--------------------------+  escalate   +------------------+  |
          |  |     System 1 Router      |  on drift,  |    System 2      |  |
          |  |   SystemOneEvaluator     |  injection, |  Deep Classifier |  |
          |  | - verdict (ALLOW/BLOCK)  |------------>| auto-gate-eval,  |  |
          |  | - in_scope & injection   |  low prob,  | host, or Direct  |  |
          |  | - context fingerprint    |  or circuit | 2D Risk & Intent |  |
          |  +------------+-------------+             +--------+---------+  |
          |               | Accept                             |            |
          +---------------|------------------------------------|------------+
                          |                                    |
                          +-----------------+------------------+
                                            |
                    +-----------------------+-----------------------+
                    |                       |                       |
                    v                       v                       v
                [ ALLOW ]               [ BLOCK ]               [ UNSURE ]
           Execute without         SAFE_TRANSFORM_REJECT    Dual-Channel Review
               prompting           Self-correction advice  +--------------------+
           (cached per turn)       (trash-cli, git stash)  | Host UI Dialog     |
                                                           |        and         |
                                                           | Ntfy Phone Push    |
                                                           +---------+----------+
                                                                     |
                                                              First response
                                                             resolves request
```

Every action that AutoGate intercepts produces one of three verdicts.

- **`ALLOW`.** Low-risk, non-destructive actions aligned with your current instructions, such as reading files, running builds and tests, or inspecting git status. The action runs without prompting, and AutoGate caches the decision for the rest of the current turn.
- **`BLOCK`.** Dangerous, destructive, or out-of-scope actions, such as `rm -rf /`, force-pushing protected branches, discarding uncommitted working-tree changes, overwriting system files, or leaking credentials. For transformable commands like `rm`, `git restore`, and `git checkout`, AutoGate injects a `[SAFE_TRANSFORM_REJECT]` message suggesting safer alternatives such as `npx trash-cli` or `git stash` so the agent can retry.
- **`UNSURE`.** Sensitive or high-impact actions, such as package publishing, pull request merges, database migrations, service deployments, global package changes, or untrusted remote scripts. AutoGate requests human approval in both your host UI and on your phone.

Agents can also ask for human review explicitly by calling `escalate_permission` or by prefixing a shell command with `AUTOGATE_ESCALATE=1`.

---

## Installation and setup

### Prerequisites

- [Bun](https://bun.sh) v1.1 or newer, including v1.4
- An API key for the System 2 classifier model in `AUTOGATE_API_KEY`, `GEMINI_API_KEY`, or `GOOGLE_API_KEY`, unless you use Paseo native provider reuse
- Optional, the [ntfy](https://ntfy.sh) app on iOS or Android for mobile approvals

### Clone and install

1. Clone the repository.

```bash
git clone https://github.com/chen-ye/autogate.git
```

2. Enter the repository directory.

```bash
cd autogate
```

3. Install workspace dependencies.

```bash
bun install
```

### Connect an agent

#### Paseo daemon plugin

1. Install the local `@autogate/paseo` plugin into your Paseo daemon, version 0.8.0 or newer.

```bash
paseo plugin install /absolute/path/to/autogate/packages/paseo
```

2. Confirm the plugin is active.

```bash
paseo plugin ls
```

3. View plugin logs when needed.

```bash
paseo plugin logs autogate
```

#### OpenCode plugins

For OpenCode v2 using `@opencode/plugin`, add `@autogate/opencode` to `~/.config/opencode/opencode.json` or `.opencode/plugins/`:

```json
{
  "plugins": ["/absolute/path/to/autogate/packages/opencode"]
}
```

For OpenCode v1 using `@opencode-ai/plugin`, point the plugin entry to `/absolute/path/to/autogate/packages/opencode1`.

#### Oh My Pi extension

If you run Oh My Pi agents through Paseo, comment out the Oh My Pi extension below in `~/.omp/agent/config.yml` so `@autogate/paseo` handles gatekeeping once and does not duplicate evaluations.

1. Add `@autogate/omp` to `~/.omp/agent/config.yml`.

```yaml
extensions:
  - /absolute/path/to/autogate/packages/omp/src/index.ts
```

2. Use `/autogate-classifier` with `on`, `off`, `status`, or `toggle`, and `/autogate-fallback` with `native`, `ntfy`, `status`, or `toggle` inside Oh My Pi sessions to change runtime behavior.

---

## Configuration

AutoGate reads configuration from `~/.config/autogate/config.json`, or from `$XDG_CONFIG_HOME/autogate/config.json`, or from the path set in `AUTOGATE_CONFIG`.

> [!WARNING]
> Anyone who can access your `ntfyTopic` or `<ntfyTopic>-response` channel can read proposed commands and send approvals to AutoGate. Use a self-hosted ntfy instance when possible. At a minimum, use a high-entropy `ntfyTopic` name rather than a guessable word like `"autogate"`, configure authentication with `ntfyToken`, or do both.

### Example configuration

```json
{
  "autoMode": true,
  "classifierModel": "google/gemini-3.5-flash-lite",
  "classifierTimeout": 45000,
  "ntfyServer": "https://ntfy.example.com",
  "ntfyTopic": "autogate-9f3c7a2e4b8d1e6f",
  "ntfyToken": "tk_your_ntfy_auth_token",
  "ntfyVerbosity": "normal",
  "notifyOnVerdict": true,
  "reviewFallbackMode": "ntfy",
  "consecutiveBlockThreshold": 3,
  "environment": {
    "trustedDomains": ["github.com", "npmjs.org"],
    "trustedGitRemotes": ["origin"],
    "trustedPaths": ["~/Projects"]
  },
  "systemOne": {
    "enabled": true,
    "executionMode": "race",
    "endpoint": "http://127.0.0.1:4006/v1/systemone",
    "model": "gemini-decision-1",
    "timeoutMs": 4000,
    "thresholds": {
      "allowMinProb": 0.92,
      "blockMinProb": 0.85,
      "minOddsRatio": 4.0,
      "minInScopeNoul": 0.7,
      "maxInjectionNoul": 0.5
    }
  },
  "paseo": {
    "timelineBadges": true,
    "evaluatorProvider": "omp",
    "useDirectApi": false,
    "notifyOnVerdict": false
  },
  "opencode": {
    "serverUrl": "http://localhost:4096"
  },
  "omp": {
    "reviewFallbackMode": "ntfy"
  }
}
```

### Configuration options

| Field                                   | Type                    | Default                                | Description                                                                                                                                                             |
| --------------------------------------- | ----------------------- | -------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `autoMode`                              | `boolean`               | `true`                                 | Run the autonomous classifier before requesting human review.                                                                                                           |
| `classifierModel`                       | `string`                | `"google/gemini-3.5-flash-lite"`       | System 2 model ID in `provider/model#variant` form.                                                                                                                     |
| `classifierTimeout`                     | `number`                | `45000`                                | Timeout in milliseconds for System 2 classification.                                                                                                                    |
| `consecutiveBlockThreshold`             | `number`                | `3`                                    | Consecutive blocks allowed before routing to human review.                                                                                                              |
| `ntfyServer`                            | `string`                | `"https://ntfy.sh"`                    | Ntfy push broker URL for public or self-hosted servers.                                                                                                                 |
| `ntfyTopic`                             | `string`                | `undefined`                            | Topic name required to enable ntfy push notifications; `<topic>-response` carries replies. When unset, AutoGate disables ntfy and falls back to native host UI prompts. |
| `ntfyToken`                             | `string`                | `undefined`                            | Optional bearer token for authenticated ntfy topics.                                                                                                                    |
| `ntfyVerbosity`                         | `"normal" \| "verbose"` | `"normal"`                             | Notification detail level; `"verbose"` adds specs, cascade trace, reasoning, and trust boundaries.                                                                      |
| `notifyOnVerdict`                       | `boolean`               | `true`                                 | Send informational ntfy alerts on `ALLOW` and `BLOCK` verdicts.                                                                                                         |
| `reviewFallbackMode`                    | `"native" \| "ntfy"`           | `"ntfy"`                               | Fallback review channel when `ntfyTopic` is set, using remote ntfy push or a native terminal prompt.                                                                    |
| `evalDbFile`                            | `string`                       | `"~/.config/autogate/evals.db"`        | SQLite WAL database path (`AUTOGATE_EVAL_DB`) for evaluation decisions, cascade traces, and zstd-compressed System 2 session transcripts.                               |
| `evalSessionCleanup`                    | `"export-and-delete" \| "archive"` | `"export-and-delete"`              | Cleanup policy (`AUTOGATE_EVAL_SESSION_CLEANUP`) for OpenCode System 2 evaluation sessions after export into `evals.db` (`"export-and-delete"` or `"archive"`).         |
| `serverUrl`                             | `string`                | `"http://localhost:4096"`              | OpenCode server URL; defaults to port `4097` when `OPENCODE_CONFIG_DIR` targets `opencode1` or `opencode2`.                                                             |
| `environment.trustedDomains`            | `string[]`              | `[]`                                   | Domains trusted for outbound network actions.                                                                                                                           |
| `environment.trustedGitRemotes`         | `string[]`              | `["origin"]`                           | Git remotes trusted for push and remote commands.                                                                                                                       |
| `environment.trustedPaths`              | `string[]`              | `["~/Projects"]`                       | Filesystem paths treated as trusted workspace roots.                                                                                                                    |
| `systemOne.enabled`                     | `boolean`               | `false`                                | Enable the System 1 decision router and System 2 cascade evaluator.                                                                                                     |
| `systemOne.executionMode`               | `"race" \| "cascade"`   | `"race"`                               | `"race"` runs System 1 and System 2 in parallel; `"cascade"` runs System 1 first.                                                                                       |
| `systemOne.endpoint`                    | `string`                | `"http://127.0.0.1:4006/v1/systemone"` | HTTP endpoint for System 1 inference, or `AUTOGATE_SYSTEM_ONE_ENDPOINT`.                                                                                                |
| `systemOne.model`                       | `string`                | `"gemini-decision-1"`                  | System 1 model ID, or `AUTOGATE_SYSTEM_ONE_MODEL`.                                                                                                                      |
| `systemOne.apiKey`                      | `string`                | `undefined`                            | Optional bearer token for System 1 requests, or `AUTOGATE_SYSTEM_ONE_API_KEY`.                                                                                          |
| `systemOne.timeoutMs`                   | `number`                | `4000`                                 | Timeout in milliseconds for System 1 inference, or `AUTOGATE_SYSTEM_ONE_TIMEOUT_MS`.                                                                                    |
| `systemOne.thresholds.allowMinProb`     | `number`                | `0.92`                                 | Minimum `ALLOW` probability required for System 1 to accept without System 2.                                                                                           |
| `systemOne.thresholds.blockMinProb`     | `number`                | `0.85`                                 | Minimum `BLOCK` probability required for System 1 to accept without System 2.                                                                                           |
| `systemOne.thresholds.minOddsRatio`     | `number`                | `4.0`                                  | Minimum winner-to-loser probability ratio required to accept System 1.                                                                                                  |
| `systemOne.thresholds.minInScopeNoul`   | `number`                | `0.7`                                  | Minimum `in_scope` score required before escalating to System 2.                                                                                                        |
| `systemOne.thresholds.maxInjectionNoul` | `number`                | `0.5`                                  | Maximum `injection_risk` score allowed before escalating to System 2.                                                                                                   |
| `paseo`                                 | `object`                | `{}`                                   | Paseo settings, including `timelineBadges`, `evaluatorProvider`, `useDirectApi`, and `notifyOnVerdict`.                                                                 |
| `paseo.timelineBadges`                  | `boolean`               | `true`                                 | Render `kind: "autogate-eval"` audit cards on the Paseo timeline.                                                                                                       |
| `paseo.evaluatorProvider`               | `string`                | `undefined`                            | Provider or model string for Paseo native evaluation, such as `"omp"` or `"antigravity"`.                                                                               |
| `paseo.useDirectApi`                    | `boolean`               | `false`                                | Use `DirectApiEvaluator` instead of Paseo agent creation.                                                                                                               |
| `opencode`                              | `object`                       | `{}`                                   | OpenCode settings, including `serverUrl`, `evalDbFile`, and `evalSessionCleanup`.                                                                                       |
| `omp`                                   | `object`                       | `{}`                                   | Oh My Pi settings, including `reviewFallbackMode` and `evalDbFile`.                                                                                                     |

---

## Mobile approvals with ntfy

> [!WARNING]
> Public ntfy topics have no access control unless your server enforces authentication. Do not use a guessable topic name like `"autogate"` on a public broker, because anyone listening on that channel can view proposed commands and approve them.

1. Install the **ntfy** app on iOS or Android, or open the web client for your ntfy server.
2. Subscribe to your high-entropy topic, such as `autogate-9f3c7a2e4b8d1e6f`.
3. If your server requires authentication, add your `ntfyToken` in the app.

When AutoGate returns `UNSURE`, your phone receives a push notification showing the tool name, target command or path, and classifier reason, along with **Allow** and **Deny** action buttons. Tapping a button sends your reply over the outbound SSE reverse webhook without requiring open inbound ports. If you answer in your desktop UI first, AutoGate updates the mobile notification to mark it resolved.

Set `"ntfyVerbosity": "verbose"` in `config.json` to include Target and Execution Specs, Evaluation Risk, Authorization, Cascade trace, Model Reasoning, Context and Hierarchy, and Trust Boundaries in each notification, and to keep that context below status updates after resolution.

---

## Architecture details

### Core components

1. **Core security engine in `@autogate/core`.** Consumes standardized `GateAction` objects with zero runtime dependencies on host SDKs. Runs target script probing via `probeTargetContext`, shell and base64 payload de-obfuscation via `deobfuscatePayload`, per-turn `ALLOW` caching, `escalate_permission` pattern matching, and the consecutive-block circuit breaker.
2. **Two-system cascade in `SystemOneEvaluator` and `CascadeEvaluator`.** Pairs a fast System 1 decision router, such as `gemini-decision-1`, with the deep System 2 LLM classifier defined in `packages/core/agents/auto-gate-eval.md`.
3. **Host adapters.** Translate host permission hooks, message transcripts, and subagent session trees into `GateAction` requests across `@autogate/opencode` for OpenCode v2, `@autogate/opencode1` for OpenCode v1, `@autogate/paseo` for Paseo, and `@autogate/omp` for Oh My Pi.
4. **Dual-channel review bridge in `NtfyAdapter`.** Shows native host permission dialogs while publishing ntfy push notifications and listening for mobile replies over SSE.

### Two-system cascade

When `systemOne.enabled` is `true`, `AutoGateCoreEngine` wraps its System 2 evaluator inside `CascadeEvaluator`.

- **Compact System 1 state.** `buildSystemOneStateWithMeta` packs bounded context into the System 1 request: up to 4096 bytes of user prompt, 2048 bytes of subagent task, bounded action fields (4096 bytes each for command and raw args, 2048 bytes for patterns, and 1024 bytes for target path), 2048 bytes of de-obfuscated payload, and 2048 bytes of probe excerpt. If an action field, de-obfuscated payload, or probe excerpt exceeds its cap (or includes a `[Truncated:` probe notice), System 1 sets `truncatedPayload` and escalates to System 2 without making an HTTP call.
- **Three System 1 signals.** `SystemOneEvaluator` sends `POST /v1/systemone` with three questions: `verdict` for `ALLOW` and `BLOCK` probabilities, `in_scope` as a `noul` score for whether the action is unambiguously routine or catastrophic from state alone, and `injection_risk` as a `noul` score for prompt injection, policy overrides, obfuscated payloads, or subagent override attempts.
- **Execution modes.** In `race` mode, System 1 and System 2 start in parallel with separate `AbortController` instances; if System 1 passes all policy gates first, `CascadeEvaluator` aborts System 2 and returns System 1's verdict. If System 1 escalates or System 2 finishes first, the in-flight System 2 call resolves the action, re-running System 2 if context drift occurred. In `cascade` mode, System 1 runs first and invokes System 2 only on escalation.
- **Fail-safe escalation gates.** System 1 never emits `UNSURE` directly. `evaluateCascadePolicy` escalates to System 2 on transport errors, timeouts, invalid output, truncated payloads, SHA-256 context fingerprint drift with reason `context_drifted`, `injection_risk >= maxInjectionNoul`, `in_scope < minInScopeNoul`, winner probability below `allowMinProb` or `blockMinProb`, or winner-to-loser odds ratio below `minOddsRatio`.
- **System 1 outage circuit breaker.** After 3 consecutive transport failures from timeouts, network errors, or HTTP 401, 403, 429, or 5xx responses, `CascadeEvaluator` opens a 30-second cooldown and routes directly to System 2 with reason `s1_circuit_open`.
- **Offline calibration.** Run `bun run eval:cascade` (or pass `-- --datasets synthetic,historical` / `-- --file <path>` to include historical evaluations in `evals.db` or legacy JSONL eval logs) to sweep `allowMinProb`, `blockMinProb`, and `minInScopeNoul` across synthetic injection or out-of-distribution cases and historical logs, producing Pareto curves of accuracy against the System 2 escalation rate.
- **SQLite migration.** Run `bun run scripts/migrate-to-sqlite.ts --dry-run` (and omit `--dry-run` to import, optionally with `--delete-opencode-sessions --vacuum`) to idempotently import legacy JSONL audit logs and historical `[auto-gate-eval]` sessions from `opencode.db` into `evals.db`.

### Paseo native evaluation

In Paseo, `PaseoNativeEvaluator` runs System 2 classification inside the host daemon instead of requiring external API keys.

- **Provider reuse.** Discovers and reuses host-configured models, corporate proxies, and `metadataGeneration` providers from Paseo.
- **Sandbox isolation.** Spawns ephemeral evaluator agents with `parent: undefined`, isolated scratch directory `/tmp/autogate-eval`, `autoArchive: true`, and `notifyOnFinish: false`.
- **Active tool denial and mode locking.** Runs evaluator agents with `modeId: "ask"` and omits `toolPolicy`; if an evaluator attempts any tool call, AutoGate denies it with `behavior: "deny"`.
- **Non-blocking dual-channel review.** On `UNSURE`, AutoGate returns from `agent.permission_requested` in under 10ms to avoid Paseo's 30-second IPC hook timeout, sends the ntfy push in the background, and lets Paseo show its desktop dialog with first-response-wins protection.
- **Timeline audit badges.** Writes read-only `kind: "autogate-eval"` cards to the Paseo session timeline showing verdict, risk level, and rationale.
- **Direct API fallback.** Uses `DirectApiEvaluator` as a fallback or whenever `paseo.useDirectApi` is `true`.

### OpenCode runtime sync

At startup, `@autogate/opencode` reads `packages/core/agents/auto-gate-eval.md` via `loadEvalAgentDefinition` and injects the `auto-gate-eval` agent along with `classify_result` and `escalate_permission` tools at runtime. `OpenCodeRuntimeSync` writes per-instance state snapshots under `<configDir>/runtime/` and watches `config.json` and `control.json` for live `autoMode` or fallback toggles and circuit-breaker resets.

---

## Development and testing

Run the full test suite and static checks:

```bash
bun test
bun run typecheck
bun run lint
bun run format:check
```

Run targeted suites or the cascade calibration script:

```bash
# Core unit tests: System 1, cascade policy, engine, agent parser, prober
bun test packages/core/test/

# OpenCode v2 and v1 unit tests
bun test packages/opencode/test/ packages/opencode1/test/

# Paseo unit and blackbox E2E tests
bun test packages/paseo/test/ test/e2e/paseo/

# OpenCode and Oh My Pi E2E tests
bun test test/e2e/opencode/ test/e2e/omp/

# Sweep System 1 cascade thresholds
bun run eval:cascade --dry-run
```

---

## Repository layout

```text
autogate/
├── packages/
│   ├── core/
│   │   ├── agents/       # auto-gate-eval.md System 2 agent definition
│   │   └── src/          # Core engine, System 1 router, cascade, prober, ntfy client
│   ├── paseo/            # Paseo daemon plugin and request inspector
│   ├── opencode/         # OpenCode v2 plugin adapter and runtime sync
│   ├── opencode1/        # OpenCode v1 plugin adapter
│   └── omp/              # Oh My Pi extension, slash commands, and approval bridge
├── scripts/
│   ├── eval-cascade.ts       # Offline System 1 cascade threshold evaluator
│   └── migrate-to-sqlite.ts  # Idempotent JSONL & OpenCode DB importer to evals.db
├── test/
│   └── e2e/
│       ├── paseo/        # RealPaseoHarness and Paseo blackbox E2E tests
│       ├── opencode/     # OpenCode blackbox E2E tests
│       └── omp/          # Oh My Pi blackbox E2E tests
├── bun.lock
├── package.json
└── tsconfig.json
```

---

## License

MIT
