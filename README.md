# AutoGate

Autonomous security gatekeeper and dual-channel permission review engine for AI coding agents.

AutoGate acts as an intelligent security boundary between autonomous coding agents and your development environment. It intercepts proposed tool calls and shell actions, evaluates their risk and alignment with user intent using an LLM classifier, automatically permits benign actions, blocks destructive operations with safe-transform guidance, and delegates ambiguous actions to both your host UI and your mobile phone via interactive push notifications.

---

## Architecture

```
                      +-----------------------------+
                      |   AI Coding Agent / Host    |
                      |  (Paseo / OpenCode / OMP)   |
                      +--------------+--------------+
                                     |
                          Tool / Action Request
                                     |
                                     v
                      +-----------------------------+
                      |       Harness Adapter       |
                      |   (@autogate/paseo, etc.)   |
                      +--------------+--------------+
                                     |
                                     v
                      +-----------------------------+
                      |     AutoGate Core Engine    |
                      |       (@autogate/core)      |
                      +--------------+--------------+
                                     |
                         Autonomous Classification
                                     |
              +----------------------+----------------------+
              |                      |                      |
              v                      v                      v
          [ ALLOW ]              [ BLOCK ]              [ UNSURE ]
          Execute         [SAFE_TRANSFORM_REJECT]       Dual-Channel Review
          silently        Feedback to Agent for         +---------------------+
                          self-correction               | Host UI Dialog      |
                                                        |        AND          |
                                                        | Ntfy Phone Push     |
                                                        +----------+----------+
                                                                   |
                                                            First response
                                                            resolves request
```

AutoGate operates across three main components:

1. **Host-Agnostic Core Security Engine (`@autogate/core`)**: Pure, decoupled security engine that consumes standardized `GateAction` contracts and evaluates safety policies without any runtime dependency on host SDKs or APIs. Contains zero host client references, loose `any` types, or host session traversal logic.
2. **Harness Adapters**: Native host adapters translating host-specific permission lifecycles, message transcripts, and subagent session hierarchies into standardized `GateAction` structures:
   - **`@autogate/opencode`**: Plugin for OpenCode intercepting tool execution requests and permission events. Encapsulates session tree traversal, subagent prompt extraction, and ephemeral evaluation session lifecycle under strict TypeScript contracts (`OpenCodePromptResolver`, `OpenCodeSessionClient`).
   - **`@autogate/paseo`**: Daemon plugin for Paseo (`>=0.8.0`) intercepting `agent.permission_requested`. Protects all agent providers (OMP, Claude, Codex, Antigravity) running inside Paseo using `PaseoNativeEvaluator` with host provider reuse, strict sandbox isolation, and UI timeline audit badges.
   - **`@autogate/omp`**: Extension for Oh My Pi (OMP) providing shadowed tool interception and terminal fallback options.
3. **Dual-Channel Review Bridge (`NtfyAdapter`)**: Concurrently presents permission prompts in the active host interface while dispatching push notifications with action buttons to an [ntfy](https://ntfy.sh) topic. A reverse webhook listener over an outbound SSE connection receives mobile tap responses with no open inbound ports required.

---

## Decision Model

Every action intercepted by AutoGate produces one of three verdicts:

- **`ALLOW`**: Low-risk, non-destructive actions aligned with current instructions (reading files, executing standard build commands, running tests, inspecting git status). Executes immediately without human interruption.
- **`BLOCK`**: Dangerous, destructive, or out-of-scope actions (arbitrary filesystem deletion like `rm -rf /`, pushing with `--force` to protected branches, overwriting system files). Injects a structured `[SAFE_TRANSFORM_REJECT]` advice string back to the agent so it can self-correct and execute a safe alternative.
- **`UNSURE`**: Sensitive or high-impact actions (database migrations, deploying services, changing global package configurations, untrusted remote scripts). Dispatches a dual-channel review request.

---

## Configuration

AutoGate uses a single canonical configuration file located at `~/.config/autogate/config.json` (or `$XDG_CONFIG_HOME/autogate/config.json`).

### Example Configuration

```json
{
  "autoMode": true,
  "classifierModel": "google/gemini-3.5-flash-lite",
  "classifierTimeout": 45000,
  "ntfyServer": "https://ntfy.sh",
  "ntfyTopic": "my-secure-autogate-topic",
  "ntfyToken": "tk_your_ntfy_auth_token",
  "consecutiveBlockThreshold": 3,
  "environment": {
    "trustedDomains": ["github.com", "npmjs.org"],
    "trustedGitRemotes": ["origin"],
    "trustedPaths": ["/home/user/Projects"]
  },
  "paseo": {
    "timelineBadges": true,
    "evaluatorProvider": "omp",
    "useDirectApi": false,
    "notifyOnVerdict": false
  },
  "opencode": {
    "serverUrl": "http://127.0.0.1:4096"
  },
  "omp": {
    "reviewFallbackMode": "ntfy"
  }
}
```

### Configuration Options

| Field | Type | Default | Description |
|---|---|---|---|
| `autoMode` | `boolean` | `true` | When enabled, runs autonomous classifier before requesting human review. |
| `classifierModel` | `string` | `"google/gemini-3.5-flash-lite"` | Model ID used for security classification. |
| `classifierTimeout` | `number` | `45000` | Timeout in milliseconds for classification inference. |
| `ntfyServer` | `string` | `"https://ntfy.sh"` | Ntfy push broker URL (supports public or self-hosted instances). |
| `ntfyTopic` | `string` | `"autogate"` | Secret topic name for push notifications. |
| `ntfyToken` | `string` | `undefined` | Optional bearer token for authenticated ntfy topics. |
| `consecutiveBlockThreshold` | `number` | `3` | Maximum consecutive blocks before halting an agent. |
| `paseo` | `object` | `{}` | Settings specific to the Paseo harness (see table below). |
| `paseo.timelineBadges` | `boolean` | `true` | Whether to render audit cards (`kind: "autogate-eval"`) on the agent's Paseo timeline. |
| `paseo.evaluatorProvider` | `string` | `undefined` | Provider or model identifier for native evaluation (e.g. `"omp"`, `"antigravity"`). Defaults to host metadata generation provider or `"omp"`. |
| `paseo.useDirectApi` | `boolean` | `false` | Force using DirectApiEvaluator instead of Paseo agent creation. |
| `opencode` | `object` | `{}` | Settings specific to the OpenCode harness. |
| `omp` | `object` | `{}` | Settings specific to the Oh My Pi harness. |

---

## Installation & Setup

### Prerequisites

- [Bun](https://bun.sh) (v1.1+ or v1.4+)
- An API key for the classifier model (`AUTOGATE_API_KEY`, `GEMINI_API_KEY`, or `GOOGLE_API_KEY`)
- (Optional) An [ntfy](https://ntfy.sh) client app installed on your iOS or Android device

### Repository Setup

```bash
git clone https://github.com/chen-ye/autogate.git
cd autogate
bun install
```

### Harness Integration

#### 1. Paseo Daemon Plugin (`@autogate/paseo`)

Install the local plugin directly into your Paseo daemon:

```bash
paseo plugin install /absolute/path/to/autogate/packages/paseo
```

Verify that the plugin is running:

```bash
paseo plugin ls
```

To view plugin logs:

```bash
paseo plugin logs autogate
```

##### Paseo Native Evaluation Architecture

In Paseo environments, AutoGate utilizes `PaseoNativeEvaluator` instead of relying on external API calls:

- **Provider Reuse (No Parallel Pipeline)**: Discovers and reuses host-configured models and corporate proxies from Paseo (such as enterprise LLM gateways or configured `metadataGeneration` models). This eliminates the need for `AUTOGATE_API_KEY` or separate inference endpoints in enterprise environments.
- **Strict Security Isolation**: Spawns ephemeral evaluation agents with zero parentage (`parent: undefined`), isolated scratch directory (`/tmp/autogate-eval`), `autoArchive: true`, and `notifyOnFinish: false`. The evaluator agent cannot mutate files or leak subagent messages to the target agent.
- **Active Tool Denial & Recursion Guard**: Evaluator sessions are strictly forbidden from executing tools. If an evaluator session ever attempts a tool call, AutoGate actively and immediately rejects it with `behavior: "deny"` and message `"AutoGate Security: Evaluator sessions are strictly forbidden from executing tools."`.
- **Mode Locking (`modeId: "ask"`)**: Evaluator sessions explicitly run with `modeId: "ask"`, preventing providers from defaulting to unattended `full` (yolo) mode where tool execution could bypass permission checks. Evaluator agents omit `toolPolicy` so providers avoid unsupported preapproval errors while enforcing interactive permission gates.
- **Non-Blocking Concurrent Dual-Channel Review**: On `UNSURE` decisions in Paseo, AutoGate returns from `agent.permission_requested` in `< 10ms`, completely eliminating Paseo's 30-second IPC hook timeout. AutoGate dispatches the Ntfy push notification asynchronously in the background while Paseo displays its native approval dialog on desktop. The user can approve or deny from either the desktop UI or their phone via Ntfy, with first-response-wins semantics and race-free double-resolution protection.
- **UI Timeline Badges**: Injects read-only audit cards into the agent's Paseo UI timeline (`kind: "autogate-eval"`). Operators and users can inspect the classifier verdict, risk level, and rationale directly in the Paseo session interface.
- **Backwards Compatibility**: Supports `DirectApiEvaluator` as a fallback or directly when `useDirectApi: true` is configured or in standalone mock environments.

#### 2. OpenCode Plugin (`@autogate/opencode`)

Register `@autogate/opencode` in your OpenCode configuration (`~/.config/opencode/opencode.json` or `.opencode/plugins/`):

```json
{
  "plugins": [
    "/absolute/path/to/autogate/packages/opencode"
  ]
}
```

#### 3. Oh My Pi Extension (`@autogate/omp`)

Add the extension to `~/.omp/agent/config.yml`:

```yaml
extensions:
  - /absolute/path/to/autogate/packages/omp/src/index.ts
```

*Note: If you run OMP agents through Paseo, Paseo's `@autogate/paseo` plugin handles gatekeeping globally. In that case, comment out the OMP extension in `~/.omp/agent/config.yml` to prevent duplicate evaluations.*

---

## Mobile Approvals via Ntfy

1. Install the **ntfy** app on your phone (iOS / Android) or use the web app at `https://ntfy.sh`.
2. Subscribe to your configured topic (e.g. `my-secure-autogate-topic`).
3. If using a private or rate-limited server, configure your authentication token in the app.
4. When AutoGate detects an `UNSURE` operation:
   - Your phone receives a push notification displaying the tool name, command/path, and classifier reason.
   - Action buttons **Allow** and **Deny** appear directly on the notification.
   - Tapping either button sends a response back to the reverse webhook, resolving the agent prompt instantly.
   - If you approve or deny in your desktop terminal first, the pending mobile notification is marked resolved automatically.

---

## Development & Testing

AutoGate includes unit tests, evaluator benchmarks, and zero-mock blackbox integration tests against live runtime binaries and brokers.

Run all tests:

```bash
bun test
```

Run specific test suites:

```bash
# Core unit tests
bun test packages/core/test/

# Paseo unit and blackbox E2E tests
bun test packages/paseo/test/ test/e2e/paseo/

# OpenCode E2E tests
bun test test/e2e/opencode/

# OMP E2E tests
bun test test/e2e/omp/
```

---

## Monorepo Structure

```
autogate/
├── packages/
│   ├── core/         # Core engine, classifier prompt, Ntfy client, types
│   ├── paseo/        # Paseo daemon plugin and request inspector
│   ├── opencode/     # OpenCode plugin adapter
│   └── omp/          # Oh My Pi extension and approval bridge
├── test/
│   └── e2e/
│       ├── paseo/    # RealPaseoHarness and Paseo blackbox E2E tests
│       ├── opencode/ # OpenCode blackbox E2E tests
│       └── omp/      # OMP blackbox E2E tests
├── bun.lock
├── package.json
└── tsconfig.json
```

---

## License

MIT
