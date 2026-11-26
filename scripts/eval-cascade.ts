#!/usr/bin/env bun
import fs from "node:fs";
import path from "node:path";
import {
  CascadeEvaluator,
  DEFAULT_SYSTEM_ONE_ENDPOINT,
  DEFAULT_SYSTEM_ONE_MODEL,
  DEFAULT_SYSTEM_ONE_THRESHOLDS,
  DEFAULT_SYSTEM_ONE_TIMEOUT_MS,
  SystemOneEvaluator,
  buildClassifierUserPrompt,
  buildSystemOneRequestPayload,
  computeContextFingerprint,
  evaluateCascadePolicy,
  getDefaultClassifierModel,
  loadConfig,
  type ClassifierResult,
  type FetchLike,
  type GateAction,
  type GateEvaluator,
  type SystemOneConfig,
  type SystemOneExecutionMode,
  type SystemOneOutcome,
  type SystemOneRawEvaluator,
  type SystemOneThresholds,
} from "../packages/core/src/index.js";
import { loadBenchDatasets, type LoadDatasetsOptions } from "./bench/adapters/index.js";
import {
  fetchDatasets,
  getDatasetSnapshotDir,
  resolveBenchCacheRoot,
  type FetchedDatasetResult,
} from "./bench/fetch.js";
import {
  DEFAULT_BENCH_SEED,
  computeBenchmarkSummary,
  evaluateS1ParetoGrid,
  isEvaluatorErrorReason,
  sampleBenchCases,
  type BenchEvalRecord,
  type EvalMode,
} from "./bench/metrics.js";
import { OpenCodeS2Runner, type OpenCodeS2RunnerOptions } from "./bench/opencode-s2-runner.js";
import { projectOpenCodeBenchCase } from "./bench/opencode-v2-events.js";
import { expandHomePath, formatHomePath } from "./bench/paths.js";
import {
  buildBenchmarkArtifact,
  compareBenchmarkArtifacts,
  computePromptProvenance,
  evaluateRegressionCheck,
  formatBenchmarkMarkdown,
  loadBenchmarkArtifact,
  writeBenchmarkArtifact,
  type BenchmarkComparison,
  type BenchmarkRunArtifact,
  type RegressionCheckResult,
  type WriteBenchmarkArtifactResult,
} from "./bench/report.js";
import {
  ALL_BENCH_DATASET_IDS,
  EXTERNAL_BENCH_DATASET_IDS,
  type BenchDatasetId,
  type DatasetManifest,
  type StaticBenchCase,
} from "./bench/schema.js";

const VALID_MODES: ReadonlySet<EvalMode> = new Set(["s1", "s2", "cascade", "race"]);
const VALID_DATASETS: ReadonlySet<string> = new Set(ALL_BENCH_DATASET_IDS);

export interface EvalCliOptions {
  readonly datasets: readonly BenchDatasetId[];
  readonly mode: EvalMode;
  readonly limit?: number;
  readonly seed: number;
  readonly concurrency: number;
  readonly classifierModel: string;
  readonly classifierTimeoutMs?: number;
  readonly s1Endpoint: string;
  readonly s1Model: string;
  readonly s1ApiKey?: string;
  readonly s1TimeoutMs: number;
  readonly s1Thresholds: SystemOneThresholds;
  readonly file?: string;
  readonly cacheDir?: string;
  readonly out?: string;
  readonly compare?: string;
  readonly check: boolean;
  readonly dryRun: boolean;
  readonly fetchOnly: boolean;
  readonly offlineOnly: boolean;
  readonly steerbenchAll: boolean;
  readonly help: boolean;
}

export interface RunEvalCascadeDeps {
  readonly s1Evaluator?: SystemOneRawEvaluator;
  readonly s2Evaluator?: GateEvaluator;
  readonly mockProvider?: OpenCodeS2RunnerOptions["mockProvider"];
  readonly fetchImpl?: FetchLike;
  readonly loadDatasets?: typeof loadBenchDatasets;
  readonly fetchDatasets?: typeof fetchDatasets;
  readonly log?: (line: string) => void;
  readonly warn?: (line: string) => void;
}

export interface RunEvalCascadeResult {
  readonly kind: "help" | "fetch" | "dry-run" | "eval";
  readonly options: EvalCliOptions;
  readonly fetched?: Partial<Record<BenchDatasetId, FetchedDatasetResult>>;
  readonly totalLoadedCases?: number;
  readonly sampledCases?: readonly StaticBenchCase[];
  readonly records?: readonly BenchEvalRecord[];
  readonly artifact?: BenchmarkRunArtifact;
  readonly comparison?: BenchmarkComparison;
  readonly checkResult?: RegressionCheckResult;
  readonly artifactPath?: WriteBenchmarkArtifactResult;
}

interface ProjectedBenchCase {
  readonly testCase: StaticBenchCase;
  readonly action: GateAction;
}

export function formatEvalCliHelp(): string {
  return [
    "AutoGate OpenCode v2 Parity Benchmark Runner",
    "",
    "Usage: bun run scripts/eval-cascade.ts [options]",
    "",
    "Options:",
    "  --datasets <list>          Comma-separated datasets: synthetic,historical,shellrisk,",
    "                             nl2sh-redcode,authgate,tsbench,steerbench (or all, external)",
    "  --mode <mode>              Evaluation mode: s1 | s2 | cascade | race (default: s1)",
    "  --limit <n>                Deterministic stratified/pair-aware sample size per dataset",
    `  --seed <n>                 Deterministic RNG seed (default: ${DEFAULT_BENCH_SEED})`,
    "  --concurrency <n>          Worker concurrency (default: 8 for s1, 4 for s2|cascade|race)",
    "  --classifier-model <id>    System 2 OpenCode classifier model override",
    "  --s1-endpoint <url>        System 1 HTTP endpoint URL",
    "  --s1-model <id>            System 1 model ID",
    "  --s1-api-key <key>         System 1 Bearer API key",
    "  --s1-timeout <ms>          System 1 request timeout in milliseconds",
    "  --classifier-timeout <ms>  System 2 classifier timeout in milliseconds",
    "  --file <path>              Historical eval SQLite DB (.db / :memory:) or JSONL eval log path",
    "  --cache-dir <dir>          Dataset cache directory (default: ~/.cache/autogate/bench)",
    "  --out <path>               Output artifact JSON path",
    "  --compare <path>           Baseline artifact JSON path for diffing and regression checks",
    "  --check                    Enforce regression gates and exit 1 on violation",
    "  --dry-run                  Load, sample, project cases, verify prompt parity & preview",
    "  --fetch-only               Fetch & SHA-256 verify external datasets and print manifests",
    "  --offline-only             Fail on dataset cache miss instead of downloading",
    "  --steerbench-all           Include all SteerBench domains instead of dev/eng/sec subset",
    "  --help, -h                 Show this help message",
  ].join("\n");
}

function parseDatasetList(raw: string): BenchDatasetId[] {
  const parts = raw
    .split(",")
    .map((item) => item.trim())
    .filter((item) => item.length > 0);
  if (parts.length === 0) {
    throw new Error("--datasets requires at least one dataset name");
  }

  const out: BenchDatasetId[] = [];
  const seen = new Set<BenchDatasetId>();
  const add = (id: BenchDatasetId) => {
    if (!seen.has(id)) {
      seen.add(id);
      out.push(id);
    }
  };

  for (const part of parts) {
    if (part === "all") {
      for (const id of ALL_BENCH_DATASET_IDS) add(id);
    } else if (part === "external") {
      for (const id of EXTERNAL_BENCH_DATASET_IDS) add(id);
    } else if (VALID_DATASETS.has(part)) {
      add(part as BenchDatasetId);
    } else {
      throw new Error(
        `Unknown dataset "${part}". Valid datasets: ${ALL_BENCH_DATASET_IDS.join(", ")}`,
      );
    }
  }

  return out;
}

function parseIntegerArg(raw: string, flag: string, min?: number): number {
  if (!/^-?\d+$/.test(raw.trim())) {
    throw new Error(`Invalid ${flag} value "${raw}": expected an integer`);
  }
  const value = Number(raw.trim());
  if (!Number.isSafeInteger(value)) {
    throw new Error(`Invalid ${flag} value "${raw}": integer out of range`);
  }
  if (min !== undefined && value < min) {
    throw new Error(`Invalid ${flag} value "${raw}": must be >= ${min}`);
  }
  return value;
}

function parsePositiveNumberArg(raw: string, flag: string): number {
  const trimmed = raw.trim();
  if (!trimmed) {
    throw new Error(`Invalid ${flag} value: expected a positive number`);
  }
  const value = Number(trimmed);
  if (!Number.isFinite(value) || value <= 0) {
    throw new Error(`Invalid ${flag} value "${raw}": expected a positive number`);
  }
  return value;
}

export function parseEvalCliArgs(argv: readonly string[]): EvalCliOptions {
  const config = loadConfig();

  let datasetsExplicit: BenchDatasetId[] | undefined;
  let mode: EvalMode = "s1";
  let limit: number | undefined;
  let seed = DEFAULT_BENCH_SEED;
  let concurrencyExplicit: number | undefined;
  let classifierModel = config.classifierModel || getDefaultClassifierModel();
  let classifierTimeoutMs = config.classifierTimeout;
  let s1Endpoint = config.systemOne?.endpoint || DEFAULT_SYSTEM_ONE_ENDPOINT;
  let s1Model = config.systemOne?.model || DEFAULT_SYSTEM_ONE_MODEL;
  let s1ApiKey = config.systemOne?.apiKey;
  let s1TimeoutMs = config.systemOne?.timeoutMs || DEFAULT_SYSTEM_ONE_TIMEOUT_MS;
  const s1Thresholds = config.systemOne?.thresholds ?? DEFAULT_SYSTEM_ONE_THRESHOLDS;
  let file: string | undefined;
  let cacheDir: string | undefined;
  let out: string | undefined;
  let compare: string | undefined;
  let check = false;
  let dryRun = false;
  let fetchOnly = false;
  let offlineOnly = false;
  let steerbenchAll = false;
  let help = false;

  const readValue = (index: number, flag: string, inlineVal?: string): [string, number] => {
    if (inlineVal !== undefined) {
      if (inlineVal.length === 0) {
        throw new Error(`Missing value for ${flag}`);
      }
      return [inlineVal, index];
    }
    if (index + 1 >= argv.length) {
      throw new Error(`Missing value for ${flag}`);
    }
    return [argv[index + 1], index + 1];
  };

  for (let i = 0; i < argv.length; i++) {
    const rawArg = argv[i];
    const eqIdx = rawArg.indexOf("=");
    const flag = eqIdx > 0 && rawArg.startsWith("--") ? rawArg.slice(0, eqIdx) : rawArg;
    const inlineVal = eqIdx > 0 && rawArg.startsWith("--") ? rawArg.slice(eqIdx + 1) : undefined;

    switch (flag) {
      case "--help":
      case "-h":
        if (inlineVal !== undefined) {
          throw new Error(`Flag ${flag} does not accept a value`);
        }
        help = true;
        break;
      case "--datasets": {
        const [val, nextIdx] = readValue(i, flag, inlineVal);
        i = nextIdx;
        datasetsExplicit = parseDatasetList(val);
        break;
      }
      case "--mode": {
        const [val, nextIdx] = readValue(i, flag, inlineVal);
        i = nextIdx;
        if (!VALID_MODES.has(val as EvalMode)) {
          throw new Error(`Invalid --mode "${val}". Expected one of: s1, s2, cascade, race`);
        }
        mode = val as EvalMode;
        break;
      }
      case "--limit": {
        const [val, nextIdx] = readValue(i, flag, inlineVal);
        i = nextIdx;
        limit = parseIntegerArg(val, "--limit", 0);
        break;
      }
      case "--seed": {
        const [val, nextIdx] = readValue(i, flag, inlineVal);
        i = nextIdx;
        seed = parseIntegerArg(val, "--seed");
        break;
      }
      case "--concurrency": {
        const [val, nextIdx] = readValue(i, flag, inlineVal);
        i = nextIdx;
        concurrencyExplicit = parseIntegerArg(val, "--concurrency", 1);
        break;
      }
      case "--classifier-model": {
        const [val, nextIdx] = readValue(i, flag, inlineVal);
        i = nextIdx;
        if (!val.trim()) throw new Error("Invalid --classifier-model: cannot be empty");
        classifierModel = val.trim();
        break;
      }
      case "--classifier-timeout": {
        const [val, nextIdx] = readValue(i, flag, inlineVal);
        i = nextIdx;
        classifierTimeoutMs = parsePositiveNumberArg(val, "--classifier-timeout");
        break;
      }
      case "--s1-endpoint": {
        const [val, nextIdx] = readValue(i, flag, inlineVal);
        i = nextIdx;
        if (!val.trim()) throw new Error("Invalid --s1-endpoint: cannot be empty");
        s1Endpoint = val.trim();
        break;
      }
      case "--s1-model": {
        const [val, nextIdx] = readValue(i, flag, inlineVal);
        i = nextIdx;
        if (!val.trim()) throw new Error("Invalid --s1-model: cannot be empty");
        s1Model = val.trim();
        break;
      }
      case "--s1-api-key": {
        const [val, nextIdx] = readValue(i, flag, inlineVal);
        i = nextIdx;
        s1ApiKey = val;
        break;
      }
      case "--s1-timeout": {
        const [val, nextIdx] = readValue(i, flag, inlineVal);
        i = nextIdx;
        s1TimeoutMs = parsePositiveNumberArg(val, "--s1-timeout");
        break;
      }
      case "--file": {
        const [val, nextIdx] = readValue(i, flag, inlineVal);
        i = nextIdx;
        if (!val.trim()) throw new Error("Invalid --file: cannot be empty");
        file = val.trim() === ":memory:" ? ":memory:" : path.resolve(expandHomePath(val.trim()));
        break;
      }
      case "--cache-dir": {
        const [val, nextIdx] = readValue(i, flag, inlineVal);
        i = nextIdx;
        if (!val.trim()) throw new Error("Invalid --cache-dir: cannot be empty");
        cacheDir = path.resolve(expandHomePath(val.trim()));
        break;
      }
      case "--out": {
        const [val, nextIdx] = readValue(i, flag, inlineVal);
        i = nextIdx;
        if (!val.trim()) throw new Error("Invalid --out: cannot be empty");
        out = val.trim();
        break;
      }
      case "--compare": {
        const [val, nextIdx] = readValue(i, flag, inlineVal);
        i = nextIdx;
        if (!val.trim()) throw new Error("Invalid --compare: cannot be empty");
        compare = val.trim();
        break;
      }
      case "--check":
        if (inlineVal !== undefined) throw new Error("Flag --check does not accept a value");
        check = true;
        break;
      case "--dry-run":
        if (inlineVal !== undefined) throw new Error("Flag --dry-run does not accept a value");
        dryRun = true;
        break;
      case "--fetch-only":
        if (inlineVal !== undefined) throw new Error("Flag --fetch-only does not accept a value");
        fetchOnly = true;
        break;
      case "--offline-only":
        if (inlineVal !== undefined) throw new Error("Flag --offline-only does not accept a value");
        offlineOnly = true;
        break;
      case "--steerbench-all":
        if (inlineVal !== undefined) {
          throw new Error("Flag --steerbench-all does not accept a value");
        }
        steerbenchAll = true;
        break;
      default:
        throw new Error(`Unknown CLI argument: ${rawArg}`);
    }
  }

  const datasets: readonly BenchDatasetId[] =
    datasetsExplicit ??
    (fetchOnly
      ? [...EXTERNAL_BENCH_DATASET_IDS]
      : file
        ? ["synthetic", "historical"]
        : ["synthetic"]);

  const concurrency = concurrencyExplicit ?? (mode === "s1" ? 8 : 4);

  return {
    datasets,
    mode,
    ...(limit !== undefined ? { limit } : {}),
    seed,
    concurrency,
    classifierModel,
    ...(classifierTimeoutMs !== undefined ? { classifierTimeoutMs } : {}),
    s1Endpoint,
    s1Model,
    ...(s1ApiKey !== undefined ? { s1ApiKey } : {}),
    s1TimeoutMs,
    s1Thresholds,
    ...(file !== undefined ? { file } : {}),
    ...(cacheDir !== undefined ? { cacheDir } : {}),
    ...(out !== undefined ? { out } : {}),
    ...(compare !== undefined ? { compare } : {}),
    check,
    dryRun,
    fetchOnly,
    offlineOnly,
    steerbenchAll,
    help,
  };
}

export function loadCachedDatasetManifests(
  datasets: readonly BenchDatasetId[],
  cacheDir?: string,
): Record<string, DatasetManifest> {
  const manifests: Record<string, DatasetManifest> = {};
  for (const dataset of datasets) {
    if (dataset === "synthetic" || dataset === "historical") {
      continue;
    }
    const snapshotDir = getDatasetSnapshotDir(dataset, cacheDir);
    const manifestPath = path.join(snapshotDir, "manifest.json");
    if (!fs.existsSync(manifestPath)) {
      continue;
    }
    try {
      const parsed: unknown = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
      if (
        typeof parsed === "object" &&
        parsed !== null &&
        "dataset" in parsed &&
        "sha" in parsed &&
        "files" in parsed &&
        Array.isArray((parsed as { files?: unknown }).files)
      ) {
        manifests[dataset] = parsed as DatasetManifest;
      }
    } catch (err) {
      console.warn(
        `[eval:cascade] Ignoring unreadable manifest at ${formatHomePath(manifestPath)}:`,
        err instanceof Error ? err.message : String(err),
      );
    }
  }
  return manifests;
}

function projectBenchCases(cases: readonly StaticBenchCase[]): ProjectedBenchCase[] {
  return cases.map((testCase) => {
    const action = projectOpenCodeBenchCase({
      event: testCase.event,
      userPrompt: testCase.promptContext.userPrompt,
      subagentPrompt: testCase.promptContext.subagentPrompt,
      subagentTitle: testCase.promptContext.subagentTitle,
      workspaceRoot: testCase.promptContext.workspaceRoot,
      environment: testCase.promptContext.environment,
    });
    if (
      testCase.promptContext.userPrompt.trim().length > 0 &&
      action.userPrompt.trim().length === 0
    ) {
      throw new Error(
        `OpenCode v2 prompt parity error: case ${testCase.id} collapsed non-empty userPrompt to empty string`,
      );
    }
    return { testCase, action };
  });
}

async function runWithConcurrency<T, R>(
  items: readonly T[],
  concurrency: number,
  fn: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  if (items.length === 0) {
    return [];
  }
  const results = new Array<R>(items.length);
  let nextIdx = 0;

  async function worker(): Promise<void> {
    while (nextIdx < items.length) {
      const idx = nextIdx++;
      results[idx] = await fn(items[idx], idx);
    }
  }

  const workerCount = Math.max(1, Math.min(concurrency, items.length));
  await Promise.all(Array.from({ length: workerCount }, () => worker()));
  return results;
}

function buildSystemOneConfigForRun(
  options: EvalCliOptions,
  executionMode: SystemOneExecutionMode,
): SystemOneConfig {
  return {
    enabled: true,
    executionMode,
    endpoint: options.s1Endpoint,
    model: options.s1Model,
    ...(options.s1ApiKey !== undefined ? { apiKey: options.s1ApiKey } : {}),
    timeoutMs: options.s1TimeoutMs,
    thresholds: options.s1Thresholds,
  };
}

function formatPreviewSnippet(text: string, maxChars = 600): string {
  const normalized = text.trim();
  if (normalized.length <= maxChars) {
    return normalized;
  }
  return `${normalized.slice(0, maxChars)}\n... [truncated ${normalized.length - maxChars} chars]`;
}

function isExternalDataset(
  dataset: BenchDatasetId,
): dataset is Exclude<BenchDatasetId, "synthetic" | "historical"> {
  return dataset !== "synthetic" && dataset !== "historical";
}

export async function runEvalCascade(
  options: EvalCliOptions,
  deps?: RunEvalCascadeDeps,
): Promise<RunEvalCascadeResult> {
  const log = deps?.log ?? ((line: string) => console.log(line));
  const warn = deps?.warn ?? ((line: string) => console.error(line));

  if (options.help) {
    log(formatEvalCliHelp());
    return { kind: "help", options };
  }

  const cacheRoot = resolveBenchCacheRoot(options.cacheDir);

  if (options.fetchOnly) {
    const externalDatasets = options.datasets.filter(isExternalDataset);
    if (externalDatasets.length === 0) {
      log("[eval:cascade] No external datasets requested for --fetch-only.");
      return { kind: "fetch", options, fetched: {} };
    }

    const fetchFn = deps?.fetchDatasets ?? fetchDatasets;
    const fetched = await fetchFn(externalDatasets, options.cacheDir, {
      offlineOnly: options.offlineOnly,
    });

    log(`[eval:cascade] Cache root: ${formatHomePath(cacheRoot)}`);
    for (const dataset of externalDatasets) {
      const res = fetched[dataset];
      if (!res) continue;
      const manifestPath = formatHomePath(path.join(res.dir, "manifest.json"));
      const fileHashes = res.manifest.files
        .map((f) => `${f.relativePath}:${f.sha256.slice(0, 12)}`)
        .join(", ");
      log(
        `  - ${dataset}: sha=${res.sha} cacheHit=${res.cacheHit} manifest=${manifestPath} files=${res.manifest.files.length} [${fileHashes}]`,
      );
    }

    return { kind: "fetch", options, fetched };
  }

  const loadOptions: LoadDatasetsOptions = {
    cacheDir: options.cacheDir,
    fetchOptions: {
      offlineOnly: options.offlineOnly,
    },
    ...(options.file !== undefined ? { historical: { file: options.file } } : {}),
    ...(options.steerbenchAll ? { steerbench: { includeAllDomains: true } } : {}),
  };

  const loadFn = deps?.loadDatasets ?? loadBenchDatasets;
  const loadedCases = await loadFn(options.datasets, loadOptions);
  const sampledCases = sampleBenchCases(loadedCases, {
    limitPerDataset: options.limit,
    seed: options.seed,
  });

  const projected = projectBenchCases(sampledCases);
  const manifests = loadCachedDatasetManifests(options.datasets, options.cacheDir);

  const s1ExecutionMode: SystemOneExecutionMode = options.mode === "cascade" ? "cascade" : "race";
  const s1Config = buildSystemOneConfigForRun(options, s1ExecutionMode);

  if (options.dryRun) {
    const provenance = computePromptProvenance({
      s1Model: options.s1Model,
      cacheDir: options.cacheDir,
    });

    const datasetCounts = new Map<BenchDatasetId, number>();
    for (const ds of options.datasets) {
      datasetCounts.set(ds, 0);
    }
    for (const item of sampledCases) {
      datasetCounts.set(item.dataset, (datasetCounts.get(item.dataset) ?? 0) + 1);
    }

    log(`[eval:cascade] Dry-run verified OpenCode v2 prompt parity`);
    log(`  Cache dir: ${formatHomePath(cacheRoot)}`);
    if (options.file) {
      log(`  Historical log: ${formatHomePath(options.file)}`);
    }
    log(
      `  Loaded cases: ${loadedCases.length} | Sampled cases: ${sampledCases.length} (seed=${options.seed}${options.limit !== undefined ? `, limit=${options.limit}` : ""})`,
    );
    log("  Dataset counts:");
    for (const [ds, count] of datasetCounts.entries()) {
      log(`    - ${ds}: ${count}`);
    }
    log(
      `  Prompt SHA-256: evalAgent=${provenance.evalAgentSystemSha256.slice(0, 12)}, s1Questions=${provenance.s1QuestionsSha256.slice(0, 12)}, s1Probe=${provenance.s1ProbeStateSha256.slice(0, 12)}, s2Probe=${provenance.s2ProbeUserPromptSha256.slice(0, 12)} (probeWs=${provenance.probeWorkspacePath})`,
    );
    log(
      `  Zero empty-prompt collapses verified across ${projected.length} projected OpenCode v2 cases.`,
    );

    if (projected.length > 0) {
      const sample = projected[0];
      const s1Payload = buildSystemOneRequestPayload(sample.action, options.s1Model);
      const s2UserPrompt = buildClassifierUserPrompt({
        userPrompt: sample.action.userPrompt,
        subagentPrompt: sample.action.subagentPrompt,
        actionName: sample.action.toolName,
        actionArgs:
          sample.action.rawArgs ??
          sample.action.patterns ??
          sample.action.metadata ??
          sample.action.commandString ??
          {},
        workspaceRoot: sample.action.workspaceRoot,
        environment: sample.action.environment,
      });

      log(
        `\n--- Sample Preview (${sample.testCase.id} [${sample.testCase.dataset}:${sample.testCase.split}] -> expected=${sample.testCase.expectedVerdict}) ---`,
      );
      log(`[System 1 State Preview (model=${s1Payload.model})]:`);
      log(formatPreviewSnippet(s1Payload.state));
      log("\n[System 2 User Prompt Preview]:");
      log(formatPreviewSnippet(s2UserPrompt));
    }

    const drySummary = computeBenchmarkSummary([], options.mode);
    const artifact = buildBenchmarkArtifact({
      mode: options.mode,
      classifierModel: options.classifierModel,
      ...(options.mode === "s2" ? {} : { systemOneConfig: s1Config }),
      datasets: manifests,
      summary: drySummary,
      runOptions: {
        seed: options.seed,
        ...(options.limit !== undefined ? { limitPerDataset: options.limit } : {}),
        concurrency: options.concurrency,
        ...(options.cacheDir !== undefined ? { cacheDir: options.cacheDir } : {}),
      },
      cacheDir: options.cacheDir,
    });

    let artifactPath: WriteBenchmarkArtifactResult | undefined;
    if (options.out) {
      artifactPath = writeBenchmarkArtifact(artifact, options.out);
      log(`\nArtifact saved: ${artifactPath.displayPath}`);
    }

    return {
      kind: "dry-run",
      options,
      totalLoadedCases: loadedCases.length,
      sampledCases,
      artifact,
      ...(artifactPath !== undefined ? { artifactPath } : {}),
    };
  }

  let ownedRunner: OpenCodeS2Runner | undefined;
  let records: BenchEvalRecord[];

  try {
    if (options.mode === "s1") {
      const s1Evaluator =
        deps?.s1Evaluator ??
        new SystemOneEvaluator({
          config: s1Config,
          fetchImpl: deps?.fetchImpl,
        });

      records = await runWithConcurrency(
        projected,
        options.concurrency,
        async ({ testCase, action }): Promise<BenchEvalRecord> => {
          const currentFingerprint = computeContextFingerprint(
            action.userPrompt,
            action.environment,
          );
          const t0 = performance.now();
          let outcome: SystemOneOutcome;
          try {
            outcome = await s1Evaluator.evaluateRaw(action, {
              fingerprint: currentFingerprint,
            });
          } catch (err) {
            const msg = err instanceof Error ? err.message : String(err);
            outcome = {
              ok: false,
              reason: "s1_error",
              message: msg,
              latencyMs: Math.round(performance.now() - t0),
              isTransportError: true,
            };
          }

          const policy = evaluateCascadePolicy(outcome, s1Config.thresholds, {
            mode: "race",
            currentFingerprint,
          });

          if (policy.kind === "accept") {
            return {
              testCase,
              verdict: policy.result.verdict,
              reason: policy.result.reason,
              latencyMs: outcome.latencyMs,
              cascade: policy.result.cascade,
              s1Outcome: outcome,
              evaluatorError: false,
            };
          }

          const reason = `System 1 escalated (${policy.reason})`;
          return {
            testCase,
            verdict: "UNSURE",
            reason,
            latencyMs: outcome.latencyMs,
            cascade: policy.trace,
            s1Outcome: outcome,
            evaluatorError: isEvaluatorErrorReason("UNSURE", reason, outcome, "s1"),
          };
        },
      );
    } else if (options.mode === "s2") {
      let s2Evaluator = deps?.s2Evaluator;
      if (!s2Evaluator) {
        ownedRunner = await OpenCodeS2Runner.create({
          classifierModel: options.classifierModel,
          ...(options.classifierTimeoutMs !== undefined
            ? { classifierTimeoutMs: options.classifierTimeoutMs }
            : {}),
          ...(deps?.mockProvider ? { mockProvider: deps.mockProvider } : {}),
        });
        s2Evaluator = ownedRunner;
      }

      const activeS2 = s2Evaluator;
      records = await runWithConcurrency(
        projected,
        options.concurrency,
        async ({ testCase, action }): Promise<BenchEvalRecord> => {
          const t0 = performance.now();
          let result: ClassifierResult;
          try {
            result = await activeS2.evaluate(action);
          } catch (err) {
            const message = err instanceof Error ? err.message : String(err);
            result = {
              verdict: "UNSURE",
              reason: `System 2 evaluator error: ${message}`,
            };
          }
          const latencyMs = Math.round(performance.now() - t0);
          const evaluatorError = isEvaluatorErrorReason(
            result.verdict,
            result.reason,
            undefined,
            "s2",
          );
          return {
            testCase,
            verdict: result.verdict,
            reason: result.reason,
            latencyMs,
            ...(result.cascade !== undefined ? { cascade: result.cascade } : {}),
            evaluatorError,
          };
        },
      );
    } else {
      const cascadeMode: SystemOneExecutionMode = options.mode;
      const cascadeS1Config = buildSystemOneConfigForRun(options, cascadeMode);
      const s1Evaluator =
        deps?.s1Evaluator ??
        new SystemOneEvaluator({
          config: cascadeS1Config,
          fetchImpl: deps?.fetchImpl,
        });

      let s2Evaluator = deps?.s2Evaluator;
      if (!s2Evaluator) {
        ownedRunner = await OpenCodeS2Runner.create({
          classifierModel: options.classifierModel,
          ...(options.classifierTimeoutMs !== undefined
            ? { classifierTimeoutMs: options.classifierTimeoutMs }
            : {}),
          ...(deps?.mockProvider ? { mockProvider: deps.mockProvider } : {}),
        });
        s2Evaluator = ownedRunner;
      }

      const cascadeEvaluator = new CascadeEvaluator({
        systemOne: s1Evaluator,
        system2: s2Evaluator,
        config: cascadeS1Config,
        getContextFingerprint: (act) => computeContextFingerprint(act.userPrompt, act.environment),
      });

      records = await runWithConcurrency(
        projected,
        options.concurrency,
        async ({ testCase, action }): Promise<BenchEvalRecord> => {
          const t0 = performance.now();
          let result: ClassifierResult;
          try {
            result = await cascadeEvaluator.evaluate(action);
          } catch (err) {
            const message = err instanceof Error ? err.message : String(err);
            result = {
              verdict: "UNSURE",
              reason: `System 2 evaluator error: ${message}`,
            };
          }
          const latencyMs = Math.round(performance.now() - t0);
          const evaluatorError = isEvaluatorErrorReason(
            result.verdict,
            result.reason,
            undefined,
            cascadeMode,
          );
          return {
            testCase,
            verdict: result.verdict,
            reason: result.reason,
            latencyMs,
            ...(result.cascade !== undefined ? { cascade: result.cascade } : {}),
            evaluatorError,
          };
        },
      );
    }
  } finally {
    if (ownedRunner) {
      await ownedRunner.dispose();
    }
  }

  const paretoGrid =
    options.mode === "s1"
      ? evaluateS1ParetoGrid(records, {
          baseThresholds: s1Config.thresholds,
          mode: "race",
        })
      : undefined;

  const artifact = buildBenchmarkArtifact({
    mode: options.mode,
    classifierModel: options.classifierModel,
    ...(options.mode === "s2" ? {} : { systemOneConfig: s1Config }),
    datasets: manifests,
    records,
    ...(paretoGrid !== undefined && paretoGrid.length > 0 ? { paretoGrid } : {}),
    runOptions: {
      seed: options.seed,
      ...(options.limit !== undefined ? { limitPerDataset: options.limit } : {}),
      concurrency: options.concurrency,
      ...(options.cacheDir !== undefined ? { cacheDir: options.cacheDir } : {}),
    },
    cacheDir: options.cacheDir,
  });

  const baseline = options.compare ? loadBenchmarkArtifact(options.compare) : undefined;
  const comparison = baseline ? compareBenchmarkArtifacts(artifact, baseline) : undefined;

  const artifactPath = writeBenchmarkArtifact(artifact, options.out);
  log(formatBenchmarkMarkdown(artifact, comparison));
  log(`\nArtifact saved: ${artifactPath.displayPath}`);

  let checkResult: RegressionCheckResult | undefined;
  if (options.check) {
    checkResult = evaluateRegressionCheck(artifact, baseline);
    if (!checkResult.passed) {
      warn("\n[eval:cascade] Regression check FAILED:");
      for (const violation of checkResult.violations) {
        warn(`  - ${violation}`);
      }
      throw new Error(`Regression check failed (${checkResult.violations.length} violation(s))`);
    }
    log("[eval:cascade] Regression check PASSED.");
  }

  return {
    kind: "eval",
    options,
    totalLoadedCases: loadedCases.length,
    sampledCases,
    records,
    artifact,
    ...(comparison !== undefined ? { comparison } : {}),
    ...(checkResult !== undefined ? { checkResult } : {}),
    artifactPath,
  };
}

async function main(): Promise<void> {
  const options = parseEvalCliArgs(process.argv.slice(2));
  await runEvalCascade(options);
}

if (import.meta.main) {
  main().catch((err) => {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`[eval:cascade] Error: ${message}`);
    process.exit(1);
  });
}
