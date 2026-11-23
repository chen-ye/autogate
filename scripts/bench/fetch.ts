import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { asyncBufferFromFile, parquetReadObjects } from "hyparquet";
import { DEFAULT_BENCH_CACHE_DIR, expandHomePath } from "./paths.js";
import type { BenchDatasetId, DatasetManifest, DatasetManifestFile } from "./schema.js";

export interface PinnedDatasetFileSpec {
  readonly relativePath: string;
  readonly url: string;
  readonly expectedSha256: string;
}

export interface PinnedDatasetSpec {
  readonly dataset: Exclude<BenchDatasetId, "synthetic" | "historical">;
  readonly sha: string;
  readonly files: readonly PinnedDatasetFileSpec[];
}

const REDCODE_SHARD_INDICES = [
  1, 2, 3, 4, 5, 6, 7, 8, 9, 12, 13, 14, 15, 16, 18, 20, 21, 22, 23, 25,
] as const;

const REDCODE_SHARD_SHA256: Readonly<Record<number, string>> = {
  1: "23db466c5a628afb9e9e514640a61f5b4407e4946def376012ec29878575d442",
  2: "2281e8046c94d46feadeda53de9e70d9de92b607f388497eb9e2447706a13b41",
  3: "b4704c6fee975a45bbcc39ea1c3412520706a2eada41e00cfbdd2c7a2f76143f",
  4: "fe933322ea14f61191e8b08dc39bb1a5a0123ac597953c38163e921973798a60",
  5: "296973edbed6d986be648ec82ce148effd9400a06f6de190adbc291e5f559f4a",
  6: "93b6c176860c8ee6f384bd80fd15cc71fcd428dbdeb234eaac3b1164cda131c4",
  7: "219614028dc8cde72afa77246f20ddcaeaeb7bb2cbee989915eb80ba8607654a",
  8: "f6548f606985fd6775814f400bb64c8350b200792b92e1b6a9de2e36bad3da86",
  9: "d50753871276ac47aabdb34ba0bfa3a1594ad607a350eae1cd2b777685a79f80",
  12: "cd123f8ac99b4cc39aafc1b7feb3aa44c1bb331a8b36bafd94a1e4894d0aac91",
  13: "47f2f0dabeb10a2244e3f9356e24475ae9ca4e07b93a93ed305685056805a636",
  14: "b521b7cb8fe55e303870b16799a6cf9a5d2d4f28cb575c3c9a230369eeb44549",
  15: "d60f63a7366304bba39cbf2bb89e436e715a694ae1eafd4b4e15c59a73a1fc77",
  16: "ae68455fd7dfc1755a40eed5dfcb57ee90d8722c1784f111e362bcd1b11360b6",
  18: "fa471b5661de1f81ccbb6735395cd6a904047664dd39287ffa485711619d4148",
  20: "bfa32dd3f7e111fe50c64e38545d05454da0c82189d0a35517f71de2300933ca",
  21: "ec4c7006f02a29d2f1e9a22156f4e27d6e2cb2148a73bd79ba35e62f3a64cdee",
  22: "df22bc621a0e0c7018a89cde9457863c5acfea4de0a75a4453fc83732d97da07",
  23: "a24691cd866f551cbd92b4e6b2f4bf9fcfb69f3f1392353116703f676fbeff00",
  25: "270d4d09fc48f26be540d8ca021b2ce4ada23f14a905b140cd7a48f44f78a27c",
};

const SHELLRISK_SHA = "437467862139b4e9cdd5322024ef3434a67c7ec8";
const NL2SH_SHA = "a99cb5784cf5c2a42b1cc26c1903d9c3b35206ba";
const REDCODE_SHA = "664e4793dc7309f98b8271baed5bbc04d6ef4c39";
const AUTHGATE_SHA = "af4048e343778c85bcc89347e7b88dd94b0f57cc";
const TSBENCH_SHA = "19047a0c4a54f54cc1ddd4a2c597105d8453b819";
const STEERBENCH_SHA = "92f4e58adffddf1f2c4836b8e416f26cbfb11410";

export const PINNED_DATASET_SPECS: Readonly<
  Record<Exclude<BenchDatasetId, "synthetic" | "historical">, PinnedDatasetSpec>
> = {
  shellrisk: {
    dataset: "shellrisk",
    sha: SHELLRISK_SHA,
    files: [
      {
        relativePath: "data/test-00000-of-00001.parquet",
        url: `https://huggingface.co/datasets/kontext-security/ShellRisk-Bench/resolve/${SHELLRISK_SHA}/data/test-00000-of-00001.parquet`,
        expectedSha256: "e9df3b50a716ad077eeab6fcc27be57834bc2ff3f28ebeaf48dfd6640e9064c8",
      },
    ],
  },
  "nl2sh-redcode": {
    dataset: "nl2sh-redcode",
    sha: `${NL2SH_SHA}_${REDCODE_SHA}`,
    files: [
      {
        relativePath: "nl2sh/test.csv",
        url: `https://huggingface.co/datasets/westenfelder/NL2SH-ALFA/resolve/${NL2SH_SHA}/test.csv`,
        expectedSha256: "65a94a14db655c4a695bde38653b7e8884b071cded604ee05e62d7a61ea44c35",
      },
      ...REDCODE_SHARD_INDICES.map((shardIndex) => ({
        relativePath: `redcode/index${shardIndex}_30_codes_full_upd.json`,
        url: `https://raw.githubusercontent.com/AI-secure/RedCode/${REDCODE_SHA}/dataset/RedCode-Exec/bash2text_dataset_json/index${shardIndex}_30_codes_full_upd.json`,
        expectedSha256: REDCODE_SHARD_SHA256[shardIndex],
      })),
    ],
  },
  authgate: {
    dataset: "authgate",
    sha: AUTHGATE_SHA,
    files: [
      {
        relativePath: "data/authgatebench.jsonl",
        url: `https://raw.githubusercontent.com/Digital-Trust-Lab/AuthGateBench/${AUTHGATE_SHA}/data/authgatebench.jsonl`,
        expectedSha256: "73573309a3cbfa700ce2eb5cb32f965c52de7705a0af028077de75f31696dffc",
      },
    ],
  },
  tsbench: {
    dataset: "tsbench",
    sha: TSBENCH_SHA,
    files: [
      {
        relativePath: "metadata/statistics.json",
        url: `https://huggingface.co/datasets/MurrayTom/TS-Bench/resolve/${TSBENCH_SHA}/metadata/statistics.json`,
        expectedSha256: "152bc0dfab7ac620597b6b6ec969665dc66c30060966a4a3c19785ce96ae502b",
      },
      {
        relativePath: "data/eval/AgentHarm-Traj.jsonl",
        url: `https://huggingface.co/datasets/MurrayTom/TS-Bench/resolve/${TSBENCH_SHA}/data/eval/AgentHarm-Traj.jsonl`,
        expectedSha256: "b3e9832b92026bb594350aff3a431c3b4f66140c3908994704305fbee84e7a5c",
      },
      {
        relativePath: "data/eval/ASB-Traj.jsonl",
        url: `https://huggingface.co/datasets/MurrayTom/TS-Bench/resolve/${TSBENCH_SHA}/data/eval/ASB-Traj.jsonl`,
        expectedSha256: "36261a98f6c38969c4c8d84ead1c3ab333e80ae1f6f4cbc3c9d379bf7d0c1f2a",
      },
      {
        relativePath: "data/eval/AgentDojo-Traj.jsonl",
        url: `https://huggingface.co/datasets/MurrayTom/TS-Bench/resolve/${TSBENCH_SHA}/data/eval/AgentDojo-Traj.jsonl`,
        expectedSha256: "740251908ffbac1f397c71f554678ccf6f73aa6d00be4a63925ea491f6c0ed9b",
      },
      {
        relativePath: "data/train/validation.jsonl",
        url: `https://huggingface.co/datasets/MurrayTom/TS-Bench/resolve/${TSBENCH_SHA}/data/train/validation.jsonl`,
        expectedSha256: "0ec0ce293acf86c1fb26a8a708deb6175b0117c6f3734a048a0a556518db1299",
      },
    ],
  },
  steerbench: {
    dataset: "steerbench",
    sha: STEERBENCH_SHA,
    files: [
      {
        relativePath: "scenarios.jsonl",
        url: `https://huggingface.co/datasets/agentdock/steerbench-work-2026-05/resolve/${STEERBENCH_SHA}/scenarios.jsonl`,
        expectedSha256: "cc0cc540a9fcff58a27eb6369ea3bd7d97cd6acb6aad832eb12c94593ebe8aec",
      },
      {
        relativePath: "checksums.txt",
        url: `https://huggingface.co/datasets/agentdock/steerbench-work-2026-05/resolve/${STEERBENCH_SHA}/checksums.txt`,
        expectedSha256: "957b8ad39ae87bea6262a6a2f494aad4765bc7cc703517c37b3e7edeaf8e7d02",
      },
    ],
  },
};

export function parseCsvMatrix(text: string): string[][] {
  const input = text.startsWith("\uFEFF") ? text.slice(1) : text;
  const rows: string[][] = [];
  let currentRow: string[] = [];
  let currentField = "";
  let inQuotes = false;
  let atFieldStart = true;

  for (let i = 0; i < input.length; i++) {
    const ch = input[i];

    if (inQuotes) {
      if (ch === '"') {
        if (input[i + 1] === '"') {
          currentField += '"';
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        currentField += ch;
      }
      continue;
    }

    if (ch === '"' && atFieldStart) {
      inQuotes = true;
      atFieldStart = false;
      continue;
    }

    if (ch === ",") {
      currentRow.push(currentField);
      currentField = "";
      atFieldStart = true;
      continue;
    }

    if (ch === "\r") {
      if (input[i + 1] === "\n") {
        i++;
      }
      currentRow.push(currentField);
      rows.push(currentRow);
      currentRow = [];
      currentField = "";
      atFieldStart = true;
      continue;
    }

    if (ch === "\n") {
      currentRow.push(currentField);
      rows.push(currentRow);
      currentRow = [];
      currentField = "";
      atFieldStart = true;
      continue;
    }

    currentField += ch;
    atFieldStart = false;
  }

  if (inQuotes) {
    throw new Error("Malformed CSV: unclosed quoted field");
  }

  if (currentField.length > 0 || currentRow.length > 0) {
    currentRow.push(currentField);
    rows.push(currentRow);
  }

  return rows;
}

export function parseCsv(text: string): Record<string, string>[] {
  const matrix = parseCsvMatrix(text);
  if (matrix.length === 0) {
    return [];
  }

  const headers = matrix[0];
  const records: Record<string, string>[] = [];

  for (let i = 1; i < matrix.length; i++) {
    const row = matrix[i];
    if (row.length === 1 && row[0] === "" && headers.length > 1) {
      continue;
    }
    if (row.length !== headers.length) {
      throw new Error(
        `Malformed CSV at row ${i + 1}: expected ${headers.length} columns, got ${row.length}`,
      );
    }
    const record: Record<string, string> = {};
    for (let col = 0; col < headers.length; col++) {
      record[headers[col]] = row[col];
    }
    records.push(record);
  }

  return records;
}

export async function readParquetFile(filePath: string): Promise<Record<string, unknown>[]> {
  const file = await asyncBufferFromFile(filePath);
  const rows = await parquetReadObjects({ file });
  return rows as Record<string, unknown>[];
}

export function parseJsonl<T = Record<string, unknown>>(text: string): T[] {
  const rows: T[] = [];
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i].trim();
    if (!trimmed) {
      continue;
    }
    try {
      rows.push(JSON.parse(trimmed) as T);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      throw new Error(`Invalid JSONL at line ${i + 1}: ${msg}`);
    }
  }
  return rows;
}

export function readJsonlFile<T = Record<string, unknown>>(filePath: string): T[] {
  const raw = fs.readFileSync(filePath, "utf8");
  return parseJsonl<T>(raw);
}

export function computeBufferSha256(buf: Uint8Array): string {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

export function computeFileSha256(filePath: string): string {
  const hash = crypto.createHash("sha256");
  const fd = fs.openSync(filePath, "r");
  try {
    const chunk = Buffer.allocUnsafe(65536);
    let bytesRead = fs.readSync(fd, chunk, 0, chunk.length, null);
    while (bytesRead > 0) {
      hash.update(chunk.subarray(0, bytesRead));
      bytesRead = fs.readSync(fd, chunk, 0, chunk.length, null);
    }
  } finally {
    fs.closeSync(fd);
  }
  return hash.digest("hex");
}

export function resolveBenchCacheRoot(cacheDir?: string): string {
  const raw = cacheDir && cacheDir.trim().length > 0 ? cacheDir.trim() : DEFAULT_BENCH_CACHE_DIR;
  return path.resolve(expandHomePath(raw));
}

export function getDatasetSnapshotDir(
  dataset: Exclude<BenchDatasetId, "synthetic" | "historical">,
  cacheDir?: string,
): string {
  const spec = PINNED_DATASET_SPECS[dataset];
  return path.join(resolveBenchCacheRoot(cacheDir), "datasets", dataset, spec.sha);
}

export interface FetchedDatasetResult {
  readonly dataset: BenchDatasetId;
  readonly sha: string;
  readonly dir: string;
  readonly manifest: DatasetManifest;
  readonly cacheHit: boolean;
  readonly filesByRelativePath: ReadonlyMap<string, string>;
}

export interface FetchDatasetsOptions {
  readonly fetchImpl?: typeof fetch;
  readonly concurrency?: number;
  readonly force?: boolean;
  readonly offlineOnly?: boolean;
}

function writeFileAtomic(targetPath: string, data: Uint8Array | string): void {
  const dir = path.dirname(targetPath);
  fs.mkdirSync(dir, { recursive: true });
  const tmpPath = `${targetPath}.tmp.${process.pid}.${Math.random().toString(36).slice(2)}`;
  try {
    fs.writeFileSync(tmpPath, data);
    fs.renameSync(tmpPath, targetPath);
  } catch (err) {
    if (fs.existsSync(tmpPath)) {
      fs.rmSync(tmpPath, { force: true });
    }
    throw err;
  }
}

async function runWithConcurrency<T, R>(
  items: readonly T[],
  concurrency: number,
  workerFn: (item: T) => Promise<R>,
): Promise<R[]> {
  const results = new Array<R>(items.length);
  let nextIdx = 0;

  async function worker(): Promise<void> {
    while (nextIdx < items.length) {
      const idx = nextIdx++;
      results[idx] = await workerFn(items[idx]);
    }
  }

  const count = Math.max(1, Math.min(concurrency, items.length));
  await Promise.all(Array.from({ length: count }, () => worker()));
  return results;
}

function readExistingManifest(manifestPath: string): DatasetManifest | null {
  if (!fs.existsSync(manifestPath)) {
    return null;
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
      return parsed as DatasetManifest;
    }
  } catch (err) {
    console.warn(`[bench/fetch] Ignoring unreadable manifest at ${manifestPath}:`, err);
  }
  return null;
}

function verifyTsBenchStatistics(
  snapshotDir: string,
  actualHashes: ReadonlyMap<string, string>,
): void {
  const statsPath = path.join(snapshotDir, "metadata/statistics.json");
  if (!fs.existsSync(statsPath)) {
    throw new Error(`TS-Bench statistics.json missing at ${statsPath}`);
  }
  const raw: unknown = JSON.parse(fs.readFileSync(statsPath, "utf8"));
  if (typeof raw !== "object" || raw === null) {
    throw new Error(`TS-Bench statistics.json is not a JSON object`);
  }
  const statsObj = raw as Record<string, { sha256?: unknown }>;
  for (const [relPath, actualSha] of actualHashes.entries()) {
    if (relPath === "metadata/statistics.json") {
      continue;
    }
    const entry = statsObj[relPath];
    if (!entry || typeof entry.sha256 !== "string") {
      throw new Error(`TS-Bench statistics.json missing sha256 entry for ${relPath}`);
    }
    if (entry.sha256 !== actualSha) {
      throw new Error(
        `TS-Bench SHA-256 mismatch vs statistics.json for ${relPath}: expected ${entry.sha256}, got ${actualSha}`,
      );
    }
  }
}

function isLocalOnlyDataset(dataset: BenchDatasetId): dataset is "synthetic" | "historical" {
  return dataset === "synthetic" || dataset === "historical";
}

export async function fetchDataset(
  dataset: BenchDatasetId,
  cacheDir?: string,
  options?: FetchDatasetsOptions,
): Promise<FetchedDatasetResult> {
  if (isLocalOnlyDataset(dataset)) {
    const localDir = path.join(resolveBenchCacheRoot(cacheDir), "datasets", dataset, "local");
    return {
      dataset,
      sha: "local",
      dir: localDir,
      manifest: {
        dataset,
        sha: "local",
        fetchedAt: new Date(0).toISOString(),
        files: [],
      },
      cacheHit: true,
      filesByRelativePath: new Map(),
    };
  }

  const spec = PINNED_DATASET_SPECS[dataset];
  const snapshotDir = getDatasetSnapshotDir(dataset, cacheDir);
  const manifestPath = path.join(snapshotDir, "manifest.json");
  const fetchImpl = options?.fetchImpl ?? fetch;
  const concurrency = options?.concurrency ?? 4;
  const force = options?.force ?? false;
  const offlineOnly = options?.offlineOnly ?? false;

  const existingManifest = !force ? readExistingManifest(manifestPath) : null;
  const manifestFileMap = new Map<string, DatasetManifestFile>();
  if (existingManifest && existingManifest.sha === spec.sha) {
    for (const entry of existingManifest.files) {
      manifestFileMap.set(entry.relativePath, entry);
    }
  }

  let allCacheHit = Boolean(existingManifest && existingManifest.sha === spec.sha);
  const actualHashes = new Map<string, string>();
  const filesByRelativePath = new Map<string, string>();

  const downloadedOrVerifiedFiles = await runWithConcurrency(
    spec.files,
    concurrency,
    async (fileSpec): Promise<{ file: DatasetManifestFile; hit: boolean }> => {
      const localPath = path.join(snapshotDir, fileSpec.relativePath);
      filesByRelativePath.set(fileSpec.relativePath, localPath);

      if (!force && fs.existsSync(localPath)) {
        const diskSha = computeFileSha256(localPath);
        if (diskSha === fileSpec.expectedSha256) {
          const stat = fs.statSync(localPath);
          actualHashes.set(fileSpec.relativePath, diskSha);
          const manifestEntry = manifestFileMap.get(fileSpec.relativePath);
          const entryValid = manifestEntry !== undefined && manifestEntry.sha256 === diskSha;
          return {
            hit: entryValid,
            file: {
              relativePath: fileSpec.relativePath,
              url: fileSpec.url,
              sha256: diskSha,
              sizeBytes: stat.size,
            },
          };
        }
      }

      if (offlineOnly) {
        throw new Error(
          `Offline cache miss or checksum mismatch for ${dataset}/${fileSpec.relativePath} at ${localPath}`,
        );
      }

      const response = await fetchImpl(fileSpec.url, { redirect: "follow" });
      if (!response.ok) {
        throw new Error(
          `Failed to download ${dataset}/${fileSpec.relativePath} from ${fileSpec.url}: HTTP ${response.status} ${response.statusText}`,
        );
      }

      const bytes = new Uint8Array(await response.arrayBuffer());
      const actualSha = computeBufferSha256(bytes);
      if (actualSha !== fileSpec.expectedSha256) {
        throw new Error(
          `SHA-256 verification failed for ${dataset}/${fileSpec.relativePath}: expected ${fileSpec.expectedSha256}, got ${actualSha}`,
        );
      }

      writeFileAtomic(localPath, bytes);
      actualHashes.set(fileSpec.relativePath, actualSha);
      return {
        hit: false,
        file: {
          relativePath: fileSpec.relativePath,
          url: fileSpec.url,
          sha256: actualSha,
          sizeBytes: bytes.byteLength,
        },
      };
    },
  );

  for (const item of downloadedOrVerifiedFiles) {
    if (!item.hit) {
      allCacheHit = false;
    }
  }

  if (dataset === "tsbench") {
    verifyTsBenchStatistics(snapshotDir, actualHashes);
  }

  const manifest: DatasetManifest =
    allCacheHit && existingManifest
      ? existingManifest
      : {
          dataset,
          sha: spec.sha,
          fetchedAt: new Date().toISOString(),
          files: downloadedOrVerifiedFiles.map((entry) => entry.file),
        };

  if (!allCacheHit || !existingManifest) {
    writeFileAtomic(manifestPath, JSON.stringify(manifest, null, 2) + "\n");
  }

  return {
    dataset,
    sha: spec.sha,
    dir: snapshotDir,
    manifest,
    cacheHit: allCacheHit,
    filesByRelativePath,
  };
}

export async function fetchDatasets(
  datasetIds: readonly BenchDatasetId[],
  cacheDir?: string,
  options?: FetchDatasetsOptions,
): Promise<Partial<Record<BenchDatasetId, FetchedDatasetResult>>> {
  const uniqueIds = Array.from(new Set(datasetIds));
  const results = await Promise.all(
    uniqueIds.map(
      async (dataset) => [dataset, await fetchDataset(dataset, cacheDir, options)] as const,
    ),
  );
  const out: Partial<Record<BenchDatasetId, FetchedDatasetResult>> = {};
  for (const [dataset, res] of results) {
    out[dataset] = res;
  }
  return out;
}
