import { fetchDataset, readParquetFile, type FetchDatasetsOptions } from "../fetch.js";
import { ensureEmptyBenchWorkspace } from "../paths.js";
import { makeShellPermissionEvent, type StaticBenchCase } from "../schema.js";

export interface ShellRiskRow {
  readonly command?: unknown;
  readonly id?: unknown;
  readonly label?: unknown;
  readonly source?: unknown;
  readonly upstream_id?: unknown;
}

export interface ShellRiskLoadOptions {
  readonly cacheDir?: string;
  readonly parquetPath?: string;
  readonly fetchOptions?: FetchDatasetsOptions;
}

function parseShellRiskVerdict(label: unknown, rowIndex: number): "ALLOW" | "BLOCK" {
  if (label === "risky") {
    return "BLOCK";
  }
  if (label === "not_risky") {
    return "ALLOW";
  }
  throw new Error(`Unexpected ShellRisk-Bench label at row ${rowIndex}: ${String(label)}`);
}

export function mapShellRiskRows(
  rows: readonly ShellRiskRow[],
  workspaceRoot: string = ensureEmptyBenchWorkspace(),
): StaticBenchCase[] {
  const seenIds = new Set<string>();
  const cases: StaticBenchCase[] = [];

  for (let i = 0; i < rows.length; i++) {
    const row = rows[i];
    const command = typeof row.command === "string" ? row.command : String(row.command ?? "");
    const rawUpstreamId =
      typeof row.upstream_id === "string" && row.upstream_id.trim().length > 0
        ? row.upstream_id.trim()
        : typeof row.id === "string" && row.id.trim().length > 0
          ? row.id.trim()
          : `row-${i}`;
    const baseId = `shellrisk:${rawUpstreamId}`;
    const caseId = seenIds.has(baseId) ? `${baseId}#${i}` : baseId;
    seenIds.add(caseId);

    const sourceTag =
      typeof row.source === "string" && row.source.trim().length > 0
        ? row.source.trim()
        : undefined;
    const expectedVerdict = parseShellRiskVerdict(row.label, i);

    cases.push({
      id: caseId,
      dataset: "shellrisk",
      split: "test",
      ...(sourceTag !== undefined ? { sourceTag } : {}),
      event: makeShellPermissionEvent({
        id: caseId,
        command,
      }),
      promptContext: {
        userPrompt: "",
        workspaceRoot,
        environment: { trustedPaths: [workspaceRoot] },
      },
      expectedVerdict,
    });
  }

  return cases;
}

export async function loadShellRiskCases(
  options?: ShellRiskLoadOptions,
): Promise<StaticBenchCase[]> {
  const workspaceRoot = ensureEmptyBenchWorkspace();
  let parquetPath = options?.parquetPath;

  if (!parquetPath) {
    const fetched = await fetchDataset("shellrisk", options?.cacheDir, options?.fetchOptions);
    parquetPath = fetched.filesByRelativePath.get("data/test-00000-of-00001.parquet");
    if (!parquetPath) {
      throw new Error("ShellRisk-Bench parquet file missing from fetched snapshot");
    }
  }

  const rows = await readParquetFile(parquetPath);
  return mapShellRiskRows(rows, workspaceRoot);
}
