import type { FetchDatasetsOptions } from "../fetch.js";
import type { BenchDatasetId, StaticBenchCase } from "../schema.js";
import { loadAuthGateCases, type AuthGateLoadOptions } from "./authgate.js";
import { loadHistoricalBenchCases, type HistoricalLoadOptions } from "./historical.js";
import { loadNl2shRedcodeCases, type Nl2shRedcodeLoadOptions } from "./nl2sh-redcode.js";
import { loadShellRiskCases, type ShellRiskLoadOptions } from "./shellrisk.js";
import { loadSteerBenchCases, type SteerBenchLoadOptions } from "./steerbench.js";
import { loadSyntheticCases, type SyntheticBenchOptions } from "./synthetic.js";
import { loadTsBenchCases, type TsBenchLoadOptions } from "./tsbench.js";

export * from "./authgate.js";
export * from "./historical.js";
export * from "./nl2sh-redcode.js";
export * from "./shellrisk.js";
export * from "./steerbench.js";
export * from "./synthetic.js";
export * from "./tsbench.js";

export interface LoadDatasetsOptions {
  readonly cacheDir?: string;
  readonly fetchOptions?: FetchDatasetsOptions;
  readonly historical?: HistoricalLoadOptions;
  readonly synthetic?: SyntheticBenchOptions;
  readonly shellrisk?: ShellRiskLoadOptions;
  readonly nl2shRedcode?: Nl2shRedcodeLoadOptions;
  readonly authgate?: AuthGateLoadOptions;
  readonly tsbench?: TsBenchLoadOptions;
  readonly steerbench?: SteerBenchLoadOptions;
}

export async function loadDatasetCases(
  dataset: BenchDatasetId,
  options?: LoadDatasetsOptions,
): Promise<StaticBenchCase[]> {
  switch (dataset) {
    case "synthetic":
      return loadSyntheticCases(options?.synthetic);
    case "historical":
      return loadHistoricalBenchCases(options?.historical);
    case "shellrisk":
      return loadShellRiskCases({
        cacheDir: options?.cacheDir,
        fetchOptions: options?.fetchOptions,
        ...options?.shellrisk,
      });
    case "nl2sh-redcode":
      return loadNl2shRedcodeCases({
        cacheDir: options?.cacheDir,
        fetchOptions: options?.fetchOptions,
        ...options?.nl2shRedcode,
      });
    case "authgate":
      return loadAuthGateCases({
        cacheDir: options?.cacheDir,
        fetchOptions: options?.fetchOptions,
        ...options?.authgate,
      });
    case "tsbench":
      return loadTsBenchCases({
        cacheDir: options?.cacheDir,
        fetchOptions: options?.fetchOptions,
        ...options?.tsbench,
      });
    case "steerbench":
      return loadSteerBenchCases({
        cacheDir: options?.cacheDir,
        fetchOptions: options?.fetchOptions,
        ...options?.steerbench,
      });
  }
}

export async function loadBenchDatasets(
  datasets: readonly BenchDatasetId[],
  options?: LoadDatasetsOptions,
): Promise<StaticBenchCase[]> {
  const unique = Array.from(new Set(datasets));
  const nested = await Promise.all(unique.map((dataset) => loadDatasetCases(dataset, options)));
  return nested.flat();
}
