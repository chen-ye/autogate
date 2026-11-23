import fs from "node:fs";
import os from "node:os";
import path from "node:path";

export const DEFAULT_BENCH_CACHE_DIR = "~/.cache/autogate/bench";
export const DEFAULT_BENCH_RUNS_DIR = "~/.cache/autogate/bench/runs";
export const BENCH_EMPTY_WORKSPACE_DIR = "/tmp/opencode/autogate-bench-empty-ws";
export const BENCH_SYNTHETIC_WORKSPACE_DIR = "/tmp/opencode/autogate-bench-syn-ws";

export function expandHomePath(p: string): string {
  const home = os.homedir();
  if (p === "~" || p === "$HOME" || p === "${HOME}") {
    return home;
  }
  if (p.startsWith("~/")) {
    return path.join(home, p.slice(2));
  }
  if (p.startsWith("$HOME/")) {
    return path.join(home, p.slice("$HOME/".length));
  }
  if (p.startsWith("${HOME}/")) {
    return path.join(home, p.slice("${HOME}/".length));
  }
  return p;
}

export function formatHomePath(p: string): string {
  const rawHome = os.homedir();
  const home = rawHome.length > 1 && rawHome.endsWith(path.sep) ? rawHome.slice(0, -1) : rawHome;
  if (p === home) {
    return "~";
  }
  if (p.startsWith(home + path.sep)) {
    return `~${p.slice(home.length)}`;
  }
  return p;
}

function lstatOrNull(targetPath: string): fs.Stats | null {
  try {
    return fs.lstatSync(targetPath);
  } catch (err) {
    if (
      typeof err === "object" &&
      err !== null &&
      "code" in err &&
      (err as { code?: unknown }).code === "ENOENT"
    ) {
      return null;
    }
    throw err;
  }
}

export function ensureEmptyBenchWorkspace(): string {
  const parentDir = path.dirname(BENCH_EMPTY_WORKSPACE_DIR);
  fs.mkdirSync(parentDir, { recursive: true });

  const stat = lstatOrNull(BENCH_EMPTY_WORKSPACE_DIR);
  if (stat && (!stat.isDirectory() || stat.isSymbolicLink())) {
    fs.rmSync(BENCH_EMPTY_WORKSPACE_DIR, { recursive: true, force: true });
    fs.mkdirSync(BENCH_EMPTY_WORKSPACE_DIR, { recursive: true });
  } else if (!stat) {
    fs.mkdirSync(BENCH_EMPTY_WORKSPACE_DIR, { recursive: true });
  }

  const entries = fs.readdirSync(BENCH_EMPTY_WORKSPACE_DIR);
  if (entries.length > 0) {
    fs.chmodSync(BENCH_EMPTY_WORKSPACE_DIR, 0o755);
    for (const entry of entries) {
      fs.rmSync(path.join(BENCH_EMPTY_WORKSPACE_DIR, entry), { recursive: true, force: true });
    }
  }

  const currentStat = fs.statSync(BENCH_EMPTY_WORKSPACE_DIR);
  if ((currentStat.mode & 0o777) !== 0o555) {
    fs.chmodSync(BENCH_EMPTY_WORKSPACE_DIR, 0o555);
  }

  return BENCH_EMPTY_WORKSPACE_DIR;
}

const SYNTHETIC_TYPES_STUB = `export type ClassifierVerdict = "ALLOW" | "BLOCK" | "UNSURE";
export type RiskLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type UserAuthorization = "NONE" | "LOW" | "MEDIUM" | "HIGH";
`;

export function ensureSyntheticBenchWorkspace(): string {
  const srcDir = path.join(BENCH_SYNTHETIC_WORKSPACE_DIR, "packages", "core", "src");
  const testDir = path.join(BENCH_SYNTHETIC_WORKSPACE_DIR, "packages", "core", "test");
  fs.mkdirSync(srcDir, { recursive: true });
  fs.mkdirSync(testDir, { recursive: true });

  const typesFile = path.join(srcDir, "types.ts");
  if (!fs.existsSync(typesFile)) {
    fs.writeFileSync(typesFile, SYNTHETIC_TYPES_STUB, "utf8");
  }

  return BENCH_SYNTHETIC_WORKSPACE_DIR;
}
