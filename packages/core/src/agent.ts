import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const EVAL_AGENT_ID = "auto-gate-eval";
export const FALLBACK_CLASSIFIER_MODEL = "google/gemini-3.5-flash-lite";

export const PASSIVE_EVALUATOR_DIRECTIVE =
  "CRITICAL: You are an isolated security evaluation judge. Your ONLY tool is classify_result. You must NEVER execute the command, run bash, edit files, or perform any operational action. Immediately invoke classify_result and stop.";

export interface AgentPermissionRule {
  action: string;
  resource: string;
  effect: "allow" | "deny" | "ask";
}

export interface EvalAgentRequestConfig {
  settings?: Record<string, unknown>;
  headers?: Record<string, string>;
  body?: Record<string, unknown>;
}

export interface EvalAgentDefinition {
  id: string;
  name: string;
  description?: string;
  mode: "primary" | "subagent" | "all";
  hidden: boolean;
  color?: string;
  system: string;
  steps?: number;
  model?: string;
  request?: EvalAgentRequestConfig;
  permissions?: AgentPermissionRule[];
}

export interface ParsedModelRef {
  providerID: string;
  modelID: string;
  variant?: string;
}

function isPlainRecord(val: unknown): val is Record<string, unknown> {
  return typeof val === "object" && val !== null && !Array.isArray(val);
}

function parseYamlScalar(raw: string): unknown {
  const trimmed = raw.trim();
  if (trimmed === "" || trimmed === "null" || trimmed === "~") return null;
  if (trimmed === "true") return true;
  if (trimmed === "false") return false;
  if (trimmed === "{}") return {};
  if (trimmed === "[]") return [];

  if (
    (trimmed.startsWith('"') && trimmed.endsWith('"') && trimmed.length >= 2) ||
    (trimmed.startsWith("'") && trimmed.endsWith("'") && trimmed.length >= 2)
  ) {
    const quote = trimmed[0];
    const inner = trimmed.slice(1, -1);
    return quote === '"'
      ? inner.replace(/\\"/g, '"').replace(/\\\\/g, "\\")
      : inner.replace(/''/g, "'");
  }

  if (/^-?\d+(?:\.\d+)?$/.test(trimmed)) {
    const num = Number(trimmed);
    if (Number.isFinite(num)) return num;
  }

  return trimmed;
}

interface YamlLine {
  indent: number;
  text: string;
}

function tokenizeYamlLines(frontmatter: string): YamlLine[] {
  const lines: YamlLine[] = [];
  for (const rawLine of frontmatter.split(/\r?\n/)) {
    const trimmed = rawLine.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const indentMatch = rawLine.match(/^(\s*)/);
    const indent = indentMatch ? indentMatch[1].length : 0;
    lines.push({ indent, text: trimmed });
  }
  return lines;
}

function splitYamlKeyValue(text: string): { key: string; value: string } | null {
  const match = text.match(/^([A-Za-z0-9_.-]+|"[^"]+"|'[^']+')\s*:\s*(.*)$/);
  if (!match || !match[1]) return null;
  const rawKey = match[1];
  const key =
    (rawKey.startsWith('"') && rawKey.endsWith('"')) ||
    (rawKey.startsWith("'") && rawKey.endsWith("'"))
      ? rawKey.slice(1, -1)
      : rawKey;
  return { key, value: match[2] ?? "" };
}

function parseYamlBlock(
  lines: YamlLine[],
  startIndex: number,
  expectedIndent: number,
): { value: unknown; nextIndex: number } {
  if (startIndex >= lines.length) {
    return { value: {}, nextIndex: startIndex };
  }

  const first = lines[startIndex];
  if (!first || first.indent < expectedIndent) {
    return { value: {}, nextIndex: startIndex };
  }

  if (first.text.startsWith("- ") || first.text === "-") {
    const arr: unknown[] = [];
    let i = startIndex;
    const seqIndent = first.indent;

    while (i < lines.length) {
      const line = lines[i];
      if (!line || line.indent < seqIndent) break;
      if (line.indent > seqIndent) break;
      if (!line.text.startsWith("- ") && line.text !== "-") break;

      const afterDash = line.text === "-" ? "" : line.text.slice(2).trim();
      if (!afterDash) {
        const nextLine = lines[i + 1];
        if (nextLine && nextLine.indent > seqIndent) {
          const nested = parseYamlBlock(lines, i + 1, nextLine.indent);
          arr.push(nested.value);
          i = nested.nextIndex;
        } else {
          arr.push(null);
          i++;
        }
        continue;
      }

      const inlineKv = splitYamlKeyValue(afterDash);
      if (inlineKv) {
        const itemObj: Record<string, unknown> = {};
        if (inlineKv.value === "") {
          const nextLine = lines[i + 1];
          if (nextLine && nextLine.indent > seqIndent + 2) {
            const nested = parseYamlBlock(lines, i + 1, nextLine.indent);
            itemObj[inlineKv.key] = nested.value;
            i = nested.nextIndex;
          } else {
            itemObj[inlineKv.key] = {};
            i++;
          }
        } else {
          itemObj[inlineKv.key] = parseYamlScalar(inlineKv.value);
          i++;
        }

        const itemIndent = seqIndent + 2;
        while (i < lines.length) {
          const subLine = lines[i];
          if (!subLine || subLine.indent < itemIndent) break;
          if (
            subLine.indent === seqIndent &&
            (subLine.text.startsWith("- ") || subLine.text === "-")
          ) {
            break;
          }
          if (subLine.indent > itemIndent) break;
          const subKv = splitYamlKeyValue(subLine.text);
          if (!subKv) break;
          if (subKv.value === "") {
            const deeper = lines[i + 1];
            if (deeper && deeper.indent > subLine.indent) {
              const nested = parseYamlBlock(lines, i + 1, deeper.indent);
              itemObj[subKv.key] = nested.value;
              i = nested.nextIndex;
            } else {
              itemObj[subKv.key] = {};
              i++;
            }
          } else {
            itemObj[subKv.key] = parseYamlScalar(subKv.value);
            i++;
          }
        }

        arr.push(itemObj);
      } else {
        arr.push(parseYamlScalar(afterDash));
        i++;
      }
    }

    return { value: arr, nextIndex: i };
  }

  const obj: Record<string, unknown> = {};
  let i = startIndex;
  const mapIndent = first.indent;

  while (i < lines.length) {
    const line = lines[i];
    if (!line || line.indent < mapIndent) break;
    if (line.indent > mapIndent) break;
    if (line.text.startsWith("- ") || line.text === "-") break;

    const kv = splitYamlKeyValue(line.text);
    if (!kv) {
      i++;
      continue;
    }

    if (kv.value === "") {
      const nextLine = lines[i + 1];
      if (nextLine && nextLine.indent > mapIndent) {
        const nested = parseYamlBlock(lines, i + 1, nextLine.indent);
        obj[kv.key] = nested.value;
        i = nested.nextIndex;
      } else {
        obj[kv.key] = {};
        i++;
      }
    } else {
      obj[kv.key] = parseYamlScalar(kv.value);
      i++;
    }
  }

  return { value: obj, nextIndex: i };
}

export function parseYamlFrontmatter(frontmatter: string): Record<string, unknown> {
  const lines = tokenizeYamlLines(frontmatter);
  if (lines.length === 0) return {};
  const parsed = parseYamlBlock(lines, 0, lines[0]!.indent);
  return isPlainRecord(parsed.value) ? parsed.value : {};
}

export function parseAgentMarkdown(content: string, id = EVAL_AGENT_ID): EvalAgentDefinition {
  const match = content.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$/);
  const data = match && match[1] !== undefined ? parseYamlFrontmatter(match[1]) : {};
  const rawBody = (match && match[2] !== undefined ? match[2] : content).trim();

  const name = typeof data.name === "string" && data.name.trim() ? data.name.trim() : id;
  const description =
    typeof data.description === "string" && data.description.trim()
      ? data.description.trim()
      : undefined;
  const mode =
    data.mode === "primary" || data.mode === "subagent" || data.mode === "all"
      ? data.mode
      : "subagent";
  const hidden = typeof data.hidden === "boolean" ? data.hidden : false;
  const color = typeof data.color === "string" && data.color.trim() ? data.color.trim() : undefined;
  const steps =
    typeof data.steps === "number" && Number.isFinite(data.steps) ? data.steps : undefined;
  const model = typeof data.model === "string" && data.model.trim() ? data.model.trim() : undefined;

  let request: EvalAgentRequestConfig | undefined;
  if (isPlainRecord(data.request)) {
    const reqObj: EvalAgentRequestConfig = {};
    if (isPlainRecord(data.request.settings)) {
      reqObj.settings = data.request.settings;
    }
    if (isPlainRecord(data.request.headers)) {
      const headers: Record<string, string> = {};
      for (const [k, v] of Object.entries(data.request.headers)) {
        if (typeof v === "string") headers[k] = v;
      }
      if (Object.keys(headers).length > 0) reqObj.headers = headers;
    }
    if (isPlainRecord(data.request.body)) {
      reqObj.body = data.request.body;
    }
    if (reqObj.settings || reqObj.headers || reqObj.body) {
      request = reqObj;
    }
  }

  let permissions: AgentPermissionRule[] | undefined;
  if (Array.isArray(data.permissions)) {
    permissions = data.permissions.map((p) => {
      const rec = isPlainRecord(p) ? p : {};
      const action = typeof rec.action === "string" ? rec.action : "*";
      const resource = typeof rec.resource === "string" ? rec.resource : "*";
      const effect =
        rec.effect === "allow" || rec.effect === "deny" || rec.effect === "ask"
          ? rec.effect
          : "allow";
      return { action, resource, effect };
    });
  } else if (isPlainRecord(data.permissions)) {
    permissions = Object.entries(data.permissions).map(([action, effect]) => ({
      action,
      resource: "*",
      effect: effect === "allow" || effect === "deny" || effect === "ask" ? effect : "allow",
    }));
  }

  const system = rawBody.includes(PASSIVE_EVALUATOR_DIRECTIVE)
    ? rawBody
    : rawBody
      ? `${rawBody}\n\n${PASSIVE_EVALUATOR_DIRECTIVE}`
      : PASSIVE_EVALUATOR_DIRECTIVE;

  return {
    id,
    name,
    ...(description !== undefined ? { description } : {}),
    mode,
    hidden,
    ...(color !== undefined ? { color } : {}),
    system,
    ...(steps !== undefined ? { steps } : {}),
    ...(model !== undefined ? { model } : {}),
    ...(request !== undefined ? { request } : {}),
    ...(permissions !== undefined ? { permissions } : {}),
  };
}

export function resolveEvalAgentPath(): string | undefined {
  const dirs: string[] = [];
  try {
    if (typeof import.meta !== "undefined" && typeof import.meta.url === "string") {
      dirs.push(path.dirname(fileURLToPath(import.meta.url)));
    }
  } catch {}
  try {
    if (typeof __dirname !== "undefined") {
      dirs.push(__dirname);
    }
  } catch {}

  for (const dir of dirs) {
    for (const rel of ["../agents/auto-gate-eval.md", "../../agents/auto-gate-eval.md"]) {
      const candidate = path.resolve(dir, rel);
      if (fs.existsSync(candidate)) {
        return candidate;
      }
    }
  }

  return undefined;
}

export function loadEvalAgentDefinition(filePath?: string): EvalAgentDefinition {
  const resolvedPath = filePath ?? resolveEvalAgentPath();
  if (!resolvedPath || !fs.existsSync(resolvedPath)) {
    throw new Error(
      `AutoGate agent definition not found: ${resolvedPath ?? "packages/core/agents/auto-gate-eval.md"}`,
    );
  }
  const content = fs.readFileSync(resolvedPath, "utf8");
  const id = path.basename(resolvedPath, ".md") || EVAL_AGENT_ID;
  return parseAgentMarkdown(content, id);
}

export function getDefaultClassifierModel(): string {
  try {
    return loadEvalAgentDefinition().model ?? FALLBACK_CLASSIFIER_MODEL;
  } catch {
    return FALLBACK_CLASSIFIER_MODEL;
  }
}

export function parseModelRef(
  modelRef?: string,
  defaultModel = getDefaultClassifierModel(),
): ParsedModelRef {
  const ref = modelRef?.trim() || defaultModel;
  const slashIdx = ref.indexOf("/");
  const providerID = slashIdx > 0 ? ref.slice(0, slashIdx) : "google";
  const rest = slashIdx > 0 ? ref.slice(slashIdx + 1) : ref;
  const hashIdx = rest.indexOf("#");
  let modelID = hashIdx > 0 ? rest.slice(0, hashIdx) : rest;
  const variant = hashIdx > 0 ? rest.slice(hashIdx + 1) : undefined;
  modelID = modelID
    .replace(/\.flash/gi, "-flash")
    .replace(/\.lite/gi, "-lite")
    .replace(/\.pro/gi, "-pro");
  return {
    providerID,
    modelID,
    ...(variant ? { variant } : {}),
  };
}
