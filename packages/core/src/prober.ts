import fs from "fs"
import path from "path"
import os from "os"

export interface ScriptTarget {
  scriptPath: string
  runner: string
}

const SCRIPT_RUNNERS = new Set([
  "bash",
  "sh",
  "zsh",
  "python",
  "python3",
  "node",
  "bun",
  "ts-node",
])

const CLI_WRAPPERS = new Set(["sudo", "env", "nohup", "time"])

/**
 * Extracts a command string from actionArgs, handling string, array, or object shapes.
 */
export function extractCommandString(actionArgs: unknown): string | null {
  if (!actionArgs) return null
  if (typeof actionArgs === "string") return actionArgs
  if (Array.isArray(actionArgs)) {
    return actionArgs.filter((a) => typeof a === "string").join(" ")
  }
  if (typeof actionArgs === "object" && actionArgs !== null) {
    const obj = actionArgs as Record<string, unknown>
    if (typeof obj.command === "string") return obj.command
    if (typeof obj.cmd === "string") return obj.cmd
    if (Array.isArray(obj.command)) {
      return obj.command.filter((a) => typeof a === "string").join(" ")
    }
    if (Array.isArray(obj.cmd)) {
      return obj.cmd.filter((a) => typeof a === "string").join(" ")
    }
    if (Array.isArray(obj.patterns)) {
      return obj.patterns.filter((a) => typeof a === "string").join(" ")
    }
    if (Array.isArray(obj.args)) {
      return obj.args.filter((a) => typeof a === "string").join(" ")
    }
  }
  return null
}

/**
 * Splits a command string into subcommands by operators (;, &&, ||, |) while respecting quotes.
 */
export function splitSubCommands(cmd: string): string[] {
  const commands: string[] = []
  let current = ""
  let inSingleQuote = false
  let inDoubleQuote = false
  let escape = false

  for (let i = 0; i < cmd.length; i++) {
    const char = cmd[i]

    if (escape) {
      current += char
      escape = false
      continue
    }

    if (char === "\\" && !inSingleQuote) {
      escape = true
      current += char
      continue
    }

    if (char === "'" && !inDoubleQuote) {
      inSingleQuote = !inSingleQuote
      current += char
      continue
    }

    if (char === '"' && !inSingleQuote) {
      inDoubleQuote = !inDoubleQuote
      current += char
      continue
    }

    if (!inSingleQuote && !inDoubleQuote) {
      if (char === ";") {
        if (current.trim()) commands.push(current.trim())
        current = ""
        continue
      }
      if (char === "&" && cmd[i + 1] === "&") {
        if (current.trim()) commands.push(current.trim())
        current = ""
        i++
        continue
      }
      if (char === "|" && cmd[i + 1] === "|") {
        if (current.trim()) commands.push(current.trim())
        current = ""
        i++
        continue
      }
      if (char === "|") {
        if (current.trim()) commands.push(current.trim())
        current = ""
        continue
      }
    }

    current += char
  }

  if (current.trim()) {
    commands.push(current.trim())
  }

  return commands
}

/**
 * Tokenizes a single command string into argument tokens while stripping quotes.
 */
export function tokenizeCommand(cmd: string): string[] {
  const tokens: string[] = []
  let current = ""
  let inSingleQuote = false
  let inDoubleQuote = false
  let escape = false

  for (let i = 0; i < cmd.length; i++) {
    const char = cmd[i]

    if (escape) {
      current += char
      escape = false
      continue
    }

    if (char === "\\" && !inSingleQuote) {
      escape = true
      continue
    }

    if (char === "'" && !inDoubleQuote) {
      inSingleQuote = !inSingleQuote
      continue
    }

    if (char === '"' && !inSingleQuote) {
      inDoubleQuote = !inDoubleQuote
      continue
    }

    if (!inSingleQuote && !inDoubleQuote && /\s/.test(char)) {
      if (current.length > 0) {
        tokens.push(current)
        current = ""
      }
      continue
    }

    current += char
  }

  if (current.length > 0) {
    tokens.push(current)
  }

  return tokens
}

/**
 * Strips enclosing quotes from a path string if present.
 */
export function unquotePath(str: string): string {
  const trimmed = str.trim()
  if (
    (trimmed.startsWith('"') && trimmed.endsWith('"')) ||
    (trimmed.startsWith("'") && trimmed.endsWith("'"))
  ) {
    return trimmed.slice(1, -1)
  }
  return trimmed
}

/**
 * Infer runner from script shebang or extension.
 */
function inferRunner(scriptPath: string, defaultRunner = "bash"): string {
  try {
    if (fs.existsSync(scriptPath)) {
      const fd = fs.openSync(scriptPath, "r")
      try {
        const buf = Buffer.alloc(256)
        const bytesRead = fs.readSync(fd, buf, 0, 256, 0)
        const firstLine = buf.subarray(0, bytesRead).toString("utf-8").split("\n")[0]
        if (firstLine.startsWith("#!")) {
          const shebang = firstLine.toLowerCase()
          if (shebang.includes("python3")) return "python3"
          if (shebang.includes("python")) return "python"
          if (shebang.includes("node")) return "node"
          if (shebang.includes("bun")) return "bun"
          if (shebang.includes("ts-node")) return "ts-node"
          if (shebang.includes("zsh")) return "zsh"
          if (shebang.includes("bash")) return "bash"
          if (shebang.includes("sh")) return "sh"
        }
      } finally {
        fs.closeSync(fd)
      }
    }
  } catch {}

  const ext = path.extname(scriptPath).toLowerCase()
  if (ext === ".py") return "python"
  if (ext === ".sh" || ext === ".bash") return "bash"
  if (ext === ".zsh") return "zsh"
  if (ext === ".js" || ext === ".mjs" || ext === ".cjs") return "node"
  if (ext === ".ts" || ext === ".mts") return "bun"

  return defaultRunner
}

/**
 * Detect script target from a single command string.
 */
function detectFromSingleCommand(cmdStr: string, root: string): ScriptTarget | null {
  const trimmed = cmdStr.trim()
  if (!trimmed) return null

  // 1. Detect executable scripts: paths matching ^\s*(\./[^\s;&|]+|scripts/[^\s;&|]+)
  const execMatch = trimmed.match(/^["']?(\.[/\\][^\s;&|'"]+|scripts[/\\][^\s;&|'"]+)["']?/i)
  if (execMatch && execMatch[1]) {
    const rawPath = unquotePath(execMatch[1])
    const scriptPath = path.isAbsolute(rawPath) ? path.resolve(rawPath) : path.resolve(root, rawPath)
    const runner = inferRunner(scriptPath, "bash")
    return { scriptPath, runner }
  }

  // 2. Tokenize and inspect runners
  const tokens = tokenizeCommand(trimmed)
  if (tokens.length === 0) return null

  // Skip leading environment variable assignments (e.g. FOO=bar) and CLI wrappers (e.g. sudo, env)
  let i = 0
  while (i < tokens.length) {
    const token = tokens[i]
    if (token.includes("=") && /^[A-Za-z_][A-Za-z0-9_]*=/.test(token)) {
      i++
      continue
    }
    if (CLI_WRAPPERS.has(token.toLowerCase())) {
      i++
      continue
    }
    break
  }

  if (i >= tokens.length) return null

  const runnerToken = tokens[i]
  const baseRunner = path.basename(runnerToken).toLowerCase()

  let runner: string | null = null
  if (SCRIPT_RUNNERS.has(baseRunner)) {
    runner = baseRunner
  } else if (/^python[23]?(?:\.\d+)?$/.test(baseRunner)) {
    runner = baseRunner.startsWith("python3") ? "python3" : "python"
  }

  if (!runner) return null

  // Process arguments following the runner
  const args = tokens.slice(i + 1)
  if (args.length === 0) return null

  // Special case: bun run <script>
  if (runner === "bun" && args[0] === "run") {
    args.shift()
  }

  // Flags that take an argument
  const FLAGS_WITH_ARG: Record<string, Set<string>> = {
    python: new Set(["-w", "-x"]),
    python3: new Set(["-w", "-x"]),
    node: new Set(["-r", "--require", "--import"]),
    bash: new Set(["-o"]),
    sh: new Set(["-o"]),
    zsh: new Set(["-o"]),
  }

  let targetIndex = -1
  for (let j = 0; j < args.length; j++) {
    const arg = args[j]

    if (arg.startsWith("-")) {
      const lower = arg.toLowerCase()

      // Inline code execution or module execution flags mean there is no script file
      if (
        (runner.startsWith("python") && (lower === "-c" || lower === "-m")) ||
        ((runner === "bash" || runner === "sh" || runner === "zsh") && lower === "-c") ||
        ((runner === "node" || runner === "bun") && (lower === "-e" || lower === "--eval" || lower === "-p" || lower === "--print"))
      ) {
        return null
      }

      // Check if this flag takes an argument that follows it
      const argFlags = FLAGS_WITH_ARG[runner]
      if (argFlags && argFlags.has(lower)) {
        j++ // Skip the flag's argument
        continue
      }

      // If flag format is --flag=val, already 1 token
      continue
    }

    // Found first non-flag argument
    targetIndex = j
    break
  }

  if (targetIndex === -1) return null

  const rawTarget = unquotePath(args[targetIndex])
  if (!rawTarget) return null

  const scriptPath = path.isAbsolute(rawTarget) ? path.resolve(rawTarget) : path.resolve(root, rawTarget)
  return { scriptPath, runner }
}

/**
 * 1. detectScriptTarget
 * Inspects command string and detects runner or executable script targets.
 */
export function detectScriptTarget(
  actionName: string,
  actionArgs: unknown,
  workspaceRoot: string
): ScriptTarget | null {
  const root = workspaceRoot || process.cwd()
  const rawCmd = extractCommandString(actionArgs)
  if (!rawCmd || !rawCmd.trim()) return null

  const subCommands = splitSubCommands(rawCmd)
  for (const subCmd of subCommands) {
    const target = detectFromSingleCommand(subCmd, root)
    if (target) return target
  }

  return null
}

/**
 * 2. inlineScriptContent
 * Safely reads and inlines script content up to maxBytes with path containment and binary checks.
 */
export function inlineScriptContent(
  scriptPath: string,
  maxBytes = 20480,
  workspaceRoot: string = process.cwd(),
  allowedPaths?: string[]
): string | null {
  try {
    if (!scriptPath || typeof scriptPath !== "string") return null

    const root = path.resolve(workspaceRoot)
    const resolvedPath = path.isAbsolute(scriptPath)
      ? path.resolve(scriptPath)
      : path.resolve(root, scriptPath)

    // Check if file exists
    if (!fs.existsSync(resolvedPath)) {
      return null
    }

    const stat = fs.statSync(resolvedPath)
    if (!stat.isFile()) {
      return null
    }

    // Explicit sensitive path exclusion before path containment check
    const lower = resolvedPath.toLowerCase()
    if (
      lower.includes("/.ssh/") ||
      lower.includes("/.aws/") ||
      lower.includes("/.gnupg/") ||
      lower.startsWith("/etc/") ||
      lower.startsWith("/private/etc/") ||
      lower.includes("/id_rsa") ||
      lower.includes("/id_ed25519")
    ) {
      return null
    }

    // Path containment check: ensure resolvedPath is within defaultAllowedRoots or allowedPaths
    const defaultAllowedRoots = [
      root,
      path.resolve(os.tmpdir()),
      path.resolve("/tmp"),
      path.resolve("/var/tmp"),
      path.resolve("/private/tmp"),
      ...(allowedPaths || []).map((p) => {
        if (p === "~") return os.homedir()
        if (p.startsWith("~/") || p.startsWith("~\\")) {
          return path.resolve(os.homedir(), p.slice(2))
        }
        return path.resolve(p)
      }),
    ]
    const allAllowedRoots = [...defaultAllowedRoots]
    for (const r of defaultAllowedRoots) {
      try {
        if (fs.existsSync(r)) {
          const realR = fs.realpathSync(r)
          if (!allAllowedRoots.includes(realR)) {
            allAllowedRoots.push(realR)
          }
        }
      } catch {}
    }

    const isWithinAllowed = (target: string) => {
      const norm = path.resolve(target)
      return allAllowedRoots.some((r) => norm === r || norm.startsWith(r + path.sep))
    }

    if (!isWithinAllowed(resolvedPath)) {
      return null
    }

    // Check realpath in case of symlink path traversal
    try {
      const real = fs.realpathSync(resolvedPath)
      const realLower = real.toLowerCase()
      if (
        realLower.includes("/.ssh/") ||
        realLower.includes("/.aws/") ||
        realLower.includes("/.gnupg/") ||
        realLower.startsWith("/etc/") ||
        realLower.startsWith("/private/etc/") ||
        realLower.includes("/id_rsa") ||
        realLower.includes("/id_ed25519")
      ) {
        return null
      }
      if (!isWithinAllowed(real)) {
        return null
      }
    } catch {
      return null
    }

    // Binary file check: inspect first 512 bytes for null bytes (\0)
    const probeSize = Math.min(512, stat.size)
    if (probeSize > 0) {
      const probeBuf = Buffer.alloc(probeSize)
      const fd = fs.openSync(resolvedPath, "r")
      try {
        fs.readSync(fd, probeBuf, 0, probeSize, 0)
      } finally {
        fs.closeSync(fd)
      }
      for (let i = 0; i < probeSize; i++) {
        if (probeBuf[i] === 0) {
          return "[Binary executable: content not inlined]"
        }
      }
    }

    // Read up to maxBytes
    if (stat.size > maxBytes) {
      const buf = Buffer.alloc(maxBytes)
      const fd = fs.openSync(resolvedPath, "r")
      let bytesRead = 0
      try {
        bytesRead = fs.readSync(fd, buf, 0, maxBytes, 0)
      } finally {
        fs.closeSync(fd)
      }
      const text = buf.subarray(0, bytesRead).toString("utf-8")
      return text + "\n\n[Truncated: script exceeds 20KB]"
    }

    return fs.readFileSync(resolvedPath, "utf-8")
  } catch {
    return null
  }
}

/**
 * Determines code block language identifier for markdown formatting.
 */
export function getCodeBlockLanguage(scriptPath: string, runner: string): string {
  const ext = path.extname(scriptPath).toLowerCase().replace(/^\./, "")
  if (ext === "py") return "python"
  if (ext === "js" || ext === "mjs" || ext === "cjs") return "javascript"
  if (ext === "ts" || ext === "mts" || ext === "cts") return "typescript"
  if (ext === "sh" || ext === "bash") return "bash"
  if (ext === "zsh") return "zsh"
  if (ext) return ext

  const r = runner.toLowerCase()
  if (r.startsWith("python")) return "python"
  if (r === "node") return "javascript"
  if (r === "bun" || r === "ts-node") return "typescript"
  if (r === "bash" || r === "sh" || r === "zsh") return "bash"
  return "text"
}

/**
 * Detect direct file target for non-script commands (e.g. rm -rf <path>, cat <path>).
 */
export function detectDirectFileTarget(
  actionName: string,
  actionArgs: unknown,
  workspaceRoot: string
): string | null {
  try {
    const root = workspaceRoot || process.cwd()

    // 1. Direct string argument
    if (typeof actionArgs === "string" && actionArgs.trim()) {
      const trimmed = actionArgs.trim()
      if (actionName !== "bash" && actionName !== "shell:run") {
        return trimmed
      }
      if (!trimmed.includes(" ") && (trimmed.includes("/") || trimmed.includes("."))) {
        return trimmed
      }
    }
    // 2. Direct array argument (e.g. patterns array)
    if (Array.isArray(actionArgs) && actionArgs.length > 0 && typeof actionArgs[0] === "string") {
      const first = actionArgs[0].trim()
      if (
        actionName === "external_directory" ||
        actionName.startsWith("fs:") ||
        actionName === "read" ||
        actionName === "edit" ||
        actionName === "write" ||
        (!first.includes(" ") && (first.includes("/") || first.includes(".")))
      ) {
        return first
      }
    }

    // 3. Direct object properties (path, file, filePath, directory, patterns)
    if (typeof actionArgs === "object" && actionArgs !== null) {
      const obj = actionArgs as Record<string, unknown>
      if (typeof obj.path === "string" && obj.path.trim()) {
        return obj.path.trim()
      }
      if (typeof obj.file === "string" && obj.file.trim()) {
        return obj.file.trim()
      }
      if (typeof obj.filePath === "string" && obj.filePath.trim()) {
        return obj.filePath.trim()
      }
      if (typeof obj.directory === "string" && obj.directory.trim()) {
        return obj.directory.trim()
      }
      if (typeof (obj.metadata as any)?.directory === "string" && (obj.metadata as any).directory.trim()) {
        return (obj.metadata as any).directory.trim()
      }
      if (!obj.path && typeof (obj.metadata as any)?.filepath === "string" && (obj.metadata as any).filepath.trim()) {
        return (obj.metadata as any).filepath.trim()
      }
      if (Array.isArray(obj.patterns) && obj.patterns.length > 0 && typeof obj.patterns[0] === "string") {
        const first = obj.patterns[0].trim()
        if (actionName === "external_directory" || actionName.startsWith("fs:") || (!first.includes(" ") && (first.includes("/") || first.includes(".")))) {
          return first
        }
      }
    }

    // 2. Command inspection (rm, unlink, rmdir, chmod, chown, cat, touch, stat)
    const rawCmd = extractCommandString(actionArgs)
    if (!rawCmd) return null

    const subCommands = splitSubCommands(rawCmd)
    for (const sub of subCommands) {
      const tokens = tokenizeCommand(sub)
      if (tokens.length === 0) continue

      let i = 0
      while (i < tokens.length && (tokens[i].includes("=") || CLI_WRAPPERS.has(tokens[i].toLowerCase()))) {
        i++
      }
      if (i >= tokens.length) continue

      const base = path.basename(tokens[i]).toLowerCase()
      const FILE_TARGET_COMMANDS = new Set([
        "rm",
        "unlink",
        "rmdir",
        "chmod",
        "chown",
        "cat",
        "touch",
        "stat",
        "truncate",
      ])

      if (FILE_TARGET_COMMANDS.has(base)) {
        let j = i + 1
        if (base === "chmod" || base === "chown") {
          j++
        }
        while (j < tokens.length && tokens[j].startsWith("-")) {
          j++
        }
        if (j < tokens.length) {
          return unquotePath(tokens[j])
        }
      }
    }

    return null
  } catch {
    return null
  }
}

/**
 * 3. probeTargetContext
 * Probes target script and inlines its content, or checks file existence for direct targets.
 */
export function probeTargetContext(
  actionName: string,
  actionArgs: unknown,
  workspaceRoot: string,
  environment?: import("./types").EnvironmentConfig
): string | null {
  try {
    const root = workspaceRoot || process.cwd()

    // 1. Check if it targets a script
    const scriptTarget = detectScriptTarget(actionName, actionArgs, root)
    if (scriptTarget) {
      const inlined = inlineScriptContent(scriptTarget.scriptPath, 20480, root, environment?.trustedPaths)
      if (inlined !== null) {
        let relPath = path.relative(root, scriptTarget.scriptPath)
        if (relPath.startsWith("..") || !relPath) {
          relPath = scriptTarget.scriptPath
        }
        const ext = getCodeBlockLanguage(scriptTarget.scriptPath, scriptTarget.runner)
        return `- **Target Script Inspected** (\`${relPath}\` via \`${scriptTarget.runner}\`):\n\`\`\`${ext}\n${inlined}\n\`\`\``
      }
      return null
    }

    // 2. Check filesystem existence for direct file targets if not a script
    const directTarget = detectDirectFileTarget(actionName, actionArgs, root)
    if (directTarget) {
      const resolved = path.isAbsolute(directTarget) ? path.resolve(directTarget) : path.resolve(root, directTarget)
      let relPath = path.relative(root, resolved)
      if (relPath.startsWith("..") || !relPath) {
        relPath = directTarget
      }
      try {
        if (fs.existsSync(resolved)) {
          const stat = fs.statSync(resolved)
          const kind = stat.isDirectory() ? "directory" : "file"
          return `- **Target Path Status**: \`${relPath}\` exists on disk (${kind}).`
        } else {
          let stripped = resolved.replace(/[\/\\]\*\*?.*$/, "")
          if (stripped === resolved) {
            stripped = resolved.replace(/[\/\\][\*\?].*$/, "")
          }
          stripped = stripped.replace(/[\/\\]+$/, "")
          if (!stripped && (resolved.startsWith("/") || resolved.startsWith("\\"))) {
            stripped = path.parse(resolved).root
          }
          if (stripped && stripped !== resolved && fs.existsSync(stripped)) {
            const stat = fs.statSync(stripped)
            const kind = stat.isDirectory() ? "directory" : "file"
            let strippedRel = path.relative(root, stripped)
            if (strippedRel.startsWith("..") || !strippedRel) {
              strippedRel = stripped
            }
            return `- **Target Path Status**: \`${relPath}\` matches \`${strippedRel}\` which exists on disk (${kind}).`
          }
          return `- **Target Path Status**: \`${relPath}\` does not exist on disk.`
        }
      } catch {
        return `- **Target Path Status**: \`${relPath}\` status unknown.`
      }
    }

    return null
  } catch {
    return null
  }
}
