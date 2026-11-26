export const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS prompt_templates (
  hash TEXT PRIMARY KEY,
  system_prompt TEXT NOT NULL,
  agent_config TEXT,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS s2_sessions (
  s2_session_id TEXT PRIMARY KEY,
  target_session_id TEXT,
  title TEXT,
  agent TEXT,
  directory TEXT,
  status TEXT NOT NULL,
  template_hash TEXT REFERENCES prompt_templates(hash),
  model_id TEXT,
  model_provider TEXT,
  prompt_tokens INTEGER,
  output_tokens INTEGER,
  reasoning_tokens INTEGER,
  cache_read_tokens INTEGER,
  cache_write_tokens INTEGER,
  cost REAL,
  message_count INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER,
  updated_at INTEGER,
  archived_at INTEGER,
  payload_zstd BLOB NOT NULL,
  raw_bytes INTEGER NOT NULL,
  compressed_bytes INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS evaluations (
  id TEXT PRIMARY KEY,
  source_format TEXT NOT NULL,
  timestamp INTEGER NOT NULL,
  session_id TEXT NOT NULL,
  s2_session_id TEXT UNIQUE,
  action_id TEXT,
  tool_name TEXT NOT NULL,
  command_string TEXT NOT NULL,
  target_path TEXT,
  workspace_root TEXT,
  user_prompt TEXT NOT NULL DEFAULT '',
  reasoning TEXT,
  thinking TEXT,
  verdict TEXT NOT NULL,
  risk_level TEXT,
  user_authorization TEXT,
  duration_ms INTEGER NOT NULL DEFAULT 0,
  model_id TEXT,
  model_provider TEXT,
  prompt_tokens INTEGER,
  output_tokens INTEGER,
  reasoning_tokens INTEGER,
  cost REAL,
  attempts INTEGER,
  error TEXT,
  cascade_json TEXT,
  cascade_winner TEXT,
  s2_aborted INTEGER NOT NULL DEFAULT 0,
  source_origin TEXT NOT NULL DEFAULT 'live'
);

CREATE TABLE IF NOT EXISTS deduped_eval_ids (
  id TEXT PRIMARY KEY,
  target_id TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_evaluations_timestamp ON evaluations(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_evaluations_session_timestamp ON evaluations(session_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_evaluations_verdict_timestamp ON evaluations(verdict, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_evaluations_action_id ON evaluations(action_id);
CREATE INDEX IF NOT EXISTS idx_s2_sessions_target_created ON s2_sessions(target_session_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_s2_sessions_created ON s2_sessions(created_at DESC);
`;

export const UPSERT_EVALUATION_BY_ID_SQL = `
INSERT INTO evaluations (
  id, source_format, timestamp, session_id, s2_session_id,
  action_id, tool_name, command_string, target_path, workspace_root,
  user_prompt, reasoning, thinking, verdict, risk_level,
  user_authorization, duration_ms, model_id, model_provider,
  prompt_tokens, output_tokens, reasoning_tokens, cost, attempts,
  error, cascade_json, cascade_winner, s2_aborted, source_origin
) VALUES (
  ?, ?, ?, ?, ?,
  ?, ?, ?, ?, ?,
  ?, ?, ?, ?, ?,
  ?, ?, ?, ?,
  ?, ?, ?, ?, ?,
  ?, ?, ?, ?, ?
)
ON CONFLICT(id) DO UPDATE SET
  source_format = COALESCE(NULLIF(evaluations.source_format, ''), excluded.source_format),
  timestamp = CASE
    WHEN evaluations.source_origin = 'opencode-db-import' AND excluded.source_origin != 'opencode-db-import' AND excluded.timestamp > 0 THEN excluded.timestamp
    WHEN evaluations.timestamp > 0 THEN evaluations.timestamp
    ELSE excluded.timestamp
  END,
  session_id = CASE
    WHEN evaluations.source_origin = 'opencode-db-import' AND excluded.source_origin != 'opencode-db-import' AND excluded.session_id != '' THEN excluded.session_id
    ELSE COALESCE(NULLIF(evaluations.session_id, ''), excluded.session_id)
  END,
  s2_session_id = COALESCE(NULLIF(evaluations.s2_session_id, ''), excluded.s2_session_id),
  action_id = COALESCE(NULLIF(evaluations.action_id, ''), excluded.action_id),
  tool_name = CASE
    WHEN evaluations.source_origin = 'opencode-db-import' AND excluded.source_origin != 'opencode-db-import' AND excluded.tool_name != '' THEN excluded.tool_name
    ELSE COALESCE(NULLIF(evaluations.tool_name, ''), excluded.tool_name)
  END,
  command_string = CASE
    WHEN evaluations.source_origin = 'opencode-db-import' AND excluded.source_origin != 'opencode-db-import' AND excluded.command_string != '' THEN excluded.command_string
    ELSE COALESCE(NULLIF(evaluations.command_string, ''), excluded.command_string)
  END,
  target_path = COALESCE(NULLIF(evaluations.target_path, ''), excluded.target_path),
  workspace_root = CASE
    WHEN evaluations.source_origin = 'opencode-db-import' AND excluded.source_origin != 'opencode-db-import' AND NULLIF(excluded.workspace_root, '') IS NOT NULL THEN excluded.workspace_root
    ELSE COALESCE(NULLIF(evaluations.workspace_root, ''), excluded.workspace_root)
  END,
  user_prompt = CASE
    WHEN evaluations.source_origin = 'opencode-db-import' AND excluded.source_origin != 'opencode-db-import' AND excluded.user_prompt != '' THEN excluded.user_prompt
    WHEN evaluations.user_prompt != '' THEN evaluations.user_prompt
    ELSE excluded.user_prompt
  END,
  reasoning = CASE
    WHEN evaluations.source_origin = 'opencode-db-import' AND excluded.source_origin != 'opencode-db-import' AND NULLIF(excluded.reasoning, '') IS NOT NULL THEN excluded.reasoning
    ELSE COALESCE(NULLIF(evaluations.reasoning, ''), excluded.reasoning)
  END,
  thinking = COALESCE(NULLIF(evaluations.thinking, ''), excluded.thinking),
  verdict = CASE
    WHEN evaluations.source_origin = 'opencode-db-import' AND excluded.source_origin != 'opencode-db-import' THEN excluded.verdict
    ELSE COALESCE(NULLIF(evaluations.verdict, ''), excluded.verdict)
  END,
  risk_level = CASE
    WHEN evaluations.source_origin = 'opencode-db-import' AND excluded.source_origin != 'opencode-db-import' AND NULLIF(excluded.risk_level, '') IS NOT NULL THEN excluded.risk_level
    ELSE COALESCE(NULLIF(evaluations.risk_level, ''), excluded.risk_level)
  END,
  user_authorization = CASE
    WHEN evaluations.source_origin = 'opencode-db-import' AND excluded.source_origin != 'opencode-db-import' AND NULLIF(excluded.user_authorization, '') IS NOT NULL THEN excluded.user_authorization
    ELSE COALESCE(NULLIF(evaluations.user_authorization, ''), excluded.user_authorization)
  END,
  duration_ms = CASE
    WHEN evaluations.source_origin = 'opencode-db-import' AND excluded.source_origin != 'opencode-db-import' AND excluded.duration_ms > 0 THEN excluded.duration_ms
    WHEN evaluations.duration_ms > 0 THEN evaluations.duration_ms
    ELSE excluded.duration_ms
  END,
  model_id = COALESCE(NULLIF(evaluations.model_id, ''), excluded.model_id),
  model_provider = COALESCE(NULLIF(evaluations.model_provider, ''), excluded.model_provider),
  prompt_tokens = COALESCE(evaluations.prompt_tokens, excluded.prompt_tokens),
  output_tokens = COALESCE(evaluations.output_tokens, excluded.output_tokens),
  reasoning_tokens = COALESCE(evaluations.reasoning_tokens, excluded.reasoning_tokens),
  cost = COALESCE(evaluations.cost, excluded.cost),
  attempts = COALESCE(evaluations.attempts, excluded.attempts),
  error = COALESCE(NULLIF(evaluations.error, ''), excluded.error),
  cascade_json = COALESCE(NULLIF(evaluations.cascade_json, ''), excluded.cascade_json),
  cascade_winner = COALESCE(NULLIF(evaluations.cascade_winner, ''), excluded.cascade_winner),
  s2_aborted = CASE
    WHEN evaluations.source_origin = 'opencode-db-import' AND excluded.source_origin != 'opencode-db-import' THEN excluded.s2_aborted
    ELSE MAX(evaluations.s2_aborted, excluded.s2_aborted)
  END,
  source_origin = CASE
    WHEN evaluations.source_origin = 'opencode-db-import' AND excluded.source_origin != 'opencode-db-import' THEN excluded.source_origin
    ELSE COALESCE(NULLIF(evaluations.source_origin, ''), excluded.source_origin)
  END
RETURNING *
`;

export const UPSERT_S2_SESSION_SQL = `
INSERT INTO s2_sessions (
  s2_session_id, target_session_id, title, agent, directory,
  status, template_hash, model_id, model_provider,
  prompt_tokens, output_tokens, reasoning_tokens,
  cache_read_tokens, cache_write_tokens, cost,
  message_count, created_at, updated_at, archived_at,
  payload_zstd, raw_bytes, compressed_bytes
) VALUES (
  ?, ?, ?, ?, ?,
  ?, ?, ?, ?,
  ?, ?, ?,
  ?, ?, ?,
  ?, ?, ?, ?,
  ?, ?, ?
)
ON CONFLICT(s2_session_id) DO UPDATE SET
  target_session_id = COALESCE(excluded.target_session_id, s2_sessions.target_session_id),
  title = COALESCE(excluded.title, s2_sessions.title),
  agent = COALESCE(excluded.agent, s2_sessions.agent),
  directory = COALESCE(excluded.directory, s2_sessions.directory),
  status = CASE
    WHEN s2_sessions.message_count > 0 AND excluded.message_count <= 0 THEN s2_sessions.status
    ELSE excluded.status
  END,
  template_hash = COALESCE(excluded.template_hash, s2_sessions.template_hash),
  model_id = COALESCE(excluded.model_id, s2_sessions.model_id),
  model_provider = COALESCE(excluded.model_provider, s2_sessions.model_provider),
  prompt_tokens = COALESCE(excluded.prompt_tokens, s2_sessions.prompt_tokens),
  output_tokens = COALESCE(excluded.output_tokens, s2_sessions.output_tokens),
  reasoning_tokens = COALESCE(excluded.reasoning_tokens, s2_sessions.reasoning_tokens),
  cache_read_tokens = COALESCE(excluded.cache_read_tokens, s2_sessions.cache_read_tokens),
  cache_write_tokens = COALESCE(excluded.cache_write_tokens, s2_sessions.cache_write_tokens),
  cost = COALESCE(excluded.cost, s2_sessions.cost),
  message_count = CASE
    WHEN excluded.message_count > 0 THEN excluded.message_count
    ELSE s2_sessions.message_count
  END,
  created_at = COALESCE(s2_sessions.created_at, excluded.created_at),
  updated_at = COALESCE(excluded.updated_at, s2_sessions.updated_at),
  archived_at = COALESCE(excluded.archived_at, s2_sessions.archived_at),
  payload_zstd = CASE
    WHEN s2_sessions.message_count > 0 AND excluded.message_count <= 0 THEN s2_sessions.payload_zstd
    ELSE excluded.payload_zstd
  END,
  raw_bytes = CASE
    WHEN s2_sessions.message_count > 0 AND excluded.message_count <= 0 THEN s2_sessions.raw_bytes
    ELSE excluded.raw_bytes
  END,
  compressed_bytes = CASE
    WHEN s2_sessions.message_count > 0 AND excluded.message_count <= 0 THEN s2_sessions.compressed_bytes
    ELSE excluded.compressed_bytes
  END
RETURNING
  s2_session_id, target_session_id, title, agent, directory,
  status, template_hash, model_id, model_provider,
  prompt_tokens, output_tokens, reasoning_tokens,
  cache_read_tokens, cache_write_tokens, cost,
  message_count, created_at, updated_at, archived_at,
  raw_bytes, compressed_bytes
`;
