-- AI 监管层（Phase 0）: 审计事实。所有 AI 建议都只是只读 advisory，
-- 不是 Store truth；Agent 不信任这些表。observation 只存脱敏投影或 digest，
-- 绝不存聊天正文/密钥/路径原文。黑盒可重放: 当时看到什么、建议了什么、最终怎样。

CREATE TABLE IF NOT EXISTS ai_advisory_requests (
  id                 BIGSERIAL PRIMARY KEY,
  task_type          TEXT NOT NULL CHECK (task_type IN (
                       'conflict_review','disaster_review','recovery_plan',
                       'schedule_recommendation','anomaly_attribution',
                       'monitoring_inspection','import_review')),
  schema_version     TEXT NOT NULL,
  prompt_version     TEXT NOT NULL,
  model_id           TEXT NOT NULL,
  observation_digest BYTEA NOT NULL,          -- SHA-256 of the redacted observation
  observation_json   JSONB,                    -- 脱敏后的 observation（黑盒重放用）
  dedup_key          TEXT NOT NULL,            -- 去重：同事实只一次
  requested_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  deadline_at        TIMESTAMPTZ NOT NULL,
  state              TEXT NOT NULL DEFAULT 'queued' CHECK (state IN (
                       'queued','running','succeeded','failed','skipped','superseded')),
  error_code         TEXT,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (dedup_key)
);
CREATE INDEX IF NOT EXISTS idx_ai_advisory_requests_state
  ON ai_advisory_requests (state, requested_at DESC);
CREATE INDEX IF NOT EXISTS idx_ai_advisory_requests_task
  ON ai_advisory_requests (task_type, requested_at DESC);

CREATE TABLE IF NOT EXISTS ai_advisories (
  id                 BIGSERIAL PRIMARY KEY,
  request_id         BIGINT NOT NULL REFERENCES ai_advisory_requests(id) ON DELETE CASCADE,
  action             TEXT NOT NULL,
  candidate_refs     JSONB NOT NULL DEFAULT '[]'::jsonb,
  confidence         DOUBLE PRECISION NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
  abstain            BOOLEAN NOT NULL DEFAULT false,
  reason_summary     TEXT NOT NULL,
  evidence_refs      JSONB NOT NULL DEFAULT '[]'::jsonb,
  risk_flags         JSONB NOT NULL DEFAULT '[]'::jsonb,
  requested_obs      JSONB NOT NULL DEFAULT '[]'::jsonb,
  raw_response_digest BYTEA NOT NULL,         -- 原始响应只存 digest
  expires_at         TIMESTAMPTZ NOT NULL,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_ai_advisories_request
  ON ai_advisories (request_id);

CREATE TABLE IF NOT EXISTS ai_advisory_outcomes (
  id                    BIGSERIAL PRIMARY KEY,
  request_id            BIGINT NOT NULL REFERENCES ai_advisory_requests(id) ON DELETE CASCADE,
  decision              TEXT NOT NULL CHECK (decision IN ('rejected','shown','accepted','ignored')),
  validator_code        TEXT,
  actor_type            TEXT NOT NULL CHECK (actor_type IN ('user','admin','system','none')),
  deterministic_ref     TEXT,                  -- 对应确定性流程引用（如 workflow id / 告警 id）
  observed_outcome      TEXT,                  -- fallback/采纳/未采纳等结果摘要
  decided_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_ai_advisory_outcomes_request
  ON ai_advisory_outcomes (request_id);
