-- AI 监管层决策④（auto_low_risk 分级采纳）：采纳效果事实与审计扩展。
-- 效果表只是确定性读路径的输入缓存，不是 Store truth；Agent 永不读写；
-- 行随 advisory 过期自然失效（partial index 保证活跃读路径零成本）。

-- auto_adopted 与人工 accepted 分开，审计一条 SQL 即可区分自动采纳与人工接受（决策⑤黑盒）。
ALTER TABLE ai_advisory_outcomes DROP CONSTRAINT ai_advisory_outcomes_decision_check;
ALTER TABLE ai_advisory_outcomes ADD CONSTRAINT ai_advisory_outcomes_decision_check
  CHECK (decision IN ('rejected','shown','accepted','auto_adopted','ignored'));

CREATE TABLE IF NOT EXISTS ai_adoption_effects (
  id          BIGSERIAL PRIMARY KEY,
  request_id  BIGINT NOT NULL REFERENCES ai_advisory_requests(id) ON DELETE CASCADE,
  advisory_id BIGINT NOT NULL REFERENCES ai_advisories(id) ON DELETE CASCADE,
  effect_kind TEXT NOT NULL CHECK (effect_kind IN
                ('inspection_summary','alert_note','node_order_hint','backup_order_hint')),
  target_ref  TEXT NOT NULL,                  -- 确定性目标（node id 列表 / 告警 user_uuid / 'cluster'）
  payload     JSONB NOT NULL,                 -- {"order":[...]} / {"note":"..."}（已过 secret scan）
  expires_at  TIMESTAMPTZ NOT NULL,           -- 与 advisory.expires_at 对齐（默认 15 分钟）
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  -- 同一请求同一种效果只落一行（幂等采纳）。
  UNIQUE (request_id, effect_kind)
);
-- 活跃读路径按 expires_at 过滤；不能用 WHERE expires_at > now() 的 partial index
-- （now() 是 STABLE 而非 IMMUTABLE，真实 PostgreSQL 会拒绝创建）。
CREATE INDEX IF NOT EXISTS idx_ai_adoption_effects_live
  ON ai_adoption_effects (effect_kind, target_ref, created_at DESC);
