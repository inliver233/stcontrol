// 管理后台 API DTO 类型定义。
//
// 字段与 Go 后端 handler 实际写出的 JSON 一一对应：
// - internal/controller/admin.go、admin_auth.go、admin_node_links.go、
//   audit_admin.go、ai_admin.go、user_data_faults.go、identity_recovery.go、
//   imports.go、protection.go
// - internal/store/ 下被直接序列化的模型（models.go、admin_pagination.go、
//   controller_rebuilds.go、node_retirements.go、node_compatibility.go、
//   ai_advisories.go、user_data_faults.go、admins.go、audit_events.go、
//   protection.go、imports.go、admin_node_links.go）
//
// 约定：
// - database/sql 的 Null* 类型经 encoding/json 序列化为
//   { "String"|"Int64"|"Float64"|"Time"|"Int32": 值, "Valid": 布尔 } 对象。
// - store.BackupJob 未打 json tag，字段按 Go 导出名原样输出（ID/UserID/...）。
// - Go 侧 omitempty、*time.Time 指针或可空 slice 映射为可选字段（`?`）。
// - 个别带注释的"别名"字段是历史上前端双读取路径（`a ?? b`）中的死分支，
//   当前后端从不输出，仅为不改运行时代码而保留类型占位。

// ---------- database/sql Null* 的 JSON 形状 ----------

export interface NullString {
  String: string
  Valid: boolean
}

export interface NullInt64 {
  Int64: number
  Valid: boolean
}

export interface NullInt32 {
  Int32: number
  Valid: boolean
}

export interface NullFloat64 {
  Float64: number
  Valid: boolean
}

export interface NullTime {
  Time: string
  Valid: boolean
}

// ---------- 通用响应 ----------

/** map[string]bool{"ok": true} 形状的最小成功响应 */
export interface OkResponse {
  ok: boolean
}

// ---------- 仪表盘（store.AdminOverviewCounts / store.ControllerRebuildStatus） ----------

export interface AdminOverview {
  nodes: number
  nodes_online: number
  nodes_offline: number
  nodes_full: number
  nodes_busy: number
  nodes_maintenance: number
  nodes_fault: number
  users: number
  backup_running: number
  backup_failed: number
}

export interface ControllerRebuildNode {
  node_id: number
  node_name: string
  role: string
  state: string
  authenticated_generation?: number
  credential_version?: number
  last_heartbeat_at?: string
  credential_activated_at?: string
  reconciled_at?: string
}

/**
 * GET /api/admin/controller/rebuild。
 * 无对账记录时后端只写 { state, total_nodes, reconciled_nodes }，
 * 因此其余字段均为可选。
 */
export interface ControllerRebuild {
  state: string
  total_nodes: number
  reconciled_nodes: number
  id?: string
  operation_id?: string
  generation?: number
  previous_generation?: number
  source?: string
  error_code?: string
  started_at?: string
  updated_at?: string
  completed_at?: string
  nodes?: ControllerRebuildNode[]
}

// ---------- 节点（store.Node） ----------

/**
 * 状态徽章所需的最小视图。四个状态维度对完整 AdminNode 总是存在，
 * 但组件（及其测试）可能只拿到部分字段，因此统一声明为可选。
 */
export interface AdminNodeStatusView {
  connectivity_state?: string
  operational_state?: string
  capacity_state?: string
  compatibility_state?: string
  capacity_reason_code?: NullString
  compatibility_reason_code?: NullString
}

/** GET /api/admin/nodes 返回的节点行（store.Node，json tag 均为 snake_case） */
export interface AdminNode {
  id: number
  name: string
  role: string
  base_url: string
  region: NullString
  status: string
  connectivity_state: string
  operational_state: string
  control_mode: string
  desired_control_mode: string
  capacity_state: string
  capacity_reason_code: NullString
  compatibility_state: string
  compatibility_reason_code: NullString
  cpu_window_avg: NullFloat64
  cpu_window_peak: NullFloat64
  mem_window_avg: NullFloat64
  mem_window_peak: NullFloat64
  disk_window_avg: NullFloat64
  disk_window_peak: NullFloat64
  disk_available_bytes: NullInt64
  disk_quota_bytes: NullInt64
  allocated_disk_bytes: NullInt64
  expected_disk_quota_bytes: number
  quota_sync_state: string
  online_users: number
  task_queue_depth: number
  tavern_version: NullString
  allow_register: boolean
  is_backup_target: boolean
  recommendation_weight: number
}

/** POST /api/admin/nodes 请求体 */
export interface AdminNodeCreateInput {
  name: string
  role: string
  /** sql.NullString：{String, Valid} 或 null（= Null 零值） */
  region: NullString | null
  base_url: string
  expected_disk_quota_bytes: number
}

/** POST /api/admin/nodes 响应 */
export interface AdminNodeCreated {
  ok: boolean
  id: number
}

/** POST /api/admin/nodes/{id}/lifecycle 响应 */
export interface AdminNodeLifecycleResult {
  ok: boolean
  state: string
}

// ---------- 节点管理员关联（store.AdminNodeLink） ----------

export interface AdminNodeLink {
  node_id: number
  node_name: string
  node_base_url?: string
  node_state: string
  local_handle?: string
  state: 'unlinked' | 'verified' | 'stale' | 'revoked'
  permission_version?: number
  last_verified_at?: string
  last_error_code?: string
}

// ---------- 注册令牌（controller/admin.go handleAdminNodeRegisterToken） ----------

export interface RegisterToken {
  token: string
  expires_at: string
  install_cmd: string
  install_hint: string
}

// ---------- 既有账号导入扫描（store.AccountImport*） ----------

export interface ScanCandidate {
  local_handle: string
  size_bytes: number
  source: string
  account_kind: string
  /** Go []string 为 nil 时序列化为 null */
  identity_providers?: string[] | null
  is_admin: boolean
  resolution_state: string
  matched_user_uuid?: string
}

export interface ScanBatch {
  node_id: number
  source: string
  state: string
  candidate_count: number
  auto_linked_count: number
  unresolved_count: number
  scanned_at: string
  created_at: string
  replayed?: boolean
}

/**
 * POST /api/admin/nodes/{id}/scan-existing 与
 * GET /api/admin/nodes/{id}/imports/latest。
 * 节点从未扫描时 batch 为 null 且 next_candidate_offset 缺失。
 */
export interface ScanResult {
  batch: ScanBatch | null
  candidates?: ScanCandidate[] | null
  candidate_offset: number
  candidate_limit: number
  next_candidate_offset?: number
  has_more: boolean
}

// ---------- 节点退役 / 兼容性复核 ----------

/** store.NodeRetirementStatus */
export interface NodeRetirement {
  id: string
  operation_id: string
  node_id: number
  state: string
  reason_code: string
  total_items: number
  pending_items: number
  waiting_items: number
  running_items: number
  blocked_items: number
  failed_items: number
  completed_items: number
  error_code?: string
  controller_generation: number
  created_at: string
  updated_at: string
  completed_at?: string
}

/** store.NodeCompatibilityIncidentStatus */
export interface CompatibilityIncident {
  state: string
  reason_code: string
  compatible_observations: number
  required_observations: number
  agent_version: string
  tavern_version: string
  first_seen_at: string
  last_seen_at: string
  resolved_at?: string
}

// ---------- 用户（store.User） ----------

export interface AdminUser {
  id: number
  uuid: string
  username: string
  display_name: string
  auth_provider: string
  avatar_url: NullString
  home_node_id: NullInt64
  status: string
  created_at: string
  // 旧读取路径别名（`u.UUID ?? u.uuid` 等）：当前后端 json tag 均为小写，
  // 以下字段从不输出，仅为兼容既有 `??` 回退表达式保留类型。
  ID?: number
  UUID?: string
  Username?: string
  DisplayName?: string
  AuthProvider?: string
  HomeNodeID?: NullInt64
  Status?: string
}

/** POST /api/admin/users/{uuid}/identity-recovery 响应 */
export interface IdentityRecoveryResult {
  ok: boolean
  identity_recovered: boolean
  sessions_revoked: boolean
  user_uuid: string
  username: string
  user_status: string
  password_version: number
  node_sync: string
  synced_nodes: number
  pending_nodes: number
  staged_nodes: number
  replayed: boolean
}

/** store.UserDataFaultStatus */
export interface UserDataFaultStatus {
  id: string
  operation_id: string
  user_uuid: string
  node_id: number
  reason_code: string
  state: string
  activity_epoch: number
  controller_generation: number
  attempt: number
  reported_at: string
  updated_at: string
  replayed: boolean
  freeze_operation_id?: string
  protection_state?: string
  error_code?: string
  frozen_at?: string
  resolved_at?: string
  resolution_kind?: string
  resolution_operation_id?: string
}

// ---------- 备份任务（store.AdminBackupJob，内嵌无 json tag 的 BackupJob） ----------

/**
 * 所有字段可选：组件按 `job.ID ?? job.id` 双路径读取历史数据，
 * 且单元测试会传入部分字段的最小对象。
 * 当前后端的真实键为 Go 导出名（ID/UserID/...）+ snake_case 扩展字段。
 */
export interface AdminBackup {
  // store.BackupJob（无 json tag → Go 导出名）
  ID?: number
  UserID?: number
  SrcNodeID?: number
  DstNodeID?: number
  Trigger?: string
  Status?: string
  DataVersion?: NullInt64
  Bytes?: NullInt64
  FileCount?: NullInt32
  Error?: NullString
  StartedAt?: NullTime
  FinishedAt?: NullTime
  CreatedAt?: string
  // AdminBackupJob 扩展列（snake_case json tag）
  workflow_state?: string
  attempt?: number
  next_attempt_at?: string | null
  cleanup_state?: string
  error_code?: string
  error_summary?: string
  can_abort?: boolean
  // 旧读取路径别名：当前后端不输出，仅为既有 `??` 回退表达式保留类型。
  WorkflowState?: string
  id?: number
  user_id?: number
  src_node_id?: number
  dst_node_id?: number
  trigger?: string
  status?: string
  bytes?: NullInt64
  error?: NullString
  Attempt?: number
  NextAttemptAt?: string | null
  CleanupState?: string
  ErrorCode?: string
  ErrorSummary?: string
  CanAbort?: boolean
}

// ---------- 保护告警（store.ProtectionAlert + controller 内联 ai_note） ----------

export interface ProtectionAlert {
  severity: string
  state: string
  category: string
  user_uuid: string
  username: string
  node_name?: string
  summary: string
  first_seen_at: string
  last_seen_at: string
  /** AI 采纳说明，与确定性 summary 分列输出，仅在存在时携带 */
  ai_note?: string
}

// ---------- 管理员（store.Admin） ----------

export interface AdminRow {
  id: number
  uuid: string
  username: string
  password_version: number
  status: string
  created_at: string
  updated_at: string
  created_by?: number
  last_login_at?: string
  disabled_at?: string
}

// ---------- 审计（store.AuditEvent） ----------

export interface AuditEvent {
  id: number
  occurred_at: string
  actor_type: string
  actor_id: string
  action: string
  target_type: string
  target_id: string
  operation_id: NullString
  controller_generation: NullInt64
  outcome: string
  /** JSONB 详情，任意合法 JSON 值（对象/数组/标量） */
  detail: unknown
}

// ---------- AI 监管（controller/ai_admin.go，snake_case） ----------

export interface AIStatus {
  enabled: boolean
  mode: string
  provider: string
  model: string
  task_counts: Record<string, number>
  auto_adopt_min_confidence: number
  auto_adopted_24h: number
  accepted_24h: number
  latest_cluster_summary: string
}

/** store.AIAdvisorySummary */
export interface AIAdvisory {
  request_id: number
  advisory_id: number
  task_type: string
  model_id: string
  action: string
  confidence: number
  abstain: boolean
  reason_summary: string
  created_at: string
}

/** store.AIAdvisoryRequest */
export interface AIRequest {
  id: number
  task_type: string
  schema_version: string
  prompt_version: string
  model_id: string
  dedup_key: string
  requested_at: string
  deadline_at: string
  state: string
  error_code: string
}

/** POST /api/admin/ai/advisories/{requestID}/adopt 响应 */
export interface AIAdoptResult {
  ok: boolean
  deterministic_ref: string
  observed_outcome: string
}
