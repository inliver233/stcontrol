// 总控 API 客户端与类型定义

export interface Node {
  id: number
  name: string
  region: string
  base_url: string
  status_label: string
  registrable: boolean
  recommended: boolean
  invitation_required: boolean
  registration_methods: Record<'password' | 'discord' | 'linuxdo', {
    registrable: boolean
    invitation_required: boolean
    guild_membership_required?: boolean
    guild_name?: string
    minimum_days?: number
  }>
  // 前端实测延迟(非后端字段)
  latency_ms?: number
}

export interface MyNode {
  node_id: number
  name: string
  region: string
  base_url: string
  kind: 'home' | 'hot_standby'
  kind_label: string
  ready: boolean
  requires_takeover: boolean
  last_synced_at?: string
  data_version: number
  latency_ms?: number
}

export interface ProtectionState {
  state: string
  label: string
  risk: string
  current_node_id?: number
  current_node_name?: string
  recovery_node_id?: number
  recovery_node_name?: string
  active_writer_node_id?: number
  active_writer_node_name?: string
  latest_recovery_at?: string
  takeover_available: boolean
  storage_restore_needed: boolean
  data_fault_state?: string
  data_fault_reason_code?: string
  version: number
}

export interface RestoreTarget {
  node_id: number
  name: string
  region: string
}

export interface RestoreStatus {
  operation_id: string
  state: 'preparing' | 'transferring' | 'verifying' | 'publishing' | 'retrying' | 'succeeded' | 'failed'
  target_node_id: number
  target_node_name: string
  latest_recovery_at: string
  error?: string
}

export interface Me {
  username: string
  display_name: string
  auth_provider: string
  avatar_url: string
  home_node_id: number
  is_admin: boolean
}

export interface BrowserHandoff {
  ok: boolean
  post_url: string
  field_name: string
  code: string
  expires_at: string
  target_node_id: number
}

export interface LoginHandoff extends BrowserHandoff {
  existing_writer: boolean
}

export interface AuthIdentity {
  provider: 'password' | 'discord' | 'linuxdo'
  password_version?: number
  status: string
  created_at: string
}

export interface PasswordSyncResult {
  ok: boolean
  node_sync: 'active' | 'pending'
  synced_nodes: number
  pending_nodes: number
}

export interface AccountImportClaim {
  node_id: number
  node_name: string
  local_handle: string
  account_kind: 'password' | 'mixed'
}

export interface RegistrationStatus {
  ok: boolean
  state: 'pending' | 'retrying' | 'succeeded'
  username?: string
}

export interface ConflictSource {
  node_id: number
  node_name: string
  node_role: 'compute' | 'storage'
  source_kind: 'active' | 'hot_standby' | 'archive'
  replica_state: string
  is_authoritative: boolean
  source_snapshot_state: 'immutable' | 'live_capture_required'
  evidence_state: 'pending' | 'capturing' | 'retry_wait' | 'ready' | 'failed'
  capture_basis?: 'verified_archive' | 'frozen_live'
  file_count?: number
  total_bytes?: number
  published_at?: string
  legacy_data_version?: number
}

export interface ReplicaConflict {
  id: string
  state: 'detected' | 'inspecting' | 'awaiting_decision' | 'resolving'
  protection_version: number
  version: number
  detected_at: string
  updated_at: string
  inspection_state: 'capture_required' | 'evidence_failed' | 'identical' | 'differences_ready'
  source_count: number
  ready_evidence_count: number
  sources: ConflictSource[]
}

export interface ConflictDifference {
  path: string
  category: 'chat_or_log' | 'structured_json' | 'text' | 'binary_or_unknown'
  difference: 'only_on_some_sources' | 'different_at_same_path'
  policy: 'auto_merge_disjoint_path' | 'choose_source_or_preserve_both'
  sources: Array<{ node_id: number; node_name: string; present: boolean; size?: number }>
}

export interface ConflictDifferences {
  conflict_id: string
  offset: number
  limit: number
  total: number
  only_on_some_sources: number
  different_at_same_path: number
  files: ConflictDifference[]
}

export interface ConflictResolutionDecision {
  path: string
  source_node_id: number
  action: 'use_source' | 'preserve_both'
}

export interface ApiError extends Error {
  status?: number
  data?: unknown
}

export interface ConflictResolutionStatus {
  operation_id: string
  state: 'preparing' | 'publishing' | 'retrying' | 'failed' | 'succeeded'
  base_node_id: number
  base_node_name: string
  error?: string
}

export interface PasskeyItem {
  id: number
  name: string
  created_at: string
  last_used_at?: string
}

export interface MyPasskeys {
  available: boolean
  allow_registration: boolean
  max_per_user: number
  rp_id: string
  passkeys: PasskeyItem[]
}

export interface PasskeyLoginConfig {
  login_enabled: boolean
  button_text: string
  hint_text: string
  rp_id: string
}

export interface PasskeyCeremony {
  ceremony_id: string
  options: { publicKey: unknown }
}

export interface PasskeySettings {
  enabled: boolean
  allow_registration: boolean
  show_on_login_page: boolean
  max_per_user: number
  user_verification: 'required' | 'preferred' | 'discouraged'
  login_button_text: string
  login_hint_text: string
  updated_at?: string
}

export interface PasskeyAdminOverview {
  settings: PasskeySettings
  configured: boolean
  config_error?: string
  rp_id: string
  origins: string[]
  overview: {
    users_with_passkeys: number
    total_passkeys: number
    users: Array<{ uuid: string; username: string; display_name: string; passkeys: PasskeyItem[] }>
    days: Array<{ day: string; registered: number; login_success: number; login_failure: number }>
  }
}

async function request<T>(path: string, options?: RequestInit): Promise<T> {
	const method = (options?.method || 'GET').toUpperCase()
	const headers = new Headers(options?.headers)
	if (options?.body && !headers.has('Content-Type')) {
	  headers.set('Content-Type', 'application/json')
	}
	if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
	  const csrf = readCookie('stcontrol_csrf')
	  if (csrf) headers.set('X-CSRF-Token', csrf)
	}
  const resp = await fetch(path, {
	...options,
    credentials: 'include',
	headers,
  })
  if (!resp.ok) {
    let msg = `请求失败 (${resp.status})`
    let data: unknown
    try {
      data = await resp.json()
      if (data && typeof data === 'object' && 'error' in data &&
          typeof (data as { error: unknown }).error === 'string') {
        msg = (data as { error: string }).error
      }
    } catch { /* ignore */ }
    const err = new Error(msg) as ApiError
    err.status = resp.status
    err.data = data
    throw err
  }
  return resp.json()
}

function readCookie(name: string): string {
	const prefix = `${encodeURIComponent(name)}=`
	for (const part of document.cookie.split(';')) {
	  const value = part.trim()
	  if (value.startsWith(prefix)) return decodeURIComponent(value.slice(prefix.length))
	}
	return ''
}

export const api = {
  // 认证
  register: (body: { operation_id: string; username: string; display_name: string; password: string; node_id: number; invitation_code?: string }) =>
    request<RegistrationStatus>('/api/auth/register', { method: 'POST', body: JSON.stringify(body) }),
  login: (body: { username: string; password: string }) =>
    request<{ ok: boolean; recovery_required: boolean }>('/api/auth/login', { method: 'POST', body: JSON.stringify(body) }),
	adminLogin: (body: { username: string; password: string }) =>
	  request<{ ok: boolean; is_admin: boolean }>('/api/auth/admin/login', { method: 'POST', body: JSON.stringify(body) }),
  completeOAuth: (node_id: number, operation_id: string, invitation_code?: string) =>
    request<RegistrationStatus>('/api/auth/oauth/complete', {
      method: 'POST', body: JSON.stringify({ node_id, operation_id, invitation_code }),
    }),
  registrationStatus: () => request<RegistrationStatus>('/api/auth/registration/status'),
  logout: () => request<{ ok: boolean }>('/api/auth/logout', { method: 'POST' }),
  // 通行密钥
  passkeyLoginConfig: () => request<PasskeyLoginConfig>('/api/auth/passkey/config'),
  passkeyLoginOptions: () => request<PasskeyCeremony>('/api/auth/passkey/login/options', { method: 'POST', body: '{}' }),
  passkeyLoginVerify: (ceremony_id: string, credential: unknown) =>
    request<{ ok: boolean; recovery_required: boolean }>('/api/auth/passkey/login/verify', {
      method: 'POST', body: JSON.stringify({ ceremony_id, credential }),
    }),
  myPasskeys: () => request<MyPasskeys>('/api/users/me/passkeys'),
  passkeyRegisterOptions: () => request<PasskeyCeremony>('/api/users/me/passkeys/register/options', { method: 'POST', body: '{}' }),
  passkeyRegisterVerify: (ceremony_id: string, name: string, credential: unknown) =>
    request<{ ok: boolean; passkey: PasskeyItem }>('/api/users/me/passkeys/register/verify', {
      method: 'POST', body: JSON.stringify({ ceremony_id, name, credential }),
    }),
  renamePasskey: (id: number, name: string) =>
    request<{ ok: boolean; passkey: PasskeyItem }>(`/api/users/me/passkeys/${id}`, { method: 'PATCH', body: JSON.stringify({ name }) }),
  deletePasskey: (id: number) => request<{ ok: boolean }>(`/api/users/me/passkeys/${id}`, { method: 'DELETE' }),
  adminPasskeys: () => request<PasskeyAdminOverview>('/api/admin/passkeys'),
  adminSavePasskeySettings: (settings: PasskeySettings) =>
    request<{ ok: boolean; settings: PasskeySettings }>('/api/admin/passkeys/settings', { method: 'PUT', body: JSON.stringify(settings) }),
  adminDeletePasskey: (id: number) => request<{ ok: boolean }>(`/api/admin/passkeys/${id}`, { method: 'DELETE' }),
  adminDeleteUserPasskeys: (uuid: string) =>
    request<{ ok: boolean; removed: number }>(`/api/admin/users/${uuid}/passkeys`, { method: 'DELETE' }),
  me: () => request<Me>('/api/users/me'),
  conflict: () => request<ReplicaConflict>('/api/conflicts/me'),
  conflictDifferences: (offset = 0, limit = 50) =>
    request<ConflictDifferences>(`/api/conflicts/me/differences?offset=${offset}&limit=${limit}`),
  startConflictResolution: (body: {
    operation_id: string
    expected_conflict_version: number
    base_node_id: number
    default_action: 'use_base' | 'preserve_all_originals'
    acknowledge_freeze: boolean
    decisions: ConflictResolutionDecision[]
  }) => request<ConflictResolutionStatus>('/api/conflicts/me/resolutions', {
    method: 'POST', body: JSON.stringify(body),
  }),
  conflictResolutionStatus: (operation_id: string) =>
    request<ConflictResolutionStatus>(`/api/conflicts/me/resolutions/${encodeURIComponent(operation_id)}`),
  currentConflictResolution: () =>
    request<ConflictResolutionStatus>('/api/conflicts/me/resolutions/current'),
  retryConflictResolution: (operation_id: string) =>
    request<ConflictResolutionStatus>(`/api/conflicts/me/resolutions/${encodeURIComponent(operation_id)}/retry`, { method: 'POST' }),
  conflictLogout: () => request<{ ok: boolean }>('/api/conflicts/auth/logout', { method: 'POST' }),

  // 节点
  availableNodes: () => request<{ nodes: Node[] }>('/api/nodes/available'),
  myNodes: () => request<{ nodes: MyNode[] }>('/api/users/me/nodes'),
  protection: () => request<ProtectionState>('/api/users/me/protection'),
  reportNodeLatency: (node_id: number, latency_ms: number) =>
    request<{ ok: boolean }>('/api/users/me/node-latency', { method: 'POST', body: JSON.stringify({ node_id, latency_ms }) }),
  confirmTakeover: (target_node_id: number, operation_id: string, expected_recovery_at: string) =>
    request<{ ok: boolean; target_node_id: number; latest_recovery_at: string; replayed: boolean }>('/api/users/me/takeover', {
      method: 'POST',
      body: JSON.stringify({ target_node_id, operation_id, expected_recovery_at, acknowledge_data_loss: true }),
    }),
  restoreTargets: () => request<{ targets: RestoreTarget[] }>('/api/users/me/restore-targets'),
  startArchiveRestore: (target_node_id: number, operation_id: string, expected_recovery_at: string) =>
    request<RestoreStatus>('/api/users/me/restore', {
      method: 'POST',
      body: JSON.stringify({ target_node_id, operation_id, expected_recovery_at, acknowledge_data_loss: true }),
    }),
  archiveRestoreStatus: (operation_id: string) =>
    request<RestoreStatus>(`/api/users/me/restores/${encodeURIComponent(operation_id)}`),
  loginHandoff: (node_id: number, operation_id: string) =>
    request<LoginHandoff>('/api/login/redirect', {
      method: 'POST',
      body: JSON.stringify({ node_id, operation_id }),
    }),

  // 改密
  changePassword: (old_password: string, new_password: string) =>
    request<PasswordSyncResult>('/api/users/me/password', { method: 'POST', body: JSON.stringify({ old_password, new_password }) }),
  identities: () => request<{ identities: AuthIdentity[]; can_unbind: boolean; supported: string[] }>('/api/users/me/identities'),
  bindPassword: (password: string) => request<PasswordSyncResult>('/api/users/me/identities/password', {
    method: 'POST', body: JSON.stringify({ password }),
  }),
  beginOAuthBinding: (provider: 'discord' | 'linuxdo') => request<{ authorization_url: string }>(`/api/users/me/identities/${provider}/bind`, { method: 'POST' }),
  unbindIdentity: (provider: string) => request<{ ok: boolean }>(`/api/users/me/identities/${provider}`, { method: 'DELETE' }),
  importClaims: () => request<{ claims: AccountImportClaim[] }>('/api/users/me/import-claims'),
  claimImportedAccount: (node_id: number, password: string, operation_id: string) =>
    request<{ ok: boolean }>('/api/users/me/import-claims', {
      method: 'POST', body: JSON.stringify({ node_id, password, operation_id }),
    }),
}

// Submit the bearer code in a request body. The form is deliberately ephemeral
// and never puts the code into history, referrers, access logs, or query strings.
export function submitLoginHandoff(handoff: BrowserHandoff): void {
  const destination = new URL(handoff.post_url, window.location.origin)
  if (destination.protocol !== 'https:' && destination.hostname !== 'localhost' && destination.hostname !== '127.0.0.1') {
    throw new Error('节点登录地址必须使用 HTTPS')
  }
  const form = document.createElement('form')
  form.method = 'POST'
  form.action = destination.toString()
  form.acceptCharset = 'UTF-8'
  form.setAttribute('referrerpolicy', 'no-referrer')
  form.style.display = 'none'

  const input = document.createElement('input')
  input.type = 'hidden'
  input.name = handoff.field_name
  input.value = handoff.code
  form.appendChild(input)
  document.body.appendChild(form)
  form.submit()
}

// 测量到某节点的延迟(浏览器对各节点 ping-public 端点测 RTT)
export async function measureLatency(baseUrl: string): Promise<number> {
  if (!baseUrl) return -1
  const start = performance.now()
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), 5000)
  try {
    await fetch(`${baseUrl.replace(/\/+$/, '')}/api/ping-public`, {
      method: 'GET',
      mode: 'cors',
      credentials: 'omit',
      cache: 'no-store',
      signal: controller.signal,
    })
    return Math.round(performance.now() - start)
  } catch {
    return -1
  } finally {
    clearTimeout(timer)
  }
}
