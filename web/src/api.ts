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

export interface LoginHandoff {
  ok: boolean
  post_url: string
  field_name: string
  code: string
  expires_at: string
  target_node_id: number
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

export interface RegistrationStatus {
  ok: boolean
  state: 'pending' | 'retrying' | 'succeeded'
  username?: string
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
    try {
      const data = await resp.json()
      if (data.error) msg = data.error
    } catch { /* ignore */ }
    throw new Error(msg)
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
    request<{ ok: boolean }>('/api/auth/login', { method: 'POST', body: JSON.stringify(body) }),
	adminLogin: (body: { username: string; password: string }) =>
	  request<{ ok: boolean; is_admin: boolean }>('/api/auth/admin/login', { method: 'POST', body: JSON.stringify(body) }),
  completeOAuth: (node_id: number, operation_id: string, invitation_code?: string) =>
    request<RegistrationStatus>('/api/auth/oauth/complete', {
      method: 'POST', body: JSON.stringify({ node_id, operation_id, invitation_code }),
    }),
  registrationStatus: () => request<RegistrationStatus>('/api/auth/registration/status'),
  logout: () => request<{ ok: boolean }>('/api/auth/logout', { method: 'POST' }),
  me: () => request<Me>('/api/users/me'),

  // 节点
  availableNodes: () => request<{ nodes: Node[] }>('/api/nodes/available'),
  myNodes: () => request<{ nodes: MyNode[] }>('/api/users/me/nodes'),
  protection: () => request<ProtectionState>('/api/users/me/protection'),
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
}

// Submit the bearer code in a request body. The form is deliberately ephemeral
// and never puts the code into history, referrers, access logs, or query strings.
export function submitLoginHandoff(handoff: LoginHandoff): void {
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
  try {
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), 5000)
    await fetch(`${baseUrl}/api/ping-public`, {
      method: 'GET',
      mode: 'no-cors',
      cache: 'no-store',
      signal: controller.signal,
    })
    clearTimeout(timer)
    return Math.round(performance.now() - start)
  } catch {
    return -1
  }
}
