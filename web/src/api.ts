// 总控 API 客户端与类型定义

export interface Node {
  id: number
  name: string
  region: string
  base_url: string
  status: string
  status_label: string
  registrable: boolean
  cpu_pct: number
  mem_pct: number
  disk_pct: number
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
  data_version: number
  latency_ms?: number
}

export interface Me {
  username: string
  display_name: string
  auth_provider: string
  avatar_url: string
  home_node_id: number
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
  register: (body: { username: string; display_name: string; password: string; node_id: number; invitation_code?: string }) =>
    request<{ ok: boolean; username: string }>('/api/auth/register', { method: 'POST', body: JSON.stringify(body) }),
  login: (body: { username: string; password: string }) =>
    request<{ ok: boolean }>('/api/auth/login', { method: 'POST', body: JSON.stringify(body) }),
	completeOAuth: (node_id: number) =>
	  request<{ ok: boolean; username: string }>('/api/auth/oauth/complete', {
		method: 'POST', body: JSON.stringify({ node_id }),
	  }),
  logout: () => request<{ ok: boolean }>('/api/auth/logout', { method: 'POST' }),
  me: () => request<Me>('/api/users/me'),

  // 节点
  availableNodes: () => request<{ nodes: Node[] }>('/api/nodes/available'),
  myNodes: () => request<{ nodes: MyNode[] }>('/api/users/me/nodes'),
  loginHandoff: (node_id: number, operation_id: string) =>
    request<LoginHandoff>('/api/login/redirect', {
      method: 'POST',
      body: JSON.stringify({ node_id, operation_id }),
    }),

  // 改密
  changePassword: (old_password: string, new_password: string) =>
    request<{ ok: boolean }>('/api/users/me/password', { method: 'POST', body: JSON.stringify({ old_password, new_password }) }),
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
