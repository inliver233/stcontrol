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

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const resp = await fetch(path, {
    credentials: 'include',
    headers: { 'Content-Type': 'application/json', ...(options?.headers || {}) },
    ...options,
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

export const api = {
  // 认证
  register: (body: { username: string; display_name: string; password: string; node_id: number; invitation_code?: string }) =>
    request<{ ok: boolean; username: string }>('/api/auth/register', { method: 'POST', body: JSON.stringify(body) }),
  login: (body: { username: string; password: string }) =>
    request<{ ok: boolean }>('/api/auth/login', { method: 'POST', body: JSON.stringify(body) }),
  logout: () => request<{ ok: boolean }>('/api/auth/logout', { method: 'POST' }),
  me: () => request<Me>('/api/users/me'),

  // 节点
  availableNodes: () => request<{ nodes: Node[] }>('/api/nodes/available'),
  myNodes: () => request<{ nodes: MyNode[] }>('/api/users/me/nodes'),
  loginRedirect: (node_id: number) =>
    request<{ ok: boolean; redirect_url: string }>('/api/login/redirect', { method: 'POST', body: JSON.stringify({ node_id }) }),

  // 改密
  changePassword: (old_password: string, new_password: string) =>
    request<{ ok: boolean }>('/api/users/me/password', { method: 'POST', body: JSON.stringify({ old_password, new_password }) }),
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
