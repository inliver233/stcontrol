import { useEffect, useRef, useState } from 'react'
import { Routes, Route, Navigate, useNavigate, useLocation } from 'react-router-dom'
import { api, submitLoginHandoff, type BrowserHandoff } from '../api'
import { useAuth } from '../App'

function readCookie(name: string): string {
  const prefix = `${encodeURIComponent(name)}=`
  for (const part of document.cookie.split(';')) {
    const value = part.trim()
    if (value.startsWith(prefix)) return decodeURIComponent(value.slice(prefix.length))
  }
  return ''
}

// ---------- 管理 API ----------
async function adminReq<T>(path: string, options?: RequestInit): Promise<T> {
  const method = (options?.method || 'GET').toUpperCase()
  const headers = new Headers(options?.headers)
  headers.set('Content-Type', 'application/json')
  if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
    const csrf = readCookie('stcontrol_csrf')
    if (csrf) headers.set('X-CSRF-Token', csrf)
  }
  const resp = await fetch(path, {
    credentials: 'include',
    ...options,
    headers,
  })
  if (!resp.ok) {
    let msg = `请求失败 (${resp.status})`
    try { const d = await resp.json(); if (d.error) msg = d.error } catch {}
    throw new Error(msg)
  }
  return resp.json()
}

const adminApi = {
  overview: () => adminReq<any>('/api/admin/overview'),
  nodes: () => adminReq<{ nodes: any[] }>('/api/admin/nodes'),
  updateNode: (id: number, body: any) => adminReq<any>(`/api/admin/nodes/${id}`, { method: 'PUT', body: JSON.stringify(body) }),
  registerToken: (id: number) => adminReq<any>(`/api/admin/nodes/${id}/register-token`, { method: 'POST' }),
  scanExisting: (id: number, operationID: string) => adminReq<any>(`/api/admin/nodes/${id}/scan-existing`, {
    method: 'POST', body: JSON.stringify({ operation_id: operationID }),
  }),
  latestImport: (id: number) => adminReq<any>(`/api/admin/nodes/${id}/imports/latest`),
  nodeLinks: () => adminReq<{ links: AdminNodeLink[] }>('/api/admin/node-links'),
  verifyNodeLink: (id: number, operationID: string, handle: string, password: string) =>
    adminReq<AdminNodeLink>(`/api/admin/nodes/${id}/admin-link`, {
      method: 'POST', body: JSON.stringify({ operation_id: operationID, handle, password }),
    }),
  revokeNodeLink: (id: number) => adminReq<{ ok: boolean }>(`/api/admin/nodes/${id}/admin-link`, { method: 'DELETE' }),
  adminHandoff: (id: number, operationID: string) => adminReq<BrowserHandoff>(`/api/admin/nodes/${id}/admin-handoff`, {
    method: 'POST', body: JSON.stringify({ operation_id: operationID }),
  }),
  users: () => adminReq<{ users: any[] }>('/api/admin/users'),
  recoverUserIdentity: (uuid: string, operationID: string, password: string) => adminReq<any>(`/api/admin/users/${uuid}/identity-recovery`, {
    method: 'POST', body: JSON.stringify({ operation_id: operationID, password }),
  }),
  triggerBackup: (id: number) => adminReq<any>(`/api/admin/users/${id}/backup`, { method: 'POST' }),
  disableUser: (id: number) => adminReq<any>(`/api/admin/users/${id}/disable`, { method: 'POST' }),
  backups: () => adminReq<{ backups: any[] }>('/api/admin/backups'),
  abortBackup: (id: number) => adminReq<any>(`/api/admin/backups/${id}/abort`, { method: 'POST' }),
  protectionAlerts: () => adminReq<{ alerts: any[] }>('/api/admin/alerts/protection?limit=100'),
  admins: () => adminReq<{ admins: any[] }>('/api/admin/admins'),
  createAdmin: (username: string, password: string) => adminReq<any>('/api/admin/admins', { method: 'POST', body: JSON.stringify({ username, password }) }),
  setAdminStatus: (id: number, status: string) => adminReq<any>(`/api/admin/admins/${id}/status`, { method: 'PUT', body: JSON.stringify({ status }) }),
  resetAdminPassword: (id: number, password: string) => adminReq<any>(`/api/admin/admins/${id}/password`, { method: 'PUT', body: JSON.stringify({ password }) }),
}

interface AdminNodeLink {
  node_id: number
  node_name: string
  node_state: string
  local_handle?: string
  state: 'unlinked' | 'verified' | 'stale' | 'revoked'
  permission_version?: number
  last_verified_at?: string
  last_error_code?: string
}

// ---------- 布局 ----------
export default function AdminPage() {
  const { me, loading, setMe } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()
  const nav = [
    { path: '/admin', label: '仪表盘' },
    { path: '/admin/nodes', label: '节点管理' },
    { path: '/admin/users', label: '用户管理' },
    { path: '/admin/backups', label: '备份任务' },
    { path: '/admin/alerts', label: '保护告警' },
    { path: '/admin/admins', label: '管理员' },
  ]
  const current = location.pathname

  if (loading) return <div className="loading">加载中…</div>
  if (!me?.is_admin) return <Navigate to="/admin/login" replace />

  const logout = async () => {
    await api.logout()
    setMe(null)
    navigate('/admin/login', { replace: true })
  }

  return (
    <div className="admin-layout">
      <div className="admin-sidebar">
        <div className="logo">云酒馆 · 总控</div>
        {nav.map(n => (
          <div
            key={n.path}
            className={`nav-item ${current === n.path ? 'active' : ''}`}
            onClick={() => navigate(n.path)}
          >
            {n.label}
          </div>
        ))}
        <div className="nav-item" style={{ marginTop: 24 }} onClick={logout}>退出管理员登录</div>
      </div>
      <div className="admin-main">
        <Routes>
          <Route path="/" element={<Overview />} />
          <Route path="/nodes" element={<NodesAdmin />} />
          <Route path="/users" element={<UsersAdmin />} />
          <Route path="/backups" element={<BackupsAdmin />} />
          <Route path="/alerts" element={<ProtectionAlertsAdmin />} />
          <Route path="/admins" element={<AdminsAdmin />} />
        </Routes>
      </div>
    </div>
  )
}

// ---------- 仪表盘 ----------
function Overview() {
  const [data, setData] = useState<any>(null)
  useEffect(() => { adminApi.overview().then(setData).catch(() => {}) }, [])
  if (!data) return <div className="loading">加载中…</div>
  const stats = [
    { label: '节点总数', value: data.nodes },
    { label: '在线节点', value: data.nodes_online },
    { label: '离线节点', value: data.nodes_offline },
    { label: '满员节点', value: data.nodes_full },
    { label: '繁忙节点', value: data.nodes_busy },
    { label: '维护节点', value: data.nodes_maintenance },
    { label: '故障节点', value: data.nodes_fault },
    { label: '注册用户', value: data.users },
    { label: '进行中备份', value: data.backup_running },
    { label: '失败备份', value: data.backup_failed },
  ]
  return (
    <>
      <h2>仪表盘</h2>
      <div className="stat-grid">
        {stats.map(s => (
          <div key={s.label} className="stat-card">
            <div className="stat-value">{s.value}</div>
            <div className="stat-label">{s.label}</div>
          </div>
        ))}
      </div>
    </>
  )
}

// ---------- 节点管理 ----------
function NodesAdmin() {
  const [nodes, setNodes] = useState<any[]>([])
  const [nodeLinks, setNodeLinks] = useState<AdminNodeLink[]>([])
  const [tokenInfo, setTokenInfo] = useState<any>(null)
  const [scanResult, setScanResult] = useState<any>(null)
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')
  const [scanningNode, setScanningNode] = useState<number>(0)
  const [linkNode, setLinkNode] = useState<any>(null)
  const [linkHandle, setLinkHandle] = useState('')
  const [linkPassword, setLinkPassword] = useState('')
  const [linkingNode, setLinkingNode] = useState<number>(0)
  const [handoffNode, setHandoffNode] = useState<number>(0)
  const scanOperations = useRef<Record<number, string>>({})
  const linkOperation = useRef('')
  const handoffOperations = useRef<Record<number, string>>({})

  const load = () => Promise.all([adminApi.nodes(), adminApi.nodeLinks()])
    .then(([nodeData, linkData]) => {
      setNodes(nodeData.nodes)
      setNodeLinks(linkData.links || [])
    })
    .catch(e => setError(e.message))
  useEffect(() => { load() }, [])

  const nodeLink = (nodeID: number) => nodeLinks.find(link => link.node_id === nodeID)
  const beginNodeLink = (node: any) => {
    const current = nodeLink(node.id)
    setError('')
    setMessage('')
    setLinkNode(node)
    setLinkHandle(current?.local_handle || '')
    setLinkPassword('')
    linkOperation.current = ''
  }
  const changeLinkHandle = (value: string) => {
    setLinkHandle(value)
    linkOperation.current = ''
  }
  const changeLinkPassword = (value: string) => {
    setLinkPassword(value)
    linkOperation.current = ''
  }
  const verifyNodeLink = async (event: React.FormEvent) => {
    event.preventDefault()
    if (!linkNode) return
    const operationID = linkOperation.current || crypto.randomUUID()
    linkOperation.current = operationID
    setError('')
    setMessage('')
    setLinkingNode(linkNode.id)
    try {
      await adminApi.verifyNodeLink(linkNode.id, operationID, linkHandle, linkPassword)
      linkOperation.current = ''
      setLinkNode(null)
      setLinkHandle('')
      setLinkPassword('')
      setMessage('节点管理员账号已验证；后续进入该节点后台无需重复输入密码。')
      await load()
    } catch (err: unknown) {
      setLinkPassword('')
      setError(err instanceof Error ? err.message : '节点管理员验证失败')
    } finally {
      setLinkingNode(0)
    }
  }
  const revokeNodeLink = async (node: any) => {
    if (!window.confirm(`撤销 ${node.name} 的管理员账号关联及未使用跳转票据？`)) return
    setError('')
    setMessage('')
    try {
      await adminApi.revokeNodeLink(node.id)
      delete handoffOperations.current[node.id]
      setMessage('节点管理员关联已撤销。')
      await load()
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : '撤销节点管理员关联失败')
    }
  }
  const enterNodeAdmin = async (node: any) => {
    const operationID = handoffOperations.current[node.id] || crypto.randomUUID()
    handoffOperations.current[node.id] = operationID
    setError('')
    setMessage('')
    setHandoffNode(node.id)
    try {
      const handoff = await adminApi.adminHandoff(node.id, operationID)
      delete handoffOperations.current[node.id]
      submitLoginHandoff(handoff)
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : '节点后台跳转失败')
      await load()
    } finally {
      setHandoffNode(0)
    }
  }

  const toggle = async (n: any, field: 'allow_register' | 'is_backup_target') => {
    setError('')
    try {
      await adminApi.updateNode(n.id, { ...n, [field]: !n[field] })
      load()
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : '节点配置更新失败')
    }
  }
  const toggleMaintenance = async (n: any) => {
    setError('')
    try {
      await adminApi.updateNode(n.id, {
        ...n, operational_state: n.operational_state === 'maintenance' ? 'active' : 'maintenance',
      })
      load()
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : '运营状态更新失败')
    }
  }
  const genToken = async (id: number) => {
    const info = await adminApi.registerToken(id)
    setTokenInfo(info)
  }
  const scan = async (id: number) => {
    setError('')
    setScanningNode(id)
    const operationID = scanOperations.current[id] || crypto.randomUUID()
    scanOperations.current[id] = operationID
    try {
      const res = await adminApi.scanExisting(id, operationID)
      delete scanOperations.current[id]
      setScanResult(res)
    } catch (err: any) {
      setError(err.message)
    } finally {
      setScanningNode(0)
    }
  }

  const viewLatestImport = async (id: number) => {
    setError('')
    try {
      setScanResult(await adminApi.latestImport(id))
    } catch (err: any) {
      setError(err.message)
    }
  }

  const importStateLabel = (state: string) => ({
    already_managed: '已在总控管理',
    auto_linked: 'OAuth 身份已自动关联',
    claim_required: '同名账号，需控制权证明',
    recovery_required: '无可用身份，需管理员恢复',
    oauth_unmatched: '需使用原 OAuth 身份证明',
    identity_conflict: '身份冲突，已禁止自动合并',
    invalid: '库存无效',
  } as Record<string, string>)[state] || state

  const healthLabel = (value: string) => ({
    online: '在线', offline: '离线', unknown: '未知', active: '运营', maintenance: '维护',
    draining: '排空', degraded: '降级', failed: '故障', retired: '退役', pending: '待接入',
    open: '开放', busy: '繁忙', full: '满载', compatible: '兼容', incompatible: '不兼容',
  } as Record<string, string>)[value] || value
  const reasonLabel = (value: string) => ({
    metrics_unavailable: '指标不可用', heartbeat_stale: '心跳过期', cpu_busy: 'CPU 繁忙',
    cpu_sustained: 'CPU 持续超载', memory_busy: '内存繁忙', memory_sustained: '内存持续超载',
    disk_busy: '磁盘繁忙', disk_sustained: '磁盘持续高水位', disk_low: '可用磁盘偏低',
    disk_low_watermark: '可用磁盘低于硬水位', quota_low: '分配配额偏低',
    quota_low_watermark: '分配配额低于硬水位', online_users_busy: '在线用户接近上限',
    online_user_limit: '在线用户达到上限', task_queue_busy: '任务队列繁忙',
    task_queue_limit: '任务队列达到上限', adapter_unavailable: '酒馆适配器不可用',
    version_unsupported: '版本不兼容', missing_capability: '适配器能力不完整',
    invalid_health: '适配器健康报告无效', invalid_report: '兼容性报告无效',
  } as Record<string, string>)[value] || value
  const metric = (value: any) => Math.round(value?.Float64 ?? value ?? 0)
  const bytes = (value: any) => {
    const raw = value?.Int64 ?? value ?? 0
    return raw > 0 ? `${(raw / 1073741824).toFixed(1)}GB` : '-'
  }

  return (
    <>
      <h2>节点管理</h2>
      {error && <div className="error-msg">{error}</div>}
      {message && <div className="success-msg">{message}</div>}
      {linkNode && (
        <form onSubmit={verifyNodeLink} className="card" style={{ margin: '0 0 20px', maxWidth: 560 }}>
          <h3>验证 {linkNode.name} 的原生管理员账号</h3>
          <p>
            密码只用于本次节点验证，不会保存。验证成功后，每次跳转前都会重新确认该账号当前仍有管理员权限。
          </p>
          <div className="field">
            <label>节点账号</label>
            <input value={linkHandle} onChange={e => changeLinkHandle(e.target.value)} maxLength={128} autoComplete="username" required />
          </div>
          <div className="field">
            <label>节点密码</label>
            <input type="password" value={linkPassword} onChange={e => changeLinkPassword(e.target.value)} maxLength={256} autoComplete="current-password" required />
          </div>
          <button className="btn" type="submit" disabled={linkingNode === linkNode.id}>
            {linkingNode === linkNode.id ? '验证中…' : '验证并关联'}
          </button>{' '}
          <button className="btn-sm" type="button" disabled={linkingNode === linkNode.id} onClick={() => {
            setLinkNode(null); setLinkHandle(''); setLinkPassword(''); linkOperation.current = ''
          }}>取消</button>
        </form>
      )}
      {tokenInfo && (
        <div className="success-msg">
          一次性注册令牌（15 分钟内有效）：<br />
          <div className="mono">{tokenInfo.install_cmd}</div>
          <button className="btn-sm" style={{ marginTop: 8 }} onClick={() => setTokenInfo(null)}>关闭</button>
        </div>
      )}
      {scanResult && (
        <div className="success-msg">
          {scanResult.batch ? (
            <>
              扫描到 {scanResult.batch.candidate_count} 个既有账号；自动关联 {scanResult.batch.auto_linked_count} 个，
              待处理 {scanResult.batch.unresolved_count} 个。
              {scanResult.batch.source === 'directory_fallback' && (
                <div>当前为目录回退扫描，不含可靠身份事实，所有候选均禁止自动合并。</div>
              )}
              {(scanResult.candidates || []).map((candidate: any, index: number) => (
                <div key={`${candidate.local_handle}-${index}`} className="mono">
                  {candidate.local_handle} ({(candidate.size_bytes / 1048576).toFixed(1)}MB) ·
                  {' '}{importStateLabel(candidate.resolution_state)}
                  {candidate.identity_providers?.length ? ` · ${candidate.identity_providers.join(' / ')}` : ''}
                  {candidate.is_admin ? ' · 节点管理员候选（尚未验证）' : ''}
                </div>
              ))}
            </>
          ) : '该节点还没有持久导入库存。'}
          <button className="btn-sm" style={{ marginTop: 8 }} onClick={() => setScanResult(null)}>关闭</button>
        </div>
      )}
      <table className="table">
        <thead>
          <tr><th>ID</th><th>名称</th><th>角色</th><th>健康维度</th><th>窗口负载</th><th>磁盘/配额</th><th>用户/队列</th><th>版本</th><th>操作</th></tr>
        </thead>
        <tbody>
          {nodes.map(n => {
            const link = nodeLink(n.id)
            return <tr key={n.id}>
              <td>{n.id}</td>
              <td>{n.name}<div className="mono" style={{ fontSize: 11 }}>{n.base_url || '未配置地址'}</div></td>
              <td>{n.role === 'compute' ? '计算' : '存储'}</td>
              <td style={{ fontSize: 12 }}>
                <span className={`badge ${n.connectivity_state === 'online' ? 'green' : n.connectivity_state === 'offline' ? 'red' : 'gray'}`}>{healthLabel(n.connectivity_state)}</span>{' '}
                <span className={`badge ${n.operational_state === 'active' ? 'green' : 'gray'}`}>{healthLabel(n.operational_state)}</span>{' '}
                <span className={`badge ${n.capacity_state === 'open' ? 'green' : n.capacity_state === 'busy' ? 'yellow' : n.capacity_state === 'full' ? 'red' : 'gray'}`}>{healthLabel(n.capacity_state)}</span>{' '}
                <span className={`badge ${n.compatibility_state === 'compatible' ? 'green' : n.compatibility_state === 'incompatible' ? 'red' : 'gray'}`}>{healthLabel(n.compatibility_state)}</span>
                {(n.capacity_reason_code?.String || n.compatibility_reason_code?.String) && (
                  <div>{reasonLabel(n.capacity_reason_code?.String || n.compatibility_reason_code?.String)}</div>
                )}
              </td>
              <td style={{ fontSize: 12 }}>
                CPU {metric(n.cpu_window_avg)}%/{metric(n.cpu_window_peak)}% ·
                内存 {metric(n.mem_window_avg)}%/{metric(n.mem_window_peak)}% ·
                硬盘 {metric(n.disk_window_avg)}%/{metric(n.disk_window_peak)}%
              </td>
              <td style={{ fontSize: 12 }}>可用 {bytes(n.disk_available_bytes)} · 已分配 {bytes(n.allocated_disk_bytes)} / {bytes(n.disk_quota_bytes)}</td>
              <td style={{ fontSize: 12 }}>{n.online_users} / {n.task_queue_depth}</td>
              <td style={{ fontSize: 12 }}>{n.tavern_version?.String ?? n.tavern_version ?? '-'}</td>
              <td style={{ whiteSpace: 'nowrap' }}>
                <button className="btn-sm" onClick={() => toggle(n, 'allow_register')}>
                  {n.allow_register ? '关注册' : '开注册'}
                </button>{' '}
                <button className="btn-sm" onClick={() => toggle(n, 'is_backup_target')}>
                  {n.is_backup_target ? '取消备份' : '设为备份'}
                </button>{' '}
                <button className="btn-sm primary" onClick={() => genToken(n.id)}>注册令牌</button>{' '}
                <button className="btn-sm" disabled={scanningNode === n.id} onClick={() => scan(n.id)}>
                  {scanningNode === n.id ? '扫描中…' : '扫描用户'}
                </button>{' '}
                <button className="btn-sm" onClick={() => viewLatestImport(n.id)}>查看导入</button>
                {' '}<button className="btn-sm" onClick={() => toggleMaintenance(n)}>
                  {n.operational_state === 'maintenance' ? '结束维护' : '进入维护'}
                </button>
                {n.role === 'compute' && <>
                  <div style={{ marginTop: 6, fontSize: 12 }}>
                    原生后台：{link?.state === 'verified'
                      ? `${link.local_handle}（已验证）`
                      : link?.state === 'stale' ? '权限已失效，需重新验证'
                        : link?.state === 'revoked' ? '已撤销' : '未关联'}
                  </div>
                  {link?.state === 'verified' ? <>
                    <button className="btn-sm primary" disabled={handoffNode === n.id} onClick={() => enterNodeAdmin(n)}>
                      {handoffNode === n.id ? '确认权限中…' : '进入原生后台'}
                    </button>{' '}
                    <button className="btn-sm" onClick={() => beginNodeLink(n)}>重新验证</button>{' '}
                    <button className="btn-sm danger" onClick={() => revokeNodeLink(n)}>撤销关联</button>
                  </> : (
                    <button className="btn-sm primary" onClick={() => beginNodeLink(n)}>验证后台账号</button>
                  )}
                </>}
              </td>
            </tr>
          })}
        </tbody>
      </table>
    </>
  )
}

// ---------- 用户管理 ----------
function UsersAdmin() {
  const [users, setUsers] = useState<any[]>([])
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')
  const [recoveryUser, setRecoveryUser] = useState<any>(null)
  const [recoveryPassword, setRecoveryPassword] = useState('')
  const [recovering, setRecovering] = useState(false)
  const recoveryOperations = useRef<Record<string, string>>({})
  const load = () => adminApi.users().then(d => setUsers(d.users)).catch(e => setError(e.message))
  useEffect(() => { load() }, [])

  const userUUID = (user: any) => user.UUID ?? user.uuid
  const beginRecovery = (user: any) => {
    setError('')
    setMessage('')
    setRecoveryUser(user)
    setRecoveryPassword('')
  }
  const changeRecoveryPassword = (value: string) => {
    if (recoveryUser) delete recoveryOperations.current[userUUID(recoveryUser)]
    setRecoveryPassword(value)
  }
  const recoverIdentity = async (event: React.FormEvent) => {
    event.preventDefault()
    if (!recoveryUser) return
    const uuid = userUUID(recoveryUser)
    const operationID = recoveryOperations.current[uuid] || crypto.randomUUID()
    recoveryOperations.current[uuid] = operationID
    setError('')
    setMessage('')
    setRecovering(true)
    try {
      const result = await adminApi.recoverUserIdentity(uuid, operationID, recoveryPassword)
      delete recoveryOperations.current[uuid]
      setRecoveryUser(null)
      setRecoveryPassword('')
      setMessage(result.user_status === 'disabled'
        ? '身份凭据已恢复且现有会话已撤销；账号继续保持禁用，重新启用前不会投递节点密码。'
        : result.pending_nodes > 0
          ? `身份已恢复并撤销现有会话；${result.pending_nodes} 个节点离线或同步失败，系统将持久重试。`
          : '身份已恢复、现有会话已撤销，所有关联节点密码已同步。')
      load()
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : '身份恢复失败')
    } finally {
      setRecovering(false)
    }
  }

  return (
    <>
      <h2>用户管理</h2>
      {error && <div className="error-msg">{error}</div>}
      {message && <div className="success-msg">{message}</div>}
      {recoveryUser && (
        <form onSubmit={recoverIdentity} className="card" style={{ margin: '0 0 20px', maxWidth: 560 }}>
          <h3>人工恢复登录身份</h3>
          <p>
            为 <strong>{recoveryUser.Username ?? recoveryUser.username}</strong>（全局 UUID：
            <span className="mono">{userUUID(recoveryUser)}</span>）设置一次新密码。
            提交会撤销该用户全部现有总控会话；暂不可达节点会保持待同步并自动重试。
          </p>
          <div className="field">
            <label>新密码（8 至 72 字节）</label>
            <input type="password" value={recoveryPassword} onChange={e => changeRecoveryPassword(e.target.value)} minLength={8} maxLength={72} autoComplete="new-password" required />
          </div>
          <button className="btn" type="submit" disabled={recovering}>{recovering ? '恢复中…' : '确认恢复身份'}</button>{' '}
          <button className="btn-sm" type="button" disabled={recovering} onClick={() => { setRecoveryUser(null); setRecoveryPassword('') }}>取消</button>
        </form>
      )}
      <table className="table">
        <thead>
          <tr><th>全局 UUID</th><th>用户名</th><th>昵称</th><th>注册方式</th><th>家节点</th><th>状态</th><th>操作</th></tr>
        </thead>
        <tbody>
          {users.map(u => (
            <tr key={userUUID(u)}>
              <td className="mono">{userUUID(u)}</td>
              <td>{u.Username ?? u.username}</td>
              <td>{u.DisplayName ?? u.display_name}</td>
              <td>{u.AuthProvider ?? u.auth_provider}</td>
              <td>{(u.HomeNodeID?.Int64 ?? u.home_node_id?.Int64 ?? u.home_node_id) || '-'}</td>
              <td><span className={`badge ${(u.Status ?? u.status) === 'active' ? 'green' : 'red'}`}>{u.Status ?? u.status}</span></td>
              <td style={{ whiteSpace: 'nowrap' }}>
                <button className="btn-sm primary" onClick={() => adminApi.triggerBackup(u.ID ?? u.id).then(load)}>备份</button>{' '}
                <button className="btn-sm danger" onClick={() => adminApi.disableUser(u.ID ?? u.id).then(load)}>禁用</button>{' '}
                <button className="btn-sm" onClick={() => beginRecovery(u)}>人工恢复身份</button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  )
}

// ---------- 备份任务 ----------
function BackupsAdmin() {
  const [jobs, setJobs] = useState<any[]>([])
  const [error, setError] = useState('')
  const load = () => adminApi.backups().then(d => setJobs(d.backups)).catch(e => setError(e.message))
  useEffect(() => { load(); const t = setInterval(load, 10000); return () => clearInterval(t) }, [])

  const statusBadge = (s: string) => {
    const map: any = { done: 'green', running: 'yellow', verifying: 'yellow', failed: 'red', aborted: 'gray', pending: 'gray' }
    return `badge ${map[s] || 'gray'}`
  }

  return (
    <>
      <h2>备份任务</h2>
      {error && <div className="error-msg">{error}</div>}
      <table className="table">
        <thead>
          <tr><th>ID</th><th>用户</th><th>源节点</th><th>目标节点</th><th>触发</th><th>状态</th><th>大小</th><th>错误</th><th>操作</th></tr>
        </thead>
        <tbody>
          {jobs.map(j => (
            <tr key={j.ID ?? j.id}>
              <td>{j.ID ?? j.id}</td>
              <td>{j.UserID ?? j.user_id}</td>
              <td>{j.SrcNodeID ?? j.src_node_id}</td>
              <td>{j.DstNodeID ?? j.dst_node_id}</td>
              <td>{j.Trigger ?? j.trigger}</td>
              <td><span className={statusBadge(j.Status ?? j.status)}>{j.Status ?? j.status}</span></td>
              <td style={{ fontSize: 12 }}>{((j.Bytes?.Int64 ?? j.bytes ?? 0) / 1048576).toFixed(1)}MB</td>
              <td style={{ fontSize: 12, maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis' }}>{j.Error?.String ?? j.error?.String ?? ''}</td>
              <td>
                {(j.Status ?? j.status) === 'running' && (
                  <button className="btn-sm danger" onClick={() => adminApi.abortBackup(j.ID ?? j.id).then(load)}>中止</button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  )
}

function ProtectionAlertsAdmin() {
  const [alerts, setAlerts] = useState<any[]>([])
  const [error, setError] = useState('')
  const load = () => adminApi.protectionAlerts()
    .then(data => { setAlerts(data.alerts); setError('') })
    .catch(err => setError(err.message))
  useEffect(() => { load(); const timer = setInterval(load, 30000); return () => clearInterval(timer) }, [])

  return (
    <>
      <h2>保护告警</h2>
      <p style={{ color: 'var(--text-dim)', marginBottom: 16 }}>
        短暂未保护状态会先进入宽限期；这里只显示已达到通知时间的真实告警。
      </p>
      {error && <div className="error-msg">{error}</div>}
      <table className="table">
        <thead><tr><th>级别</th><th>用户</th><th>节点</th><th>说明</th><th>首次发现</th><th>最近确认</th></tr></thead>
        <tbody>
          {alerts.map((alert, index) => (
            <tr key={`${alert.user_uuid}-${alert.category}-${index}`}>
              <td><span className={`badge ${alert.severity === 'critical' ? 'red' : 'yellow'}`}>{alert.severity === 'critical' ? '严重' : '警告'}</span></td>
              <td>{alert.username}<div className="mono" style={{ fontSize: 11 }}>{alert.user_uuid}</div></td>
              <td>{alert.node_name || '-'}</td>
              <td>{alert.summary}</td>
              <td>{new Date(alert.first_seen_at).toLocaleString()}</td>
              <td>{new Date(alert.last_seen_at).toLocaleString()}</td>
            </tr>
          ))}
          {alerts.length === 0 && <tr><td colSpan={6}>当前没有达到通知条件的保护告警</td></tr>}
        </tbody>
      </table>
    </>
  )
}

function AdminsAdmin() {
  const [admins, setAdmins] = useState<any[]>([])
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')

  const load = () => adminApi.admins().then(data => setAdmins(data.admins)).catch(err => setError(err.message))
  useEffect(() => { load() }, [])

  const create = async (event: React.FormEvent) => {
    event.preventDefault()
    setError('')
    setMessage('')
    try {
      await adminApi.createAdmin(username, password)
      setUsername('')
      setPassword('')
      setMessage('管理员已创建')
      load()
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : '创建失败')
    }
  }

  const toggle = async (admin: any) => {
    setError('')
    try {
      await adminApi.setAdminStatus(admin.id, admin.status === 'active' ? 'disabled' : 'active')
      load()
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : '状态更新失败')
    }
  }

  const resetPassword = async (admin: any) => {
    const next = window.prompt(`为 ${admin.username} 设置至少 12 位新密码`)
    if (!next) return
    setError('')
    try {
      await adminApi.resetAdminPassword(admin.id, next)
      setMessage('密码已重置，该管理员的现有会话已撤销')
      load()
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : '密码重置失败')
    }
  }

  return (
    <>
      <h2>管理员</h2>
      {error && <div className="error-msg">{error}</div>}
      {message && <div className="success-msg">{message}</div>}
      <form onSubmit={create} className="card" style={{ margin: '0 0 20px', maxWidth: 520 }}>
        <div className="field"><label>新管理员用户名</label><input value={username} onChange={e => setUsername(e.target.value)} minLength={3} maxLength={32} required /></div>
        <div className="field"><label>初始密码（至少 12 位）</label><input type="password" value={password} onChange={e => setPassword(e.target.value)} minLength={12} required /></div>
        <button className="btn" type="submit">创建同级管理员</button>
      </form>
      <table className="table">
        <thead><tr><th>用户名</th><th>状态</th><th>密码版本</th><th>最近登录</th><th>操作</th></tr></thead>
        <tbody>
          {admins.map(admin => (
            <tr key={admin.id}>
              <td>{admin.username}</td>
              <td><span className={`badge ${admin.status === 'active' ? 'green' : 'gray'}`}>{admin.status === 'active' ? '有效' : '已禁用'}</span></td>
              <td>{admin.password_version}</td>
              <td>{admin.last_login_at ? new Date(admin.last_login_at).toLocaleString() : '从未'}</td>
              <td>
                <button className="btn-sm" onClick={() => resetPassword(admin)}>重置密码</button>{' '}
                <button className={`btn-sm ${admin.status === 'active' ? 'danger' : 'primary'}`} onClick={() => toggle(admin)}>{admin.status === 'active' ? '禁用' : '启用'}</button>
              </td>
            </tr>
          ))}
          {admins.length === 0 && <tr><td colSpan={5}>暂无管理员</td></tr>}
        </tbody>
      </table>
    </>
  )
}
