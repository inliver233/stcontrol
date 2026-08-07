import { useEffect, useState } from 'react'
import { Routes, Route, useNavigate, useLocation } from 'react-router-dom'

// ---------- 管理 API ----------
async function adminReq<T>(path: string, options?: RequestInit): Promise<T> {
  const resp = await fetch(path, {
    credentials: 'include',
    headers: { 'Content-Type': 'application/json', ...(options?.headers || {}) },
    ...options,
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
  scanExisting: (id: number) => adminReq<any>(`/api/admin/nodes/${id}/scan-existing`, { method: 'POST' }),
  users: () => adminReq<{ users: any[] }>('/api/admin/users'),
  triggerBackup: (id: number) => adminReq<any>(`/api/admin/users/${id}/backup`, { method: 'POST' }),
  disableUser: (id: number) => adminReq<any>(`/api/admin/users/${id}/disable`, { method: 'POST' }),
  backups: () => adminReq<{ backups: any[] }>('/api/admin/backups'),
  abortBackup: (id: number) => adminReq<any>(`/api/admin/backups/${id}/abort`, { method: 'POST' }),
  createInvitation: (body: any) => adminReq<any>('/api/admin/invitations', { method: 'POST', body: JSON.stringify(body) }),
}

// ---------- 布局 ----------
export default function AdminPage() {
  const navigate = useNavigate()
  const location = useLocation()
  const nav = [
    { path: '/admin', label: '仪表盘' },
    { path: '/admin/nodes', label: '节点管理' },
    { path: '/admin/users', label: '用户管理' },
    { path: '/admin/backups', label: '备份任务' },
    { path: '/admin/invitations', label: '邀请码' },
  ]
  const current = location.pathname

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
        <div className="nav-item" style={{ marginTop: 24 }} onClick={() => navigate('/')}>← 返回用户页</div>
      </div>
      <div className="admin-main">
        <Routes>
          <Route path="/" element={<Overview />} />
          <Route path="/nodes" element={<NodesAdmin />} />
          <Route path="/users" element={<UsersAdmin />} />
          <Route path="/backups" element={<BackupsAdmin />} />
          <Route path="/invitations" element={<InvitationsAdmin />} />
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
  const [tokenInfo, setTokenInfo] = useState<any>(null)
  const [scanResult, setScanResult] = useState<any>(null)
  const [error, setError] = useState('')

  const load = () => adminApi.nodes().then(d => setNodes(d.nodes)).catch(e => setError(e.message))
  useEffect(() => { load() }, [])

  const toggle = async (n: any, field: 'allow_register' | 'is_backup_target') => {
    await adminApi.updateNode(n.id, { ...n, [field]: !n[field] })
    load()
  }
  const genToken = async (id: number) => {
    const info = await adminApi.registerToken(id)
    setTokenInfo(info)
  }
  const scan = async (id: number) => {
    const res = await adminApi.scanExisting(id)
    setScanResult(res)
  }

  return (
    <>
      <h2>节点管理</h2>
      {error && <div className="error-msg">{error}</div>}
      {tokenInfo && (
        <div className="success-msg">
          一次性注册令牌（24小时内有效）：<br />
          <div className="mono">{tokenInfo.install_cmd}</div>
          <button className="btn-sm" style={{ marginTop: 8 }} onClick={() => setTokenInfo(null)}>关闭</button>
        </div>
      )}
      {scanResult && (
        <div className="success-msg">
          扫描到 {scanResult.users?.length || 0} 个既有用户：
          {(scanResult.users || []).map((u: any) => <div key={u.handle} className="mono">{u.handle} ({(u.size_bytes/1048576).toFixed(1)}MB)</div>)}
          <button className="btn-sm" style={{ marginTop: 8 }} onClick={() => setScanResult(null)}>关闭</button>
        </div>
      )}
      <table className="table">
        <thead>
          <tr><th>ID</th><th>名称</th><th>角色</th><th>状态</th><th>负载</th><th>对外地址</th><th>版本</th><th>操作</th></tr>
        </thead>
        <tbody>
          {nodes.map(n => (
            <tr key={n.id}>
              <td>{n.id}</td>
              <td>{n.name}</td>
              <td>{n.role === 'compute' ? '计算' : '存储'}</td>
              <td><span className={`badge ${n.status === 'online' ? 'green' : n.status === 'offline' ? 'red' : 'gray'}`}>{n.status}</span></td>
              <td style={{ fontSize: 12 }}>
                CPU {Math.round(n.cpu_pct?.Float64 ?? n.cpu_pct ?? 0)}% · 内存 {Math.round(n.mem_pct?.Float64 ?? n.mem_pct ?? 0)}% · 硬盘 {Math.round(n.disk_pct?.Float64 ?? n.disk_pct ?? 0)}%
              </td>
              <td className="mono">{n.base_url || '未配置'}</td>
              <td style={{ fontSize: 12 }}>{n.tavern_version?.String ?? n.tavern_version ?? '-'}</td>
              <td style={{ whiteSpace: 'nowrap' }}>
                <button className="btn-sm" onClick={() => toggle(n, 'allow_register')}>
                  {n.allow_register ? '关注册' : '开注册'}
                </button>{' '}
                <button className="btn-sm" onClick={() => toggle(n, 'is_backup_target')}>
                  {n.is_backup_target ? '取消备份' : '设为备份'}
                </button>{' '}
                <button className="btn-sm primary" onClick={() => genToken(n.id)}>注册令牌</button>{' '}
                <button className="btn-sm" onClick={() => scan(n.id)}>扫描用户</button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  )
}

// ---------- 用户管理 ----------
function UsersAdmin() {
  const [users, setUsers] = useState<any[]>([])
  const [error, setError] = useState('')
  const load = () => adminApi.users().then(d => setUsers(d.users)).catch(e => setError(e.message))
  useEffect(() => { load() }, [])

  return (
    <>
      <h2>用户管理</h2>
      {error && <div className="error-msg">{error}</div>}
      <table className="table">
        <thead>
          <tr><th>ID</th><th>用户名</th><th>昵称</th><th>注册方式</th><th>家节点</th><th>状态</th><th>操作</th></tr>
        </thead>
        <tbody>
          {users.map(u => (
            <tr key={u.ID ?? u.id}>
              <td>{u.ID ?? u.id}</td>
              <td>{u.Username ?? u.username}</td>
              <td>{u.DisplayName ?? u.display_name}</td>
              <td>{u.AuthProvider ?? u.auth_provider}</td>
              <td>{(u.HomeNodeID?.Int64 ?? u.home_node_id?.Int64 ?? u.home_node_id) || '-'}</td>
              <td><span className={`badge ${(u.Status ?? u.status) === 'active' ? 'green' : 'red'}`}>{u.Status ?? u.status}</span></td>
              <td style={{ whiteSpace: 'nowrap' }}>
                <button className="btn-sm primary" onClick={() => adminApi.triggerBackup(u.ID ?? u.id).then(load)}>备份</button>{' '}
                <button className="btn-sm danger" onClick={() => adminApi.disableUser(u.ID ?? u.id).then(load)}>禁用</button>
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

// ---------- 邀请码 ----------
function InvitationsAdmin() {
  const [code, setCode] = useState('')
  const [maxUses, setMaxUses] = useState(1)
  const [result, setResult] = useState('')
  const [error, setError] = useState('')

  const create = async () => {
    setError(''); setResult('')
    try {
      const res = await adminApi.createInvitation({ code: code || undefined, max_uses: maxUses })
      setResult(`创建成功: ${res.code}`)
      setCode('')
    } catch (e: any) {
      setError(e.message)
    }
  }

  return (
    <>
      <h2>邀请码</h2>
      {error && <div className="error-msg">{error}</div>}
      {result && <div className="success-msg">{result}</div>}
      <div className="card" style={{ maxWidth: 420 }}>
        <div className="field">
          <label>邀请码（留空自动生成）</label>
          <input value={code} onChange={e => setCode(e.target.value)} />
        </div>
        <div className="field">
          <label>可用次数</label>
          <input type="number" value={maxUses} min={1} onChange={e => setMaxUses(parseInt(e.target.value) || 1)} />
        </div>
        <button className="btn" onClick={create}>生成邀请码</button>
      </div>
    </>
  )
}
