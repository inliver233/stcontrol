import { useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { api, Node, measureLatency } from '../api'
import { useAuth } from '../App'
import { NodeCard } from '../components/NodeCard'

export default function RegisterPage() {
  const [tab, setTab] = useState<'password' | 'oauth'>('password')
  const [username, setUsername] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [inviteCode, setInviteCode] = useState('')
  const [nodes, setNodes] = useState<Node[]>([])
  const [selectedNode, setSelectedNode] = useState<number>(0)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [loadingNodes, setLoadingNodes] = useState(true)
  const { refresh } = useAuth()
  const navigate = useNavigate()

  // 拉取节点并逐个测延迟
  useEffect(() => {
    let cancelled = false
    ;(async () => {
      try {
        const { nodes: list } = await api.availableNodes()
        if (cancelled) return
        setNodes(list)
        setLoadingNodes(false)
        // 并发测延迟
        const withLatency = await Promise.all(
          list.map(async n => ({ ...n, latency_ms: await measureLatency(n.base_url) })),
        )
        if (!cancelled) setNodes(withLatency)
      } catch {
        setLoadingNodes(false)
      }
    })()
    return () => { cancelled = true }
  }, [])

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    if (password !== confirm) {
      setError('两次输入的密码不一致')
      return
    }
    if (!selectedNode) {
      setError('请选择一个节点')
      return
    }
    setBusy(true)
    try {
      await api.register({
        username,
        display_name: displayName || username,
        password,
        node_id: selectedNode,
        invitation_code: inviteCode || undefined,
      })
      await refresh()
      navigate('/')
    } catch (err: any) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  const oauth = (provider: string) => {
    if (!selectedNode) {
      setError('请先选择一个节点')
      return
    }
    window.location.href = `/api/auth/oauth/${provider}?node_id=${selectedNode}`
  }

  return (
    <div className="page">
      <div className="card wide">
        <div className="brand">
          <h1>注册云酒馆</h1>
          <p>选择一个节点，开始你的旅程</p>
        </div>
        {error && <div className="error-msg">{error}</div>}

        {/* 节点选择 */}
        <div className="section-title">选择服务器节点</div>
        {loadingNodes ? (
          <div className="loading">正在加载节点…</div>
        ) : nodes.length === 0 ? (
          <div className="error-msg">暂无可用节点，请联系管理员</div>
        ) : (
          <div className="node-grid">
            {nodes.map(n => (
              <NodeCard
                key={n.id}
                node={n}
                selected={selectedNode === n.id}
                onSelect={() => n.registrable && setSelectedNode(n.id)}
              />
            ))}
          </div>
        )}

        {/* 注册方式 */}
        <div className="tabs">
          <div className={`tab ${tab === 'password' ? 'active' : ''}`} onClick={() => setTab('password')}>
            账号密码注册
          </div>
          <div className={`tab ${tab === 'oauth' ? 'active' : ''}`} onClick={() => setTab('oauth')}>
            第三方注册
          </div>
        </div>

        {tab === 'password' ? (
          <form onSubmit={submit}>
            <div className="field">
              <label>用户名（登录用，字母/数字/横杠）</label>
              <input value={username} onChange={e => setUsername(e.target.value)} required />
            </div>
            <div className="field">
              <label>昵称（可选）</label>
              <input value={displayName} onChange={e => setDisplayName(e.target.value)} />
            </div>
            <div className="field">
              <label>密码（至少 6 位）</label>
              <input type="password" value={password} onChange={e => setPassword(e.target.value)} required minLength={6} />
            </div>
            <div className="field">
              <label>确认密码</label>
              <input type="password" value={confirm} onChange={e => setConfirm(e.target.value)} required />
            </div>
            <div className="field">
              <label>邀请码（如节点要求）</label>
              <input value={inviteCode} onChange={e => setInviteCode(e.target.value)} placeholder="无邀请码可留空" />
            </div>
            <button className="btn" type="submit" disabled={busy || !selectedNode}>
              {busy ? '注册中…' : '注 册'}
            </button>
          </form>
        ) : (
          <div>
            <p style={{ color: 'var(--text-dim)', fontSize: 14, marginBottom: 14 }}>
              通过第三方账号注册，将使用上方所选节点：
            </p>
            <div style={{ display: 'flex', gap: 10 }}>
              <button className="btn secondary" onClick={() => oauth('discord')} disabled={!selectedNode}>
                使用 Discord 注册
              </button>
              <button className="btn secondary" onClick={() => oauth('linuxdo')} disabled={!selectedNode}>
                使用 LinuxDo 注册
              </button>
            </div>
          </div>
        )}

        <div className="link-row">
          已有账号？<Link to="/login">直接登录</Link>
        </div>
      </div>
    </div>
  )
}
