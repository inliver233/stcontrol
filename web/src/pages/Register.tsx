import { useEffect, useRef, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { api, Node, measureLatency } from '../api'
import { useAuth } from '../App'
import { NodeCard } from '../components/NodeCard'
import { waitForRegistration } from '../registration'

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
  const [nodesLoadError, setNodesLoadError] = useState('')
  const [nodesReload, setNodesReload] = useState(0)
  const operationID = useRef(crypto.randomUUID())
  const { refresh } = useAuth()
  const navigate = useNavigate()
  const resetOperation = () => { operationID.current = crypto.randomUUID() }

  // 拉取节点并逐个测延迟
  useEffect(() => {
    let cancelled = false
    ;(async () => {
      setLoadingNodes(true)
      setNodesLoadError('')
      try {
        const { nodes: list } = await api.availableNodes()
        if (cancelled) return
        setNodes(list)
        setLoadingNodes(false)
        // 并发测延迟
        const withLatency = await Promise.all(
          list.map(async n => {
            const latency_ms = await measureLatency(n.base_url)
            if (latency_ms >= 0) {
              api.reportNodeLatency(n.id, latency_ms).catch(() => undefined)
            }
            return { ...n, latency_ms }
          }),
        )
        if (!cancelled) setNodes(withLatency)
      } catch (err: unknown) {
        if (!cancelled) {
          setNodesLoadError(err instanceof Error ? err.message : '加载可用节点失败')
          setLoadingNodes(false)
        }
      }
    })()
    return () => { cancelled = true }
  }, [nodesReload])

  useEffect(() => {
    let cancelled = false
    let resumed = false
    api.registrationStatus().then(async status => {
      if (cancelled) return
      resumed = true
      setBusy(true)
      if (status.state !== 'succeeded') await waitForRegistration()
      if (!cancelled) {
        await refresh()
        navigate('/')
      }
    }).catch(err => {
      if (!cancelled && resumed) {
        setError(err instanceof Error ? err.message : '注册状态查询失败')
        setBusy(false)
      }
    })
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
      const started = await api.register({
        operation_id: operationID.current,
        username,
        display_name: displayName || username,
        password,
        node_id: selectedNode,
        invitation_code: inviteCode || undefined,
      })
      if (started.state !== 'succeeded') await waitForRegistration()
      await refresh()
      navigate('/')
    } catch (err: any) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  const selectedPolicy = nodes.find(node => node.id === selectedNode)

  const oauth = (provider: string) => {
    if (!selectedNode || busy) {
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
          <div className="loading" role="status">正在加载节点…</div>
        ) : nodesLoadError ? (
          <div className="empty-state">
            <p role="alert">{nodesLoadError}</p>
            <button className="btn-sm primary" type="button" onClick={() => setNodesReload(value => value + 1)}>重试加载节点</button>
          </div>
        ) : nodes.length === 0 ? (
          <div className="empty-state">暂无可用节点，请联系管理员</div>
        ) : (
          <div className="node-grid">
            {nodes.map(n => (
              <NodeCard
                key={n.id}
                node={n}
                selected={selectedNode === n.id}
                onSelect={() => {
                  if (n.registrable && !busy) {
                    setSelectedNode(n.id)
                    resetOperation()
                  }
                }}
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
              <input value={username} onChange={e => { setUsername(e.target.value); resetOperation() }} required />
            </div>
            <div className="field">
              <label>昵称（可选）</label>
              <input value={displayName} onChange={e => { setDisplayName(e.target.value); resetOperation() }} />
            </div>
            <div className="field">
              <label>密码（至少 8 位）</label>
              <input type="password" value={password} onChange={e => { setPassword(e.target.value); resetOperation() }} required minLength={8} />
            </div>
            <div className="field">
              <label>确认密码</label>
              <input type="password" value={confirm} onChange={e => { setConfirm(e.target.value); resetOperation() }} required />
            </div>
            <div className="field">
              <label>邀请码{selectedPolicy?.invitation_required ? '（该节点必填）' : '（可选）'}</label>
              <input value={inviteCode} onChange={e => { setInviteCode(e.target.value); resetOperation() }}
                placeholder={selectedPolicy?.invitation_required ? '请输入该节点邀请码' : '无邀请码可留空'}
                required={selectedPolicy?.invitation_required} />
            </div>
            <button className="btn" type="submit" disabled={busy || !selectedNode}>
              {busy ? '注册中…' : '注 册'}
            </button>
          </form>
        ) : (
          <div>
            <p style={{ color: 'var(--text-dim)', fontSize: 14, marginBottom: 14 }}>
              通过第三方账号验证后，将再次确认上方所选节点及其邀请码：
            </p>
            <div style={{ display: 'flex', gap: 10 }}>
              <button className="btn secondary" onClick={() => oauth('discord')} disabled={!selectedNode || busy}>
                使用 Discord 注册
              </button>
              <button className="btn secondary" onClick={() => oauth('linuxdo')} disabled={!selectedNode || busy}>
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
