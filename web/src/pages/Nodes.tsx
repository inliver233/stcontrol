import { useEffect, useState } from 'react'
import { api, MyNode, measureLatency } from '../api'
import { useAuth } from '../App'
import { useNavigate } from 'react-router-dom'

export default function NodesPage() {
  const [nodes, setNodes] = useState<MyNode[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [jumping, setJumping] = useState(false)
  const { me, setMe } = useAuth()
  const navigate = useNavigate()

  useEffect(() => {
    let cancelled = false
    ;(async () => {
      try {
        const { nodes: list } = await api.myNodes()
        if (cancelled) return
        const withLatency = await Promise.all(
          list.map(async n => ({ ...n, latency_ms: await measureLatency(n.base_url) })),
        )
        if (cancelled) return
        setNodes(withLatency)
        setLoading(false)
        // 只有一个可用节点 → 自动跳转
        const ready = withLatency.filter(n => n.ready)
        if (ready.length === 1) {
          enterNode(ready[0].node_id)
        }
      } catch {
        setLoading(false)
      }
    })()
    return () => { cancelled = true }
  }, [])

  const enterNode = async (nodeId: number) => {
    setJumping(true)
    setError('')
    try {
      const { redirect_url } = await api.loginRedirect(nodeId)
      window.location.href = redirect_url
    } catch (err: any) {
      setError(err.message)
      setJumping(false)
    }
  }

  const logout = async () => {
    await api.logout()
    setMe(null)
    navigate('/login')
  }

  return (
    <div className="page">
      <div className="card">
        <div className="brand">
          <h1>欢迎，{me?.display_name || me?.username}</h1>
          <p>选择要进入的服务器</p>
        </div>
        {error && <div className="error-msg">{error}</div>}
        {loading ? (
          <div className="loading">正在加载你的服务器…</div>
        ) : nodes.length === 0 ? (
          <div className="error-msg">你还没有可用的服务器，请联系管理员</div>
        ) : (
          nodes.map(n => (
            <div
              key={n.node_id}
              className={`my-node ${!n.ready ? 'disabled' : ''}`}
              onClick={() => n.ready && !jumping && enterNode(n.node_id)}
            >
              <div className="info">
                <div className="name">{n.name}</div>
                <div className="sub">
                  {n.kind_label} · {n.region || '默认区域'}
                  {n.latency_ms !== undefined && n.latency_ms >= 0 && ` · ${n.latency_ms}ms`}
                  {!n.ready && ' · 未就绪'}
                </div>
              </div>
              <div className="go">{n.ready ? '→' : '⏳'}</div>
            </div>
          ))
        )}
        {jumping && <div className="loading">正在跳转…</div>}
        <div className="link-row">
          <a onClick={logout} style={{ cursor: 'pointer' }}>退出登录</a>
        </div>
      </div>
    </div>
  )
}
