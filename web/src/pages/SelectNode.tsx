import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { api, Node, measureLatency } from '../api'
import { NodeCard } from '../components/NodeCard'

// OAuth 回调时新用户未选节点 → 在此页选节点后重新发起 OAuth 完成注册
export default function SelectNodePage() {
  const [params] = useSearchParams()
  const provider = params.get('provider') || ''
  const [nodes, setNodes] = useState<Node[]>([])
  const [selected, setSelected] = useState<number>(0)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let cancelled = false
    ;(async () => {
      try {
        const { nodes: list } = await api.availableNodes()
        if (cancelled) return
        setNodes(list)
        setLoading(false)
        const withLatency = await Promise.all(
          list.map(async n => ({ ...n, latency_ms: await measureLatency(n.base_url) })),
        )
        if (!cancelled) setNodes(withLatency)
      } catch {
        setLoading(false)
      }
    })()
    return () => { cancelled = true }
  }, [])

  const confirm = () => {
    if (!selected || !provider) return
    // 重新走 OAuth begin, 携带所选节点
    window.location.href = `/api/auth/oauth/${provider}?node_id=${selected}`
  }

  return (
    <div className="page">
      <div className="card wide">
        <div className="brand">
          <h1>选择节点</h1>
          <p>完成注册前，请选择你的服务器节点</p>
        </div>
        {loading ? (
          <div className="loading">正在加载节点…</div>
        ) : (
          <>
            <div className="node-grid">
              {nodes.map(n => (
                <NodeCard key={n.id} node={n} selected={selected === n.id} onSelect={() => n.registrable && setSelected(n.id)} />
              ))}
            </div>
            <button className="btn" onClick={confirm} disabled={!selected}>
              确认并继续
            </button>
          </>
        )}
      </div>
    </div>
  )
}
