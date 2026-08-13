import { useEffect, useRef, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { api, Node, measureLatency } from '../api'
import { NodeCard } from '../components/NodeCard'
import { useAuth } from '../App'
import { waitForRegistration } from '../registration'

// OAuth 回调时新用户未选节点 → 在此页选节点后重新发起 OAuth 完成注册
export default function SelectNodePage() {
  const [nodes, setNodes] = useState<Node[]>([])
  const [selected, setSelected] = useState<number>(0)
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [invitationCode, setInvitationCode] = useState('')
  const operationID = useRef(crypto.randomUUID())
  const { refresh } = useAuth()
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()
  const requestedNodeID = Number(searchParams.get('node_id') || 0)
  const resetOperation = () => { operationID.current = crypto.randomUUID() }

  useEffect(() => {
    let cancelled = false
    ;(async () => {
      try {
        const { nodes: list } = await api.availableNodes()
        if (cancelled) return
        setNodes(list)
        if (Number.isSafeInteger(requestedNodeID) && list.some(node => node.id === requestedNodeID && node.registrable)) {
          setSelected(requestedNodeID)
        }
        setLoading(false)
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
        setError(err instanceof Error ? err.message : '加载节点失败')
        setLoading(false)
      }
    })()
    return () => { cancelled = true }
  }, [requestedNodeID])

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

  const confirm = async () => {
    if (!selected || busy) return
    setBusy(true)
    setError('')
    try {
      const started = await api.completeOAuth(selected, operationID.current, invitationCode || undefined)
      if (started.state !== 'succeeded') await waitForRegistration()
      await refresh()
      navigate('/')
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : '完成注册失败')
      setBusy(false)
    }
  }

  const selectedPolicy = nodes.find(node => node.id === selected)

  return (
    <div className="page">
      <div className="card wide">
        <div className="brand">
          <h1>选择节点</h1>
          <p>完成注册前，请选择你的服务器节点</p>
        </div>
        {error && <div className="error-msg">{error}</div>}
        {loading ? (
          <div className="loading">正在加载节点…</div>
        ) : (
          <>
            <div className="node-grid">
              {nodes.map(n => (
                <NodeCard key={n.id} node={n} selected={selected === n.id} onSelect={() => {
                  if (n.registrable && !busy) {
                    setSelected(n.id)
                    resetOperation()
                  }
                }} />
              ))}
            </div>
            {selectedPolicy?.invitation_required && (
              <div className="field">
                <label>该节点邀请码</label>
                <input value={invitationCode} onChange={event => {
                  setInvitationCode(event.target.value)
                  resetOperation()
                }} required placeholder="请输入节点邀请码" />
              </div>
            )}
            <button className="btn" onClick={confirm}
              disabled={!selected || busy || (!!selectedPolicy?.invitation_required && !invitationCode)}>
              {busy ? '正在完成注册…' : '确认并继续'}
            </button>
          </>
        )}
      </div>
    </div>
  )
}
