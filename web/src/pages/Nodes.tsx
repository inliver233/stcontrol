import { useEffect, useRef, useState } from 'react'
import { api, MyNode, ProtectionState, RestoreStatus, RestoreTarget, measureLatency, submitLoginHandoff } from '../api'
import { useAuth } from '../App'
import { Link, useNavigate } from 'react-router-dom'

export default function NodesPage() {
  const [nodes, setNodes] = useState<MyNode[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [jumping, setJumping] = useState(false)
  const [protection, setProtection] = useState<ProtectionState | null>(null)
  const [takeoverNode, setTakeoverNode] = useState<MyNode | null>(null)
  const [returnNode, setReturnNode] = useState<MyNode | null>(null)
  const [takingOver, setTakingOver] = useState(false)
	const [restoreTargets, setRestoreTargets] = useState<RestoreTarget[]>([])
	const [restoreTargetsLoading, setRestoreTargetsLoading] = useState(false)
	const [selectedRestoreTarget, setSelectedRestoreTarget] = useState<number | null>(null)
	const [restoreStatus, setRestoreStatus] = useState<RestoreStatus | null>(null)
	const [restoring, setRestoring] = useState(false)
	const mounted = useRef(true)
  const handoffOperations = useRef(new Map<number, string>())
  const takeoverOperations = useRef(new Map<number, string>())
  const { me, setMe } = useAuth()
  const navigate = useNavigate()

  useEffect(() => {
    let cancelled = false
		mounted.current = true
    ;(async () => {
      try {
        const [{ nodes: list }, protectionState] = await Promise.all([api.myNodes(), api.protection()])
        if (cancelled) return
        setProtection(protectionState)
				if (protectionState.storage_restore_needed) {
					setRestoreTargetsLoading(true)
					try {
						const { targets } = await api.restoreTargets()
						const targetList = targets ?? []
						if (!cancelled) {
							setRestoreTargets(targetList)
							if (targetList.length === 1) setSelectedRestoreTarget(targetList[0].node_id)
						}
					} catch (err: unknown) {
						if (!cancelled) setError(err instanceof Error ? err.message : '加载恢复目标失败')
					} finally {
						if (!cancelled) setRestoreTargetsLoading(false)
					}
				}
        const withLatency = await Promise.all(
          list.map(async n => {
            const latency_ms = await measureLatency(n.base_url)
            if (latency_ms >= 0) {
              // R18: persist the sample so future selections see stable latency.
              api.reportNodeLatency(n.node_id, latency_ms).catch(() => undefined)
            }
            return { ...n, latency_ms }
          }),
        )
        if (cancelled) return
        setNodes(withLatency)
        setLoading(false)
        // 仅有一个节点且它无需风险确认时才自动跳转；有热备时保留选择机会。
        const ready = withLatency.filter(n => n.ready)
        if (ready.length === 1 && !ready[0].requires_takeover) {
          enterNode(ready[0].node_id)
        }
      } catch (err: unknown) {
        setError(err instanceof Error ? err.message : '加载节点失败')
        setLoading(false)
      }
    })()
    return () => { cancelled = true; mounted.current = false }
  }, [])

  const enterNode = async (nodeId: number) => {
    setJumping(true)
    setError('')
    try {
      let operationId = handoffOperations.current.get(nodeId)
      if (!operationId) {
        operationId = crypto.randomUUID()
        handoffOperations.current.set(nodeId, operationId)
      }
      const handoff = await api.loginHandoff(nodeId, operationId)
      submitLoginHandoff(handoff)
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : '登录交接失败')
      setJumping(false)
    }
  }

  const chooseNode = (node: MyNode) => {
    if (!node.ready || jumping || takingOver || restoring) return
    if (node.requires_takeover) {
      if (protection?.active_writer_node_id && protection.active_writer_node_id !== node.node_id) {
        const writer = nodes.find(candidate => candidate.node_id === protection.active_writer_node_id)
        if (writer) {
          setReturnNode(writer)
        } else {
          setError(`当前写入会话仍在 ${protection.active_writer_node_name || '另一节点'}，请从该节点继续使用。`)
        }
        return
      }
      setTakeoverNode(node)
      return
    }
    enterNode(node.node_id)
  }

  const confirmTakeover = async () => {
    if (!takeoverNode) return
    if (!takeoverNode.last_synced_at) {
      setError('该热备没有可确认的不可变恢复点，请刷新后重试。')
      return
    }
    const nodeId = takeoverNode.node_id
    let operationId = takeoverOperations.current.get(nodeId)
    if (!operationId) {
      operationId = crypto.randomUUID()
      takeoverOperations.current.set(nodeId, operationId)
    }
    setTakingOver(true)
    setError('')
    try {
      await api.confirmTakeover(nodeId, operationId, takeoverNode.last_synced_at)
      takeoverOperations.current.delete(nodeId)
      setTakeoverNode(null)
      setReturnNode(null)
      setNodes(current => current.map(node => {
        if (node.node_id === nodeId) {
          return { ...node, kind: 'home', kind_label: '我的服务器', ready: true, requires_takeover: false }
        }
        if (node.kind === 'home') {
          return { ...node, kind: 'hot_standby', kind_label: '备用服务器', ready: false, requires_takeover: true }
        }
        return node
      }))
      void api.protection().then(setProtection).catch(() => undefined)
      await enterNode(nodeId)
      setTakingOver(false)
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : '接管失败'
      if (message.includes('旧节点写入租约仍在有效期内')) {
        const writer = nodes.find(node => node.kind === 'home')
        if (writer) {
          setReturnNode(writer)
          setTakeoverNode(null)
        }
      }
      setError(message)
      setTakingOver(false)
    }
  }

	const restoreOperationKey = (targetNodeID: number, recoveryAt: string) =>
		`stcontrol_restore_operation:${targetNodeID}:${recoveryAt}`

	const refreshAfterRestore = async (targetNodeID: number) => {
		const [{ nodes: list }, protectionState] = await Promise.all([api.myNodes(), api.protection()])
		const withLatency = await Promise.all(
			list.map(async node => {
				const latency_ms = await measureLatency(node.base_url)
				if (latency_ms >= 0) {
					api.reportNodeLatency(node.node_id, latency_ms).catch(() => undefined)
				}
				return { ...node, latency_ms }
			}),
		)
		if (!mounted.current) return
		setNodes(withLatency)
		setProtection(protectionState)
		setRestoreTargets([])
		setSelectedRestoreTarget(null)
		setRestoring(false)
		const target = withLatency.find(node => node.node_id === targetNodeID && node.ready && !node.requires_takeover)
		if (target) await enterNode(targetNodeID)
	}

	const pollArchiveRestore = async (initial: RestoreStatus, storageKey: string) => {
		let status = initial
		while (mounted.current && status.state !== 'succeeded' && status.state !== 'failed') {
			await new Promise(resolve => window.setTimeout(resolve, 2000))
			if (!mounted.current) return
			status = await api.archiveRestoreStatus(status.operation_id)
			if (!mounted.current) return
			setRestoreStatus(status)
		}
		if (!mounted.current) return
		if (status.state === 'succeeded') {
			sessionStorage.removeItem(storageKey)
			await refreshAfterRestore(status.target_node_id)
			return
		}
		sessionStorage.removeItem(storageKey)
		setRestoring(false)
		setError(status.error || '恢复未完成，请重新选择目标后重试。')
	}

	const confirmArchiveRestore = async () => {
		if (!selectedRestoreTarget || !protection?.latest_recovery_at || restoring) return
		const storageKey = restoreOperationKey(selectedRestoreTarget, protection.latest_recovery_at)
		let operationID = sessionStorage.getItem(storageKey)
		if (!operationID) {
			operationID = crypto.randomUUID()
			sessionStorage.setItem(storageKey, operationID)
		}
		setRestoring(true)
		setError('')
		try {
			const status = await api.startArchiveRestore(
				selectedRestoreTarget, operationID, protection.latest_recovery_at,
			)
			setRestoreStatus(status)
			await pollArchiveRestore(status, storageKey)
		} catch (err: unknown) {
			setError(err instanceof Error ? err.message : '恢复任务提交失败')
			setRestoring(false)
		}
	}

	const restoreStateLabel = (state: RestoreStatus['state']) => ({
		preparing: '正在准备目标账号',
		transferring: '正在传输恢复数据',
		verifying: '正在逐文件校验',
		publishing: '正在原子发布',
		retrying: '暂时中断，正在安全重试',
		succeeded: '恢复完成',
		failed: '恢复未完成',
	}[state])

  const logout = async () => {
    await api.logout()
    setMe(null)
    navigate('/login')
  }

  const takeoverRecoveryAt = protection && takeoverNode && protection.recovery_node_id === takeoverNode.node_id
    ? protection.latest_recovery_at
    : takeoverNode?.last_synced_at

  return (
    <div className="page">
      <div className="card">
        <div className="brand">
          <h1>欢迎，{me?.display_name || me?.username}</h1>
          <p>选择要进入的服务器</p>
        </div>
        {error && <div className="error-msg">{error}</div>}
        {protection && (
          <div className={protection.state === 'protected' ? 'success-msg' : protection.state === 'conflict' || protection.state === 'unavailable' ? 'error-msg' : 'warning-msg'}>
            <strong>数据保护：{protection.label}</strong><br />{protection.risk}
            {protection.latest_recovery_at && <div>最近可恢复时间：{new Date(protection.latest_recovery_at).toLocaleString()}</div>}
          </div>
        )}
        {returnNode && (
          <div className="warning-msg">
            <strong>当前会话仍在 {returnNode.name}</strong>
            <p>系统不会强制切换，也不会允许另一节点同时写入。请返回当前节点继续使用。</p>
            <button className="btn-sm primary" disabled={!returnNode.ready || jumping} onClick={() => enterNode(returnNode.node_id)}>
              {returnNode.ready ? `返回 ${returnNode.name}` : '当前节点暂不可达'}
            </button>{' '}
            <button className="btn-sm" disabled={jumping} onClick={() => setReturnNode(null)}>取消</button>
          </div>
        )}
        {takeoverNode && (
          <div className="error-msg">
            <strong>确认由 {takeoverNode.name} 接管？</strong>
            <p>
              这会把当前家节点降为陈旧副本，并撤销尚未使用的登录短码。
              {takeoverRecoveryAt
                ? ` 最近完整同步时间为 ${new Date(takeoverRecoveryAt).toLocaleString()}，此时间之后的数据可能丢失。`
                : ' 当前没有可展示的同步时间，系统会拒绝不具备不可变快照的接管。'}
            </p>
            <button className="btn-sm danger" disabled={takingOver} onClick={confirmTakeover}>{takingOver ? '接管中…' : '理解风险并确认接管'}</button>{' '}
            <button className="btn-sm" disabled={takingOver} onClick={() => setTakeoverNode(null)}>取消</button>
          </div>
        )}
				{protection?.storage_restore_needed && (
					<div className="error-msg">
						<strong>从纯存储副本恢复到计算节点</strong>
						<p>
							请选择恢复目标。系统会先供应并验证节点账号，再传输、逐文件校验和原子发布；
							完成前该节点不能登录。最近完整恢复点为{' '}
							{protection.latest_recovery_at
								? new Date(protection.latest_recovery_at).toLocaleString()
								: '不可用'}，此时间之后的数据可能丢失。
						</p>
						{restoreTargetsLoading ? (
							<div className="loading">正在查找合格计算节点…</div>
						) : restoreTargets.length === 0 ? (
							<p>当前没有同时满足容量、兼容性和账号供应条件的计算节点，请稍后重试或联系管理员。</p>
						) : (
							<div className="restore-targets">
								{restoreTargets.map(target => (
									<label key={target.node_id} className={`restore-target ${selectedRestoreTarget === target.node_id ? 'selected' : ''}`}>
										<input
											type="radio"
											name="restore-target"
											checked={selectedRestoreTarget === target.node_id}
											disabled={restoring}
											onChange={() => setSelectedRestoreTarget(target.node_id)}
										/>
										<span><strong>{target.name}</strong><small>{target.region || '默认区域'}</small></span>
									</label>
								))}
							</div>
						)}
						{restoreStatus && (
							<div className={restoreStatus.state === 'failed' ? 'error-msg' : 'warning-msg'}>
								{restoreStateLabel(restoreStatus.state)}
								{restoreStatus.error && `：${restoreStatus.error}`}
							</div>
						)}
						<button
							className="btn-sm danger"
							disabled={!selectedRestoreTarget || !protection.latest_recovery_at || restoring || restoreTargetsLoading}
							onClick={confirmArchiveRestore}
						>
							{restoring ? '恢复进行中…' : '理解风险并开始恢复'}
						</button>
					</div>
				)}
        {loading ? (
          <div className="loading">正在加载你的服务器…</div>
        ) : nodes.length === 0 ? (
          <div className="error-msg">你还没有可用的服务器，请联系管理员</div>
        ) : (
          nodes.map(n => (
            <div
              key={n.node_id}
              className={`my-node ${!n.ready ? 'disabled' : ''}`}
              onClick={() => chooseNode(n)}
            >
              <div className="info">
                <div className="name">{n.name}</div>
                <div className="sub">
                  {n.kind_label} · {n.region || '默认区域'}
                  {n.latency_ms !== undefined && n.latency_ms >= 0 && ` · ${n.latency_ms}ms`}
                  {!n.ready && ' · 未就绪'}
                  {n.ready && n.requires_takeover && ' · 需确认接管'}
                </div>
              </div>
              <div className="go">{n.ready ? (n.requires_takeover ? '⚠' : '→') : '⏳'}</div>
            </div>
          ))
        )}
        {jumping && <div className="loading">正在跳转…</div>}
        <div className="link-row">
          <Link to="/account">登录方式与账号安全</Link>{' · '}
          <a onClick={logout} style={{ cursor: 'pointer' }}>退出登录</a>
        </div>
      </div>
    </div>
  )
}
