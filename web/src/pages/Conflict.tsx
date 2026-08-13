import { useCallback, useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api, ConflictDifferences, ConflictResolutionDecision, ConflictResolutionStatus, ReplicaConflict } from '../api'

const pageSize = 50

const evidenceLabel: Record<string, string> = {
  pending: '等待安全捕获',
  capturing: '正在生成不可变证据',
  retry_wait: '暂时失败，等待重试',
  ready: '证据已验证',
  failed: '证据捕获失败',
}

const categoryLabel: Record<string, string> = {
  chat_or_log: '聊天/日志',
  structured_json: 'JSON',
  text: '文本',
  binary_or_unknown: '二进制/未知',
}

function formatBytes(value?: number) {
  if (value === undefined) return '—'
  if (value < 1024) return `${value} B`
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KiB`
  if (value < 1024 * 1024 * 1024) return `${(value / 1024 / 1024).toFixed(1)} MiB`
  return `${(value / 1024 / 1024 / 1024).toFixed(1)} GiB`
}

export default function ConflictPage() {
  const [conflict, setConflict] = useState<ReplicaConflict | null>(null)
  const [differences, setDifferences] = useState<ConflictDifferences | null>(null)
  const [offset, setOffset] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [baseNodeID, setBaseNodeID] = useState(0)
  const [defaultAction, setDefaultAction] = useState<'use_base' | 'preserve_all_originals'>('preserve_all_originals')
  const [decisions, setDecisions] = useState<Record<string, ConflictResolutionDecision>>({})
  const [resolution, setResolution] = useState<ConflictResolutionStatus | null>(null)
  const [submitting, setSubmitting] = useState(false)
  const operationID = useRef<string>(crypto.randomUUID())
  const navigate = useNavigate()

  const loadConflict = useCallback(async () => {
    try {
      const current = await api.conflict()
      setConflict(current)
      setBaseNodeID(previous => previous || current.sources.find(source => source.is_authoritative && source.node_role === 'compute')?.node_id || current.sources.find(source => source.node_role === 'compute')?.node_id || 0)
      setError('')
    } catch (err: any) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void loadConflict()
	if (conflict?.inspection_state === 'differences_ready' || conflict?.inspection_state === 'identical' || conflict?.inspection_state === 'evidence_failed') return
    const timer = window.setInterval(() => void loadConflict(), 3000)
    return () => window.clearInterval(timer)
  }, [conflict?.inspection_state, loadConflict])

  useEffect(() => {
	if (conflict?.inspection_state !== 'differences_ready' && conflict?.inspection_state !== 'identical') {
	  setDifferences(null)
	  return
	}
	void api.conflictDifferences(offset, pageSize)
	  .then(page => { setDifferences(page); setError('') })
	  .catch((err: any) => setError(err.message))
  }, [conflict?.id, conflict?.inspection_state, offset])

  useEffect(() => {
    if (!conflict?.id || resolution) return
    const key = `stcontrol_conflict_resolution:${conflict.id}`
    const savedOperation = window.sessionStorage.getItem(key)
    if (!savedOperation) return
    operationID.current = savedOperation
    void api.conflictResolutionStatus(savedOperation)
      .then(setResolution)
      .catch(() => window.sessionStorage.removeItem(key))
  }, [conflict?.id, resolution])

  useEffect(() => {
    if (!differences) return
    setDecisions(previous => {
      const next = { ...previous }
      for (const file of differences.files) {
        if (file.difference !== 'different_at_same_path' || next[file.path]) continue
        const basePresent = file.sources.some(source => source.node_id === baseNodeID && source.present)
        if (!basePresent) {
          const fallback = file.sources.find(source => source.present)
          if (fallback) next[file.path] = { path: file.path, source_node_id: fallback.node_id, action: 'use_source' }
        }
      }
      return next
    })
  }, [baseNodeID, differences])

  useEffect(() => {
    if (!resolution || resolution.state === 'failed' || resolution.state === 'succeeded') return
    let timer: number | undefined
    const terminalStates = ['resolved', 'succeeded', 'failed', 'cancelled']
    const poll = () => {
      void api.conflictResolutionStatus(resolution.operation_id)
        .then(status => {
          setResolution(status)
          // A genuine 200 response reports the resolution as complete.
          if (status.state === 'succeeded') {
            if (timer !== undefined) window.clearInterval(timer)
            navigate('/login', { replace: true, state: { message: '冲突处理已完成，请重新登录。' } })
          }
        })
        .catch((err: any) => {
          const statusCode = typeof err?.status === 'number' ? err.status : 0
          // Authentication/session loss: leave the page like any other login expiry.
          if (statusCode === 401 || statusCode === 403) {
            if (timer !== undefined) window.clearInterval(timer)
            navigate('/login', { replace: true, state: { message: '冲突处理已完成，请重新登录。' } })
            return
          }
          const reported = err?.data?.state as string | undefined
          // Another 4xx is only terminal when the server says the case is done.
          if (statusCode >= 400 && statusCode < 500 && reported && terminalStates.includes(reported)) {
            if (timer !== undefined) window.clearInterval(timer)
            setError(err?.message || '冲突处理无法继续。')
            return
          }
          // Network or transient 5xx errors: keep polling so we don't lose the job.
        })
    }
    timer = window.setInterval(poll, 2000)
    return () => { if (timer !== undefined) window.clearInterval(timer) }
  }, [navigate, resolution])

  const updateDecision = (path: string, sourceNodeID: number, preserveBoth: boolean) => {
    setDecisions(previous => ({
      ...previous,
      [path]: { path, source_node_id: sourceNodeID, action: preserveBoth ? 'preserve_both' : 'use_source' },
    }))
  }

  const submitResolution = async () => {
    if (!conflict || baseNodeID <= 0) return
    if (!window.confirm('确认后系统会继续冻结写入，先保留全部原始证据，再在所选计算节点原子发布结果。是否继续？')) return
    setSubmitting(true)
    setError('')
    try {
      const status = await api.startConflictResolution({
        operation_id: operationID.current,
        expected_conflict_version: conflict.version,
        base_node_id: baseNodeID,
        default_action: defaultAction,
        acknowledge_freeze: true,
        decisions: Object.values(decisions).sort((left, right) => left.path.localeCompare(right.path)),
      })
      window.sessionStorage.setItem(`stcontrol_conflict_resolution:${conflict.id}`, operationID.current)
      setResolution(status)
    } catch (err: any) {
      setError(err.message)
    } finally {
      setSubmitting(false)
    }
  }

  const retryResolution = async () => {
    if (!resolution) return
    setSubmitting(true)
    setError('')
    try {
      setResolution(await api.retryConflictResolution(resolution.operation_id))
    } catch (err: any) {
      setError(err.message)
    } finally {
      setSubmitting(false)
    }
  }

  const logout = async () => {
	try {
	  await api.conflictLogout()
	  navigate('/login', { replace: true })
	} catch (err: any) {
	  setError(err.message)
	}
  }

  if (loading) return <div className="loading">正在读取冲突证据…</div>

  return (
    <div className="page conflict-page">
      <div className="card conflict-card">
        <div className="brand">
          <h1>副本冲突已冻结</h1>
          <p>系统不会自动覆盖任一份数据。证据准备完成前，请勿在节点上手工改动文件。</p>
        </div>
        {error && <div className="error-msg">{error}</div>}
        {conflict && <>
          <div className="warning-msg">
            检测时间：{new Date(conflict.detected_at).toLocaleString()}。普通登录、改密和节点写入保持关闭；此页面只有冲突恢复权限。
          </div>
          <div className="conflict-sources">
            {conflict.sources.map(source => (
              <div className="conflict-source" key={source.node_id}>
                <div>
                  <strong>{source.node_name}</strong>
                  {source.is_authoritative && <span className="badge yellow">检测时家节点</span>}
                </div>
                <small>{source.node_role === 'storage' ? '纯存储副本' : source.source_kind === 'hot_standby' ? '计算热备' : '计算活动副本'}</small>
                <div className={source.evidence_state === 'ready' ? 'evidence-ready' : source.evidence_state === 'failed' ? 'evidence-failed' : 'evidence-pending'}>
                  {evidenceLabel[source.evidence_state] || source.evidence_state}
                </div>
                {source.evidence_state === 'ready' && <small>
                  {source.file_count ?? 0} 个文件 · {formatBytes(source.total_bytes)} · {source.capture_basis === 'verified_archive' ? '已复核原归档' : '冻结时现场捕获'}
                </small>}
              </div>
            ))}
          </div>

          {conflict.inspection_state === 'capture_required' && <div className="loading">正在逐文件计算摘要并加密汇总，请稍候…</div>}
          {conflict.inspection_state === 'evidence_failed' && <div className="error-msg">至少一个节点无法生成可信证据。系统保持冻结，不会用不完整结果继续。</div>}
          {conflict.inspection_state === 'identical' && <div className="success-msg">各来源的文件路径、大小和内容摘要一致，没有检测到文件差异。</div>}

          {(conflict.inspection_state === 'differences_ready' || conflict.inspection_state === 'identical') && !resolution && <div className="conflict-resolution-panel">
            <div className="section-title">选择最终主版本</div>
            <label>最终写入节点</label>
            <select value={baseNodeID} onChange={event => setBaseNodeID(Number(event.target.value))}>
              {conflict.sources.filter(source => source.node_role === 'compute').map(source =>
                <option value={source.node_id} key={source.node_id}>{source.node_name}{source.is_authoritative ? '（检测时家节点）' : ''}</option>)}
            </select>
            <label>未逐项指定的同路径冲突</label>
            <select value={defaultAction} onChange={event => setDefaultAction(event.target.value as 'use_base' | 'preserve_all_originals')}>
              <option value="preserve_all_originals">以主版本为准，并把其他不同内容另存（推荐）</option>
              <option value="use_base">仅使用主版本</option>
            </select>
            <small>不同路径会自动并入。原始冻结证据不会因完成处理而立即删除。</small>
          </div>}

          {differences && differences.total > 0 && <>
            <div className="section-title">可理解差异</div>
            <div className="warning-msg">
              不同路径文件可在后续方案中安全并入；同一路径内容不同时必须选择来源或保留双份。聊天、JSON 和二进制不会被宣称可以自动语义合并。
            </div>
            <div className="conflict-summary">
              <span>不同路径：{differences.only_on_some_sources}</span>
              <span>同路径不同内容：{differences.different_at_same_path}</span>
            </div>
            <div className="conflict-table-wrap">
              <table className="table conflict-table">
                <thead><tr><th>路径</th><th>类型</th><th>差异</th><th>来源</th><th>处理</th></tr></thead>
                <tbody>{differences.files.map(file => <tr key={file.path}>
                  <td className="mono conflict-path">{file.path}</td>
                  <td>{categoryLabel[file.category] || file.category}</td>
                  <td>{file.difference === 'only_on_some_sources' ? '仅部分来源存在，可按路径并入' : '同路径内容不同，必须选择'}</td>
                  <td>{file.sources.map(source => <div key={source.node_id}>
                    {source.node_name}：{source.present ? formatBytes(source.size) : '不存在'}
                  </div>)}</td>
                  <td>{file.difference === 'different_at_same_path' ? <div className="conflict-choice">
                    <select
                      aria-label={`${file.path} 主来源`}
                      value={decisions[file.path]?.source_node_id || (file.sources.some(source => source.node_id === baseNodeID && source.present) ? baseNodeID : file.sources.find(source => source.present)?.node_id || 0)}
                      onChange={event => updateDecision(file.path, Number(event.target.value), decisions[file.path]?.action === 'preserve_both')}
                    >
                      {file.sources.filter(source => source.present).map(source => <option value={source.node_id} key={source.node_id}>{source.node_name}</option>)}
                    </select>
                    <label className="inline-check">
                      <input type="checkbox" checked={decisions[file.path]?.action === 'preserve_both'} onChange={event => {
                        const selected = decisions[file.path]?.source_node_id || (file.sources.some(source => source.node_id === baseNodeID && source.present) ? baseNodeID : file.sources.find(source => source.present)?.node_id || 0)
                        updateDecision(file.path, selected, event.target.checked)
                      }} /> 保留其他不同内容
                    </label>
                    {!decisions[file.path] && <small>当前沿用上方默认策略</small>}
                  </div> : '自动并入'}</td>
                </tr>)}</tbody>
              </table>
            </div>
            <div className="conflict-pagination">
              <button className="btn-sm" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - pageSize))}>上一页</button>
              <span>{offset + 1}–{Math.min(offset + pageSize, differences.total)} / {differences.total}</span>
              <button className="btn-sm" disabled={offset + pageSize >= differences.total} onClick={() => setOffset(offset + pageSize)}>下一页</button>
            </div>
          </>}
          {!resolution && (conflict.inspection_state === 'differences_ready' || conflict.inspection_state === 'identical') && <button className="btn primary conflict-submit" disabled={submitting || baseNodeID <= 0} onClick={submitResolution}>
            {submitting ? '正在安全排队…' : '确认选择并开始处理'}
          </button>}
          {resolution && <div className={resolution.state === 'failed' ? 'error-msg' : 'warning-msg'}>
            {resolution.state === 'preparing' && '正在把所有不可变原始证据汇集到主计算节点…'}
            {resolution.state === 'publishing' && '正在逐文件校验并原子发布结果…'}
            {resolution.state === 'retrying' && '节点暂时不可用，系统正在使用原任务自动重试…'}
            {resolution.state === 'failed' && `自动处理未能收敛：${resolution.error || '原始证据仍保持冻结，请稍后重试。'}`}
            {resolution.state === 'succeeded' && '冲突已处理完成。请重新登录。'}
          </div>}
          {resolution?.state === 'failed' && <button className="btn primary conflict-submit" disabled={submitting} onClick={retryResolution}>
            {submitting ? '正在重新排队…' : '使用原始冻结证据重试'}
          </button>}
          <button className="btn secondary conflict-logout" onClick={logout}>退出冲突恢复</button>
        </>}
      </div>
    </div>
  )
}
