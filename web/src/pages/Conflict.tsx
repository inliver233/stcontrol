import { useCallback, useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api, ConflictDifferences, ReplicaConflict } from '../api'

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
  const navigate = useNavigate()

  const loadConflict = useCallback(async () => {
    try {
      const current = await api.conflict()
      setConflict(current)
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
                <thead><tr><th>路径</th><th>类型</th><th>差异</th><th>来源</th></tr></thead>
                <tbody>{differences.files.map(file => <tr key={file.path}>
                  <td className="mono conflict-path">{file.path}</td>
                  <td>{categoryLabel[file.category] || file.category}</td>
                  <td>{file.difference === 'only_on_some_sources' ? '仅部分来源存在，可按路径并入' : '同路径内容不同，必须选择'}</td>
                  <td>{file.sources.map(source => <div key={source.node_id}>
                    {source.node_name}：{source.present ? formatBytes(source.size) : '不存在'}
                  </div>)}</td>
                </tr>)}</tbody>
              </table>
            </div>
            <div className="conflict-pagination">
              <button className="btn-sm" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - pageSize))}>上一页</button>
              <span>{offset + 1}–{Math.min(offset + pageSize, differences.total)} / {differences.total}</span>
              <button className="btn-sm" disabled={offset + pageSize >= differences.total} onClick={() => setOffset(offset + pageSize)}>下一页</button>
            </div>
          </>}
          <button className="btn secondary conflict-logout" onClick={logout}>退出冲突恢复</button>
        </>}
      </div>
    </div>
  )
}
