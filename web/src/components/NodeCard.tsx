import { Node } from '../api'

export function badgeClass(label: string): string {
  switch (label) {
    case '空闲': return 'green'
    case '满员': return 'yellow'
    case '宕机': return 'red'
    default: return 'gray'
  }
}

function latencyClass(ms?: number): string {
  if (ms === undefined || ms < 0) return ''
  if (ms < 100) return 'fast'
  if (ms < 250) return 'mid'
  return 'slow'
}

function latencyText(ms?: number): string {
  if (ms === undefined) return '测速中…'
  if (ms < 0) return '不可达'
  return `${ms}ms`
}

function barClass(pct: number): string {
  if (pct >= 80) return 'danger'
  if (pct >= 50) return 'warn'
  return ''
}

export function NodeCard({ node, selected, onSelect }: {
  node: Node
  selected: boolean
  onSelect: () => void
}) {
  const cls = [
    'node-card',
    node.registrable ? 'selectable' : 'disabled',
    selected ? 'selected' : '',
  ].join(' ')

  return (
    <div className={cls} onClick={onSelect}>
      <div className="node-name">{node.name}</div>
      <div className="node-region">{node.region || '默认区域'}</div>
      <div className="node-meta">
        <span className={`badge ${badgeClass(node.status_label)}`}>{node.status_label}</span>
        {node.invitation_required && <span className="badge gray">需邀请码</span>}
        <span className={`latency ${latencyClass(node.latency_ms)}`}>{latencyText(node.latency_ms)}</span>
      </div>
      <div className="load-bars">
        <LoadBar label="CPU" pct={node.cpu_pct} />
        <LoadBar label="内存" pct={node.mem_pct} />
        <LoadBar label="硬盘" pct={node.disk_pct} />
      </div>
    </div>
  )
}

function LoadBar({ label, pct }: { label: string; pct: number }) {
  const v = Math.round(pct || 0)
  return (
    <div className="load-bar">
      <span style={{ width: 30 }}>{label}</span>
      <div className="bar"><div className={barClass(v)} style={{ width: `${Math.min(v, 100)}%` }} /></div>
      <span style={{ width: 34, textAlign: 'right' }}>{v}%</span>
    </div>
  )
}
