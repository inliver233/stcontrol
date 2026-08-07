import { Node } from '../api'

export function badgeClass(label: string): string {
  switch (label) {
    case '开放': return 'green'
    case '繁忙': return 'yellow'
    case '满载': return 'yellow'
    case '故障': return 'red'
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
        {node.recommended && <span className="badge green">推荐</span>}
        {node.invitation_required && <span className="badge gray">需邀请码</span>}
        <span className={`latency ${latencyClass(node.latency_ms)}`}>{latencyText(node.latency_ms)}</span>
      </div>
    </div>
  )
}
