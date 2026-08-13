import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it, vi } from 'vitest'

import { BackupJobRow, backupWorkflowStateLabel, StatusBadge } from './Admin'

describe('backup workflow presentation', () => {
  it('labels every durable snapshot phase deterministically', () => {
    expect([
      'scheduled', 'quiescing', 'drained', 'snapshotting', 'transferring',
      'verifying', 'publishing', 'retry_wait', 'succeeded', 'cancelled', 'failed',
    ].map(backupWorkflowStateLabel)).toEqual([
      '等待调度', '排空写入', '已排空', '生成快照', '传输中',
      '校验中', '原子发布', '等待重试', '已完成', '已取消', '失败',
    ])
  })

  it('renders retry, cleanup and safe reason facts from the backend', () => {
    const html = renderToStaticMarkup(
      <table><tbody><BackupJobRow job={{
        ID: 17,
        UserID: 7,
        SrcNodeID: 1,
        DstNodeID: 2,
        Trigger: 'offline',
        Status: 'running',
        workflow_state: 'retry_wait',
        attempt: 2,
        next_attempt_at: '2026-08-09T12:30:00Z',
        cleanup_state: 'not_required',
        error_code: 'target_unavailable',
        error_summary: '目标节点暂不可用',
        can_abort: true,
      }} onAbort={vi.fn()} /></tbody></table>,
    )
    expect(html).toContain('等待重试')
    expect(html).toContain('第 2 次重试')
    expect(html).toContain('无需清理')
    expect(html).toContain('目标节点暂不可用')
    expect(html).toContain('>中止</button>')
  })

  it('never infers abortability from the legacy running status', () => {
    const html = renderToStaticMarkup(
      <table><tbody><BackupJobRow job={{
        ID: 18,
        UserID: 7,
        SrcNodeID: 1,
        DstNodeID: 2,
        Trigger: 'offline',
        Status: 'running',
        workflow_state: 'succeeded',
        cleanup_state: 'succeeded',
        can_abort: false,
      }} onAbort={vi.fn()} /></tbody></table>,
    )
    expect(html).toContain('已完成')
    expect(html).toContain('已清理')
    expect(html).not.toContain('>中止</button>')
  })

  it('disables duplicate abort submissions while one is in flight', () => {
    const html = renderToStaticMarkup(
      <table><tbody><BackupJobRow job={{
        ID: 19,
        Status: 'pending',
        workflow_state: 'scheduled',
        can_abort: true,
      }} aborting onAbort={vi.fn()} /></tbody></table>,
    )
    expect(html).toContain('disabled=""')
    expect(html).toContain('中止中…')
  })
})

describe('node composite status presentation', () => {
  const labels: Record<string, string> = {
    online: '在线', offline: '离线', unknown: '未知', active: '运营', maintenance: '维护',
    draining: '排空', decommissioned: '已下线', failed: '故障', retired: '退役',
    open: '开放', busy: '繁忙', full: '满载', compatible: '兼容', incompatible: '不兼容',
  }
  const hl = (v: string) => labels[v] || v
  const rl = (v: string) => v

  const cases: Array<[any, string]> = [
    [{ operational_state: 'retired', connectivity_state: 'offline' }, '已退役'],
    [{ operational_state: 'decommissioned' }, '已退役'],
    [{ operational_state: 'maintenance', connectivity_state: 'online' }, '维护'],
    [{ operational_state: 'draining' }, '排空中'],
    [{ operational_state: 'failed' }, '故障'],
    [{ operational_state: 'active', connectivity_state: 'offline', capacity_state: 'open', compatibility_state: 'compatible' }, '离线'],
    [{ operational_state: 'active', connectivity_state: 'online', compatibility_state: 'incompatible', capacity_state: 'open' }, '不兼容'],
    [{ operational_state: 'active', connectivity_state: 'online', compatibility_state: 'compatible', capacity_state: 'full' }, '已满'],
    [{ operational_state: 'active', connectivity_state: 'online', compatibility_state: 'compatible', capacity_state: 'busy' }, '繁忙'],
    [{ operational_state: 'active', connectivity_state: 'online', compatibility_state: 'compatible', capacity_state: 'open' }, '可用'],
  ]

  it.each(cases)('compositeStatus priority %# -> %s', (node, expected) => {
    const html = renderToStaticMarkup(<StatusBadge node={node} healthLabel={hl} reasonLabel={rl} />)
    expect(html).toContain(expected)
  })

  it('shows stale capacity/compatibility notes while offline', () => {
    const html = renderToStaticMarkup(<StatusBadge node={{
      operational_state: 'active', connectivity_state: 'offline', capacity_state: 'open', compatibility_state: 'compatible',
    }} healthLabel={hl} reasonLabel={rl} />)
    expect(html).toContain('最后上报')
    expect(html).toContain('最后检测')
  })

  it('keeps dimensions visible in a healthy online node', () => {
    const html = renderToStaticMarkup(<StatusBadge node={{
      operational_state: 'active', connectivity_state: 'online', capacity_state: 'open', compatibility_state: 'compatible',
    }} healthLabel={hl} reasonLabel={rl} />)
    expect(html).toContain('连通性：在线')
    expect(html).toContain('运营：运营')
    expect(html).toContain('容量：开放')
    expect(html).toContain('兼容：兼容')
    expect(html).not.toContain('最后上报')
  })
})

