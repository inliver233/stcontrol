import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it, vi } from 'vitest'

import { BackupJobRow, backupWorkflowStateLabel } from './Admin'

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
