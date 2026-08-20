import { describe, expect, it } from 'vitest'

import type { AdminNode } from '../adminTypes'
import { filterAdminNodes } from './Admin'

const node = (overrides: Partial<AdminNode>): AdminNode => ({
  id: 1,
  name: '默认节点',
  role: 'compute',
  base_url: 'https://node.example',
  region: { String: 'east-asia', Valid: true },
  status: 'online',
  connectivity_state: 'online',
  operational_state: 'active',
  control_mode: 'managed',
  desired_control_mode: 'managed',
  capacity_state: 'open',
  capacity_reason_code: { String: '', Valid: false },
  compatibility_state: 'compatible',
  compatibility_reason_code: { String: '', Valid: false },
  cpu_window_avg: { Float64: 0, Valid: false },
  cpu_window_peak: { Float64: 0, Valid: false },
  mem_window_avg: { Float64: 0, Valid: false },
  mem_window_peak: { Float64: 0, Valid: false },
  disk_window_avg: { Float64: 0, Valid: false },
  disk_window_peak: { Float64: 0, Valid: false },
  disk_available_bytes: { Int64: 0, Valid: false },
  disk_quota_bytes: { Int64: 0, Valid: false },
  allocated_disk_bytes: { Int64: 0, Valid: false },
  expected_disk_quota_bytes: 0,
  quota_sync_state: 'unknown',
  online_users: 0,
  task_queue_depth: 0,
  tavern_version: { String: '', Valid: false },
  allow_register: false,
  is_backup_target: false,
  recommendation_weight: 0,
  ...overrides,
})

describe('admin node filters', () => {
  const nodes = [
    node({ id: 1, name: '香港计算', role: 'compute' }),
    node({ id: 2, name: '东京存储', role: 'storage', base_url: 'https://storage.example', connectivity_state: 'offline', operational_state: 'maintenance' }),
  ]

  it('combines keyword, role and any of the four backend state dimensions', () => {
    expect(filterAdminNodes(nodes, '东京', 'storage', 'offline')).toEqual([nodes[1]])
    expect(filterAdminNodes(nodes, 'storage.example', '', 'maintenance')).toEqual([nodes[1]])
    expect(filterAdminNodes(nodes, '', 'compute', 'open')).toEqual([nodes[0]])
  })

  it('supports IDs and regions and returns no false matches', () => {
    expect(filterAdminNodes(nodes, '2', '', '')).toEqual([nodes[1]])
    expect(filterAdminNodes(nodes, 'EAST-ASIA', '', '')).toHaveLength(2)
    expect(filterAdminNodes(nodes, 'missing', '', '')).toEqual([])
  })
})
