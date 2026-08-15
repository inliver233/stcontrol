import { describe, expect, it } from 'vitest'

import { classifyConflictResolutionPollError, conflictRefreshIntervalMs } from './Conflict'

describe('conflict page polling helpers', () => {
  it('keeps polling a failed evidence capture so durable rearm can recover the page', () => {
    expect(conflictRefreshIntervalMs('capture_required')).toBe(3000)
    expect(conflictRefreshIntervalMs('evidence_failed')).toBe(30000)
    expect(conflictRefreshIntervalMs('differences_ready')).toBeNull()
    expect(conflictRefreshIntervalMs('identical')).toBeNull()
  })

  it('only redirects to login for auth loss, not 404 or transient server errors', () => {
    expect(classifyConflictResolutionPollError({ status: 401 })).toBe('redirect_login')
    expect(classifyConflictResolutionPollError({ status: 403 })).toBe('redirect_login')
    expect(classifyConflictResolutionPollError({ status: 404 })).toBe('continue_polling')
    expect(classifyConflictResolutionPollError({ status: 503 })).toBe('continue_polling')
    expect(classifyConflictResolutionPollError(new Error('network'))).toBe('continue_polling')
  })

  it('stops polling only when a 4xx explicitly reports a terminal workflow state', () => {
    expect(classifyConflictResolutionPollError({ status: 409, data: { state: 'failed' } })).toBe('stop_with_error')
    expect(classifyConflictResolutionPollError({ status: 410, data: { state: 'cancelled' } })).toBe('stop_with_error')
    expect(classifyConflictResolutionPollError({ status: 409, data: { state: 'retrying' } })).toBe('continue_polling')
  })
})
