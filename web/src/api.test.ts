import { afterEach, describe, expect, it, vi } from 'vitest'

import { measureLatency } from './api'

afterEach(() => {
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('measureLatency', () => {
  it('uses a credential-free CORS request to the public node probe', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 204 }))
    vi.stubGlobal('fetch', fetchMock)

    const latency = await measureLatency('https://node.example/tavern/')

    expect(latency).toBeGreaterThanOrEqual(0)
    expect(fetchMock).toHaveBeenCalledOnce()
    expect(fetchMock).toHaveBeenCalledWith(
      'https://node.example/tavern/api/ping-public',
      expect.objectContaining({
        method: 'GET',
        mode: 'cors',
        credentials: 'omit',
        cache: 'no-store',
      }),
    )
  })

  it('reports an unreachable probe without throwing', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('blocked')))
    await expect(measureLatency('https://node.example')).resolves.toBe(-1)
  })
})
