import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it, vi } from 'vitest'

import type { AccountImportClaim } from '../api'
import { filterImportClaims, ImportClaimsPanel, importClaimKey } from './Account'

const claims: AccountImportClaim[] = [
  { node_id: 7, node_name: '香港节点', local_handle: 'OldAlice', account_kind: 'password' },
  { node_id: 9, node_name: 'Tokyo', local_handle: 'alice-oauth', account_kind: 'mixed' },
]

describe('legacy account claim candidates', () => {
  it('filters candidates by node, handle and numeric node id without mutating input', () => {
    expect(filterImportClaims(claims, ' 香港 ')).toEqual([claims[0]])
    expect(filterImportClaims(claims, 'ALICE-OAUTH')).toEqual([claims[1]])
    expect(filterImportClaims(claims, '7')).toEqual([claims[0]])
    expect(filterImportClaims(claims, '')).toEqual(claims)
    expect(claims).toHaveLength(2)
  })

  it('renders an explicit safe empty state when no claims are pending', () => {
    const html = renderToStaticMarkup(<ImportClaimsPanel
      claims={[]}
      query=""
      passwords={{}}
      claimingKey={null}
      onQueryChange={vi.fn()}
      onPasswordChange={vi.fn()}
      onClaim={vi.fn()}
    />)
    expect(html).toContain('当前没有待认领的同名旧账号')
    expect(html).not.toContain('type="password"')
  })

  it('shows proof boundaries and only matching candidates', () => {
    const key = importClaimKey(claims[1])
    const html = renderToStaticMarkup(<ImportClaimsPanel
      claims={claims}
      query="Tokyo"
      passwords={{ [key]: 'proof-only' }}
      claimingKey={key}
      onQueryChange={vi.fn()}
      onPasswordChange={vi.fn()}
      onClaim={vi.fn()}
    />)
    expect(html).toContain('alice-oauth')
    expect(html).not.toContain('OldAlice')
    expect(html).toContain('不会写入总控数据库')
    expect(html).toContain('不覆盖节点数据')
    expect(html).toContain('验证中…')
    expect(html).toContain('disabled=""')
  })
})
