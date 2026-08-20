import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { api, AccountImportClaim, AuthIdentity, ProtectionState } from '../api'

const providerLabel: Record<string, string> = {
  password: '账号密码', discord: 'Discord', linuxdo: 'LinuxDo',
}

export const importClaimKey = (claim: AccountImportClaim) => `${claim.node_id}:${claim.local_handle}`

export function filterImportClaims(claims: AccountImportClaim[], query: string): AccountImportClaim[] {
  const normalized = query.trim().toLocaleLowerCase()
  if (!normalized) return claims
  return claims.filter(claim => [claim.node_name, claim.local_handle, String(claim.node_id)]
    .some(value => value.toLocaleLowerCase().includes(normalized)))
}

export function ImportClaimsPanel({
  claims, query, passwords, claimingKey, onQueryChange, onPasswordChange, onClaim,
}: {
  claims: AccountImportClaim[]
  query: string
  passwords: Record<string, string>
  claimingKey: string | null
  onQueryChange: (value: string) => void
  onPasswordChange: (claim: AccountImportClaim, value: string) => void
  onClaim: (claim: AccountImportClaim) => void
}) {
  const visibleClaims = filterImportClaims(claims, query)
  return (
    <section className="claim-section" aria-labelledby="import-claims-title">
      <div className="section-title" id="import-claims-title">旧账号候选合并</div>
      {claims.length === 0 ? (
        <div className="empty-state">当前没有待认领的同名旧账号。</div>
      ) : (
        <>
          <div className="warning-msg" role="note">
            同名账号不会自动合并。请输入该节点原密码证明控制权；验证只在目标节点内完成，密码不会写入总控数据库。
          </div>
          <div className="field claim-filter">
            <label htmlFor="claim-filter">筛选节点或本地账号</label>
            <input
              id="claim-filter"
              type="search"
              value={query}
              onChange={event => onQueryChange(event.target.value)}
              placeholder="输入节点名、账号或节点 ID"
            />
          </div>
          {visibleClaims.length === 0 ? (
            <div className="empty-state">没有匹配的候选账号。</div>
          ) : visibleClaims.map(claim => {
            const key = importClaimKey(claim)
            const isClaiming = claimingKey === key
            return (
              <form className="my-node claim-row" key={key} onSubmit={event => { event.preventDefault(); onClaim(claim) }}>
                <div className="info">
                  <div className="name">{claim.node_name}</div>
                  <div className="sub">本地账号：{claim.local_handle} · {claim.account_kind === 'mixed' ? '密码 / OAuth 混合账号' : '密码账号'}</div>
                  <div className="sub">验证成功后关联到当前全局 UUID，不覆盖节点数据。</div>
                </div>
                <div className="claim-actions">
                  <input
                    aria-label={`${claim.node_name} 原密码`}
                    autoComplete="current-password"
                    type="password"
                    value={passwords[key] || ''}
                    onChange={event => onPasswordChange(claim, event.target.value)}
                    required
                  />
                  <button className="btn-sm primary" type="submit" disabled={claimingKey !== null || !passwords[key]}>
                    {isClaiming ? '验证中…' : '验证并认领'}
                  </button>
                </div>
              </form>
            )
          })}
        </>
      )}
    </section>
  )
}

export default function AccountPage() {
  const [identities, setIdentities] = useState<AuthIdentity[]>([])
  const [canUnbind, setCanUnbind] = useState(false)
  const [loading, setLoading] = useState(true)
  const [loadFailed, setLoadFailed] = useState(false)
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [oldPassword, setOldPassword] = useState('')
  const [changedPassword, setChangedPassword] = useState('')
  const [claims, setClaims] = useState<AccountImportClaim[]>([])
  const [claimPasswords, setClaimPasswords] = useState<Record<string, string>>({})
  const [claimQuery, setClaimQuery] = useState('')
  const [claimingKey, setClaimingKey] = useState<string | null>(null)
  const claimOperations = useRef<Record<string, string>>({})
  const [protection, setProtection] = useState<ProtectionState | null>(null)

  const load = async () => {
    setError('')
    try {
      const [result, imported, protectionState] = await Promise.all([
        api.identities(), api.importClaims(), api.protection().catch(() => null),
      ])
      setIdentities(result.identities ?? [])
      setCanUnbind(result.can_unbind)
      setClaims(imported.claims ?? [])
      setProtection(protectionState)
      setLoadFailed(false)
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : '加载登录方式失败')
      setLoadFailed(true)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])
  const linked = new Set(identities.map(identity => identity.provider))

  const bindOAuth = async (provider: 'discord' | 'linuxdo') => {
    setError('')
    try {
      const result = await api.beginOAuthBinding(provider)
      window.location.assign(result.authorization_url)
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : '发起绑定失败')
    }
  }

  const bindPassword = async (event: React.FormEvent) => {
    event.preventDefault()
    setError('')
    try {
      const result = await api.bindPassword(newPassword)
      setNewPassword('')
      setMessage(result.node_sync === 'active' ? '密码登录已绑定并同步到节点' : '密码登录已绑定，节点同步将在后台重试')
      await load()
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : '绑定密码失败')
    }
  }

  const changePassword = async (event: React.FormEvent) => {
    event.preventDefault()
    setError('')
    try {
      const result = await api.changePassword(oldPassword, changedPassword)
      setOldPassword('')
      setChangedPassword('')
      setMessage(result.node_sync === 'active' ? '密码已更新并同步到节点' : '密码已更新，节点同步将在后台重试')
      await load()
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : '修改密码失败')
    }
  }

  const unbind = async (provider: string) => {
    if (!window.confirm(`确认解绑 ${providerLabel[provider] || provider}？`)) return
    setError('')
    try {
      await api.unbindIdentity(provider)
      setMessage('登录方式已解绑')
      await load()
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : '解绑失败')
    }
  }

  const claimImportedAccount = async (claim: AccountImportClaim) => {
    const key = importClaimKey(claim)
    const password = claimPasswords[key] || ''
    if (!password) return
    setError('')
    setMessage('')
    setClaimingKey(key)
    const operationID = claimOperations.current[key] || crypto.randomUUID()
    claimOperations.current[key] = operationID
    try {
      await api.claimImportedAccount(claim.node_id, password, operationID)
      delete claimOperations.current[key]
      setClaimPasswords(current => ({ ...current, [key]: '' }))
      setMessage(`已安全认领 ${claim.node_name} 上的原账号；系统不会覆盖该节点的数据`)
      await load()
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : '节点账号认领失败')
    } finally {
      setClaimingKey(null)
    }
  }

  const changeClaimPassword = (claim: AccountImportClaim, value: string) => {
    const key = importClaimKey(claim)
    delete claimOperations.current[key]
    setClaimPasswords(current => ({ ...current, [key]: value }))
  }

  return (
    <div className="page">
      <div className="card wide">
        <div className="brand"><h1>账号安全</h1><p>最多绑定密码、Discord、LinuxDo 三种登录方式，且必须至少保留一种</p></div>
        {!loading && protection && (
          <div className={protection.state === 'protected' ? 'success-msg' : protection.state === 'conflict' || protection.state === 'unavailable' ? 'error-msg' : 'warning-msg'} style={{ marginBottom: 12 }}>
            <strong>数据保护：{protection.label}</strong><br />{protection.risk}
          </div>
        )}
        {!loading && protection?.state === 'unprotected' && (
          <div className="warning-msg" style={{ marginBottom: 12 }}>
            当前还没有可用的备份副本。你仍可正常使用；系统会在检测到合格备份目标后自动为你建立首次同步保护。
          </div>
        )}
        {error && <div className="error-msg" role="alert">{error}</div>}
        {message && <div className="success-msg" role="status">{message}</div>}
        {loading ? <div className="loading" role="status">加载中…</div> : loadFailed ? (
          <div className="empty-state">
            <p>账号资料未能完整加载，为避免误操作已暂停编辑。</p>
            <button className="btn-sm primary" type="button" onClick={() => { setLoading(true); void load() }}>重试加载</button>
          </div>
        ) : (
          <>
            <div className="section-title">已绑定登录方式</div>
            {identities.map(identity => (
              <div className="my-node" key={identity.provider}>
                <div className="info"><div className="name">{providerLabel[identity.provider]}</div><div className="sub">已绑定 · {new Date(identity.created_at).toLocaleDateString()}</div></div>
                <button className="btn-sm danger" disabled={!canUnbind} onClick={() => unbind(identity.provider)}>解绑</button>
              </div>
            ))}
            <div className="section-title">添加登录方式</div>
            <div style={{ display: 'flex', gap: 10, marginBottom: 20 }}>
              {!linked.has('discord') && <button className="btn secondary" onClick={() => bindOAuth('discord')}>绑定 Discord</button>}
              {!linked.has('linuxdo') && <button className="btn secondary" onClick={() => bindOAuth('linuxdo')}>绑定 LinuxDo</button>}
            </div>
            {!linked.has('password') ? (
              <form onSubmit={bindPassword}>
                <div className="field"><label>设置密码登录（至少 8 位）</label><input type="password" minLength={8} value={newPassword} onChange={e => setNewPassword(e.target.value)} required /></div>
                <button className="btn" type="submit">绑定密码登录</button>
              </form>
            ) : (
              <form onSubmit={changePassword}>
                <div className="section-title">修改密码</div>
                <div className="field"><label>原密码</label><input type="password" value={oldPassword} onChange={e => setOldPassword(e.target.value)} required /></div>
                <div className="field"><label>新密码</label><input type="password" minLength={8} value={changedPassword} onChange={e => setChangedPassword(e.target.value)} required /></div>
                <button className="btn" type="submit">更新密码</button>
              </form>
            )}
            <ImportClaimsPanel
              claims={claims}
              query={claimQuery}
              passwords={claimPasswords}
              claimingKey={claimingKey}
              onQueryChange={setClaimQuery}
              onPasswordChange={changeClaimPassword}
              onClaim={claimImportedAccount}
            />
          </>
        )}
        <div className="link-row"><Link to="/">返回节点选择</Link></div>
      </div>
    </div>
  )
}
