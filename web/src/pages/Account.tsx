import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api, AccountImportClaim, AuthIdentity } from '../api'

const providerLabel: Record<string, string> = {
  password: '账号密码', discord: 'Discord', linuxdo: 'LinuxDo',
}

export default function AccountPage() {
  const [identities, setIdentities] = useState<AuthIdentity[]>([])
  const [canUnbind, setCanUnbind] = useState(false)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [oldPassword, setOldPassword] = useState('')
  const [changedPassword, setChangedPassword] = useState('')
  const [claims, setClaims] = useState<AccountImportClaim[]>([])
  const [claimPasswords, setClaimPasswords] = useState<Record<number, string>>({})
  const [claimingNode, setClaimingNode] = useState<number | null>(null)

  const load = async () => {
    try {
      const [result, imported] = await Promise.all([api.identities(), api.importClaims()])
      setIdentities(result.identities)
      setCanUnbind(result.can_unbind)
      setClaims(imported.claims)
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : '加载登录方式失败')
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
    const password = claimPasswords[claim.node_id] || ''
    if (!password) return
    setError('')
    setClaimingNode(claim.node_id)
    try {
      await api.claimImportedAccount(claim.node_id, password, crypto.randomUUID())
      setClaimPasswords(current => ({ ...current, [claim.node_id]: '' }))
      setMessage(`已安全认领 ${claim.node_name} 上的原账号；系统不会覆盖该节点的数据`)
      await load()
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : '节点账号认领失败')
    } finally {
      setClaimingNode(null)
    }
  }

  return (
    <div className="page">
      <div className="card wide">
        <div className="brand"><h1>账号安全</h1><p>最多绑定密码、Discord、LinuxDo 三种登录方式，且必须至少保留一种</p></div>
        {error && <div className="error-msg">{error}</div>}
        {message && <div className="success-msg">{message}</div>}
        {loading ? <div className="loading">加载中…</div> : (
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
            {claims.length > 0 && (
              <>
                <div className="section-title">认领旧节点账号</div>
                <div className="warning-msg">同名账号不会自动合并。请输入该节点原密码证明控制权；验证只在目标节点内完成，密码不会写入总控数据库。</div>
                {claims.map(claim => (
                  <div className="my-node" key={claim.node_id}>
                    <div className="info">
                      <div className="name">{claim.node_name}</div>
                      <div className="sub">本地账号：{claim.local_handle}</div>
                    </div>
                    <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                      <input
                        aria-label={`${claim.node_name} 原密码`}
                        type="password"
                        value={claimPasswords[claim.node_id] || ''}
                        onChange={event => setClaimPasswords(current => ({ ...current, [claim.node_id]: event.target.value }))}
                      />
                      <button className="btn-sm primary" disabled={claimingNode !== null} onClick={() => claimImportedAccount(claim)}>
                        {claimingNode === claim.node_id ? '验证中…' : '验证并认领'}
                      </button>
                    </div>
                  </div>
                ))}
              </>
            )}
          </>
        )}
        <div className="link-row"><Link to="/">返回节点选择</Link></div>
      </div>
    </div>
  )
}
