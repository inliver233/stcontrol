import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api, AuthIdentity } from '../api'

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

  const load = async () => {
    try {
      const result = await api.identities()
      setIdentities(result.identities)
      setCanUnbind(result.can_unbind)
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
          </>
        )}
        <div className="link-row"><Link to="/">返回节点选择</Link></div>
      </div>
    </div>
  )
}
