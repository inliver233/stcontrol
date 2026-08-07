import { useState } from 'react'
import { Link, Navigate, useNavigate } from 'react-router-dom'
import { api } from '../api'
import { useAuth } from '../App'

export default function AdminLoginPage() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const { me, refresh } = useAuth()
  const navigate = useNavigate()

  if (me?.is_admin) return <Navigate to="/admin" replace />

  const submit = async (event: React.FormEvent) => {
    event.preventDefault()
    setError('')
    setBusy(true)
    try {
      await api.adminLogin({ username, password })
      await refresh()
      navigate('/admin', { replace: true })
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : '管理员登录失败')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="page">
      <div className="card">
        <div className="brand"><h1>总控管理</h1><p>使用独立管理员账号登录</p></div>
        {error && <div className="error-msg">{error}</div>}
        <form onSubmit={submit}>
          <div className="field"><label>管理员用户名</label><input value={username} onChange={e => setUsername(e.target.value)} required autoFocus /></div>
          <div className="field"><label>密码</label><input type="password" value={password} onChange={e => setPassword(e.target.value)} minLength={12} required /></div>
          <button className="btn" type="submit" disabled={busy}>{busy ? '登录中…' : '管理员登录'}</button>
        </form>
        <div className="link-row"><Link to="/login">返回用户登录</Link></div>
      </div>
    </div>
  )
}
