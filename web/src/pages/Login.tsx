import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { api } from '../api'
import { useAuth } from '../App'

export default function LoginPage() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const { refresh } = useAuth()
  const navigate = useNavigate()

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setBusy(true)
    try {
	  const result = await api.login({ username, password })
	  if (result.recovery_required) {
		navigate('/conflict', { replace: true })
		return
	  }
      await refresh()
      navigate('/')
    } catch (err: any) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  const oauth = (provider: string) => {
    window.location.href = `/api/auth/oauth/${provider}`
  }

  return (
    <div className="page">
      <div className="card">
        <div className="brand">
          <h1>云酒馆</h1>
          <p>登录以进入你的酒馆</p>
        </div>
        {error && <div className="error-msg">{error}</div>}
        <form onSubmit={submit}>
          <div className="field">
            <label>用户名</label>
            <input value={username} onChange={e => setUsername(e.target.value)} required autoFocus />
          </div>
          <div className="field">
            <label>密码</label>
            <input type="password" value={password} onChange={e => setPassword(e.target.value)} required />
          </div>
          <button className="btn" type="submit" disabled={busy}>
            {busy ? '登录中…' : '登 录'}
          </button>
        </form>

        <div style={{ margin: '16px 0', textAlign: 'center', color: 'var(--text-dim)', fontSize: 13 }}>或使用以下方式</div>
        <div style={{ display: 'flex', gap: 10 }}>
          <button className="btn secondary" onClick={() => oauth('discord')}>Discord</button>
          <button className="btn secondary" onClick={() => oauth('linuxdo')}>LinuxDo</button>
        </div>

        <div className="link-row">
          还没有账号？<Link to="/register">立即注册</Link>
        </div>
      </div>
    </div>
  )
}
