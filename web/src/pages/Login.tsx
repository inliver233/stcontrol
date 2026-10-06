import { useEffect, useState } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { api, type ApiError, type PasskeyLoginConfig } from '../api'
import { useAuth } from '../App'
import DcNotice from '../components/DcNotice'
import { describePasskeyError, forgetPasskey, getPasskey, isPasskeySupported } from '../webauthn'
import PasskeyIcon from '../components/PasskeyIcon'

// Only same-site paths, so a crafted link cannot send a fresh session elsewhere.
function safeNext(value: string | null): string {
  return value && value.startsWith('/') && !value.startsWith('//') && !value.startsWith('/\\') ? value : '/'
}

export default function LoginPage() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [passkey, setPasskey] = useState<PasskeyLoginConfig | null>(null)
  const [passkeyBusy, setPasskeyBusy] = useState(false)
  const { refresh } = useAuth()
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()
  const next = safeNext(searchParams.get('next'))

  useEffect(() => {
    if (!isPasskeySupported()) return
    let cancelled = false
    api.passkeyLoginConfig()
      .then(config => { if (!cancelled && config.login_enabled) setPasskey(config) })
      .catch(() => undefined)
    return () => { cancelled = true }
  }, [])

  const enter = async (recoveryRequired: boolean) => {
    if (recoveryRequired) {
      navigate('/conflict', { replace: true })
      return
    }
    await refresh()
    navigate(next)
  }

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setBusy(true)
    try {
      const result = await api.login({ username, password })
      await enter(result.recovery_required)
    } catch (err: any) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  const passkeyLogin = async () => {
    setError('')
    setPasskeyBusy(true)
    let credentialID = ''
    try {
      const ceremony = await api.passkeyLoginOptions()
      let credential: { id: string }
      try {
        credential = await getPasskey(ceremony.options.publicKey)
      } catch (err) {
        const message = describePasskeyError(err, 'get')
        if (message) setError(message)
        return
      }
      credentialID = credential.id
      const result = await api.passkeyLoginVerify(ceremony.ceremony_id, credential)
      await enter(result.recovery_required)
    } catch (err) {
      const apiError = err as ApiError
      const code = (apiError.data as { code?: string } | undefined)?.code
      if (code === 'unknown_credential' && passkey?.rp_id && credentialID) {
        forgetPasskey(passkey.rp_id, credentialID)
      }
      setError(apiError.message || '通行密钥登录失败，请再试一次。')
    } finally {
      setPasskeyBusy(false)
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
        <DcNotice />
        {error && <div className="error-msg" role="alert">{error}</div>}
        {passkey && (
          <div className="passkey-login">
            <button className="btn passkey-btn" type="button" onClick={passkeyLogin} disabled={passkeyBusy || busy}>
              <PasskeyIcon />
              {passkeyBusy ? '请在设备上确认…' : passkey.button_text}
            </button>
            {passkey.hint_text && <div className="passkey-hint">{passkey.hint_text}</div>}
            <div className="passkey-divider">或使用账号密码</div>
          </div>
        )}
        <form onSubmit={submit}>
          <div className="field">
            <label>用户名</label>
            <input value={username} onChange={e => setUsername(e.target.value)} required autoFocus={!passkey} autoComplete="username" />
          </div>
          <div className="field">
            <label>密码</label>
            <input type="password" value={password} onChange={e => setPassword(e.target.value)} required autoComplete="current-password" />
          </div>
          <button className="btn" type="submit" disabled={busy || passkeyBusy}>
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
