import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api'
import { addPasskey } from '../passkeys'
import { isPasskeySupported } from '../webauthn'

const DISMISS_KEY = 'stcontrol-passkey-prompt-dismissed'

function dismissed(): boolean {
  try {
    return window.localStorage.getItem(DISMISS_KEY) === '1'
  } catch {
    return false
  }
}

// 节点页上的提示条：功能已开启、这台浏览器支持、账号还没有通行密钥时，提示添加。
export default function PasskeyPrompt() {
  const [show, setShow] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [added, setAdded] = useState(false)

  useEffect(() => {
    if (!isPasskeySupported() || dismissed()) return
    let cancelled = false
    api.myPasskeys()
      .then(data => {
        if (!cancelled && data.available && data.allow_registration && data.passkeys.length === 0) setShow(true)
      })
      .catch(() => undefined)
    return () => { cancelled = true }
  }, [])

  if (!show) return null
  if (added) {
    return <div className="success-msg passkey-prompt" role="status">已添加通行密钥，下次登录点「通行密钥登录」即可。</div>
  }

  const add = async () => {
    setError('')
    setBusy(true)
    try {
      if (await addPasskey()) setAdded(true)
    } catch (err: any) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  const hide = () => {
    try {
      window.localStorage.setItem(DISMISS_KEY, '1')
    } catch {
      // 无痕模式等情况下只隐藏本次。
    }
    setShow(false)
  }

  return (
    <div className="passkey-prompt" role="region" aria-label="通行密钥">
      <div className="passkey-prompt-text">
        <strong>下次用指纹一键登录</strong>
        <span>添加通行密钥后，不用再输密码或打开 Discord。<Link to="/account#passkeys">了解与管理</Link></span>
      </div>
      {error && <div className="error-msg" role="alert">{error}</div>}
      <div className="passkey-prompt-actions">
        <button className="btn-sm primary" type="button" onClick={add} disabled={busy}>{busy ? '请在设备上确认…' : '添加'}</button>
        <button className="btn-sm" type="button" onClick={hide} disabled={busy}>不再提示</button>
      </div>
    </div>
  )
}
