import { useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api'
import { addPasskey } from '../passkeys'
import { isPasskeySupported } from '../webauthn'

const SNOOZE_KEY = 'stcontrol-passkey-prompt-snoozed-until'
const SNOOZE_MS = 30 * 24 * 60 * 60 * 1000

function snoozed(): boolean {
  try {
    return Number(window.localStorage.getItem(SNOOZE_KEY) || 0) > Date.now()
  } catch {
    return false
  }
}

function snooze() {
  try {
    window.localStorage.setItem(SNOOZE_KEY, String(Date.now() + SNOOZE_MS))
  } catch {
    // 无痕模式等情况下只在本次跳过。
  }
}

/** 是否该提示添加通行密钥：功能已开启、这台浏览器支持、账号还没有、近 30 天没有跳过。 */
export async function shouldPromptPasskey(): Promise<boolean> {
  if (!isPasskeySupported() || snoozed()) return false
  try {
    const data = await api.myPasskeys()
    return data.available && data.allow_registration && data.passkeys.length === 0
  } catch {
    return false
  }
}

// 节点页上的提示：添加成功或跳过后调用 onFinish（节点页据此继续自动进入酒馆）。
export default function PasskeyPrompt({ onFinish, entering }: { onFinish: (added: boolean) => void; entering: boolean }) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [added, setAdded] = useState(false)

  if (added) {
    return <div className="success-msg passkey-prompt" role="status">已添加通行密钥，下次登录点「通行密钥登录」即可。{entering && '正在进入酒馆…'}</div>
  }

  const add = async () => {
    setError('')
    setBusy(true)
    try {
      if (await addPasskey()) {
        setAdded(true)
        // Going on into the tavern: leave the confirmation up for a moment first.
        if (entering) window.setTimeout(() => onFinish(true), 1200)
      }
    } catch (err: any) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  const skip = () => {
    snooze()
    onFinish(false)
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
        <button className="btn-sm" type="button" onClick={skip} disabled={busy}>{entering ? '跳过，进入酒馆' : '跳过'}</button>
      </div>
    </div>
  )
}
