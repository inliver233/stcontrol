import { useEffect, useRef, useState } from 'react'
import { api, type MyPasskeys, type PasskeyItem } from '../api'
import { addPasskey } from '../passkeys'
import { isPasskeySupported } from '../webauthn'
import PasskeyIcon from './PasskeyIcon'

function formatDate(value?: string) {
  return value ? new Date(value).toLocaleDateString() : ''
}

// 账号页里的「通行密钥」：列表、添加、改名、删除。管理员关闭功能时整块隐藏。
export default function PasskeysPanel() {
  const [data, setData] = useState<MyPasskeys | null>(null)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [busy, setBusy] = useState(false)
  const [editing, setEditing] = useState(0)
  const [editName, setEditName] = useState('')
  const section = useRef<HTMLElement | null>(null)
  const supported = isPasskeySupported()

  const load = async () => {
    try {
      setData(await api.myPasskeys())
    } catch (err: any) {
      setError(err.message)
    }
  }
  useEffect(() => { void load() }, [])
  useEffect(() => {
    if (data?.available && window.location.hash === '#passkeys') {
      section.current?.scrollIntoView({ block: 'start' })
    }
  }, [data?.available])

  if (!data) return error ? <div className="error-msg">{error}</div> : null
  if (!data.available) return null

  const count = data.passkeys.length
  const full = count >= data.max_per_user

  const run = async (action: () => Promise<void>) => {
    setError('')
    setNotice('')
    setBusy(true)
    try {
      await action()
    } catch (err: any) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  const add = () => run(async () => {
    if (await addPasskey()) {
      setNotice('已添加。下次登录时点「通行密钥登录」，按一下指纹或面容就能进来。')
      await load()
    }
  })

  const startRename = (item: PasskeyItem) => {
    setEditing(item.id)
    setEditName(item.name)
  }

  const saveRename = (item: PasskeyItem) => run(async () => {
    await api.renamePasskey(item.id, editName)
    setEditing(0)
    await load()
  })

  const remove = (item: PasskeyItem) => {
    if (!window.confirm(`删除通行密钥「${item.name}」？删除后就不能再用它登录了，其他登录方式不受影响。`)) return
    void run(async () => {
      await api.deletePasskey(item.id)
      setNotice('已删除。')
      await load()
    })
  }

  return (
    <section className="passkey-panel" id="passkeys" ref={section} aria-labelledby="passkeys-title">
      <div className="passkey-panel-head">
        <div className="section-title" id="passkeys-title">通行密钥</div>
        <span className="passkey-count">已添加 {count} / {data.max_per_user}</span>
      </div>
      <p className="passkey-desc">用指纹、面容或设备锁屏密码一键登录，不用再输密码或打开 Discord。原来的登录方式照常可用。</p>
      {!supported && (
        <div className="warning-msg">当前浏览器不支持通行密钥，换用系统自带浏览器（Safari / Chrome / Edge）打开本页即可添加。</div>
      )}
      {error && <div className="error-msg" role="alert">{error}</div>}
      {notice && <div className="success-msg" role="status">{notice}</div>}
      {data.passkeys.map(item => (
        <div className="passkey-row" key={item.id}>
          {editing === item.id ? (
            <form className="passkey-rename" onSubmit={e => { e.preventDefault(); void saveRename(item) }}>
              <input value={editName} maxLength={40} onChange={e => setEditName(e.target.value)} autoFocus aria-label="通行密钥名称" />
              <button className="btn-sm primary" type="submit" disabled={busy}>保存</button>
              <button className="btn-sm" type="button" onClick={() => setEditing(0)}>取消</button>
            </form>
          ) : (
            <>
              <div className="passkey-info">
                <div className="passkey-name">{item.name}</div>
                <div className="passkey-sub">
                  添加于 {formatDate(item.created_at)}{item.last_used_at ? ` · 上次使用 ${formatDate(item.last_used_at)}` : ' · 还没用过'}
                </div>
              </div>
              <div className="passkey-actions">
                <button className="btn-sm" type="button" disabled={busy} onClick={() => startRename(item)}>改名</button>
                <button className="btn-sm danger" type="button" disabled={busy} onClick={() => remove(item)}>删除</button>
              </div>
            </>
          )}
        </div>
      ))}
      <button className="btn passkey-btn" type="button" onClick={add}
        disabled={!supported || busy || full || !data.allow_registration}>
        <PasskeyIcon />
        {busy ? '请在设备上确认…' : !data.allow_registration ? '暂停添加' : full ? '已达上限' : count ? '再添加一个' : '添加通行密钥'}
      </button>
      {!data.allow_registration && <div className="passkey-hint">管理员暂时关闭了添加，已添加的照常能用。</div>}
    </section>
  )
}
