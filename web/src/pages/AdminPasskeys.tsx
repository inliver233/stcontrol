import { useEffect, useState } from 'react'
import { api, type PasskeyAdminOverview, type PasskeySettings } from '../api'
import PasskeyIcon from '../components/PasskeyIcon'

const verificationLabels: Record<PasskeySettings['user_verification'], string> = {
  preferred: '尽量验证指纹 / 面容（推荐）',
  required: '必须验证指纹 / 面容',
  discouraged: '不要求验证',
}

function formatDate(value?: string) {
  return value ? new Date(value).toLocaleDateString() : '—'
}

// 管理后台「通行密钥」：开关与文案、使用统计、按用户查看与删除。
export default function PasskeysAdmin() {
  const [data, setData] = useState<PasskeyAdminOverview | null>(null)
  const [draft, setDraft] = useState<PasskeySettings | null>(null)
  const [error, setError] = useState('')
  const [status, setStatus] = useState<{ state: 'ok' | 'error' | 'saving'; text: string } | null>(null)
  const [busy, setBusy] = useState(false)

  const load = async () => {
    try {
      const next = await api.adminPasskeys()
      setData(next)
      setDraft(next.settings)
      setError('')
    } catch (err: any) {
      setError(err.message)
    }
  }
  useEffect(() => { void load() }, [])

  if (!data || !draft) return <div><h2>通行密钥</h2>{error ? <div className="error-msg">{error}</div> : <div className="loading">加载中…</div>}</div>

  const set = <K extends keyof PasskeySettings>(key: K, value: PasskeySettings[K]) => {
    setDraft({ ...draft, [key]: value })
    setStatus(null)
  }
  const changed = JSON.stringify({ ...draft, updated_at: undefined }) !== JSON.stringify({ ...data.settings, updated_at: undefined })

  const save = async () => {
    if (data.settings.enabled && !draft.enabled &&
      !window.confirm('关闭后所有人都不能用通行密钥登录（已添加的密钥会保留，重新开启后照常可用）。确定关闭？')) return
    setStatus({ state: 'saving', text: '保存中…' })
    try {
      await api.adminSavePasskeySettings(draft)
      await load()
      setStatus({ state: 'ok', text: '已保存，立即生效' })
    } catch (err: any) {
      setStatus({ state: 'error', text: err.message })
    }
  }

  const removePasskey = async (id: number, name: string, user: string) => {
    if (!window.confirm(`删除 ${user} 的通行密钥「${name}」？`)) return
    setBusy(true)
    try {
      await api.adminDeletePasskey(id)
      await load()
    } catch (err: any) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  const removeUser = async (uuid: string, user: string, count: number) => {
    if (!window.confirm(`删除 ${user} 的全部 ${count} 个通行密钥？`)) return
    setBusy(true)
    try {
      await api.adminDeleteUserPasskeys(uuid)
      await load()
    } catch (err: any) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  const { overview } = data
  const lastWeek = overview.days.slice(-7)
  const weekLogins = lastWeek.reduce((sum, day) => sum + day.login_success, 0)
  const weekFailures = lastWeek.reduce((sum, day) => sum + day.login_failure, 0)
  const peak = Math.max(1, ...overview.days.map(day => day.login_success + day.login_failure + day.registered))
  const pill = !data.configured ? { cls: 'red', text: '域名未配置' } : data.settings.enabled ? { cls: 'green', text: '已开启' } : { cls: 'gray', text: '已关闭' }

  return (
    <div className="passkey-admin">
      <div className="passkey-admin-head">
        <h2>通行密钥</h2>
        <span className={`badge ${pill.cls}`}>{pill.text}</span>
      </div>
      {error && <div className="error-msg">{error}</div>}
      {data.configured ? (
        <div className="passkey-admin-domain">
          绑定域名 <code>{data.rp_id}</code> · 可用于 {data.origins.map(origin => <code key={origin}>{origin}</code>)}
        </div>
      ) : (
        <div className="error-msg">配置文件里的通行密钥域名不可用：{data.config_error}。在 passkeys.rp_id / origins 里设置后重启总控。</div>
      )}

      <div className="stat-grid passkey-stats">
        <div className="stat-card"><div className="stat-value">{overview.users_with_passkeys}</div><div className="stat-label">已添加的用户</div></div>
        <div className="stat-card"><div className="stat-value">{overview.total_passkeys}</div><div className="stat-label">密钥总数</div></div>
        <div className="stat-card"><div className="stat-value">{weekLogins}</div><div className="stat-label">近 7 天登录</div></div>
        <div className="stat-card"><div className="stat-value">{weekFailures}</div><div className="stat-label">近 7 天失败</div></div>
      </div>

      <div className="passkey-chart" aria-label="近 21 天">
        {overview.days.map(day => (
          <div className="passkey-chart-day" key={day.day}
            title={`${day.day}：登录 ${day.login_success}，失败 ${day.login_failure}，新增 ${day.registered}`}>
            <div className="bar failure" style={{ height: `${(day.login_failure / peak) * 100}%` }} />
            <div className="bar success" style={{ height: `${(day.login_success / peak) * 100}%` }} />
            <div className="bar registered" style={{ height: `${(day.registered / peak) * 100}%` }} />
          </div>
        ))}
      </div>
      <div className="passkey-chart-legend"><span className="success">登录</span><span className="failure">失败</span><span className="registered">新增</span><span>近 21 天</span></div>

      <div className="passkey-admin-card">
        <div className="passkey-switches">
          <label><input type="checkbox" checked={draft.enabled} onChange={e => set('enabled', e.target.checked)} /> 开启通行密钥</label>
          <label><input type="checkbox" checked={draft.allow_registration} onChange={e => set('allow_registration', e.target.checked)} /> 允许添加新密钥</label>
          <label><input type="checkbox" checked={draft.show_on_login_page} onChange={e => set('show_on_login_page', e.target.checked)} /> 登录页显示按钮</label>
        </div>
        <div className="passkey-fields">
          <label className="field">
            <span>每人最多</span>
            <select value={draft.max_per_user} onChange={e => set('max_per_user', Number(e.target.value))}>
              {Array.from({ length: 10 }, (_, i) => i + 1).map(n => <option key={n} value={n}>{n} 个</option>)}
            </select>
          </label>
          <label className="field">
            <span>指纹 / 面容验证</span>
            <select value={draft.user_verification} onChange={e => set('user_verification', e.target.value as PasskeySettings['user_verification'])}>
              {Object.entries(verificationLabels).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
            </select>
          </label>
          <label className="field">
            <span>登录按钮文字</span>
            <input value={draft.login_button_text} maxLength={24} onChange={e => set('login_button_text', e.target.value)} />
          </label>
          <label className="field">
            <span>按钮下方提示（可留空）</span>
            <input value={draft.login_hint_text} maxLength={80} onChange={e => set('login_hint_text', e.target.value)} />
          </label>
        </div>
        <div className="passkey-preview">
          <span className="passkey-preview-label">登录页预览</span>
          <div className="passkey-login">
            <div className="btn passkey-btn" aria-hidden="true"><PasskeyIcon />{draft.login_button_text || '通行密钥登录'}</div>
            {draft.login_hint_text && <div className="passkey-hint">{draft.login_hint_text}</div>}
          </div>
        </div>
        <div className="passkey-save">
          <button className="btn-sm primary" type="button" onClick={save} disabled={!changed || status?.state === 'saving'}>保存设置</button>
          {status && <span className={`passkey-save-status ${status.state}`} role="status">{status.text}</span>}
        </div>
      </div>

      <h3 className="passkey-users-title">已添加的用户（{overview.users_with_passkeys}）</h3>
      {overview.users.length === 0 ? <div className="empty-state"><p>还没有人添加通行密钥。</p></div> : (
        <div className="passkey-users">
          {overview.users.map(user => {
            const label = user.display_name && user.display_name !== user.username ? `${user.display_name}（${user.username}）` : user.username
            return (
              <div className="passkey-user" key={user.uuid}>
                <div className="passkey-user-head">
                  <strong>{label}</strong>
                  <span className="passkey-count">{user.passkeys.length} 个</span>
                  <button className="btn-sm danger" type="button" disabled={busy}
                    onClick={() => removeUser(user.uuid, label, user.passkeys.length)}>全部删除</button>
                </div>
                {user.passkeys.map(passkey => (
                  <div className="passkey-row" key={passkey.id}>
                    <div className="passkey-info">
                      <div className="passkey-name">{passkey.name}</div>
                      <div className="passkey-sub">添加于 {formatDate(passkey.created_at)} · 上次使用 {formatDate(passkey.last_used_at)}</div>
                    </div>
                    <button className="btn-sm danger" type="button" disabled={busy}
                      onClick={() => removePasskey(passkey.id, passkey.name, label)}>删除</button>
                  </div>
                ))}
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
