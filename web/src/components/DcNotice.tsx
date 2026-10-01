const DC_LOGIN_URL = 'https://dc.sillytarven.online/login'

// dc 酒馆（Oracle）已独立运行、不受本主控管理。dc 用户误用同一个第三方账号登录这里，
// 会被关联到已脱离的旧节点并冻结为副本冲突，所以在入口处显著提示。
export default function DcNotice({ variant = 'login' }: { variant?: 'login' | 'conflict' }) {
  return (
    <div className="dc-notice" role="alert">
      <div className="dc-notice-head">
        <strong>dc 酒馆用户请勿在本站登录</strong>
        <a className="dc-notice-link" href={DC_LOGIN_URL}>前往 dc 酒馆 →</a>
      </div>
      {variant === 'conflict'
        ? <p>如您为 dc 酒馆用户，<b className="dc-key">数据完好无损</b>，本页面无需处理，请<b className="dc-key">前往 dc 酒馆登录</b>。</p>
        : <p>两站账号与数据<b className="dc-key">不互通</b>，使用 dc 酒馆的第三方账号在此登录将导致<b className="dc-key">账号被冻结</b>。如已出现<b className="dc-key">「副本冲突已冻结」</b>，请直接前往 dc 酒馆登录，数据不受影响。</p>}
    </div>
  )
}
