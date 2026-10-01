const DC_LOGIN_URL = 'https://dc.sillytarven.online/login'

// dc 酒馆（Oracle）已独立运行、不受本主控管理。dc 用户误用同一个第三方账号登录这里，
// 会被关联到已脱离的旧节点并冻结为副本冲突，所以在入口处显著提示。
export default function DcNotice({ variant = 'login' }: { variant?: 'login' | 'conflict' }) {
  return (
    <div className="dc-notice" role="alert">
      <strong>重要提示：dc 酒馆用户请勿在本站登录</strong>
      {variant === 'conflict'
        ? <p>如您为 dc 酒馆（dc.sillytarven.online）用户，您的数据仍完整保存在 dc 酒馆，本页面无需处理。请前往 dc 酒馆登录使用。</p>
        : <>
          <p>本站与 dc 酒馆（dc.sillytarven.online）为两套相互独立的服务，账号与数据不互通。请勿使用 dc 酒馆的 Discord / LinuxDo 账号在本站登录或注册，否则本站账号将被系统冻结。dc 酒馆中的数据不受影响。</p>
          <p>如您登录后看到「副本冲突已冻结」页面，说明该账号属于 dc 酒馆，请直接前往 dc 酒馆登录使用，您的数据仍完整保存在 dc 酒馆。</p>
        </>}
      <a className="dc-notice-btn" href={DC_LOGIN_URL}>前往 dc 酒馆登录</a>
    </div>
  )
}
