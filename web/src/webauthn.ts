// 通行密钥（WebAuthn）浏览器端：把服务器给的 JSON 选项转成 WebAuthn 调用，再把结果转回 JSON。

function fromBase64Url(value: string): ArrayBuffer {
  const base64 = String(value).replace(/-/g, '+').replace(/_/g, '/')
  const binary = atob(base64 + '='.repeat((4 - (base64.length % 4)) % 4))
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return bytes.buffer
}

function toBase64Url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer)
  let binary = ''
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000))
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/** 当前浏览器、当前页面能否使用通行密钥。 */
export function isPasskeySupported(): boolean {
  return Boolean(window.isSecureContext && window.PublicKeyCredential &&
    navigator.credentials && typeof navigator.credentials.create === 'function' &&
    typeof navigator.credentials.get === 'function')
}

/** 创建通行密钥。options 是服务器返回的 { publicKey } 里的内容。 */
export async function createPasskey(options: any): Promise<any> {
  const publicKey = {
    ...options,
    challenge: fromBase64Url(options.challenge),
    user: { ...options.user, id: fromBase64Url(options.user.id) },
    excludeCredentials: (options.excludeCredentials || []).map((item: any) => ({ ...item, id: fromBase64Url(item.id) })),
  }
  const credential = await navigator.credentials.create({ publicKey }) as PublicKeyCredential
  const response = credential.response as AuthenticatorAttestationResponse
  return {
    id: credential.id,
    rawId: toBase64Url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: toBase64Url(response.clientDataJSON),
      attestationObject: toBase64Url(response.attestationObject),
      transports: typeof response.getTransports === 'function' ? response.getTransports() : [],
    },
    authenticatorAttachment: credential.authenticatorAttachment ?? undefined,
    clientExtensionResults: credential.getClientExtensionResults(),
  }
}

/** 用用户选择的通行密钥签名。options 是服务器返回的 { publicKey } 里的内容。 */
export async function getPasskey(options: any): Promise<any> {
  const publicKey = {
    ...options,
    challenge: fromBase64Url(options.challenge),
    allowCredentials: (options.allowCredentials || []).map((item: any) => ({ ...item, id: fromBase64Url(item.id) })),
  }
  const credential = await navigator.credentials.get({ publicKey }) as PublicKeyCredential
  const response = credential.response as AuthenticatorAssertionResponse
  return {
    id: credential.id,
    rawId: toBase64Url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: toBase64Url(response.clientDataJSON),
      authenticatorData: toBase64Url(response.authenticatorData),
      signature: toBase64Url(response.signature),
      userHandle: response.userHandle ? toBase64Url(response.userHandle) : undefined,
    },
    authenticatorAttachment: credential.authenticatorAttachment ?? undefined,
    clientExtensionResults: credential.getClientExtensionResults(),
  }
}

/** 告诉密码管理器某个通行密钥在本站已不存在，以后不再提示它（新版 Chrome 支持，其他浏览器无操作）。 */
export function forgetPasskey(rpId: string, credentialId: string) {
  try {
    void (window.PublicKeyCredential as any)?.signalUnknownCredential?.({ rpId, credentialId })?.catch?.(() => undefined)
  } catch {
    // 可选功能。
  }
}

/** 给用户看的错误说明；用户自己取消时返回 null。 */
export function describePasskeyError(error: unknown, action: 'create' | 'get'): string | null {
  const name = error instanceof Error || error instanceof DOMException ? error.name : ''
  switch (name) {
    case 'NotAllowedError':
    case 'AbortError':
      return null
    case 'InvalidStateError':
      return action === 'create' ? '这台设备（或这个密码管理器）里已经有本账号的通行密钥了，可以直接用它登录。' : '通行密钥暂时不可用，请再试一次。'
    case 'SecurityError':
      return '当前网址不能使用通行密钥，请从总控的正式地址打开。'
    case 'NotSupportedError':
      return '这台设备不支持通行密钥。'
    default:
      return action === 'create' ? '添加通行密钥失败，请再试一次。' : '通行密钥登录失败，请再试一次。'
  }
}

/** 按当前设备起一个默认名字，例如「iPhone · Safari」。 */
export function guessDeviceName(): string {
  const ua = navigator.userAgent
  const device = /iPhone/.test(ua) ? 'iPhone'
    : /iPad/.test(ua) || (/Macintosh/.test(ua) && navigator.maxTouchPoints > 1) ? 'iPad'
      : /Android/.test(ua) ? 'Android 手机'
        : /Macintosh|Mac OS X/.test(ua) ? 'Mac'
          : /Windows/.test(ua) ? 'Windows 电脑'
            : /CrOS/.test(ua) ? 'Chromebook'
              : /Linux/.test(ua) ? 'Linux 电脑' : '我的设备'
  const browser = /Edg\//.test(ua) ? 'Edge' : /Firefox\//.test(ua) ? 'Firefox' : /Chrome\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : ''
  return browser ? `${device} · ${browser}` : device
}
