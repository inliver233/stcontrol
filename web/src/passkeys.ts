// 添加通行密钥的完整流程（账号页面板和节点页提示条共用）。
import { api } from './api'
import { createPasskey, describePasskeyError, guessDeviceName } from './webauthn'

/**
 * 在当前设备上创建并登记一个通行密钥。
 * 用户自己取消时返回 false；其他失败抛出带中文说明的错误。
 */
export async function addPasskey(): Promise<boolean> {
  const ceremony = await api.passkeyRegisterOptions()
  let credential: unknown
  try {
    credential = await createPasskey(ceremony.options.publicKey)
  } catch (err) {
    const message = describePasskeyError(err, 'create')
    if (!message) return false
    throw new Error(message)
  }
  await api.passkeyRegisterVerify(ceremony.ceremony_id, guessDeviceName(), credential)
  return true
}
