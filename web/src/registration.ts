import { api, RegistrationStatus } from './api'

const pollIntervalMs = 1000
const registrationWaitMs = 2 * 60 * 1000

export async function waitForRegistration(
  onState?: (status: RegistrationStatus) => void,
): Promise<RegistrationStatus> {
  const deadline = Date.now() + registrationWaitMs
  while (Date.now() < deadline) {
    const status = await api.registrationStatus()
    onState?.(status)
    if (status.state === 'succeeded') return status
    await new Promise(resolve => window.setTimeout(resolve, pollIntervalMs))
  }
  throw new Error('注册仍在后台处理中，请稍后刷新页面继续查询')
}
