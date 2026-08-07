// 交叉验证: 用酒馆 federated-login.js 同款逻辑, 校验"总控签发的票据"。
// 模拟: 给定 psk, 总控侧(Go)签发的 JWT 是否能被酒馆(Node)验签通过。
import crypto from 'node:crypto';

// ---- 酒馆侧逻辑(与 federated-login.js 完全一致) ----
function base64UrlDecode(str) {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) str += '=';
    return Buffer.from(str, 'base64');
}
function verifyTicketJWT(secret, token) {
    if (!token || typeof token !== 'string') return null;
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const [h, p, s] = parts;
    const signingInput = `${h}.${p}`;
    const expect = crypto.createHmac('sha256', secret).update(signingInput).digest();
    const actual = base64UrlDecode(s);
    if (expect.length !== actual.length || !crypto.timingSafeEqual(expect, actual)) return null;
    let payload;
    try { payload = JSON.parse(base64UrlDecode(p).toString('utf8')); } catch { return null; }
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp && now >= payload.exp) return null;
    return payload;
}
function deriveTicketSecret(psk) {
    return crypto.createHash('sha256').update('stcontrol-ticket:' + psk).digest();
}

// ---- 模拟总控侧签发(Go 的 IssueTicket 等价物) ----
function b64url(buf) {
    return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function issueTicket(secret, handle, aud, jti, ttlSec) {
    const header = b64url(Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })));
    const now = Math.floor(Date.now() / 1000);
    const payload = b64url(Buffer.from(JSON.stringify({
        sub: handle, aud, nonce: 'x', jti, iat: now, exp: now + ttlSec,
    })));
    const sig = b64url(crypto.createHmac('sha256', secret).update(`${header}.${payload}`).digest());
    return `${header}.${payload}.${sig}`;
}

// ---- 测试 ----
const psk = 'interop-test-psk';
const secret = deriveTicketSecret(psk);
const token = issueTicket(secret, 'alice', 'https://a.example.com', 'jti-123', 60);
const payload = verifyTicketJWT(secret, token);

if (!payload) { console.error('FAIL: 酒馆侧验签失败'); process.exit(1); }
if (payload.sub !== 'alice') { console.error('FAIL: sub 不匹配'); process.exit(1); }
if (payload.aud !== 'https://a.example.com') { console.error('FAIL: aud 不匹配'); process.exit(1); }
if (payload.jti !== 'jti-123') { console.error('FAIL: jti 不匹配'); process.exit(1); }
console.log('OK: 总控签发的票据可被酒馆侧验签通过 (互操作一致)');
console.log('    payload =', JSON.stringify(payload));

// 错误密钥应失败
const badSecret = deriveTicketSecret('wrong-psk');
if (verifyTicketJWT(badSecret, token) !== null) { console.error('FAIL: 错误密钥竟验签通过'); process.exit(1); }
console.log('OK: 错误密钥被正确拒绝');

// 过期票据应失败
const expired = issueTicket(secret, 'alice', 'https://a.example.com', 'jti-124', -10);
if (verifyTicketJWT(secret, expired) !== null) { console.error('FAIL: 过期票据竟验签通过'); process.exit(1); }
console.log('OK: 过期票据被正确拒绝');
