package agent

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strconv"
	"time"
)

// receive 接口是流式传输, 无法用标准 HMAC(需先读整个 body)。
// 改为对 "method\npath\nquery\ntimestamp\nnonce" 签名, body 完整性由接收端
// 解压 tar.zst + 后续清单 SHA256 校验保证。

const (
	hdrRecvNodeID = "X-Recv-Node-Id"
	hdrRecvTs     = "X-Recv-Timestamp"
	hdrRecvNonce  = "X-Recv-Nonce"
	hdrRecvSig    = "X-Recv-Signature"
)

func recvCanonical(method, path, query, ts, nonce string) string {
	return method + "\n" + path + "\n" + query + "\n" + ts + "\n" + nonce
}

// signBackupReceive 为源节点发往目标节点的 receive 请求签名。
func signBackupReceive(req *http.Request, dstNodeID int64, dstPSK string) {
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := hexNonce()
	query := req.URL.RawQuery
	mac := hmac.New(sha256.New, []byte(dstPSK))
	mac.Write([]byte(recvCanonical(req.Method, req.URL.Path, query, ts, nonce)))
	sig := hex.EncodeToString(mac.Sum(nil))

	req.Header.Set(hdrRecvNodeID, strconv.FormatInt(dstNodeID, 10))
	req.Header.Set(hdrRecvTs, ts)
	req.Header.Set(hdrRecvNonce, nonce)
	req.Header.Set(hdrRecvSig, sig)
}

// verifyBackupReceive 目标节点校验 receive 请求签名。
func verifyBackupReceive(r *http.Request, dstPSK string) bool {
	ts := r.Header.Get(hdrRecvTs)
	nonce := r.Header.Get(hdrRecvNonce)
	sig := r.Header.Get(hdrRecvSig)
	if ts == "" || nonce == "" || sig == "" {
		return false
	}
	tsInt, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return false
	}
	if d := time.Since(time.Unix(tsInt, 0)); d > 60*time.Second || d < -60*time.Second {
		return false
	}
	mac := hmac.New(sha256.New, []byte(dstPSK))
	mac.Write([]byte(recvCanonical(r.Method, r.URL.Path, r.URL.RawQuery, ts, nonce)))
	expect := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expect), []byte(sig))
}

func hexNonce() string {
	b := make([]byte, 16)
	rndRead(b)
	return hex.EncodeToString(b)
}
