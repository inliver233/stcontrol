package crypto

import "crypto/sha256"

// sha256Of 返回输入的 SHA256 字节切片。
func sha256Of(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}
