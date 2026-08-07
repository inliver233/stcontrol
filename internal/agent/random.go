package agent

import "crypto/rand"

// rndRead 填充随机字节。
func rndRead(b []byte) {
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
}
