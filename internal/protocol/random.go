package protocol

import "crypto/rand"

// rndRead 填充随机字节（抽出来便于测试替换）。
func rndRead(b []byte) {
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
}
