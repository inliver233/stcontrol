package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"stcontrol/internal/config"
	"stcontrol/internal/controller"
	"stcontrol/internal/crypto"
	"stcontrol/internal/store"
)

func main() {
	cfgPath := flag.String("config", "controller.yaml", "配置文件路径")
	flag.Parse()

	cfg := config.DefaultController()
	if err := config.Load(*cfgPath, cfg); err != nil {
		log.Fatalf("加载配置失败: %v", err)
	}

	// 用户凭据 AES 密钥（环境变量优先）
	keyB64 := os.Getenv(cfg.SecretKeyEnv)
	if keyB64 == "" {
		log.Printf("警告: 环境变量 %s 未设置, 生成临时密钥(重启后用户凭据将无法解密!)", cfg.SecretKeyEnv)
		var err error
		keyB64, err = crypto.GenerateKey()
		if err != nil {
			log.Fatalf("生成密钥失败: %v", err)
		}
		log.Printf("请设置环境变量: %s=%s", cfg.SecretKeyEnv, keyB64)
	}
	secretKey, err := crypto.LoadKey(keyB64)
	if err != nil {
		log.Fatalf("密钥无效: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	st, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("连接数据库失败: %v", err)
	}
	defer st.Close()

	srv := controller.New(cfg, st, secretKey)
	log.Printf("总控启动, 监听 %s, 对外地址 %s", cfg.Listen, cfg.PublicURL)
	if err := srv.Run(ctx); err != nil {
		log.Fatalf("服务退出: %v", err)
	}
}
