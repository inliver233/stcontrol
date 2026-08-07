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

	// 控制面主密钥必须稳定配置；禁止生成并打印临时密钥。
	keyB64 := os.Getenv(cfg.SecretKeyEnv)
	if keyB64 == "" {
		log.Fatalf("必须设置控制面主密钥环境变量 %s（32 字节 base64）", cfg.SecretKeyEnv)
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
