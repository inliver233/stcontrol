package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

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
	hasAdmin, err := st.HasActiveAdmin(ctx)
	if err != nil {
		log.Fatalf("检查管理员状态失败: %v", err)
	}
	if !hasAdmin {
		bootstrapPassword := os.Getenv(cfg.Admin.PasswordEnv)
		if len(bootstrapPassword) < 12 {
			log.Fatalf("首次启动必须通过环境变量 %s 提供至少 12 位管理员密码", cfg.Admin.PasswordEnv)
		}
		passwordHash, err := crypto.HashPassword(bootstrapPassword)
		if err != nil {
			log.Fatalf("管理员密码哈希失败: %v", err)
		}
		created, err := st.BootstrapAdmin(ctx, cfg.Admin.Username, passwordHash, time.Now().UTC())
		if err != nil {
			log.Fatalf("创建首位管理员失败: %v", err)
		}
		if created {
			log.Printf("已创建首位总控管理员 %s", cfg.Admin.Username)
		} else {
			log.Fatalf("数据库已有管理员记录但没有有效管理员；拒绝用引导密码覆盖，需按恢复手册处理")
		}
	}

	srv := controller.New(cfg, st, secretKey)
	log.Printf("总控启动, 监听 %s, 对外地址 %s", cfg.Listen, cfg.PublicURL)
	if err := srv.Run(ctx); err != nil {
		log.Fatalf("服务退出: %v", err)
	}
}
