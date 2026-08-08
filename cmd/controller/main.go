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
	passive := flag.Bool("passive", false, "作为被动副控等待 PostgreSQL 领导锁，取得后自动提升")
	promote := flag.Bool("promote", false, "取得领导锁后显式提升 controller generation")
	flag.Parse()

	cfg := config.DefaultController()
	if err := config.Load(*cfgPath, cfg); err != nil {
		log.Fatalf("加载配置失败: %v", err)
	}
	if err := controller.ValidateRuntimeConfig(cfg); err != nil {
		log.Fatalf("总控监听配置无效: %v", err)
	}
	if err := controller.ValidateRuntimeTLSFiles(cfg); err != nil {
		log.Fatalf("总控 TLS 配置无效: %v", err)
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

	var leadership *store.ControllerLeadership
	for {
		candidate, acquired, err := st.TryAcquireControllerLeadership(ctx)
		if err != nil {
			log.Fatalf("取得总控领导锁失败: %v", err)
		}
		if acquired {
			leadership = candidate
			break
		}
		if !*passive {
			log.Fatalf("已有活动总控持有数据库领导锁；请使用 --passive 启动被动副控")
		}
		log.Printf("被动副控等待活动总控释放领导锁")
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
	defer leadership.Close()
	if *passive || *promote {
		generation, err := st.PromoteControllerEpoch(ctx, "postgres-leadership-promotion", time.Now().UTC())
		if err != nil {
			log.Fatalf("提升总控世代失败: %v", err)
		}
		log.Printf("总控已原子提升到 generation=%d；旧会话和票据已撤销", generation)
	}
	runCtx, cancelLeadership := context.WithCancel(ctx)
	defer cancelLeadership()
	go func() {
		if err := leadership.Watch(runCtx); err != nil && runCtx.Err() == nil {
			log.Printf("总控领导锁连接失效，立即停止服务: %v", err)
			cancelLeadership()
		}
	}()
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
	log.Printf("总控启动, 监听 %s, 对外 HTTPS 端点已配置", cfg.Listen)
	if err := srv.Run(runCtx); err != nil && runCtx.Err() == nil {
		log.Fatalf("服务退出: %v", err)
	}
}
