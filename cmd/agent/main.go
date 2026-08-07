package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"stcontrol/internal/agent"
	"stcontrol/internal/config"
)

func main() {
	cfgPath := flag.String("config", "agent.yaml", "配置文件路径")
	token := flag.String("token", "", "一次性注册令牌(首次注册用)")
	controller := flag.String("controller", "", "总控地址(覆盖配置)")
	role := flag.String("role", "", "节点角色 compute|storage(覆盖配置)")
	tavernDir := flag.String("tavern-dir", "", "酒馆安装目录(覆盖配置)")
	register := flag.Bool("register", false, "执行注册后退出")
	flag.Parse()

	cfg := config.DefaultAgent()
	if err := config.Load(*cfgPath, cfg); err != nil {
		log.Fatalf("加载配置失败: %v", err)
	}
	// 命令行覆盖
	if *controller != "" {
		cfg.ControllerURL = *controller
	}
	if *role != "" {
		cfg.Role = *role
	}
	if *tavernDir != "" {
		cfg.TavernDir = *tavernDir
	}

	a, err := agent.New(cfg)
	if err != nil {
		log.Fatalf("初始化 Agent 失败: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// 注册流程: 提供了 token 且尚未有 node_id
	if *token != "" {
		if cfg.Role == "compute" && cfg.TavernDir == "" {
			log.Fatalf("计算节点注册需指定酒馆目录: --tavern-dir 或配置 tavern_dir")
		}
		if cfg.ControllerURL == "" {
			log.Fatalf("注册需指定总控地址: --controller 或配置 controller_url")
		}
		if err := a.RegisterToController(ctx, *token); err != nil {
			log.Fatalf("注册到总控失败: %v", err)
		}
		// 写回配置(含 node_id + agent_psk)
		if err := config.Save(*cfgPath, cfg); err != nil {
			log.Fatalf("保存配置失败: %v", err)
		}
		log.Printf("注册成功! node_id=%d 已写入 %s", cfg.NodeID, *cfgPath)
		if *register {
			return
		}
	}

	if cfg.NodeID == 0 || cfg.AgentPSK == "" {
		log.Fatalf("子控尚未注册。请先运行: agent --register --token <令牌> --controller <总控地址> --tavern-dir <酒馆目录>")
	}

	// 启动心跳
	go a.StartHeartbeat(ctx)
	go a.StartCommandLoop(ctx)

	// 启动 HTTP 服务
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           a.Handler(),
		ReadHeaderTimeout: 15 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	log.Printf("子控启动, node_id=%d 角色=%s 监听 %s, 总控 %s", cfg.NodeID, cfg.Role, cfg.Listen, cfg.ControllerURL)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("服务退出: %v", err)
	}
}
