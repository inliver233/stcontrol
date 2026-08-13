package main

import (
	"archive/tar"
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/klauspost/compress/zstd"

	"stcontrol/internal/config"
	"stcontrol/internal/controller"
	"stcontrol/internal/crypto"
	"stcontrol/internal/store"
)

func main() {
	cfgPath := flag.String("config", "controller.yaml", "配置文件路径")
	passive := flag.Bool("passive", false, "作为被动副控等待 PostgreSQL 领导锁，取得后自动提升")
	promote := flag.Bool("promote", false, "把本次启动标记为显式恢复（每次取得领导锁都会提升世代）")
	recoverKey := flag.String("recover-master-key", "", "从总控灾备归档解出主密钥恢复信封并输出 base64 主密钥（Round 61）")
	flag.Parse()

	cfg := config.DefaultController()
	if err := config.Load(*cfgPath, cfg); err != nil {
		log.Fatalf("加载配置失败: %v", err)
	}
	if *recoverKey != "" {
		runMasterKeyRecovery(*recoverKey, cfg)
		return
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
	promotionSource := "controller-process-start"
	if *passive {
		promotionSource = "passive-controller-takeover"
	} else if *promote {
		promotionSource = "explicit-controller-recovery"
	}
	generation, err := st.PromoteControllerEpoch(ctx, promotionSource, time.Now().UTC())
	if err != nil {
		log.Fatalf("提升总控世代并建立恢复对账失败: %v", err)
	}
	log.Printf("总控已原子提升到 generation=%d；新操作保持关闭直至节点凭据轮换与模式对账完成", generation)
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
	srv.ConfigPath = *cfgPath
	log.Printf("总控启动, 监听 %s, 对外 HTTPS 端点已配置", cfg.Listen)
	if err := srv.Run(runCtx); err != nil && runCtx.Err() == nil {
		log.Fatalf("服务退出: %v", err)
	}
}
// runMasterKeyRecovery extracts the master-key recovery envelope from a
// controller disaster backup archive and, with the recovery passphrase,
// prints the unwrapped base64 master key (Round 61).  The archive is a
// tar.zst containing master_key_recovery.json plus the pg dump and config.
func runMasterKeyRecovery(archivePath string, cfg *config.ControllerConfig) {
	passphraseEnv := "CONTROLLER_RECOVERY_PASSPHRASE"
	if cfg != nil && cfg.ControllerBackup.RecoveryPassphraseEnv != "" {
		passphraseEnv = cfg.ControllerBackup.RecoveryPassphraseEnv
	}
	passphrase := os.Getenv(passphraseEnv)
	if len(passphrase) < 8 {
		log.Fatalf("必须通过环境变量 %s 提供至少 8 位的恢复口令", passphraseEnv)
	}
	archive, err := os.Open(archivePath)
	if err != nil {
		log.Fatalf("打开灾备归档失败: %v", err)
	}
	defer archive.Close()
	info, err := archive.Stat()
	if err != nil || info.Size() <= 0 {
		log.Fatalf("无效的灾备归档")
	}
	decoder, err := zstd.NewReader(archive, zstd.WithDecoderMaxMemory(256<<20), zstd.WithDecoderMaxWindow(256<<20))
	if err != nil {
		log.Fatalf("解压灾备归档失败: %v", err)
	}
	defer decoder.Close()
	tarReader := tar.NewReader(decoder)
	var found []byte
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatalf("读取灾备归档失败: %v", err)
		}
		if header.Typeflag != tar.TypeReg || header.Name != "master_key_recovery.json" {
			continue
		}
		if header.Size <= 0 || header.Size > 1<<20 {
			log.Fatalf("恢复信封大小非法")
		}
		data, err := io.ReadAll(io.LimitReader(tarReader, header.Size+1))
		if err != nil || int64(len(data)) != header.Size {
			log.Fatalf("读取恢复信封失败")
		}
		found = data
		break
	}
	if found == nil {
		log.Fatalf("归档中不存在 master_key_recovery.json；该备份未包含主密钥恢复材料")
	}
	envelope, err := crypto.DecodeMasterKeyRecoveryJSON(found)
	if err != nil {
		log.Fatalf("解析恢复信封失败: %v", err)
	}
	masterKey, err := crypto.OpenMasterKeyRecovery(passphrase, envelope)
	if err != nil {
		log.Fatalf("解出主密钥失败（口令错误或信封损坏）: %v", err)
	}
	fmt.Printf("%s\n", base64.StdEncoding.EncodeToString(masterKey))
}
