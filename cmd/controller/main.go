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
	promote := flag.Bool("promote", false, "把本次启动标记为显式恢复：即使上次总控正常退出也提升世代")
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
	if err := runController(ctx, cfg, *cfgPath, secretKey, *passive, *promote); err != nil {
		log.Fatal(err)
	}
}

// cleanRestartResumeWindow bounds how long a cleanly stopped Controller may
// stay down and still continue its generation. It stays well below the
// activity lease TTL and the Agents' switch to independent mode (15 minutes),
// so a resumed generation never meets leases or nodes that moved on without it.
const cleanRestartResumeWindow = 10 * time.Minute

// runController owns the database leadership for the life of the process and
// serves until ctx is cancelled (SIGINT/SIGTERM) or leadership is lost.
func runController(
	ctx context.Context,
	cfg *config.ControllerConfig,
	cfgPath string,
	secretKey []byte,
	passive, promote bool,
) error {
	st, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("连接数据库失败: %w", err)
	}
	defer st.Close()

	var leadership *store.ControllerLeadership
	for {
		candidate, acquired, err := st.TryAcquireControllerLeadership(ctx)
		if err != nil {
			return fmt.Errorf("取得总控领导锁失败: %w", err)
		}
		if acquired {
			leadership = candidate
			break
		}
		if !passive {
			return fmt.Errorf("已有活动总控持有数据库领导锁；请使用 --passive 启动被动副控")
		}
		log.Printf("被动副控等待活动总控释放领导锁")
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(5 * time.Second):
		}
	}
	defer leadership.Close()

	// A planned restart continues the generation its predecessor stopped
	// cleanly, so signed-in users keep their sessions and activity leases. A
	// crash, a lost lock, a passive takeover or an explicit recovery promotes.
	var generation int64
	resumed := false
	if !passive && !promote {
		generation, resumed, err = st.ResumeControllerEpoch(ctx, "controller-clean-restart",
			cleanRestartResumeWindow, time.Now().UTC())
		if err != nil {
			return fmt.Errorf("检查上次总控是否正常退出失败: %w", err)
		}
	}
	if resumed {
		log.Printf("上次总控正常退出，继续使用 generation=%d；在线用户的会话与活动租约保持有效", generation)
	} else {
		promotionSource := "controller-process-start"
		if passive {
			promotionSource = "passive-controller-takeover"
		} else if promote {
			promotionSource = "explicit-controller-recovery"
		}
		generation, err = st.PromoteControllerEpoch(ctx, promotionSource, time.Now().UTC())
		if err != nil {
			return fmt.Errorf("提升总控世代并建立恢复对账失败: %w", err)
		}
		log.Printf("总控已原子提升到 generation=%d；新操作保持关闭直至节点凭据轮换与模式对账完成", generation)
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
		return fmt.Errorf("检查管理员状态失败: %w", err)
	}
	if !hasAdmin {
		bootstrapPassword := os.Getenv(cfg.Admin.PasswordEnv)
		if len(bootstrapPassword) < 12 {
			return fmt.Errorf("首次启动必须通过环境变量 %s 提供至少 12 位管理员密码", cfg.Admin.PasswordEnv)
		}
		passwordHash, err := crypto.HashPassword(bootstrapPassword)
		if err != nil {
			return fmt.Errorf("管理员密码哈希失败: %w", err)
		}
		created, err := st.BootstrapAdmin(ctx, cfg.Admin.Username, passwordHash, time.Now().UTC())
		if err != nil {
			return fmt.Errorf("创建首位管理员失败: %w", err)
		}
		if !created {
			return fmt.Errorf("数据库已有管理员记录但没有有效管理员；拒绝用引导密码覆盖，需按恢复手册处理")
		}
		log.Printf("已创建首位总控管理员 %s", cfg.Admin.Username)
	}

	srv := controller.New(cfg, st, secretKey)
	srv.ConfigPath = cfgPath
	log.Printf("总控启动, 监听 %s, 对外 HTTPS 端点已配置", cfg.Listen)
	runErr := srv.Run(runCtx)
	if ctx.Err() != nil {
		// Stopped on purpose: let the next process continue this generation.
		// This only succeeds while the leadership connection still holds the lock.
		markCtx, cancelMark := context.WithTimeout(context.Background(), 3*time.Second)
		marked, err := leadership.MarkCleanShutdown(markCtx, generation, time.Now().UTC())
		cancelMark()
		switch {
		case err != nil:
			log.Printf("未能记录总控正常退出，下次启动将提升世代: %v", err)
		case marked:
			log.Printf("总控已正常退出，下次启动将继续 generation=%d", generation)
		default:
			log.Printf("generation=%d 已不是活动世代，未记录正常退出", generation)
		}
	}
	if runErr != nil && runCtx.Err() == nil {
		return fmt.Errorf("服务退出: %w", runErr)
	}
	return nil
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
	encoded, err := recoverMasterKeyFromArchive(archivePath, passphrase)
	if err != nil {
		log.Fatalf("恢复主密钥失败: %v", err)
	}
	fmt.Printf("%s\n", encoded)
}

// recoverMasterKeyFromArchive performs the security-sensitive archive parsing
// without terminating the process. Keeping the core operation testable lets
// acceptance tests cover malformed/truncated archives and wrong passphrases;
// the CLI wrapper above remains responsible only for environment and output.
func recoverMasterKeyFromArchive(archivePath, passphrase string) (string, error) {
	if len(passphrase) < 8 {
		return "", fmt.Errorf("recovery passphrase must be at least 8 characters")
	}
	archive, err := os.Open(archivePath)
	if err != nil {
		return "", fmt.Errorf("open disaster backup: %w", err)
	}
	defer archive.Close()
	info, err := archive.Stat()
	if err != nil || info.Size() <= 0 {
		return "", fmt.Errorf("invalid disaster backup archive")
	}
	decoder, err := zstd.NewReader(archive, zstd.WithDecoderMaxMemory(256<<20), zstd.WithDecoderMaxWindow(256<<20))
	if err != nil {
		return "", fmt.Errorf("decompress disaster backup: %w", err)
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
			return "", fmt.Errorf("read disaster backup: %w", err)
		}
		if header.Typeflag != tar.TypeReg || header.Name != "master_key_recovery.json" {
			continue
		}
		if header.Size <= 0 || header.Size > 1<<20 {
			return "", fmt.Errorf("invalid recovery envelope size")
		}
		data, err := io.ReadAll(io.LimitReader(tarReader, header.Size+1))
		if err != nil || int64(len(data)) != header.Size {
			return "", fmt.Errorf("read recovery envelope")
		}
		found = data
		break
	}
	if found == nil {
		return "", fmt.Errorf("master_key_recovery.json is absent from disaster backup")
	}
	envelope, err := crypto.DecodeMasterKeyRecoveryJSON(found)
	if err != nil {
		return "", fmt.Errorf("decode recovery envelope: %w", err)
	}
	masterKey, err := crypto.OpenMasterKeyRecovery(passphrase, envelope)
	if err != nil {
		return "", fmt.Errorf("unwrap master key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(masterKey), nil
}
