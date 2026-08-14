// Package config 加载总控与子控的配置。
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// ---------- 总控配置 ----------

// ControllerConfig 总控配置。
type ControllerConfig struct {
	PublicURL        string                         `yaml:"public_url"` // 总控对外地址
	Listen           string                         `yaml:"listen"`     // 监听地址 :8080
	TLSCertFile      string                         `yaml:"tls_cert_file"`
	TLSKeyFile       string                         `yaml:"tls_key_file"`
	DatabaseURL      string                         `yaml:"database_url"`
	SecretKeyEnv     string                         `yaml:"secret_key_env"` // 控制面凭证加密主密钥的环境变量名
	StaticDir        string                         `yaml:"static_dir"`     // React 构建产物目录
	Node             NodePolicy                     `yaml:"node"`
	Ticket           TicketPolicy                   `yaml:"ticket"`
	Activity         ActivityPolicy                 `yaml:"activity"`
	Backup           BackupPolicy                   `yaml:"backup"`
	OAuth            OAuthConfig                    `yaml:"oauth"`
	Admin            AdminConfig                    `yaml:"admin"`
	Relay            RelayConfig                    `yaml:"relay"`
	ControllerBackup ControllerDisasterBackupPolicy `yaml:"controller_backup"`
	ImportScan       ImportScanPolicy               `yaml:"import_scan"`
	AISupervisor     AISupervisorPolicy             `yaml:"ai_supervisor"`
}

// AISupervisorPolicy controls the AI 监管层 (read-only advisory layer, Phase 0).
// It is fully optional: when disabled (default) the system behaves exactly as
// before. When enabled, a background worker builds redacted observations and
// asks a user-configured LLM provider for structured advisory JSON; every
// advisory is validated against allowlists/hard gates and never executes
// anything by itself. Model/URL/key are entirely user-defined (Cherry Studio
// style); the API key comes only from STCONTROL_AI_API_KEY env.
type AISupervisorPolicy struct {
	Enabled         bool   `yaml:"enabled"`           // default false; AI off = zero behavior difference
	Mode            string `yaml:"mode"`              // shadow|advisory|auto_low_risk; default shadow
	Provider        string `yaml:"provider"`          // openai|openai_responses|anthropic|gemini|openai_compatible
	BaseURL         string `yaml:"base_url"`          // provider endpoint (user-defined)
	Model           string `yaml:"model"`             // pinned model snapshot (user-defined)
	APIKeyEnv       string `yaml:"api_key_env"`       // env var name holding the API key; default STCONTROL_AI_API_KEY
	TimeoutMS       int    `yaml:"timeout_ms"`        // per-call timeout; default 5000
	InspectEverySec int    `yaml:"inspect_every_sec"` // monitoring inspection cadence; default 600
	// AutoAdoptMinConfidence is the decision-④ hard gate: an advisory needs at
	// least this confidence before the auto_low_risk executor may apply it.
	// Default 0.8; the controller clamps to [0.5,1).
	AutoAdoptMinConfidence float64 `yaml:"auto_adopt_min_confidence"`
}

// ControllerDisasterBackupPolicy controls automatic backup of the Controller's
// own control-plane state (postgres dump + control snapshot + keys/config) to a
// pure-storage node.
type ControllerDisasterBackupPolicy struct {
	Enabled        bool `yaml:"enabled"`
	IntervalSec    int  `yaml:"interval_sec"` // default 86400 (24h)
	RetryMax       int  `yaml:"retry_max"`    // default 3
	KeepLatestOnly bool `yaml:"keep_latest_only"`
	PgDump         bool `yaml:"pg_dump"` // include postgres dump; default true (graceful if pg_dump missing)
	// RecoveryPassphraseEnv names an environment variable holding the out-of-band
	// passphrase used to seal the master key into the backup (Round 61).  Empty
	// means the backup omits master-key recovery material (key stays out of the
	// archive entirely).
	RecoveryPassphraseEnv string `yaml:"recovery_passphrase_env,omitempty"`
}

// ImportScanPolicy controls the unattended legacy-account import scanner
// (R16).  When enabled, the controller periodically scans compute nodes that
// have never been scanned or whose inventory revision changed.  Disabled by
// default so operators keep full control over when scanning runs.
type ImportScanPolicy struct {
	Enabled        bool `yaml:"enabled"`
	IntervalSec    int  `yaml:"interval_sec"`      // default 6h
	MaxNodesPerRun int  `yaml:"max_nodes_per_run"` // default 2
}

// NodePolicy 节点策略。
type NodePolicy struct {
	RegisterCPU         float64 `yaml:"register_cpu"` // 繁忙降权阈值 % (默认50)
	RegisterMem         float64 `yaml:"register_mem"`
	RegisterDisk        float64 `yaml:"register_disk"`
	AllocationHardPct   float64 `yaml:"allocation_hard_pct"`   // 持续超过后停止新分配(默认60)
	CapacityWindowSec   int     `yaml:"capacity_window_sec"`   // 指标窗口(默认120)
	CapacitySustainSec  int     `yaml:"capacity_sustain_sec"`  // 超载持续时间(默认120)
	CapacityRecoverySec int     `yaml:"capacity_recovery_sec"` // 恢复低水位持续时间(默认180)
	CapacityCooldownSec int     `yaml:"capacity_cooldown_sec"` // 满载后的最短冷却(默认300)
	MinDiskFreeBytes    int64   `yaml:"min_disk_free_bytes"`   // 真实磁盘和配额各自保留字节
	MaxOnlineUsers      int     `yaml:"max_online_users"`      // 新分配硬门槛
	MaxTaskQueueDepth   int     `yaml:"max_task_queue_depth"`  // 新分配硬门槛
	HeartbeatTimeoutSec int     `yaml:"heartbeat_timeout_sec"` // 心跳超时判离线(默认45)
}

// TicketPolicy 票据策略。
type TicketPolicy struct {
	TTLSec int `yaml:"ttl_sec"` // 默认60
}

// ActivityPolicy controls the generation-fenced single-writer lease. It is
// separate from ticket lifetime: a short handoff secret must not silently
// shorten or lengthen an authenticated browser activity lease.
type ActivityPolicy struct {
	LeaseTTLSec int `yaml:"lease_ttl_sec"` // 默认900
}

// BackupPolicy 备份策略。
type BackupPolicy struct {
	OfflineGraceMin     int  `yaml:"offline_grace_min"`     // 离线保护期(默认12)
	UnprotectedAlertMin int  `yaml:"unprotected_alert_min"` // 未保护持续多久后告警(默认60)
	RetainVersions      int  `yaml:"retain_versions"`       // 固定为1: 仅最新成功副本
	ZstdLevel           int  `yaml:"zstd_level"`            // 默认3
	RetryMax            int  `yaml:"retry_max"`             // 默认3
	AbortOnLogin        bool `yaml:"abort_on_user_login"`   // 默认true
}

// OAuthConfig 第三方登录。
type OAuthConfig struct {
	Discord OAuthProvider `yaml:"discord"`
	LinuxDo OAuthProvider `yaml:"linuxdo"`
}

// OAuthProvider 单个 OAuth 提供方。
type OAuthProvider struct {
	Enabled      bool   `yaml:"enabled"`
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
	CallbackURL  string `yaml:"callback_url"`
	// LinuxDo 专用
	AuthURL     string `yaml:"auth_url"`
	TokenURL    string `yaml:"token_url"`
	UserInfoURL string `yaml:"user_info_url"`
	// Discord 公会校验
	GuildID string `yaml:"guild_id"`
}

// AdminConfig 管理员。
type AdminConfig struct {
	Username    string `yaml:"username"`
	PasswordEnv string `yaml:"password_env"` // 仅首次引导；明文只从环境变量读取
}

// RelayConfig is a separately-listened, short-lived ciphertext spool used
// only after a direct Agent-to-Agent transfer has failed. PublicURL must be
// HTTPS outside loopback; the Controller never receives either endpoint's
// ephemeral private key.
type RelayConfig struct {
	Listen        string `yaml:"listen"`
	PublicURL     string `yaml:"public_url"`
	DataDir       string `yaml:"data_dir"`
	TLSCertFile   string `yaml:"tls_cert_file"`
	TLSKeyFile    string `yaml:"tls_key_file"`
	MaxBytes      int64  `yaml:"max_bytes"`
	RetentionMin  int    `yaml:"retention_min"`
	MaxConcurrent int    `yaml:"max_concurrent"`
}

// ---------- 子控配置 ----------

// AgentConfig 子控配置。
type AgentConfig struct {
	ControllerURL        string              `yaml:"controller_url"`               // 总控地址
	Listen               string              `yaml:"listen"`                       // 子控监听 127.0.0.1:9100
	Role                 string              `yaml:"role"`                         // compute|storage
	NodeID               int64               `yaml:"node_id"`                      // 注册后写入
	AgentPSK             string              `yaml:"agent_psk"`                    // 注册后写入
	TavernAdapterPSK     string              `yaml:"tavern_adapter_psk,omitempty"` // 本机 adapter 独立密钥
	CredentialVersion    int64               `yaml:"credential_version"`
	ControllerGeneration int64               `yaml:"controller_generation"`
	TavernDir            string              `yaml:"tavern_dir"`          // 酒馆安装目录(含 config.yaml/data)
	TavernURL            string              `yaml:"tavern_url"`          // 酒馆本地地址 http://127.0.0.1:8000
	TransferPublicURL    string              `yaml:"transfer_public_url"` // 可选 HTTPS 直连数据面地址
	TLSCertFile          string              `yaml:"tls_cert_file"`       // 非 loopback 监听必须配置
	TLSKeyFile           string              `yaml:"tls_key_file"`
	BackupDir            string              `yaml:"backup_dir"`       // 存储节点备份存放目录
	DiskQuotaBytes       int64               `yaml:"disk_quota_bytes"` // 0 表示使用数据分区总容量
	HeartbeatSec         int                 `yaml:"heartbeat_sec"`    // 默认15
	DataDir              string              `yaml:"data_dir"`         // 子控自身数据目录(状态/临时)
	Disaster             AgentDisasterPolicy `yaml:"disaster"`
	ConfigPath           string              `yaml:"-"`
}

// AgentDisasterPolicy controls the conservative controller-loss state
// machine. Independent mode needs both a sustained heartbeat outage and a
// sustained failure of the controller health probe; a single flaky request
// can therefore never open native logins.
type AgentDisasterPolicy struct {
	UnreachableAfterSec  int      `yaml:"unreachable_after_sec"`
	IndependentAfterSec  int      `yaml:"independent_after_sec"`
	MinFailedHeartbeats  int      `yaml:"min_failed_heartbeats"`
	PeerWitnessURLs      []string `yaml:"peer_witness_urls,omitempty"`
	PeerWitnessSecretEnv string   `yaml:"peer_witness_secret_env,omitempty"`
}

// Default 总控默认配置。
func DefaultController() *ControllerConfig {
	return &ControllerConfig{
		PublicURL:    "http://127.0.0.1:8080",
		Listen:       "127.0.0.1:8080",
		DatabaseURL:  "postgres://postgres:postgres@127.0.0.1:5432/stcontrol?sslmode=disable",
		SecretKeyEnv: "CONTROLLER_SECRET_KEY",
		StaticDir:    "./web/dist",
		Node: NodePolicy{
			RegisterCPU: 50, RegisterMem: 50, RegisterDisk: 50,
			AllocationHardPct: 60, CapacityWindowSec: 120, CapacitySustainSec: 120,
			CapacityRecoverySec: 180, CapacityCooldownSec: 300,
			MinDiskFreeBytes: 5 << 30, MaxOnlineUsers: 500, MaxTaskQueueDepth: 50,
			HeartbeatTimeoutSec: 45,
		},
		Ticket:   TicketPolicy{TTLSec: 60},
		Activity: ActivityPolicy{LeaseTTLSec: 15 * 60},
		Backup: BackupPolicy{
			OfflineGraceMin: 12, UnprotectedAlertMin: 60, RetainVersions: 1,
			ZstdLevel: 3, RetryMax: 3, AbortOnLogin: true,
		},
		Admin: AdminConfig{Username: "admin", PasswordEnv: "CONTROLLER_BOOTSTRAP_ADMIN_PASSWORD"},
		Relay: RelayConfig{
			DataDir: "./controller-relay-data", MaxBytes: 110 << 30,
			RetentionMin: 720, MaxConcurrent: 4,
		},
		ControllerBackup: ControllerDisasterBackupPolicy{
			Enabled: true, IntervalSec: 24 * 3600, RetryMax: 3, KeepLatestOnly: true, PgDump: true,
		},
		ImportScan: ImportScanPolicy{
			Enabled: false, IntervalSec: 6 * 3600, MaxNodesPerRun: 2,
		},
		AISupervisor: AISupervisorPolicy{
			Enabled: false, Mode: "shadow", Provider: "openai_compatible",
			APIKeyEnv: "STCONTROL_AI_API_KEY", TimeoutMS: 5000, InspectEverySec: 600,
			AutoAdoptMinConfidence: 0.8,
		},
	}
}

// DefaultAgent 子控默认配置。
func DefaultAgent() *AgentConfig {
	return &AgentConfig{
		Listen:       "127.0.0.1:9100",
		Role:         "compute",
		TavernURL:    "http://127.0.0.1:8000",
		HeartbeatSec: 15,
		DataDir:      "./agent-data",
		BackupDir:    "./agent-data/backups",
		Disaster: AgentDisasterPolicy{
			UnreachableAfterSec:  45,
			IndependentAfterSec:  15 * 60,
			MinFailedHeartbeats:  4,
			PeerWitnessSecretEnv: "STCONTROL_PEER_WITNESS_PSK",
		},
	}
}

// Load 读取 YAML 配置（不存在则用默认值并写出一份模板）。
func Load(path string, out any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// 写出默认模板
			b, merr := yaml.Marshal(out)
			if merr == nil {
				_ = os.WriteFile(path, b, 0o600)
			}
			return nil
		}
		return err
	}
	if err := yaml.Unmarshal(data, out); err != nil {
		return fmt.Errorf("parse config %s: %w", path, err)
	}
	return nil
}

// Save 把配置写回 YAML 文件（如子控注册后保存 node_id/agent_psk）。
func Save(path string, in any) error {
	b, err := yaml.Marshal(in)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}
