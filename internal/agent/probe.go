package agent

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"gopkg.in/yaml.v3"
	"stcontrol/internal/protocol"
)

// tavernConfig 酒馆 config.yaml 的关键字段（只读需要的）。
type tavernConfig struct {
	Port     int    `yaml:"port"`
	DataRoot string `yaml:"dataRoot"`
	Listen   bool   `yaml:"listen"`
}

// ProbeTavern 探测酒馆安装信息：端口、数据目录、版本。
func ProbeTavern(tavernDir string) (*protocol.NodeInfo, error) {
	info := &protocol.NodeInfo{
		OS:   runtime.GOOS,
		Arch: runtime.GOARCH,
	}

	cfgPath := filepath.Join(tavernDir, "config.yaml")
	data, err := os.ReadFile(cfgPath)
	if err == nil {
		var tc tavernConfig
		if yerr := yaml.Unmarshal(data, &tc); yerr == nil {
			info.TavernPort = tc.Port
			dataRoot := tc.DataRoot
			if dataRoot == "" {
				dataRoot = "./data"
			}
			if !filepath.IsAbs(dataRoot) {
				dataRoot = filepath.Join(tavernDir, dataRoot)
			}
			info.DataRoot = dataRoot
		}
	}
	if info.TavernPort == 0 {
		info.TavernPort = 8000
	}

	// 版本: 读 package.json
	pkgPath := filepath.Join(tavernDir, "package.json")
	if pdata, err := os.ReadFile(pkgPath); err == nil {
		if v := extractJSONString(pdata, "version"); v != "" {
			info.TavernVersion = v
		}
	}

	return info, nil
}

// extractJSONString 极简提取 JSON 顶层字符串字段（避免引入完整解析）。
func extractJSONString(data []byte, key string) string {
	s := string(data)
	needle := `"` + key + `"`
	i := strings.Index(s, needle)
	if i < 0 {
		return ""
	}
	rest := s[i+len(needle):]
	c := strings.Index(rest, `"`)
	if c < 0 {
		return ""
	}
	rest = rest[c+1:]
	e := strings.Index(rest, `"`)
	if e < 0 {
		return ""
	}
	return rest[:e]
}

// CollectMetrics 采集系统负载（CPU/内存/磁盘百分比）。
// 使用 gopsutil, 跨平台。
func CollectMetrics(dataDir string) (cpu, mem, disk float64, err error) {
	return collectMetricsImpl(dataDir)
}
