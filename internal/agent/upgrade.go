package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"stcontrol/internal/protocol"
)

const (
	maxAgentArtifactBytes = 128 << 20
	agentUpgradeService   = "stcontrol-agent.service"
)

type preparedAgentUpgrade struct {
	CommandID     string `json:"command_id"`
	TargetVersion string `json:"target_version"`
	SHA256        string `json:"sha256"`
	TargetPath    string `json:"target_path"`
	StagedPath    string `json:"staged_path"`
	UpdaterPath   string `json:"updater_path"`
	MetadataPath  string `json:"metadata_path"`
	Scheduled     bool   `json:"scheduled"`
}

type ApplyAgentUpgradeParams struct {
	TargetPath    string
	StagedPath    string
	UpdaterPath   string
	MetadataPath  string
	ExpectedSHA   string
	TargetVersion string
	Service       string
	Delay         time.Duration
}

func (a *Agent) prepareAndScheduleAgentUpgrade(
	ctx context.Context,
	commandID string,
	req protocol.AgentUpgradeRequest,
) (protocol.AgentUpgradeReceipt, error) {
	if a == nil || a.Cfg == nil || !validUUID(commandID) ||
		!validAgentVersion(req.TargetVersion) || compareAgentVersions(req.TargetVersion, Version) <= 0 {
		return protocol.AgentUpgradeReceipt{}, fmt.Errorf("invalid Agent upgrade request")
	}
	if runtime.GOOS != "linux" || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		return protocol.AgentUpgradeReceipt{}, fmt.Errorf("unsupported Agent platform")
	}
	baseURL, err := trustedControllerArtifactURL(a.Cfg.ControllerURL, runtime.GOARCH)
	if err != nil {
		return protocol.AgentUpgradeReceipt{}, err
	}
	expectedSHA, err := a.downloadAgentChecksum(ctx, baseURL+".sha256")
	if err != nil {
		return protocol.AgentUpgradeReceipt{}, err
	}
	executable, err := os.Executable()
	if err != nil {
		return protocol.AgentUpgradeReceipt{}, err
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil || !filepath.IsAbs(executable) {
		return protocol.AgentUpgradeReceipt{}, fmt.Errorf("resolve Agent executable")
	}
	directory := filepath.Dir(executable)
	shortID := strings.ReplaceAll(commandID, "-", "")[:16]
	stagedPath := filepath.Join(directory, ".stcontrol-agent.update-"+shortID)
	updaterPath := filepath.Join(directory, ".stcontrol-agent.updater-"+shortID)
	if err := a.downloadAgentArtifact(ctx, baseURL, stagedPath, expectedSHA); err != nil {
		return protocol.AgentUpgradeReceipt{}, err
	}
	if err := verifyAgentBinaryVersion(stagedPath, req.TargetVersion); err != nil {
		_ = os.Remove(stagedPath)
		return protocol.AgentUpgradeReceipt{}, err
	}
	if err := copyExecutable(executable, updaterPath); err != nil {
		_ = os.Remove(stagedPath)
		return protocol.AgentUpgradeReceipt{}, err
	}
	metadataDir, err := filepath.Abs(filepath.Join(a.Cfg.DataDir, "agent-upgrades"))
	if err != nil {
		return protocol.AgentUpgradeReceipt{}, err
	}
	if err := os.MkdirAll(metadataDir, 0o700); err != nil {
		return protocol.AgentUpgradeReceipt{}, err
	}
	metadataPath := filepath.Join(metadataDir, commandID+".json")
	prepared := preparedAgentUpgrade{
		CommandID: commandID, TargetVersion: req.TargetVersion, SHA256: expectedSHA,
		TargetPath: executable, StagedPath: stagedPath, UpdaterPath: updaterPath,
		MetadataPath: metadataPath, Scheduled: true,
	}
	if err := writePreparedAgentUpgrade(prepared); err != nil {
		return protocol.AgentUpgradeReceipt{}, err
	}
	unit := "stcontrol-agent-upgrade-" + shortID
	command := exec.CommandContext(ctx, "systemd-run", "--unit="+unit, "--collect", "--property=Type=exec",
		updaterPath, "--apply-agent-update", "--upgrade-target", executable,
		"--upgrade-staged", stagedPath, "--upgrade-updater", updaterPath,
		"--upgrade-metadata", metadataPath, "--upgrade-sha256", expectedSHA,
		"--upgrade-version", req.TargetVersion, "--upgrade-service", agentUpgradeService,
		"--upgrade-delay", "15s")
	if output, err := command.CombinedOutput(); err != nil {
		return protocol.AgentUpgradeReceipt{}, fmt.Errorf("schedule Agent upgrade: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return protocol.AgentUpgradeReceipt{
		TargetVersion: req.TargetVersion, SHA256: expectedSHA, Scheduled: true,
	}, nil
}

func trustedControllerArtifactURL(controllerURL, arch string) (string, error) {
	parsed, err := url.Parse(strings.TrimRight(controllerURL, "/"))
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("invalid Controller URL")
	}
	host := parsed.Hostname()
	ip := net.ParseIP(host)
	loopback := strings.EqualFold(host, "localhost") || (ip != nil && ip.IsLoopback())
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && loopback) {
		return "", fmt.Errorf("Controller artifact URL must use HTTPS")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/") + "/dist/agent-linux-" + arch
	return parsed.String(), nil
}

func (a *Agent) downloadAgentChecksum(ctx context.Context, rawURL string) (string, error) {
	data, err := a.downloadBounded(ctx, rawURL, 4096)
	if err != nil {
		return "", err
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return "", fmt.Errorf("empty Agent checksum")
	}
	digest, err := hex.DecodeString(strings.ToLower(fields[0]))
	if err != nil || len(digest) != sha256.Size {
		return "", fmt.Errorf("invalid Agent checksum")
	}
	return hex.EncodeToString(digest), nil
}

func (a *Agent) downloadAgentArtifact(ctx context.Context, rawURL, destination, expectedSHA string) error {
	data, err := a.downloadBounded(ctx, rawURL, maxAgentArtifactBytes)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(data)
	if !strings.EqualFold(hex.EncodeToString(digest[:]), expectedSHA) {
		return fmt.Errorf("Agent artifact checksum mismatch")
	}
	temporary := destination + ".tmp"
	if err := os.WriteFile(temporary, data, 0o755); err != nil {
		return err
	}
	if err := os.Rename(temporary, destination); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return nil
}

func (a *Agent) downloadBounded(ctx context.Context, rawURL string, limit int64) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	response, err := a.httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Agent artifact returned status %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("Agent artifact exceeds size limit")
	}
	return data, nil
}

func writePreparedAgentUpgrade(prepared preparedAgentUpgrade) error {
	encoded, err := json.Marshal(prepared)
	if err != nil {
		return err
	}
	temporary := prepared.MetadataPath + ".tmp"
	if err := os.WriteFile(temporary, encoded, 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, prepared.MetadataPath)
}

func copyExecutable(source, destination string) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	temporary := destination + ".tmp"
	output, err := os.OpenFile(temporary, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(output, input)
	syncErr := output.Sync()
	closeErr := output.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil {
		_ = os.Remove(temporary)
		if copyErr != nil {
			return copyErr
		}
		if syncErr != nil {
			return syncErr
		}
		return closeErr
	}
	return os.Rename(temporary, destination)
}

func verifyAgentBinaryVersion(path, expected string) error {
	output, err := exec.Command(path, "--version").CombinedOutput()
	if err != nil || strings.TrimSpace(string(output)) != expected {
		return fmt.Errorf("Agent artifact version mismatch")
	}
	return nil
}

func validAgentVersion(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 3 || len(value) > 32 {
		return false
	}
	for _, part := range parts {
		if part == "" || (len(part) > 1 && part[0] == '0') {
			return false
		}
		number, err := strconv.Atoi(part)
		if err != nil || number < 0 || number > 9999 {
			return false
		}
	}
	return true
}

func compareAgentVersions(left, right string) int {
	if !validAgentVersion(left) || !validAgentVersion(right) {
		return 0
	}
	l := strings.Split(left, ".")
	r := strings.Split(right, ".")
	for index := range l {
		lv, _ := strconv.Atoi(l[index])
		rv, _ := strconv.Atoi(r[index])
		if lv < rv {
			return -1
		}
		if lv > rv {
			return 1
		}
	}
	return 0
}

// ApplyPreparedAgentUpgrade runs only in a separate transient systemd unit.
// It never accepts a URL or shell fragment. The already-downloaded binary is
// checked again, atomically installed, and rolled back if the service cannot
// remain active after restart.
func ApplyPreparedAgentUpgrade(p ApplyAgentUpgradeParams) error {
	if p.Service != agentUpgradeService || p.TargetVersion == "" || !validAgentVersion(p.TargetVersion) ||
		!filepath.IsAbs(p.TargetPath) || !filepath.IsAbs(p.StagedPath) || !filepath.IsAbs(p.UpdaterPath) ||
		filepath.Dir(p.TargetPath) != filepath.Dir(p.StagedPath) ||
		filepath.Dir(p.TargetPath) != filepath.Dir(p.UpdaterPath) ||
		len(p.ExpectedSHA) != sha256.Size*2 {
		return fmt.Errorf("invalid Agent upgrade apply parameters")
	}
	if p.Delay > 0 {
		time.Sleep(p.Delay)
	}
	if err := verifyFileSHA256(p.StagedPath, p.ExpectedSHA); err != nil {
		return err
	}
	if err := verifyAgentBinaryVersion(p.StagedPath, p.TargetVersion); err != nil {
		return err
	}
	backupPath := p.TargetPath + ".previous"
	_ = os.Remove(backupPath)
	if err := copyExecutable(p.TargetPath, backupPath); err != nil {
		return err
	}
	if err := os.Rename(p.StagedPath, p.TargetPath); err != nil {
		return err
	}
	if err := restartAgentService(p.Service); err == nil && waitAgentServiceStable(p.Service, 45*time.Second) {
		_ = os.Remove(p.MetadataPath)
		_ = os.Remove(p.UpdaterPath)
		return nil
	}
	failedPath := p.TargetPath + ".failed-" + strconv.FormatInt(time.Now().UTC().Unix(), 10)
	_ = os.Rename(p.TargetPath, failedPath)
	if err := os.Rename(backupPath, p.TargetPath); err != nil {
		return fmt.Errorf("Agent upgrade failed and rollback could not restore binary: %w", err)
	}
	if err := restartAgentService(p.Service); err != nil {
		return fmt.Errorf("Agent upgrade rolled back but service restart failed: %w", err)
	}
	return fmt.Errorf("Agent upgrade failed health check and was rolled back")
}

func verifyFileSHA256(path, expected string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, io.LimitReader(file, maxAgentArtifactBytes+1)); err != nil {
		return err
	}
	if !strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), expected) {
		return fmt.Errorf("staged Agent checksum changed")
	}
	return nil
}

func restartAgentService(service string) error {
	output, err := exec.Command("systemctl", "restart", service).CombinedOutput()
	if err != nil {
		return fmt.Errorf("restart Agent service: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func waitAgentServiceStable(service string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	consecutive := 0
	for time.Now().Before(deadline) {
		if exec.Command("systemctl", "is-active", "--quiet", service).Run() == nil {
			consecutive++
			if consecutive >= 10 {
				return true
			}
		} else {
			consecutive = 0
		}
		time.Sleep(time.Second)
	}
	return false
}
