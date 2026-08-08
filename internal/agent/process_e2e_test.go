package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lib/pq"
	"gopkg.in/yaml.v3"
	"stcontrol/internal/config"
	"stcontrol/internal/store"
)

const processE2EPostgresDSNEnv = "STCONTROL_TEST_POSTGRES_DSN"

// TestControllerAgentTavernProcessesRecoverAcrossRestarts is the opt-in,
// process-level acceptance path. It deliberately crosses every transport and
// persistence boundary: real PostgreSQL, Controller HTTP, the outbound Agent
// command channel, and the real SillyTavern adapter. It also proves that a
// command queued while the Agent is down and a Controller generation rebuild
// both converge after their respective process restarts.
func TestControllerAgentTavernProcessesRecoverAcrossRestarts(t *testing.T) {
	if testing.Short() {
		t.Skip("process acceptance test is disabled in short mode")
	}
	if strings.TrimSpace(os.Getenv(processE2EPostgresDSNEnv)) == "" {
		t.Skipf("set %s to run the process acceptance test", processE2EPostgresDSNEnv)
	}
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go command is unavailable")
	}
	nodeBinary, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node command is unavailable")
	}

	repositoryRoot, tavernRoot := processE2ERepositoryRoots(t)
	fixture := filepath.Join(tavernRoot, "tests", "fixtures", "stcontrol-adapter-server.mjs")
	fixtureConfig := filepath.Join(tavernRoot, "tests", "fixtures", "stcontrol-config.yaml")
	for _, required := range []string{fixture, fixtureConfig} {
		if _, err := os.Stat(required); err != nil {
			t.Skipf("SillyTavern process fixture is unavailable: %v", err)
		}
	}

	dsn, cleanupSchema := newProcessE2ESchema(t)
	t.Cleanup(cleanupSchema)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	t.Cleanup(cancel)
	st, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open isolated process store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	testRoot := t.TempDir()
	binDir := filepath.Join(testRoot, "bin")
	if err := os.MkdirAll(binDir, 0o700); err != nil {
		t.Fatal(err)
	}
	executableSuffix := ""
	if runtime.GOOS == "windows" {
		executableSuffix = ".exe"
	}
	controllerBinary := filepath.Join(binDir, "controller"+executableSuffix)
	agentBinary := filepath.Join(binDir, "agent"+executableSuffix)
	buildProcessE2EBinary(t, goBinary, repositoryRoot, controllerBinary, "./cmd/controller")
	buildProcessE2EBinary(t, goBinary, repositoryRoot, agentBinary, "./cmd/agent")

	controllerPort := reserveProcessE2EPort(t)
	controllerURL := fmt.Sprintf("http://127.0.0.1:%d", controllerPort)
	controllerConfigPath := filepath.Join(testRoot, "controller.yaml")
	controllerConfig := config.DefaultController()
	controllerConfig.PublicURL = controllerURL
	controllerConfig.Listen = fmt.Sprintf("127.0.0.1:%d", controllerPort)
	controllerConfig.DatabaseURL = dsn
	controllerConfig.StaticDir = filepath.Join(testRoot, "missing-static")
	controllerConfig.Relay.Listen = ""
	controllerConfig.SecretKeyEnv = "STCONTROL_PROCESS_E2E_SECRET_KEY"
	controllerConfig.Admin.PasswordEnv = "STCONTROL_PROCESS_E2E_ADMIN_PASSWORD"
	if err := config.Save(controllerConfigPath, controllerConfig); err != nil {
		t.Fatalf("write controller config: %v", err)
	}
	controllerKey := base64.StdEncoding.EncodeToString([]byte("01234567890123456789012345678901"))
	adminPassword := "process-e2e-admin-password"
	controllerEnvironment := append(os.Environ(),
		"STCONTROL_PROCESS_E2E_SECRET_KEY="+controllerKey,
		"STCONTROL_PROCESS_E2E_ADMIN_PASSWORD="+adminPassword,
	)
	startController := func() *processE2EChild {
		child := startProcessE2EChild(
			t, "controller", controllerBinary, []string{"--config", controllerConfigPath},
			repositoryRoot, controllerEnvironment,
		)
		waitForProcessE2EHTTP(t, child, controllerURL+"/api/health", 30*time.Second)
		return child
	}
	controllerProcess := startController()

	node := &store.Node{Name: "process-compute", Role: "compute", Status: "pending"}
	if err := st.CreateNode(ctx, node); err != nil {
		t.Fatalf("create process node: %v", err)
	}
	enrollmentToken := "process-e2e-one-use-enrollment-token"
	tokenHash := sha256.Sum256([]byte(enrollmentToken))
	if err := st.CreateEnrollmentToken(ctx, store.CreateEnrollmentTokenParams{
		ID: "81000000-0000-4000-8000-000000000001", OperationID: "81000000-0000-4000-8000-000000000002",
		TokenHash: tokenHash[:], ExpectedNodeID: node.ID, ExpectedRole: "compute",
		ExpiresAt: time.Now().UTC().Add(10 * time.Minute), Now: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("create process enrollment: %v", err)
	}

	tavernDir := filepath.Join(testRoot, "tavern")
	if err := os.MkdirAll(tavernDir, 0o700); err != nil {
		t.Fatal(err)
	}
	tavernConfigPath := filepath.Join(tavernDir, "config.yaml")
	copyProcessE2EFile(t, fixtureConfig, tavernConfigPath)
	copyProcessE2EFile(t, filepath.Join(tavernRoot, "package.json"), filepath.Join(tavernDir, "package.json"))
	agentConfigPath := filepath.Join(testRoot, "agent.yaml")
	agentDataDir := filepath.Join(testRoot, "agent-data")
	agentConfig := config.DefaultAgent()
	agentConfig.ControllerURL = controllerURL
	agentConfig.Listen = fmt.Sprintf("127.0.0.1:%d", reserveProcessE2EPort(t))
	agentConfig.TavernDir = tavernDir
	agentConfig.DataDir = agentDataDir
	agentConfig.BackupDir = filepath.Join(testRoot, "agent-backups")
	agentConfig.HeartbeatSec = 1
	if err := config.Save(agentConfigPath, agentConfig); err != nil {
		t.Fatalf("write initial agent config: %v", err)
	}
	register := exec.Command(agentBinary,
		"--config", agentConfigPath, "--register", "--token", enrollmentToken,
		"--controller", controllerURL, "--role", "compute", "--tavern-dir", tavernDir,
	)
	register.Dir = repositoryRoot
	register.Env = os.Environ()
	if output, err := register.CombinedOutput(); err != nil {
		t.Fatalf("register Agent process: %v\n%s", err, output)
	}
	if err := config.Load(agentConfigPath, agentConfig); err != nil {
		t.Fatalf("load enrolled Agent config: %v", err)
	}
	if agentConfig.NodeID != node.ID || agentConfig.AgentPSK == "" ||
		agentConfig.TavernAdapterPSK != agentConfig.AgentPSK || agentConfig.ControllerGeneration <= 0 {
		t.Fatalf("incomplete enrolled Agent identity: node=%d generation=%d", agentConfig.NodeID, agentConfig.ControllerGeneration)
	}
	initialAgentPSK := agentConfig.AgentPSK
	assertProcessE2ETavernMount(t, tavernConfigPath, node.ID, controllerURL, initialAgentPSK)

	adapterDataRoot := filepath.Join(testRoot, "tavern-data")
	adapterPortFile := filepath.Join(testRoot, "adapter.port")
	adapterProcess := startProcessE2EChild(t, "tavern-adapter", nodeBinary, []string{fixture}, tavernRoot,
		append(os.Environ(),
			"STCONTROL_E2E_DATA_ROOT="+adapterDataRoot,
			"STCONTROL_E2E_PORT_FILE="+adapterPortFile,
			"STCONTROL_E2E_CONFIG_PATH="+tavernConfigPath,
		),
	)
	adapterPort := waitForProcessE2EPortFile(t, adapterProcess, adapterPortFile, 20*time.Second)
	agentConfig.TavernURL = "http://127.0.0.1:" + adapterPort
	if err := config.Save(agentConfigPath, agentConfig); err != nil {
		t.Fatalf("write running Agent config: %v", err)
	}
	startAgent := func() *processE2EChild {
		return startProcessE2EChild(
			t, "agent", agentBinary, []string{"--config", agentConfigPath}, repositoryRoot, os.Environ(),
		)
	}
	agentProcess := startAgent()
	waitForProcessE2ENodeReady(t, st, node.ID, 45*time.Second)

	adminClient := newProcessE2EAdminClient(t, controllerURL)
	if err := adminClient.login(ctx, "admin", adminPassword); err != nil {
		t.Fatalf("admin login before process scans: %v", err)
	}
	firstScan := "81000000-0000-4000-8000-000000000003"
	if response, err := adminClient.scan(ctx, node.ID, firstScan); err != nil {
		t.Fatalf("initial Controller-Agent-Tavern scan: %v response=%s", err, response)
	}

	// Queue through the Controller while the Agent process is absent. The HTTP
	// request remains pending while PostgreSQL durably owns the command.
	agentProcess.stop()
	secondScan := "81000000-0000-4000-8000-000000000004"
	type scanResult struct {
		body []byte
		err  error
	}
	scanDone := make(chan scanResult, 1)
	go func() {
		body, scanErr := adminClient.scan(ctx, node.ID, secondScan)
		scanDone <- scanResult{body: body, err: scanErr}
	}()
	waitForProcessE2ECondition(t, 15*time.Second, func() (bool, error) {
		var queued int
		err := st.DB.QueryRowContext(ctx, `
			SELECT count(*) FROM agent_commands WHERE node_id=$1 AND state='queued'`, node.ID).Scan(&queued)
		return queued > 0, err
	}, "Controller did not durably queue a command while Agent was stopped")
	agentProcess = startAgent()
	select {
	case result := <-scanDone:
		if result.err != nil {
			t.Fatalf("queued scan did not recover after Agent restart: %v response=%s\n%s", result.err, result.body, agentProcess.output.String())
		}
	case <-time.After(60 * time.Second):
		t.Fatalf("queued scan timed out after Agent restart\n%s", agentProcess.output.String())
	}

	previousGeneration, err := st.GetActiveControllerGeneration(ctx)
	if err != nil {
		t.Fatalf("read generation before Controller restart: %v", err)
	}
	controllerProcess.stop()
	controllerProcess = startController()
	waitForProcessE2ECondition(t, 60*time.Second, func() (bool, error) {
		generation, err := st.GetActiveControllerGeneration(ctx)
		if err != nil || generation <= previousGeneration {
			return false, err
		}
		rebuild, err := st.GetLatestControllerRebuild(ctx)
		if err != nil {
			return false, err
		}
		ready, err := st.IsControlPlaneReady(ctx)
		return rebuild != nil && rebuild.Generation == generation && rebuild.State == "succeeded" &&
			rebuild.ReconciledNodes == 1 && ready, err
	}, "Controller generation rebuild did not reconcile the running Agent")
	if err := adminClient.login(ctx, "admin", adminPassword); err != nil {
		t.Fatalf("admin re-login after Controller generation change: %v", err)
	}
	thirdScan := "81000000-0000-4000-8000-000000000005"
	if response, err := adminClient.scan(ctx, node.ID, thirdScan); err != nil {
		t.Fatalf("post-rebuild Controller-Agent-Tavern scan: %v response=%s", err, response)
	}

	// No process output may reveal the enrollment/controller credential.
	logs := controllerProcess.output.String() + agentProcess.output.String() + adapterProcess.output.String()
	if strings.Contains(logs, initialAgentPSK) {
		t.Fatal("process logs exposed the Agent credential")
	}
}

func processE2ERepositoryRoots(t *testing.T) (string, string) {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve process test source path")
	}
	repositoryRoot := filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
	return repositoryRoot, filepath.Clean(filepath.Join(repositoryRoot, "..", "Sillytarven-online"))
}

func newProcessE2ESchema(t *testing.T) (string, func()) {
	t.Helper()
	baseDSN := strings.TrimSpace(os.Getenv(processE2EPostgresDSNEnv))
	parsed, err := url.Parse(baseDSN)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") {
		t.Fatalf("%s must be a PostgreSQL URL: %v", processE2EPostgresDSNEnv, err)
	}
	adminDB, err := sql.Open("postgres", baseDSN)
	if err != nil {
		t.Fatalf("open PostgreSQL process database: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := adminDB.PingContext(ctx); err != nil {
		_ = adminDB.Close()
		t.Fatalf("ping PostgreSQL process database: %v", err)
	}
	schema := fmt.Sprintf("stcontrol_process_%d_%d", os.Getpid(), time.Now().UnixNano())
	if _, err := adminDB.ExecContext(ctx, `CREATE SCHEMA `+pq.QuoteIdentifier(schema)); err != nil {
		_ = adminDB.Close()
		t.Fatalf("create PostgreSQL process schema: %v", err)
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	query.Set("application_name", "stcontrol-process-e2e")
	parsed.RawQuery = query.Encode()
	return parsed.String(), func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cleanupCancel()
		if _, err := adminDB.ExecContext(cleanupCtx, `DROP SCHEMA `+pq.QuoteIdentifier(schema)+` CASCADE`); err != nil {
			t.Errorf("drop PostgreSQL process schema: %v", err)
		}
		_ = adminDB.Close()
	}
}

func buildProcessE2EBinary(t *testing.T, goBinary, root, output, target string) {
	t.Helper()
	command := exec.Command(goBinary, "build", "-o", output, target)
	command.Dir = root
	command.Env = os.Environ()
	if data, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", target, err, data)
	}
}

type processE2ESafeBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (buffer *processE2ESafeBuffer) Write(data []byte) (int, error) {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.buffer.Write(data)
}

func (buffer *processE2ESafeBuffer) String() string {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.buffer.String()
}

type processE2EChild struct {
	name     string
	command  *exec.Cmd
	output   *processE2ESafeBuffer
	finished chan struct{}
	mu       sync.Mutex
	err      error
	stopOnce sync.Once
}

func startProcessE2EChild(
	t *testing.T,
	name, executable string,
	args []string,
	directory string,
	environment []string,
) *processE2EChild {
	t.Helper()
	output := &processE2ESafeBuffer{}
	command := exec.Command(executable, args...)
	command.Dir = directory
	command.Env = environment
	command.Stdout = output
	command.Stderr = output
	child := &processE2EChild{name: name, command: command, output: output, finished: make(chan struct{})}
	if err := command.Start(); err != nil {
		t.Fatalf("start %s process: %v", name, err)
	}
	go func() {
		err := command.Wait()
		child.mu.Lock()
		child.err = err
		child.mu.Unlock()
		close(child.finished)
	}()
	t.Cleanup(child.stop)
	return child
}

func (child *processE2EChild) stop() {
	child.stopOnce.Do(func() {
		select {
		case <-child.finished:
			return
		default:
		}
		if child.command.Process != nil {
			_ = child.command.Process.Kill()
		}
		select {
		case <-child.finished:
		case <-time.After(10 * time.Second):
		}
	})
}

func (child *processE2EChild) exitError() (error, bool) {
	select {
	case <-child.finished:
		child.mu.Lock()
		defer child.mu.Unlock()
		return child.err, true
	default:
		return nil, false
	}
}

func reserveProcessE2EPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

func waitForProcessE2EHTTP(t *testing.T, child *processE2EChild, endpoint string, timeout time.Duration) {
	t.Helper()
	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		response, err := client.Get(endpoint)
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode >= 200 && response.StatusCode < 300 {
				return
			}
		}
		if processErr, exited := child.exitError(); exited {
			t.Fatalf("%s exited before readiness: %v\n%s", child.name, processErr, child.output.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("%s readiness timed out\n%s", child.name, child.output.String())
}

func waitForProcessE2EPortFile(
	t *testing.T,
	child *processE2EChild,
	path string,
	timeout time.Duration,
) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err == nil && strings.TrimSpace(string(data)) != "" {
			return strings.TrimSpace(string(data))
		}
		if processErr, exited := child.exitError(); exited {
			t.Fatalf("%s exited before readiness: %v\n%s", child.name, processErr, child.output.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("%s port-file readiness timed out\n%s", child.name, child.output.String())
	return ""
}

func waitForProcessE2ECondition(
	t *testing.T,
	timeout time.Duration,
	condition func() (bool, error),
	failure string,
) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		ready, err := condition()
		if err == nil && ready {
			return
		}
		lastErr = err
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("%s: %v", failure, lastErr)
}

func waitForProcessE2ENodeReady(t *testing.T, st *store.Store, nodeID int64, timeout time.Duration) {
	t.Helper()
	waitForProcessE2ECondition(t, timeout, func() (bool, error) {
		node, err := st.GetNodeByID(context.Background(), nodeID)
		if err != nil || node == nil {
			return false, err
		}
		ready, err := st.IsControlPlaneReady(context.Background())
		return node.ConnectivityState == "online" && node.OperationalState == "active" &&
			node.CompatibilityState == "compatible" && node.TelemetrySource == "adapter" && ready, err
	}, "Agent did not report a compatible real adapter heartbeat")
}

func copyProcessE2EFile(t *testing.T, source, destination string) {
	t.Helper()
	data, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertProcessE2ETavernMount(t *testing.T, path string, nodeID int64, controllerURL, psk string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var mounted struct {
		STControl struct {
			Enabled              bool   `yaml:"enabled"`
			NodeID               int64  `yaml:"nodeId"`
			AgentPSK             string `yaml:"agentPsk"`
			ControllerURL        string `yaml:"controllerUrl"`
			ControllerGeneration int64  `yaml:"controllerGeneration"`
		} `yaml:"stcontrol"`
	}
	if err := yaml.Unmarshal(data, &mounted); err != nil {
		t.Fatalf("decode mounted SillyTavern config: %v", err)
	}
	if !mounted.STControl.Enabled || mounted.STControl.NodeID != nodeID ||
		mounted.STControl.AgentPSK != psk || mounted.STControl.ControllerURL != controllerURL ||
		mounted.STControl.ControllerGeneration <= 0 {
		t.Fatalf("SillyTavern adapter identity was not atomically mounted: node=%d generation=%d",
			mounted.STControl.NodeID, mounted.STControl.ControllerGeneration)
	}
}

type processE2EAdminClient struct {
	baseURL string
	client  *http.Client
	csrf    string
}

func newProcessE2EAdminClient(t *testing.T, baseURL string) *processE2EAdminClient {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &processE2EAdminClient{baseURL: baseURL, client: &http.Client{Jar: jar, Timeout: 70 * time.Second}}
}

func (client *processE2EAdminClient) login(ctx context.Context, username, password string) error {
	body, _ := json.Marshal(map[string]string{"username": username, "password": password})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.baseURL+"/api/auth/admin/login", bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", client.baseURL)
	response, err := client.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d: %s", response.StatusCode, data)
	}
	parsed, _ := url.Parse(client.baseURL)
	client.csrf = ""
	for _, cookie := range client.client.Jar.Cookies(parsed) {
		if cookie.Name == "stcontrol_csrf" {
			client.csrf = cookie.Value
		}
	}
	if client.csrf == "" {
		return fmt.Errorf("CSRF cookie missing")
	}
	return nil
}

func (client *processE2EAdminClient) scan(ctx context.Context, nodeID int64, operationID string) ([]byte, error) {
	body, _ := json.Marshal(map[string]string{"operation_id": operationID})
	endpoint := fmt.Sprintf("%s/api/admin/nodes/%d/scan-existing", client.baseURL, nodeID)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", client.baseURL)
	request.Header.Set("X-CSRF-Token", client.csrf)
	response, err := client.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return data, err
	}
	if response.StatusCode != http.StatusOK {
		return data, fmt.Errorf("status %d", response.StatusCode)
	}
	var result struct {
		Batch struct {
			NodeID         int64  `json:"node_id"`
			State          string `json:"state"`
			CandidateCount int    `json:"candidate_count"`
		} `json:"batch"`
	}
	if err := json.Unmarshal(data, &result); err != nil || result.Batch.NodeID != nodeID ||
		result.Batch.State != "resolved" || result.Batch.CandidateCount != 0 {
		return data, fmt.Errorf("invalid scan result")
	}
	return data, nil
}
