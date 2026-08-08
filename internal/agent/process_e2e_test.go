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
	// The acceptance workspace may run under a small filesystem quota even
	// when the host volume has ample capacity. Keep the deterministic capacity
	// reserve positive while avoiding an environment-specific false "full".
	controllerConfig.Node.MinDiskFreeBytes = 1 << 20
	controllerConfig.Node.AllocationHardPct = 99.9
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

	primary := startProcessE2ENode(t, processE2ENodeOptions{
		Sequence: 1, AllowRegister: true, Store: st, Context: ctx,
		TestRoot: testRoot, RepositoryRoot: repositoryRoot, TavernRoot: tavernRoot,
		Fixture: fixture, FixtureConfig: fixtureConfig, NodeBinary: nodeBinary,
		AgentBinary: agentBinary, ControllerURL: controllerURL,
	})
	secondary := startProcessE2ENode(t, processE2ENodeOptions{
		Sequence: 2, AllowRegister: false, Store: st, Context: ctx,
		TestRoot: testRoot, RepositoryRoot: repositoryRoot, TavernRoot: tavernRoot,
		Fixture: fixture, FixtureConfig: fixtureConfig, NodeBinary: nodeBinary,
		AgentBinary: agentBinary, ControllerURL: controllerURL,
	})
	node := primary.node
	agentProcess := primary.agentProcess

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
	agentProcess = primary.startAgent(t)
	primary.agentProcess = agentProcess
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
			rebuild.ReconciledNodes == 2 && ready, err
	}, "Controller generation rebuild did not reconcile the running Agent")
	if err := adminClient.login(ctx, "admin", adminPassword); err != nil {
		t.Fatalf("admin re-login after Controller generation change: %v", err)
	}
	thirdScan := "81000000-0000-4000-8000-000000000005"
	if response, err := adminClient.scan(ctx, node.ID, thirdScan); err != nil {
		t.Fatalf("post-rebuild Controller-Agent-Tavern scan: %v response=%s", err, response)
	}
	userClient := newProcessE2EUserClient(t, controllerURL)
	registrationOperation := "81000000-0000-4000-8000-000000000006"
	registration := processE2ERegistrationRequest{
		OperationID: registrationOperation, Username: "process-alice", DisplayName: "Process Alice",
		Password: "process-e2e-user-password", NodeID: primary.node.ID,
	}
	if status, body, err := userClient.register(ctx, registration); err != nil ||
		(status != http.StatusAccepted && status != http.StatusOK) {
		t.Fatalf("start real registration: status=%d err=%v body=%s", status, err, body)
	}
	// A new browser retries the exact operation after the original response is
	// presumed lost. The durable workflow must be reused and issue a fresh
	// pending capability rather than provisioning a second account.
	userClient = newProcessE2EUserClient(t, controllerURL)
	if err := userClient.registerUntilComplete(ctx, registration, 60*time.Second); err != nil {
		t.Fatalf("idempotent registration retry did not complete: %v", err)
	}
	registeredUser, err := st.GetUserByUsername(ctx, registration.Username)
	if err != nil || registeredUser == nil || registeredUser.HomeNodeID.Int64 != primary.node.ID {
		t.Fatalf("registered user facts=%+v err=%v", registeredUser, err)
	}
	var workflowCount, userCount int
	if err := st.DB.QueryRowContext(ctx, `SELECT count(*) FROM workflows WHERE operation_id=$1`, registrationOperation).Scan(&workflowCount); err != nil {
		t.Fatal(err)
	}
	if err := st.DB.QueryRowContext(ctx, `SELECT count(*) FROM users WHERE username=$1`, registration.Username).Scan(&userCount); err != nil {
		t.Fatal(err)
	}
	if workflowCount != 1 || userCount != 1 {
		t.Fatalf("registration replay duplicated facts: workflows=%d users=%d", workflowCount, userCount)
	}
	conflicting := registration
	conflicting.DisplayName = "Conflicting Replay"
	if status, _, err := userClient.register(ctx, conflicting); err != nil || status != http.StatusConflict {
		t.Fatalf("conflicting registration replay status=%d err=%v", status, err)
	}
	if err := st.UpsertReplica(ctx, &store.UserReplica{
		UserID: registeredUser.ID, NodeID: secondary.node.ID, Kind: "hot_standby", State: "ready",
	}); err != nil {
		t.Fatalf("authorize ready standby replica: %v", err)
	}

	firstHandoff, err := userClient.createHandoff(
		ctx, primary.node.ID, "81000000-0000-4000-8000-000000000007",
	)
	if err != nil || firstHandoff.ExistingWriter || firstHandoff.TargetNodeID != primary.node.ID {
		t.Fatalf("first writer handoff=%+v err=%v", firstHandoff, err)
	}
	wrongNodeURL := strings.TrimRight(secondary.adapterURL, "/") + "/api/users/me?stcontrol_handoff=user"
	if status, err := redeemProcessE2EHandoff(ctx, wrongNodeURL, firstHandoff.Code); err != nil || status != http.StatusForbidden {
		t.Fatalf("wrong-node redemption status=%d err=%v", status, err)
	}
	if status, err := redeemProcessE2EHandoff(ctx, firstHandoff.PostURL, firstHandoff.Code); err != nil || status != http.StatusSeeOther {
		t.Fatalf("correct-node redemption status=%d err=%v", status, err)
	}

	standbyHandoff, err := userClient.createHandoff(
		ctx, secondary.node.ID, "81000000-0000-4000-8000-000000000008",
	)
	if err != nil || !standbyHandoff.ExistingWriter || standbyHandoff.TargetNodeID != primary.node.ID ||
		!strings.HasPrefix(standbyHandoff.PostURL, primary.adapterURL) {
		t.Fatalf("standby did not route to existing writer: handoff=%+v err=%v", standbyHandoff, err)
	}
	if status, err := redeemProcessE2EHandoff(ctx, standbyHandoff.PostURL, standbyHandoff.Code); err != nil || status != http.StatusSeeOther {
		t.Fatalf("existing-writer redemption status=%d err=%v", status, err)
	}
	if status, err := redeemProcessE2EHandoff(ctx, standbyHandoff.PostURL, standbyHandoff.Code); err != nil || status != http.StatusForbidden {
		t.Fatalf("one-use handoff replay status=%d err=%v", status, err)
	}

	// No process output may reveal the enrollment/controller credential.
	logs := controllerProcess.output.String() + agentProcess.output.String() + secondary.agentProcess.output.String() +
		primary.adapterProcess.output.String() + secondary.adapterProcess.output.String()
	if strings.Contains(logs, primary.initialAgentPSK) || strings.Contains(logs, secondary.initialAgentPSK) {
		t.Fatal("process logs exposed the Agent credential")
	}
}

type processE2ENodeOptions struct {
	Sequence       int
	AllowRegister  bool
	Store          *store.Store
	Context        context.Context
	TestRoot       string
	RepositoryRoot string
	TavernRoot     string
	Fixture        string
	FixtureConfig  string
	NodeBinary     string
	AgentBinary    string
	ControllerURL  string
}

type processE2ENode struct {
	node            *store.Node
	agentBinary     string
	agentConfigPath string
	repositoryRoot  string
	adapterURL      string
	initialAgentPSK string
	agentProcess    *processE2EChild
	adapterProcess  *processE2EChild
}

func startProcessE2ENode(t *testing.T, options processE2ENodeOptions) *processE2ENode {
	t.Helper()
	if options.Sequence <= 0 || options.Store == nil {
		t.Fatal("invalid process node options")
	}
	node := &store.Node{
		Name: fmt.Sprintf("process-compute-%d", options.Sequence), Role: "compute", Status: "pending",
		AllowRegister: options.AllowRegister,
	}
	if err := options.Store.CreateNode(options.Context, node); err != nil {
		t.Fatalf("create process node %d: %v", options.Sequence, err)
	}
	enrollmentToken := fmt.Sprintf("process-e2e-one-use-enrollment-token-%d", options.Sequence)
	tokenHash := sha256.Sum256([]byte(enrollmentToken))
	id := fmt.Sprintf("81000000-0000-4000-8000-%012d", options.Sequence*10+1)
	operationID := fmt.Sprintf("81000000-0000-4000-8000-%012d", options.Sequence*10+2)
	if err := options.Store.CreateEnrollmentToken(options.Context, store.CreateEnrollmentTokenParams{
		ID: id, OperationID: operationID, TokenHash: tokenHash[:], ExpectedNodeID: node.ID,
		ExpectedRole: "compute", ExpiresAt: time.Now().UTC().Add(10 * time.Minute), Now: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("create process enrollment %d: %v", options.Sequence, err)
	}

	nodeRoot := filepath.Join(options.TestRoot, fmt.Sprintf("node-%d", options.Sequence))
	tavernDir := filepath.Join(nodeRoot, "tavern")
	if err := os.MkdirAll(tavernDir, 0o700); err != nil {
		t.Fatal(err)
	}
	tavernConfigPath := filepath.Join(tavernDir, "config.yaml")
	copyProcessE2EFile(t, options.FixtureConfig, tavernConfigPath)
	copyProcessE2EFile(t, filepath.Join(options.TavernRoot, "package.json"), filepath.Join(tavernDir, "package.json"))
	agentConfigPath := filepath.Join(nodeRoot, "agent.yaml")
	agentConfig := config.DefaultAgent()
	agentConfig.ControllerURL = options.ControllerURL
	agentConfig.Listen = fmt.Sprintf("127.0.0.1:%d", reserveProcessE2EPort(t))
	agentConfig.TavernDir = tavernDir
	agentConfig.DataDir = filepath.Join(nodeRoot, "agent-data")
	agentConfig.BackupDir = filepath.Join(nodeRoot, "agent-backups")
	agentConfig.HeartbeatSec = 1
	if err := config.Save(agentConfigPath, agentConfig); err != nil {
		t.Fatalf("write initial Agent %d config: %v", options.Sequence, err)
	}
	register := exec.Command(options.AgentBinary,
		"--config", agentConfigPath, "--register", "--token", enrollmentToken,
		"--controller", options.ControllerURL, "--role", "compute", "--tavern-dir", tavernDir,
	)
	register.Dir = options.RepositoryRoot
	register.Env = os.Environ()
	if output, err := register.CombinedOutput(); err != nil {
		t.Fatalf("register Agent %d process: %v\n%s", options.Sequence, err, output)
	}
	if err := config.Load(agentConfigPath, agentConfig); err != nil {
		t.Fatalf("load enrolled Agent %d config: %v", options.Sequence, err)
	}
	if agentConfig.NodeID != node.ID || agentConfig.AgentPSK == "" ||
		agentConfig.TavernAdapterPSK != agentConfig.AgentPSK || agentConfig.ControllerGeneration <= 0 {
		t.Fatalf("incomplete enrolled Agent %d identity: node=%d generation=%d",
			options.Sequence, agentConfig.NodeID, agentConfig.ControllerGeneration)
	}
	assertProcessE2ETavernMount(
		t, tavernConfigPath, node.ID, options.ControllerURL, "http://"+agentConfig.Listen, agentConfig.AgentPSK,
	)

	adapterDataRoot := filepath.Join(tavernDir, "data")
	if err := os.MkdirAll(adapterDataRoot, 0o700); err != nil {
		t.Fatalf("create Tavern data root %d: %v", options.Sequence, err)
	}
	adapterPortFile := filepath.Join(nodeRoot, "adapter.port")
	adapterProcess := startProcessE2EChild(
		t, fmt.Sprintf("tavern-adapter-%d", options.Sequence), options.NodeBinary, []string{options.Fixture},
		options.TavernRoot, append(os.Environ(),
			"STCONTROL_E2E_DATA_ROOT="+adapterDataRoot,
			"STCONTROL_E2E_PORT_FILE="+adapterPortFile,
			"STCONTROL_E2E_CONFIG_PATH="+tavernConfigPath,
		),
	)
	adapterPort := waitForProcessE2EPortFile(t, adapterProcess, adapterPortFile, 20*time.Second)
	adapterURL := "http://127.0.0.1:" + adapterPort
	agentConfig.TavernURL = adapterURL
	if err := config.Save(agentConfigPath, agentConfig); err != nil {
		t.Fatalf("write running Agent %d config: %v", options.Sequence, err)
	}
	node.BaseURL = adapterURL
	if err := options.Store.UpdateNodeSettings(options.Context, node); err != nil {
		t.Fatalf("publish process node %d base URL: %v", options.Sequence, err)
	}
	harness := &processE2ENode{
		node: node, agentBinary: options.AgentBinary, agentConfigPath: agentConfigPath,
		repositoryRoot: options.RepositoryRoot, adapterURL: adapterURL,
		initialAgentPSK: agentConfig.AgentPSK, adapterProcess: adapterProcess,
	}
	harness.agentProcess = harness.startAgent(t)
	waitForProcessE2ENodeReady(t, options.Store, node.ID, 45*time.Second)
	return harness
}

func (node *processE2ENode) startAgent(t *testing.T) *processE2EChild {
	t.Helper()
	return startProcessE2EChild(
		t, "agent-"+node.node.Name, node.agentBinary, []string{"--config", node.agentConfigPath},
		node.repositoryRoot, os.Environ(),
	)
}

type processE2ERegistrationRequest struct {
	OperationID string `json:"operation_id"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	Password    string `json:"password"`
	NodeID      int64  `json:"node_id"`
}

type processE2EHandoff struct {
	PostURL        string `json:"post_url"`
	Code           string `json:"code"`
	TargetNodeID   int64  `json:"target_node_id"`
	ExistingWriter bool   `json:"existing_writer"`
}

type processE2EUserClient struct {
	baseURL string
	client  *http.Client
	csrf    string
}

func newProcessE2EUserClient(t *testing.T, baseURL string) *processE2EUserClient {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &processE2EUserClient{baseURL: baseURL, client: &http.Client{Jar: jar, Timeout: 30 * time.Second}}
}

func (client *processE2EUserClient) register(
	ctx context.Context,
	registration processE2ERegistrationRequest,
) (int, []byte, error) {
	encoded, err := json.Marshal(registration)
	if err != nil {
		return 0, nil, err
	}
	request, err := http.NewRequestWithContext(
		ctx, http.MethodPost, client.baseURL+"/api/auth/register", bytes.NewReader(encoded),
	)
	if err != nil {
		return 0, nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", client.baseURL)
	response, err := client.client.Do(request)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	client.refreshCSRF()
	return response.StatusCode, data, err
}

func (client *processE2EUserClient) registerUntilComplete(
	ctx context.Context,
	registration processE2ERegistrationRequest,
	timeout time.Duration,
) error {
	status, body, err := client.register(ctx, registration)
	if err != nil {
		return err
	}
	if status == http.StatusOK {
		return nil
	}
	if status != http.StatusAccepted {
		return fmt.Errorf("registration status %d: %s", status, body)
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		request, err := http.NewRequestWithContext(
			ctx, http.MethodGet, client.baseURL+"/api/auth/registration/status", nil,
		)
		if err != nil {
			return err
		}
		response, err := client.client.Do(request)
		if err != nil {
			return err
		}
		data, readErr := io.ReadAll(io.LimitReader(response.Body, 64<<10))
		_ = response.Body.Close()
		if readErr != nil {
			return readErr
		}
		client.refreshCSRF()
		if response.StatusCode == http.StatusOK {
			return nil
		}
		if response.StatusCode != http.StatusAccepted {
			return fmt.Errorf("registration poll status %d: %s", response.StatusCode, data)
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("registration completion timed out")
}

func (client *processE2EUserClient) createHandoff(
	ctx context.Context,
	nodeID int64,
	operationID string,
) (processE2EHandoff, error) {
	if client.csrf == "" {
		return processE2EHandoff{}, fmt.Errorf("user CSRF cookie missing")
	}
	encoded, _ := json.Marshal(map[string]any{"node_id": nodeID, "operation_id": operationID})
	request, err := http.NewRequestWithContext(
		ctx, http.MethodPost, client.baseURL+"/api/login/redirect", bytes.NewReader(encoded),
	)
	if err != nil {
		return processE2EHandoff{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", client.baseURL)
	request.Header.Set("X-CSRF-Token", client.csrf)
	response, err := client.client.Do(request)
	if err != nil {
		return processE2EHandoff{}, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	if err != nil {
		return processE2EHandoff{}, err
	}
	if response.StatusCode != http.StatusOK {
		return processE2EHandoff{}, fmt.Errorf("handoff status %d: %s", response.StatusCode, data)
	}
	var handoff processE2EHandoff
	if err := json.Unmarshal(data, &handoff); err != nil {
		return processE2EHandoff{}, err
	}
	if handoff.Code == "" || handoff.PostURL == "" || handoff.TargetNodeID <= 0 {
		return processE2EHandoff{}, fmt.Errorf("incomplete handoff: %s", data)
	}
	return handoff, nil
}

func (client *processE2EUserClient) refreshCSRF() {
	parsed, err := url.Parse(client.baseURL)
	if err != nil {
		return
	}
	for _, cookie := range client.client.Jar.Cookies(parsed) {
		if cookie.Name == "stcontrol_csrf" {
			client.csrf = cookie.Value
			return
		}
	}
}

func redeemProcessE2EHandoff(ctx context.Context, endpoint, code string) (int, error) {
	encoded, _ := json.Marshal(map[string]string{"stcontrol_code": code})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(encoded))
	if err != nil {
		return 0, err
	}
	request.Header.Set("Content-Type", "application/json")
	client := &http.Client{
		Timeout:       15 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}
	response, err := client.Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	return response.StatusCode, nil
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

func assertProcessE2ETavernMount(
	t *testing.T,
	path string,
	nodeID int64,
	controllerURL, agentURL, psk string,
) {
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
			AgentURL             string `yaml:"agentUrl"`
			ControllerGeneration int64  `yaml:"controllerGeneration"`
		} `yaml:"stcontrol"`
	}
	if err := yaml.Unmarshal(data, &mounted); err != nil {
		t.Fatalf("decode mounted SillyTavern config: %v", err)
	}
	if !mounted.STControl.Enabled || mounted.STControl.NodeID != nodeID ||
		mounted.STControl.AgentPSK != psk || mounted.STControl.ControllerURL != controllerURL ||
		mounted.STControl.AgentURL != agentURL ||
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
