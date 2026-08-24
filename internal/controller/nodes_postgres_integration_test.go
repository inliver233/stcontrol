package controller

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"stcontrol/internal/config"
	"stcontrol/internal/store"
)

func TestMyNodesRequiresExactImmutableRecoveryPointPostgres(t *testing.T) {
	if testing.Short() {
		t.Skip("Controller node read-model PostgreSQL integration is disabled in short mode")
	}
	dsn, cleanupSchema := newControllerBackupPostgresSchema(t)
	t.Cleanup(cleanupSchema)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	st, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open isolated node read-model store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	home := createControllerBackupNode(t, ctx, st, "my-nodes-home", "compute", false, 1)
	archive := createControllerBackupNode(t, ctx, st, "my-nodes-archive", "storage", true, 1)
	unboundHot := createControllerBackupNode(t, ctx, st, "my-nodes-unbound-hot", "compute", false, 1)
	boundHot := createControllerBackupNode(t, ctx, st, "my-nodes-bound-hot", "compute", false, 1)
	user := createControllerBackupUser(t, ctx, st, home.ID, "my-nodes-user")
	now := time.Now().UTC().Truncate(time.Microsecond)
	for _, replica := range []struct {
		nodeID      int64
		kind, state string
		version     int64
	}{
		{home.ID, "home", "ready", 9},
		{archive.ID, "archive", "ready", 8},
		{unboundHot.ID, "hot_standby", "ready", 7},
		{boundHot.ID, "hot_standby", "ready", 8},
	} {
		if _, err := st.DB.ExecContext(ctx, `
			INSERT INTO user_replicas (user_id,node_id,kind,data_version,state,last_sync_at,checksum,size_bytes)
			VALUES ($1,$2,$3,$4,$5,$6,'safe-checksum',128)`,
			user.ID, replica.nodeID, replica.kind, replica.version, replica.state, now.Add(-time.Hour)); err != nil {
			t.Fatalf("seed %s replica on node %d: %v", replica.kind, replica.nodeID, err)
		}
	}
	for _, nodeID := range []int64{unboundHot.ID, boundHot.ID} {
		if _, err := st.DB.ExecContext(ctx, `
			INSERT INTO node_accounts (user_id,node_id,local_handle,status,verified_at,updated_at)
			VALUES ($1,$2,$3,'active',$4,$4)`, user.GlobalID, nodeID, user.Username, now); err != nil {
			t.Fatalf("seed active hot-standby account on node %d: %v", nodeID, err)
		}
	}

	workflowID := "75200000-0000-4000-8000-000000000001"
	operationID := "75200000-0000-4000-8000-000000000002"
	snapshotID := "75200000-0000-4000-8000-000000000003"
	digest := sha256.Sum256([]byte("my-nodes-bound-hot-recovery"))
	if _, err := st.DB.ExecContext(ctx, `
		INSERT INTO workflows (
		  id,operation_id,workflow_type,state,user_id,source_node_id,target_node_id,
		  activity_epoch,controller_generation,created_at,updated_at,finished_at
		) VALUES ($1,$2,'snapshot','succeeded',$3,$4,$5,9,1,$6,$6,$6)`,
		workflowID, operationID, user.GlobalID, home.ID, boundHot.ID, now); err != nil {
		t.Fatalf("seed immutable hot-standby workflow: %v", err)
	}
	if _, err := st.DB.ExecContext(ctx, `
		INSERT INTO snapshot_manifests (
		  id,workflow_id,user_id,source_node_id,activity_epoch,format_version,
		  manifest_sha256,archive_sha256,file_count,total_bytes,state,created_at
		) VALUES ($1,$2,$3,$4,9,1,$5,$5,1,128,'immutable',$6)`,
		snapshotID, workflowID, user.GlobalID, home.ID, digest[:], now); err != nil {
		t.Fatalf("seed immutable hot-standby manifest: %v", err)
	}
	if _, err := st.DB.ExecContext(ctx, `
		INSERT INTO replica_copies (
		  id,user_id,node_id,snapshot_id,replica_kind,state,origin,is_authoritative,
		  compatibility_state,published_at,verified_at,created_at,updated_at
		) VALUES (gen_random_uuid(),$1,$2,$3,'hot_standby','ready','configured',false,
		  'compatible',$4,$4,$4,$4)`, user.GlobalID, boundHot.ID, snapshotID, now); err != nil {
		t.Fatalf("bind hot standby to immutable recovery point: %v", err)
	}

	server := New(config.DefaultController(), st, []byte("0123456789abcdef0123456789abcdef"))
	unauthorized := httptest.NewRecorder()
	server.handleMyNodes(unauthorized, httptest.NewRequest(http.MethodGet, "/api/users/me/nodes", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated my-nodes status=%d body=%s", unauthorized.Code, unauthorized.Body.String())
	}

	request := httptest.NewRequest(http.MethodGet, "/api/users/me/nodes", nil)
	request = request.WithContext(context.WithValue(request.Context(), ctxUser, user.ID))
	recorder := httptest.NewRecorder()
	server.handleMyNodes(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("my-nodes status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Nodes []myNode `json:"nodes"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode my-nodes: %v body=%s", err, recorder.Body.String())
	}
	if len(response.Nodes) != 3 {
		t.Fatalf("my-nodes exposed archive or omitted compute replica: %+v", response.Nodes)
	}
	byID := make(map[int64]myNode, len(response.Nodes))
	for _, node := range response.Nodes {
		byID[node.NodeID] = node
	}
	if got := byID[home.ID]; !got.Ready || got.RequiresTakeover || got.KindLabel != "我的服务器" || got.LastSyncedAt == nil {
		t.Fatalf("home node projection=%+v", got)
	}
	if got := byID[unboundHot.ID]; got.Ready || !got.RequiresTakeover || got.LastSyncedAt != nil {
		t.Fatalf("unbound hot standby projection=%+v", got)
	}
	if got := byID[boundHot.ID]; !got.Ready || !got.RequiresTakeover || got.LastSyncedAt == nil || !got.LastSyncedAt.Equal(now) {
		t.Fatalf("bound hot standby projection=%+v, want recovery=%s", got, now)
	}
	if _, exposed := byID[archive.ID]; exposed {
		t.Fatal("pure storage archive was exposed as a login node")
	}
}
