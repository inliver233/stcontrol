package store

import (
	"context"
	"testing"
	"time"
)

func TestRegistrationMethodPolicyVersionFencingPostgres(t *testing.T) {
	dsn, cleanupSchema := newPostgresIntegrationSchema(t)
	defer cleanupSchema()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, err := Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open registration policy store: %v", err)
	}
	defer st.Close()

	generation, err := st.GetActiveControllerGeneration(ctx)
	if err != nil {
		t.Fatalf("read controller generation: %v", err)
	}
	nodeID := insertIntegrationNode(t, st, "registration-method-version-fence")
	now := time.Now().UTC().Truncate(time.Microsecond)
	facts := testNodeHeartbeat(now)
	facts.RegistrationPolicy = NodeRegistrationPolicy{
		State: "open", Version: 9, ExpiresAt: now.Add(time.Minute), ObservedAt: now,
		Methods: RegistrationMethodPolicies{
			"password": {Enabled: true},
		},
	}
	if err := st.UpdateNodeHeartbeat(ctx, nodeID, generation, facts, testNodeCapacityPolicy()); err != nil {
		t.Fatalf("publish initial method policy: %v", err)
	}

	facts.ObservedAt = now.Add(time.Second)
	facts.RegistrationPolicy.ObservedAt = facts.ObservedAt
	facts.RegistrationPolicy.ExpiresAt = facts.ObservedAt.Add(time.Minute)
	facts.RegistrationPolicy.Methods = RegistrationMethodPolicies{
		"discord": {Enabled: true},
	}
	if err := st.UpdateNodeHeartbeat(ctx, nodeID, generation, facts, testNodeCapacityPolicy()); err != nil {
		t.Fatalf("process reused method policy version: %v", err)
	}

	var state, errorCode string
	var methods RegistrationMethodPolicies
	if err := st.DB.QueryRowContext(ctx, `
		SELECT registration_policy_state,registration_policy_error_code,registration_methods
		FROM nodes WHERE id=$1`, nodeID).Scan(&state, &errorCode, &methods); err != nil {
		t.Fatalf("read fenced method policy: %v", err)
	}
	if state != "error" || errorCode != "version_reuse" ||
		!methods["password"].Enabled || methods["discord"].Enabled {
		t.Fatalf("reused version was not fenced: state=%q error=%q methods=%+v", state, errorCode, methods)
	}
}

func TestRegistrationMethodPolicyRecoversFromTransientErrorPostgres(t *testing.T) {
	dsn, cleanupSchema := newPostgresIntegrationSchema(t)
	defer cleanupSchema()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, err := Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open registration policy store: %v", err)
	}
	defer st.Close()

	generation, err := st.GetActiveControllerGeneration(ctx)
	if err != nil {
		t.Fatalf("read controller generation: %v", err)
	}
	nodeID := insertIntegrationNode(t, st, "registration-policy-transient-recovery")
	now := time.Now().UTC().Truncate(time.Microsecond)
	methods := RegistrationMethodPolicies{
		"discord": {Enabled: true},
	}
	facts := testNodeHeartbeat(now)
	facts.RegistrationPolicy = NodeRegistrationPolicy{
		State: "open", Version: 9, ExpiresAt: now.Add(time.Minute), ObservedAt: now,
		Methods: methods,
	}
	if err := st.UpdateNodeHeartbeat(ctx, nodeID, generation, facts, testNodeCapacityPolicy()); err != nil {
		t.Fatalf("publish initial method policy: %v", err)
	}

	facts.ObservedAt = now.Add(time.Second)
	facts.RegistrationPolicy = NodeRegistrationPolicy{
		State: "error", Version: 9, ExpiresAt: facts.ObservedAt, ObservedAt: facts.ObservedAt,
		ErrorCode: "adapter_unavailable",
	}
	if err := st.UpdateNodeHeartbeat(ctx, nodeID, generation, facts, testNodeCapacityPolicy()); err != nil {
		t.Fatalf("publish transient policy error: %v", err)
	}

	facts.ObservedAt = now.Add(2 * time.Second)
	facts.RegistrationPolicy = NodeRegistrationPolicy{
		State: "open", Version: 9, ExpiresAt: facts.ObservedAt.Add(time.Minute), ObservedAt: facts.ObservedAt,
		Methods: methods,
	}
	if err := st.UpdateNodeHeartbeat(ctx, nodeID, generation, facts, testNodeCapacityPolicy()); err != nil {
		t.Fatalf("recover trusted method policy: %v", err)
	}

	var state string
	var errorCode *string
	var storedMethods RegistrationMethodPolicies
	if err := st.DB.QueryRowContext(ctx, `
		SELECT registration_policy_state,registration_policy_error_code,registration_methods
		FROM nodes WHERE id=$1`, nodeID).Scan(&state, &errorCode, &storedMethods); err != nil {
		t.Fatalf("read recovered method policy: %v", err)
	}
	if state != "open" || errorCode != nil || !storedMethods["discord"].Enabled {
		t.Fatalf("policy did not recover: state=%q error=%v methods=%+v", state, errorCode, storedMethods)
	}
}
