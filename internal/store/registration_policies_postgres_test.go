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
