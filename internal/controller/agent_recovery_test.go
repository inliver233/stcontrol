package controller

import (
	"reflect"
	"testing"

	"stcontrol/internal/protocol"
)

func TestRecoveryHeartbeatAcknowledgesTakeoversOnlyAfterDurableRecord(t *testing.T) {
	t.Parallel()
	takeovers := []protocol.IndependentTakeover{
		{OperationID: "11111111-1111-4111-8111-111111111111"},
		{OperationID: "22222222-2222-4222-8222-222222222222"},
	}
	if got := durableTakeoverAcknowledgements(takeovers, false); got != nil {
		t.Fatalf("recovery-only heartbeat acknowledged unrecorded takeovers: %v", got)
	}
	want := []string{takeovers[0].OperationID, takeovers[1].OperationID}
	if got := durableTakeoverAcknowledgements(takeovers, true); !reflect.DeepEqual(got, want) {
		t.Fatalf("durable acknowledgements=%v, want %v", got, want)
	}
}
