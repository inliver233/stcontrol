# Architecture Review

Review scope: `origin/main..flash` in `stcontrol` plus the directly coupled `Sillytarven-online` adapter paths.

## Summary

- Total findings: 3
- Critical: 1
- High: 2
- Focus areas hit: session/lease state machine, recovery/draining state propagation, controller repair/backup scheduling boundary

## Findings

### Critical

1. `Sillytarven-online/src/stcontrol.js:973`

   Managed write admission is not atomic with the state mutation that records the request as in flight:

   ```js
   const lease = state.leases[handle];
   if (isWrite && envelope.loginMode === STCONTROL_MODES.MANAGED && (!lease || ...)) {
       return response.status(409)...
   }
   await mutateState(current => { ... current.sessions[envelope.sessionId] = session; });
   ```

   Impact: one stale managed write can pass after a concurrent lease revocation or mode flip, breaking the single-writer invariant during failover.

   Recommendation: re-run lease/gate/session validation inside the same `mutateState()` section that increments the in-flight counter, and only continue the HTTP pipeline if that atomic section returns success.

### High

1. `Sillytarven-online/src/stcontrol.js:945`

   Managed-to-independent promotion mutates the browser envelope but leaves the durable session record unchanged:

   ```js
   if (state.mode === STCONTROL_MODES.INDEPENDENT && envelope.loginMode !== STCONTROL_MODES.INDEPENDENT) {
       envelope.loginMode = STCONTROL_MODES.INDEPENDENT;
   }
   const session = current.sessions[envelope.sessionId] ?? { handle, loginMode: envelope.loginMode, ... };
   ```

   Impact: the agent can underreport `activeIndependentSessions` and `pendingUserSyncs`, and draining mode can later mis-handle a legitimate disaster session because the persisted role never stopped being `managed`.

   Recommendation: when promoting the request envelope, overwrite the persisted session role/fences in the same mutation and add a regression test for managed -> independent -> draining.

2. `internal/controller/storage_repair.go:67`

   Repair/backup schedulers rely on an in-memory recovery gate before they enter the store claim transaction:

   ```go
   if s.checkNewOperations() != nil { return false }
   execution, err := s.Store.ClaimAndCreateStorageRepair(ctx, params)
   ```

   `internal/store/storage_repair.go` and `internal/store/controller_disaster_backups.go` do not re-check control-plane readiness in those transactions.

   Impact: a concurrent heartbeat can close the recovery gate after the controller-side check but before the DB claim finishes, allowing new repair or controller-backup workflows to start while the control plane is already supposed to be frozen for reconciliation.

   Recommendation: enforce the recovery predicate inside the store transaction, or pass a readiness/generation fence that the store must validate before inserting workflow state.
