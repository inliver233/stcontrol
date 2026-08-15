# Deep dive: request admission is not atomic with lease, gate, or logout revocation

## Verdict

The finding remains **Critical**.

`stcontrolRequestTracker()` checks session freshness, current mode, write gates, and the managed lease on a snapshot loaded before `mutateState()` (`src/stcontrol.js:934-978`). The request is only recorded as in flight later (`src/stcontrol.js:980-1000`), and that queued mutation does not revalidate any of the predicates that made the request eligible. One concurrent revoker can therefore invalidate the single-writer fence and the original request still reaches `next()` once.

## Requirement context

Round 28 says already authenticated users should survive controller loss, but only after the node has durably moved onto independent-mode rules and recovery bookkeeping (`.workflow/.analysis/ANL-多节点云酒馆总控方案复盘优化-2026-08-07/discussion.md:895-922`).

That requirement does **not** permit a managed-path write to slip through after the local node has already:

- cleared managed leases for outage takeover,
- logged the session out,
- or frozen the user behind a snapshot/data-fault gate.

The current split admission path allows exactly that one-request overlap.

## Dependency and timing graph

```text
Request thread
  loadStateSync()
    -> cleanExpiredSessions / cleanExpiredSnapshotGates
    -> stale session check
    -> mode-based envelope rewrite
    -> gate check
    -> managed lease check
    -> await mutateState(...)
         -> increment inFlightWrites / inFlightReads
         -> maybe mark pendingSyncUsers
    -> next()

Concurrent revokers sharing the same stateQueue
  applyStcontrolActivityLeaseConfirmations()  src/stcontrol.js:826-847
  applyStcontrolMode()                        src/stcontrol.js:500-547
  noteStcontrolLogout()                       src/stcontrol.js:901-912
  setUserWriteGate()/...Gate()                src/stcontrol.js:1060-1150
```

The bug is the missing atomic boundary between "this request is allowed" and "this request is now durably admitted."

## Confirmed race windows

### 1. Lease confirmation revoke

```text
T1 request: snapshot lease check passes at 973-978
T2 agent:   applyStcontrolActivityLeaseConfirmations deletes lease at 832-838
T1 request: mutateState increments inFlightWrites at 994 and calls next()
```

Result: one managed write crosses after the Controller-confirmed lease has already been revoked.

### 2. Mode flip to independent/draining

```text
T1 request: snapshot still says mode=managed, so no independent failover path runs
T2 mode:    applyStcontrolMode switches to independent and clears leases at 518-525
T1 request: mutateState still admits the write as the old managed session
```

Result: the request bypasses the Round 28 failover boundary and writes once without the post-outage ownership proof.

### 3. Logout or write-gate establishment

```text
T1 request: snapshot sees no loggedOutAt and no state.gates[handle]
T2 revoke:  noteStcontrolLogout() or establishSnapshotWriteGate()/establishUserDataFaultGate()
T1 request: mutateState still increments counters and next() continues
```

Result: one post-logout or post-freeze mutation escapes.

## Minimal atomic repair

The smallest safe fix is to keep async cross-node ownership/quorum work outside the queue, but move every **local** revocable predicate into the same serialized admission mutation:

1. Add an admission helper that runs inside `mutateState()` and returns `{ allowed, code, sessionMode, ... }`.
2. In that queued section, rerun cleanup and recheck the current durable session, `loggedOutAt`, `hadSessionEnvelope && !session`, current mode, current gate, and exact managed lease match before incrementing counters.
3. If the queued state now says `independent` or `draining` while the request still carries a managed envelope, fail closed and let the next request retry through the normal independent ownership/login path.
4. Only on success should the mutation increment in-flight counters, update timestamps, and durably create the `pendingSyncUsers` marker for independent writes.
5. Only after that queued section returns success should the middleware call `next()`.

This is the minimum correctness patch. It does not require a schema change and can be implemented before any performance refactor.

## Regression gap

Current tests are good but not sufficient:

- `tests/stcontrol-adapter.node.test.mjs:316-374` covers an already-stale managed page.
- `tests/stcontrol-adapter.node.test.mjs:384-472` covers lease omission/deadline fencing when revocation happens before the request starts.
- `tests/stcontrol-adapter.node.test.mjs:548-625` covers a pre-existing snapshot gate.
- `tests/stcontrol-adapter.node.test.mjs:762-799` covers outage clearing leases before later requests.

What is missing is an interleaving test that pauses admission after the pre-queue check and then runs:

- `applyStcontrolActivityLeaseConfirmations()`,
- `applyStcontrolMode(INDEPENDENT|DRAINING)`,
- `noteStcontrolLogout()`,
- or `establishSnapshotWriteGate()/establishUserDataFaultGate()`

before the request's admission mutation executes, and asserts that `next()` is **not** called.

## Baseline validation

`node --test tests/stcontrol-adapter.node.test.mjs` passed (`14/14`) on August 15, 2026. That confirms the race is an uncovered concurrency gap, not a currently failing baseline test.

## Performance note

The atomic fix should have negligible extra cost relative to today's behavior because request admission already enters one serialized, durable `mutateState()` call. The change mostly relocates existing checks into that critical section. The broader fsync bottleneck is separate and is already covered by `perf-001-6a1c2b9d`.
