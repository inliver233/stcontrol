# Deep dive: adapter request-path persistence bottleneck

## Verdict

The finding remains **High**. The queue itself is useful for making the lease/gate check and request admission atomic; the defect is that serialization is inseparable from a synchronous full-state checkpoint.

Every tracked request currently performs one atomic JSON rewrite before `next()` and another from the `finish`/`close` callback. Browser heartbeat performs another rewrite. These mutations include in-flight counters which the loader deliberately resets to zero after restart, so writing them durably on every event brings no recovery guarantee.

## Root cause and dependency boundary

`mutateState()` is the only state synchronization primitive and unconditionally calls `persistState()`. The latter synchronously creates the directory and invokes `writeFileAtomicSync` for the entire state document. Because `stateQueue` is process-wide, disk latency for one user delays authorization and telemetry for every other user.

The state must nevertheless stay immediately durable for mode/gate/lease transitions, session creation and logout, signed-command nonces and operation results, and especially the first `pendingSyncUsers` marker for an independent write. Request in-flight counters are runtime-only. Activity timestamps can use a bounded checkpoint because process restart already changes their runtime interpretation.

## Remediation

1. Split “serialize access to cached state” from “checkpoint cached state”, keeping durable persistence as the default.
2. Run the current lease/gate/session recheck and in-flight increment in one serialized section.
3. Use a volatile mutation for managed request admission/completion and ordinary page heartbeat.
4. If admission observes an independent write, create and durably persist the pending-sync marker before calling `next()`.
5. Add tests which count persistent writes and prove the independent recovery marker remains synchronous.

This preserves the single-writer fix from `arch-001-7d2a4c9e` while removing disk I/O from the common managed request path. No state schema change is required, and rollback only requires routing volatile callers through the durable wrapper again.
