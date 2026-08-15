# Deep dive: managed-to-independent promotion must be durably committed

## Verdict

The finding remains **High**.

Round 28 does not support force-logging out every already-authenticated browser when the controller is confirmed dead. The later requirement is narrower: existing sessions may survive, but they must cross the same ownership boundary as a fresh disaster login before they can keep writing. The adapter already models that correctly in principle: `applyStcontrolMode()` clears managed leases immediately, then `stcontrolRequestTracker()` requires `canUseNativeLogin()` before promoting a managed envelope in `independent` mode.

The defect is what happens next. After the ownership proof succeeds, only the browser envelope is changed to `independent`. The durable session record stays `managed`, keeps its old managed `activityEpoch` and `controllerGeneration`, never emits the first `pendingSyncUsers` marker on write, and therefore under-reports the exact recovery facts that Agent and Store use to keep the node in `independent-draining`.

## Correct identity boundary

The correct split is:

1. `applyStcontrolMode()` must **not** bulk-convert every session on mode switch.
2. A pre-outage logged-in session must **not** be unconditionally dropped.
3. The first post-outage request must prove the same cross-Agent ownership rule as disaster login.
4. Only after that proof succeeds may the session become `independent`.

That chain is visible in the current code and requirement history:

- `src/stcontrol.js:518-523` says confirmed outage clears managed leases but intentionally delays conversion until a later request proves ownership.
- `src/stcontrol.js:623-636` and `src/stcontrol.js:676-724` implement the ownership/quorum gate.
- `src/endpoints/users-public.js:171-195` uses the same gate for explicit independent login.
- Round 28 through Round 30 define the product rule: keep service available after confirmed controller loss, allow only the last active node automatically, and require user-confirmed takeover for double failure.

So the minimal repair is not “force re-login for all old sessions”. That would be a product-policy change and it would contradict the later Round28 continuity decision. The minimal repair is: once request-path ownership proof passes, persist the promotion durably in the same serialized state mutation.

## Durable state divergence

The divergence is concrete and local:

- `src/stcontrol.js:945-953` flips only `request.session.stcontrol` to `independent`, zeroes `activityEpoch`, and refreshes controller generation.
- `src/stcontrol.js:982-999` then loads `current.sessions[sessionId] ?? {...}` and reuses the existing durable session object without overwriting those fields.
- `src/stcontrol.js:997-998` creates `pendingSyncUsers` only when the durable `session.loginMode` is already `independent`.
- `src/stcontrol.js:482-489`, `553-555`, and `1030-1037` count active independent sessions and emit telemetry from the durable record, not from the browser envelope.
- `src/stcontrol.js:526-531` seeds draining-time sync markers only from durable independent sessions.

The current test at `tests/stcontrol-adapter.node.test.mjs:762-799` explicitly asserts this stale behavior, so the bug is both real and test-frozen.

## Managed recovery boundary

This is why the bug is architectural rather than cosmetic.

Agent and Store already enforce the right managed-recovery boundary:

- `internal/agent/control_mode.go:233-241` refuses a direct `independent-draining -> managed` step while `ActiveIndependentSessions > 0` or `PendingUserSyncs > 0`.
- `internal/store/control_modes.go:230-249` only asks for `managed` after adapter facts are zero/zero **and** no durable reconciliation rows remain.

But the adapter feeds those guards from the wrong place:

- active-independent counts come from durable `state.sessions`
- pending-sync facts come from durable `state.pendingSyncUsers`

If a request-path-promoted browser keeps writing while the durable session still says `managed`, the node can report `0 active independent / 0 pending sync` even though the browser is already in disaster-write mode. That weakens the `independent-draining` fence and can let recovery proceed on false clean-state evidence.

## Minimal fix and tests

Minimal fix:

1. Keep `applyStcontrolMode()` unchanged on policy: clear leases on confirmed outage, do not auto-promote all sessions there.
2. In `stcontrolRequestTracker()`, record whether ownership proof just succeeded for a managed session.
3. Inside the existing `mutateState()` admission block, if that promotion flag is set, overwrite the durable session's `loginMode`, `activityEpoch = 0`, and `controllerGeneration` before counting or writing markers.
4. Evaluate `pendingSyncUsers` after the overwrite so the first independent write becomes durably visible immediately.

Minimal tests:

1. Replace the current outage assertion at `tests/stcontrol-adapter.node.test.mjs:762-799`. After confirmed outage, drive one tracked request through a successful ownership proof and assert the durable session is now `independent`, `activityEpoch` is `0`, `controllerGeneration` is refreshed, and telemetry reports `independent`.
2. In the same regression or a second one, make the promoted session perform a write and assert a durable `independent_write` marker appears.
3. Add a draining-boundary regression: after promotion plus write, `applyStcontrolMode(DRAINING)` must report non-zero `active_independent_sessions` / `pending_user_syncs`; `markUserSynchronized()` must fail while the session is still active; only logout or idle expiry plus exact marker completion may return the node to `managed`.

That keeps the later product decision intact, closes the durable-state hole, and restores the recovery fence that the Go side already expects.
