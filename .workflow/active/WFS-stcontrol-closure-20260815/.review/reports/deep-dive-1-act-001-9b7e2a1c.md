# Deep dive: mixed admin/user handoffs contaminate one browser cookie and bypass fenced writes

## Verdict

The finding remains **High**.

The bypass is real for both `admin -> user` and `user -> admin` reuse of the same browser cookie:

- `src/endpoints/stcontrol.js:446-450` stores `request.session.stcontrolAdmin` for admin handoff.
- `src/endpoints/stcontrol.js:478` stores the managed user envelope via `registerStcontrolSession()` for user handoff.
- Neither branch clears the opposite role marker.
- `src/stcontrol.js:932` returns from `stcontrolRequestTracker()` immediately whenever `request.session.stcontrolAdmin` exists, so later user writes skip stale-writer, lease, quiesce, and data-fault checks.

That is sufficient to invalidate the R04/R05 closure claim in the acceptance artifact.

## Source-backed contamination paths

### 1. `admin -> user`

1. Admin handoff writes:

```js
request.session.stcontrolAdmin = {
    adminId: claims.admin_id,
    permissionVersion: claims.permission_version,
    controllerGeneration: claims.controller_generation,
};
```

Source: `src/endpoints/stcontrol.js:446-450`

2. Later user handoff writes:

```js
if (kind === 'user') await registerStcontrolSession(request, claims, STCONTROL_MODES.MANAGED);
```

Source: `src/endpoints/stcontrol.js:478`

3. Nothing deletes `request.session.stcontrolAdmin`, so the same cookie now carries both markers.

4. Any later authenticated write hits:

```js
if (request.session?.stcontrolAdmin) return next();
```

Source: `src/stcontrol.js:932`

Result: managed-user fencing is skipped.

### 2. `user -> admin`

1. User handoff populates `request.session.stcontrol` and durable session/lease state at `src/stcontrol.js:865-893`.
2. Later admin handoff adds `request.session.stcontrolAdmin` at `src/endpoints/stcontrol.js:446-450`.
3. Nothing retires the old managed envelope.
4. The same cookie again carries both markers, and subsequent user writes still bypass `stcontrolRequestTracker()` because the admin marker wins first.

This direction is just as real as `admin -> user`; it is not a one-way bug.

## What existing tests prove, and what they miss

Existing route tests only cover isolated handoffs:

- `tests/stcontrol-routes.node.test.mjs:221-235` proves user handoff populates `sharedSession.stcontrol`.
- `tests/stcontrol-routes.node.test.mjs:327-339` proves admin handoff populates `sharedSession.stcontrolAdmin`.

Existing adapter tests only cover stale writes without the admin marker:

- `tests/stcontrol-adapter.node.test.mjs:347-373` correctly expects `409 stale_writer_session` for a stale managed write.

What is missing:

- one cookie reused across `admin -> user`,
- one cookie reused across `user -> admin`,
- and a follow-up POST through `stcontrolRequestTracker()` showing the stale managed write is incorrectly admitted when `stcontrolAdmin` remains.

## Logout and heartbeat boundary

### Logout

`src/endpoints/users-public.js:219-235` does two important things:

1. `await noteStcontrolLogout(request);`
2. `request.session = null;`

`noteStcontrolLogout()` itself only tombstones the current `request.session.stcontrol.sessionId` and removes that exact lease (`src/stcontrol.js:901-912`). It does **not** clear `stcontrolAdmin` on its own.

So the boundary is:

- explicit `/api/users/logout` does clear the contamination, because the whole session object is discarded;
- successful handoff does **not** clear the contamination;
- until logout, the mixed-role cookie persists.

### Heartbeat

The more surprising boundary is heartbeat:

- `src/server-main.js:347` mounts `/api/users` public routes.
- `src/server-main.js:393` only then installs `requireLoginMiddleware`.
- `src/server-startup.js:154-161` installs `stcontrolRequestTracker()` inside the private authenticated stack later.

That means `/api/users/heartbeat` is handled by the public router path, not by the private fenced path.

The route body at `src/endpoints/users-public.js:242-268` calls:

```js
const renewed = await noteStcontrolPageHeartbeat(request);
if (isStcontrolEnabled() && !renewed) {
    return response.status(409).json({ error: '当前页面会话已过期，请重新登录', code: 'stale_writer_session' });
}
```

But `noteStcontrolPageHeartbeat()` (`src/stcontrol.js:915-927`) only checks whether the durable session exists and is not logged out. It does **not** validate the managed write lease.

Read-only inline reproduction on August 15, 2026 confirmed:

- without `stcontrolAdmin`, `stcontrolRequestTracker()` returns `409 stale_writer_session` for a stale managed heartbeat/write request;
- with `stcontrolAdmin`, the same request continues;
- `noteStcontrolPageHeartbeat()` returns `true` in both cases because the durable session row still exists.

So heartbeat does not mitigate the handoff bug, and it should not be treated as proof that managed lease fencing is active.

## Minimum safe fix

The smallest fix that closes **this** finding is role exclusivity at handoff time:

1. Before a successful user handoff completes, delete any existing `request.session.stcontrolAdmin`.
2. Before a successful admin handoff completes, retire any existing managed user envelope:
   - call `noteStcontrolLogout(request)` if `request.session.stcontrol?.sessionId` exists;
   - delete `request.session.stcontrol`;
   - then write `request.session.stcontrolAdmin`.

That restores the intended meaning of `src/stcontrol.js:932`: only a real admin session bypasses the managed-user fence.

## Regression tests to add

### Required to close act-001

1. `tests/stcontrol-routes.node.test.mjs`
   Reuse one `sharedSession` across `admin -> user` and assert the final session has `stcontrol` only and no `stcontrolAdmin`.

2. `tests/stcontrol-routes.node.test.mjs`
   Reuse one `sharedSession` across `user -> admin` and assert the final session has `stcontrolAdmin` only and no `stcontrol`.

3. `tests/stcontrol-adapter.node.test.mjs`
   Seed a stale or missing managed lease, attach a mixed cookie, and prove a POST routed through `stcontrolRequestTracker()` returns `409 stale_writer_session` after the handoff cleanup is in place.

### Boundary coverage worth adding

4. `tests/stcontrol-routes.node.test.mjs`
   Prove `/api/users/logout` clears the entire session and tombstones only the exact durable session id.

5. Follow-up decision test
   Either:
   - document that `/api/users/heartbeat` is intentionally public and not part of the managed lease fence,
   - or move/equate its lease check and then add a route regression for stale managed heartbeat.

## Baseline validation

These existing suites passed on August 15, 2026:

- `node --test tests/stcontrol-routes.node.test.mjs`
- `node --test tests/stcontrol-adapter.node.test.mjs`
- `node --test tests/stcontrol-native-entry-guards.node.test.mjs`

That confirms the gap is coverage and state-shape design, not an already failing baseline.

## Final assessment

`act-001-9b7e2a1c`, `sec-001-6e8c19a4`, and `qua-001-8f1c2d3a` all point to the same defect:

- the adapter treats admin and user handoffs as additive state,
- the tracker treats admin state as an unconditional bypass,
- and the test suite never reuses the same cookie across role transitions.

Clearing the opposite role marker on every successful handoff is the minimum repair that restores write fencing without redesigning the whole session model.
