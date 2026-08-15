# Security Review

Scope reviewed on 2026-08-15:

- `E:\Sillytarvennew\stcontrol\.flash-worktree` security-sensitive controller, store, agent, backup, AI, and router paths
- `E:\Sillytarvennew\Sillytarven-online\src\stcontrol.js`
- `E:\Sillytarvennew\Sillytarven-online\src\endpoints\stcontrol.js`
- `E:\Sillytarvennew\Sillytarven-online\public\scripts\user-heartbeat.js`

Confirmed findings:

1. High: mixed admin/user handoffs can bypass user lease and write-gate enforcement
   - Evidence:
     - `E:\Sillytarvennew\Sillytarven-online\src\endpoints\stcontrol.js:446-450` stores `request.session.stcontrolAdmin` for admin handoff.
     - `E:\Sillytarvennew\Sillytarven-online\src\endpoints\stcontrol.js:476-479` completes user handoff without clearing that admin marker.
     - `E:\Sillytarvennew\Sillytarven-online\src\stcontrol.js:930-932` makes `stcontrolRequestTracker` return before any user lease, gate, or reconciliation checks when `request.session.stcontrolAdmin` exists.
   - Impact:
     - A single browser session can retain admin status from an earlier admin handoff and then perform user writes after a user handoff without the managed-writer fence.
     - That weakens the core protections around stale writer rejection, snapshot quiescing, and independent reconciliation.
   - Recommendation:
     - Clear `request.session.stcontrolAdmin` on successful user handoff.
     - Clear any stale user envelope on successful admin handoff.
     - Make the request tracker evaluate user fencing from the active user session even if an admin marker also exists.

2. High: OAuth login state is not bound to the initiating browser session
   - Evidence:
     - `E:\Sillytarvennew\stcontrol\.flash-worktree\internal\controller\oauth.go:55-72` creates a login state and redirects immediately.
     - `E:\Sillytarvennew\stcontrol\.flash-worktree\internal\store\oauth.go:36-41` persists only `state_hash`, `provider`, optional `node_id`, purpose, generation, expiry, and timestamp.
     - `E:\Sillytarvennew\stcontrol\.flash-worktree\internal\controller\oauth.go:87-123` redeems the callback by consuming that stored state when no bound session matches.
     - `E:\Sillytarvennew\stcontrol\.flash-worktree\internal\store\oauth.go:70-78` validates only state hash, provider, expiry, and generation on login-state consumption.
   - Impact:
     - The state is one-time, but it is still bearer-style. If an attacker completes provider authorization in their own browser and causes the victim browser to hit the callback URL first, the victim browser can be logged into the attacker's account or seeded with the attacker's pending OAuth enrollment.
     - This is classic login CSRF / account confusion, not just a usability defect.
   - Recommendation:
     - Bind login-purpose OAuth state to a browser-held cookie or pre-auth session identifier and require that binding on callback redemption.
     - Keep the existing bind-purpose session checks as the model for the login-purpose flow.

Notes:

- I did not confirm the suspected nonce-pruning issue as an exploitable bypass from the reviewed code alone; the HMAC plus loopback-only transport materially narrows that surface.
- I did not find a stronger finding than the two High items above in the reviewed timebox.
