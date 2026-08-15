# Action-Items Review

Review ID: `review-20260815-acceptance`
Dimension: `action-items`
Status: `3 high findings`

## High

### ACT-001 Admin state bypass breaks the claimed R04/R05 closure
- Evidence: `E:\Sillytarvennew\Sillytarven-online\src\endpoints\stcontrol.js:446-450` writes `request.session.stcontrolAdmin`, while `E:\Sillytarvennew\Sillytarven-online\src\stcontrol.js:932` returns early for any request carrying that marker.
- Gap: the later user handoff path (`...endpoints\stcontrol.js:451-478`) never clears the admin flag, so one browser cookie can enter admin mode first and then user mode second without re-enabling managed write fencing.
- Acceptance impact: `E:\Sillytarvennew\stcontrol\docs\requirements-traceability.md:22-23` currently marks R04 and R05 `完成`, but that closure is false for mixed admin/user sessions.
- Test gap: `E:\Sillytarvennew\Sillytarven-online\tests\stcontrol-routes.node.test.mjs:291-349` only checks isolated admin handoff and never reuses the same cookie for a later user handoff.
- Recommendation: clear `stcontrolAdmin` on user handoff, clear stale user envelopes on admin handoff, and add a mixed-session regression.

### ACT-002 Managed cookies can turn into independent sessions on ordinary requests
- Evidence: `E:\Sillytarvennew\Sillytarven-online\src\stcontrol.js:945-953` mutates any non-independent envelope into `INDEPENDENT` during request tracking, and `...src\stcontrol.js:623-635` allows that path whenever activity ownership resolves to `automatic`.
- Gap: the explicit disaster-login gate in `E:\Sillytarvennew\Sillytarven-online\src\endpoints\users-public.js:114-195` is bypassed for an already-authenticated managed browser session.
- Acceptance impact: `E:\Sillytarvennew\stcontrol\docs\requirements-traceability.md:20` says independent mode only opens via explicit password login; current code still permits silent request-path conversion.
- Test gap: `E:\Sillytarvennew\Sillytarven-online\tests\stcontrol-adapter.node.test.mjs:762-799` only verifies that leases are cleared after outage, not that a managed cookie is rejected until the user logs in again.
- Recommendation: fail closed for old managed envelopes in `independent` / `independent-draining`, and only mint independent envelopes from a successful `/api/users/login`.

### ACT-003 P0->P3 acceptance closure is still not enforceable
- Evidence: `E:\Sillytarvennew\stcontrol\docs\requirements-traceability.md:44` says current combined coverage is `66.7%` and explicitly says this is still below the final `80%` gate.
- Evidence: `E:\Sillytarvennew\stcontrol\.flash-worktree\internal\agent\process_e2e_test.go:43-63` and `...internal\agent\tavern_crossrepo_e2e_test.go:23-38` skip the real process/cross-repo acceptance path whenever short mode, DSN, Node, or fixtures are unavailable.
- Acceptance impact: `E:\Sillytarvennew\stcontrol\.flash-worktree\.workflow\active\WFS-stcontrol-closure-20260815\.review\review-state.json` targets `all_confirmed_requirements_closed_and_basic_tests_green`, but the repository does not currently enforce the required real-environment suites in that green path.
- Recommendation: make the DSN-backed PostgreSQL, process-restart, and cross-repo suites mandatory in the acceptance command/CI path, and keep P3 open until the documented gate is met or revised.

## Conclusion

The current branch does not support a truthful P0->P3 closure claim. Two active Online session-path bugs still contradict rows already marked `完成`, and the acceptance harness itself is not yet strong enough to certify release readiness.
