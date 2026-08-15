# Quality Review

Scope:
- `E:\Sillytarvennew\stcontrol\.flash-worktree` changed Go/controller/store paths related to state persistence, storage repair, AI supervision, and controller backups
- directly coupled `E:\Sillytarvennew\Sillytarven-online` adapter/session code and its stcontrol route tests

Summary:
- 4 findings total
- High: 2
- Medium: 2
- Low: 0

## High

1. Split admin and user session envelopes let stale admin state bypass managed-user fences
   - Evidence:
     - `E:\Sillytarvennew\Sillytarven-online\src\endpoints\stcontrol.js:446-450` stores `request.session.stcontrolAdmin` for admin handoff.
     - `E:\Sillytarvennew\Sillytarven-online\src\endpoints\stcontrol.js:476-478` later performs user handoff by writing only `request.session.stcontrol` through `registerStcontrolSession(...)`.
     - `E:\Sillytarvennew\Sillytarven-online\src\stcontrol.js:930-978` makes `stcontrolRequestTracker` return before stale-writer, quiesce, and lease checks whenever `request.session.stcontrolAdmin` exists.
   - Snippet:
     - `request.session.stcontrolAdmin = {`
   - Impact:
     - Session persistence across admin->user transitions is not normalized. A stale admin marker can shadow the managed-user fence model and let writes run under the wrong session semantics.
   - Recommendation:
     - Clear the opposite envelope on every successful handoff/logout or move both handoff modes to one canonical session structure.
     - Add a same-cookie regression that executes admin handoff, then user handoff, then a managed write.

2. Controller disaster backup reconciliation drops background failures before they become observable
   - Evidence:
     - `E:\Sillytarvennew\stcontrol\.flash-worktree\internal\controller\controller_backup.go:72-84` returns immediately on reconciliation, operation-check, scheduling, and `executeControllerBackup` errors.
     - Only some internal branches in `executeControllerBackup` call `fail(...)`; early returns from `MarkControllerDisasterBackupProgress(...)` and the outer reconciler do not emit state or telemetry.
     - `E:\Sillytarvennew\stcontrol\.flash-worktree\internal\controller\controller_backup_test.go:13-43` covers defaults and gating, but not these negative background paths.
   - Snippet:
     - `if _, err := s.Store.ReconcileControllerDisasterBackups(ctx, now, maxAttempts); err != nil { return }`
   - Impact:
     - Backup progress can stop silently and leave operators with no clear distinction between “nothing due” and “backup loop broken,” which is a real disaster-readiness quality problem.
   - Recommendation:
     - Emit structured logs/metrics/audit breadcrumbs for every early-return path.
     - Add tests for scheduler failure, progress-marking failure, and `checkNewOperations()` failure.

## Medium

3. AI phase observation builders are copy-pasted and already drifted once
   - Evidence:
     - `E:\Sillytarvennew\stcontrol\.flash-worktree\internal\controller\ai_phase_tasks.go:24-28` documents a prior D5 regression where omitting `candidate_catalog` broke advisory validation.
     - The same file repeats the observation/redaction/marshal/dedup pattern across six enqueue functions (`:34-78`, `:83-133`, `:148-181`, `:201-230`, `:251-285`, `:307-337`).
     - `E:\Sillytarvennew\stcontrol\.flash-worktree\internal\controller\ai_phase_tasks.go:59-73` still carries an unused `evidenceCatalog` local in `enqueueAnomalyAttribution`, which is dead-code fallout from the duplication.
   - Snippet:
     - `// ... omitting it made every ordering advisory fail with empty_candidates (D5).`
   - Impact:
     - Contract changes will keep drifting phase-by-phase instead of once per shared builder, and failures surface as missing advisories instead of compile-time feedback.
   - Recommendation:
     - Extract a shared observation-builder helper and reusable contract assertions for `ai_phase_tasks_test.go`.

4. Storage repair claim logic is too large for branch-level reasoning and its tests mostly snapshot SQL text
   - Evidence:
     - `E:\Sillytarvennew\stcontrol\.flash-worktree\internal\store\storage_repair.go:238-498` combines intent claim, writer-fence validation, target selection, workflow seeding, transfer capability persistence, replica updates, and audit emission in one function.
     - The function contains several separate decision points (`:321-352`, `:358-398`, `:400-492`) that are hard to reason about independently.
     - `E:\Sillytarvennew\stcontrol\.flash-worktree\internal\store\storage_repair_test.go:45-205` mainly asserts large SQL regexes and a few outcomes, which is useful for shape checks but weak for naming and isolating each invariant.
   - Snippet:
     - `func (s *Store) ClaimAndCreateStorageRepair(`
   - Impact:
     - A small change to one fence or side effect can regress another branch inside the same serializable transaction, and the failure mode is expensive to localize.
   - Recommendation:
     - Split the transaction into small internal helpers and add invariant-focused tests around each fence and side effect.

## Testability Notes

- `E:\Sillytarvennew\Sillytarven-online\tests\stcontrol-routes.node.test.mjs:175-349` covers user handoff and admin handoff separately, but it does not reuse the same browser session across both flows. That missing mixed-flow regression is why the split-session bug above remained easy to ship.
- `E:\Sillytarvennew\stcontrol\.flash-worktree\internal\controller\controller_backup_test.go` currently lacks failure-path assertions for the background reconciler.
