# Maintainability Review

Scope: `origin/main..flash` in `E:\Sillytarvennew\stcontrol\.flash-worktree`, with targeted cross-repo checks against `E:\Sillytarvennew\Sillytarven-online` adapter and its tests.

Summary:
- No critical maintainability findings.
- High: 3
- Medium: 1

## High

### `mai-001` Protocol invariants are hand-copied across Go, adapter JS, UI, and JS tests
- Evidence:
  - `internal/protocol/protocol.go:23`, `:94`, `:303` define the authoritative skew, mode, and inventory limits.
  - `Sillytarven-online/src/endpoints/stcontrol.js:47`, `:454`, `:627` and `src/stcontrol.js:48`, `:802` re-encode the same limits in JS validation paths.
  - `internal/store/user_data_faults.go:22`, `internal/controller/user_data_faults.go:125`, and `web/src/pages/Admin.tsx:1002`, `:1048` each keep their own reason-code list.
  - `Sillytarven-online/tests/stcontrol-routes.node.test.mjs:130`, `:208` and `tests/stcontrol-adapter.node.test.mjs:423` mirror current literals again.
- Impact:
  - A future lease-window, inventory, or reason-code change can make the adapter reject valid controller claims or hide valid operator actions while local tests still pass, because the tests duplicate the stale JS assumptions instead of the Go contract.
  - This is a realistic recovery-state-machine regression vector, not a cosmetic duplication issue.
- Recommendation:
  - Generate a shared protocol manifest from Go and consume it from adapter/UI, or add a cross-repo contract test that validates the JS boundary checks against the Go contract.

### `mai-002` AI observation builders already show copy-paste drift and dead scaffolding
- Evidence:
  - `internal/controller/ai_phase_tasks.go:24` documents a prior D5 regression where omitting `candidate_catalog` broke every ordering advisory.
  - `internal/controller/ai_phase_tasks.go:59-73` builds `evidenceCatalog` and then discards it with `_ = evidenceCatalog`.
  - The file repeats the same marshal/dedup pipeline across anomaly, schedule, recovery, import, disaster, and conflict tasks.
  - `internal/controller/ai_phase_tasks_test.go:164` and `:236` validate individual task shapes, but there is no single contract harness forcing all task builders to evolve together.
- Impact:
  - Schema or redaction changes can land in only some AI task families, producing phase-specific advisory failures that are hard to diagnose during incidents.
- Recommendation:
  - Extract one shared observation-builder helper and one table-driven contract suite for all AI task types.

### `mai-003` Storage repair scheduling is a 266-line transaction with regex-oriented tests
- Evidence:
  - `internal/store/storage_repair.go:238-498` claims the task, rechecks controller/lease fences, selects a target, creates backup/workflow artifacts, updates replica/task state, and writes audit rows in one method.
  - `internal/store/storage_repair_test.go:70`, `:98`, `:104`, `:122`, `:191` mostly assert ordered SQL regexes.
- Impact:
  - Small changes to one fence or side effect can disturb another branch and reopen stale-writer, duplicate-workflow, or reservation-leak behavior.
  - The tests are expensive to maintain and weak at explaining which state-machine invariant actually failed.
- Recommendation:
  - Split the transaction into internal helpers and add branch/invariant tests around lease validation, target selection, reservation release, and retry behavior.

## Medium

### `mai-004` Admin.tsx concentrates eight admin surfaces plus duplicated state helpers in one module
- Evidence:
  - `web/src/pages/Admin.tsx:149` routes eight admin surfaces from one file.
  - `:338-372` duplicates quota GiB→bytes parsing.
  - `:875-902` and `:1354-1384` duplicate cursor/history/load pagination logic.
  - `:1002-1052` and `:1558-1570` hardcode backend reason/task/action dictionaries inline.
  - `:1573-1574` adds another ad-hoc pagination reload path for AI supervision.
- Impact:
  - Backend feature work now requires editing multiple unrelated sections in one monolith, which increases UI drift and makes targeted regression testing harder.
- Recommendation:
  - Split each admin area into its own module and centralize shared hooks/constants for pagination, label dictionaries, and unit conversions.

## Overall Assessment

The maintainability risk is concentrated in three places:
1. Cross-repo protocol contracts that are manually synchronized instead of generated.
2. Recovery/AI state-machine code that has already grown past easy branch-level reasoning.
3. Admin/UI surfaces that encode control-plane vocabulary inline instead of consuming shared definitions.

Those are the areas most likely to produce future security or recovery regressions during otherwise routine feature work.
