# stcontrol acceptance review summary

Completed seven review dimensions over `origin/main..flash` and one focused deep-dive iteration.

## Raw results

- Critical: 1
- High: 16
- Medium: 5
- Low: 0
- Dimensions: 7/7
- Deep dives: 4/4

The raw count contains intentional cross-dimension duplicates. The Critical finding is confirmed: the Online adapter checks session, gate and managed lease against one cached snapshot, then admits the request in a later serialized mutation. A concurrent revoke, logout, gate or mode transition can therefore allow one stale write.

## Cross-cutting roots

1. Online session admission must atomically recheck durable session, mode, gate and lease while recording in-flight state.
2. Managed-to-independent promotion is permitted for an already authenticated user by the later Round 28–30 answers, but only after an equivalent ownership proof; envelope and durable session state must be promoted together.
3. Admin and user handoffs must be mutually exclusive in one browser session.
4. Runtime request counters and heartbeats must not force a synchronous full-state rewrite, while independent pending-sync evidence remains durable before admission.
5. OAuth login state needs initiating-browser binding.
6. Controller-backup retry/restart, observability and streaming hash remain incomplete.
7. Repair/backup scheduling must revalidate the controller recovery barrier inside the store transaction.
8. Cross-repository protocol changes need symmetric tests and exact version/fence fields.
9. Real PostgreSQL/process/cross-repository acceptance and the documented coverage gate remain opt-in or below target.

## Requirement conflict adjudication

The action-items claim that every managed cookie must be rejected after a switch to independent mode is too broad and conflicts with later Round 28–30 answers. Existing authenticated users may remain usable after confirmed controller failure. The accepted rule is to prove local ownership/takeover, atomically promote both session representations, and durably mark the first independent write.

## Deferred AI findings

The AI admin pagination, advisory EOF validation and duplicated AI phase builders are retained as confirmed findings but are not changed during the main-flow remediation. Per the user's ordering constraint, AI supervision changes begin only after main-flow acceptance and explicit confirmation of the seven AI requirement changes.

## Disposition

Review completion is partial because confirmed Critical/High findings remain. The user already authorized the automated fix path, so the workflow continues directly into fix discovery, dependency batching, implementation and board-level basic tests.

## P1 remediation checkpoint

The original review disposition above records the pre-fix state. As of 2026-08-15, G1–G4 are implemented and board-verified. The Online stale-write admission root, independent ownership/session conversion, OAuth initiating-browser binding, R14 removal contract, controller rebuild generation fencing, compatibility heartbeat constraint, durable data-fault release, R06 timeout coverage, and conflict polling recovery have no remaining confirmed Critical/High blocker after an independent combined-diff review.

Checkpoint evidence: Online P1 tests 44/44; stcontrol web 19/19 plus production build; `go test ./...`, `go vet ./...`, and `go build ./...` all pass when Go TEMP/TMP is placed on the E: project volume. PostgreSQL-only cases compile and intentionally skip without `STCONTROL_TEST_POSTGRES_DSN`. G5–G7 remain active work, so the overall workflow is not complete and Phase 9 finalization has not begun.

## Final remediation checkpoint — 2026-08-21

The preceding checkpoint is historical. G5–G8 are now complete: Controller backup/storage barriers and retry recovery, Agent limiter/audit closure, cross-repository protocol/process acceptance, and the authorized AI tail are implemented and verified. The Online rebase is conflict-free; OAuth convergence has one durable operation identity across Controller, command queue, Agent and adapter.

Final evidence includes real PostgreSQL Store/Controller packages with 0 fail/0 skip, Online 47/47, web 24/24 plus production build, cross-repository adapter/full-server tests, and the real Controller/two-Agent/Tavern restart scenario (218.83s). That scenario found and closed a recovery-only mode-generation deadlock and premature takeover acknowledgement. `go test -short`, vet, build and diff checks are green.

No confirmed development blocker remains. Linux race/coverage, cross-machine TLS/NAT, real disk/power faults, capacity/browser/soak and upgrade evidence remain release-environment acceptance and are enumerated in `服务器测试清单.md`; they are not represented as locally passed.
