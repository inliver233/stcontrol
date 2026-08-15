# Performance Review

Review scope: `origin/main..flash` in `stcontrol` plus the directly coupled `Sillytarven-online` adapter paths.

## Summary

- Total findings: 3
- Critical: 0
- High: 2
- Medium: 1
- Focus areas hit: synchronous request-path blocking, controller backup retry scheduling, large-backup memory pressure

## Findings

### High

1. `Sillytarven-online/src/stcontrol.js:340`

   Every stcontrol-tracked request uses one global `stateQueue`, and each queued mutation ends in synchronous state persistence:

   ```js
   let stateQueue = Promise.resolve();
   ...
   const run = stateQueue.then(async () => {
       const state = loadStateSync();
       const result = await mutator(state);
       persistState(state);
       return result;
   });
   ```

   `persistState()` calls `mkdirSync` and `writeFileAtomicSync`, and `stcontrolRequestTracker()` awaits this before admitting the request (`src/stcontrol.js:277-280`, `930-1015`). `/api/users/heartbeat` also calls `noteStcontrolPageHeartbeat()` (`src/endpoints/users-public.js:242-268`), while the browser sends managed heartbeats every 2 minutes in the foreground and 5 minutes in the background (`public/scripts/user-heartbeat.js:11-12`, `60-63`, `192-203`).

   Impact: all managed users share one disk-backed critical section. At 1,000 active pages, steady heartbeat traffic alone can keep this queue hot, and one slow flush delays unrelated requests because request entry and request completion both enqueue more synchronous persistence.

   Recommendation: remove fsync-backed persistence from the request hot path, shard locking by session/user, and batch durable snapshots asynchronously instead of `await`ing a process-wide queue before `next()`.

2. `internal/controller/controller_backup.go:78`

   The controller backup reconciler only executes a backup when scheduling returns a brand-new run:

   ```go
   run, err := s.Store.ScheduleControllerDisasterBackup(...)
   if err != nil || run == nil { return }
   if err := s.executeControllerBackup(ctx, run); err != nil { return }
   ```

   But `ScheduleControllerDisasterBackup()` treats any `retry_wait` row as already covered (`internal/store/controller_disaster_backups.go:103-113`, `145-154`), and `FailControllerDisasterBackup()` moves transient failures into `retry_wait` (`272-296`). There is no second caller that re-claims an existing retrying run.

   Impact: one transient backup failure can stall controller own-state backups indefinitely. The reconciler neither retries the failed run after backoff nor creates a replacement while the stale `retry_wait` row exists, so backup throughput drops to zero until manual cleanup.

   Recommendation: claim due `scheduled`/`retry_wait` runs on every pass, with due-time and lease-expiry checks, and only schedule a fresh run when no runnable backup already exists.

### Medium

1. `internal/controller/controller_backup.go:252`

   Backup hashing reads the entire archive into RAM before upload:

   ```go
   data, err := os.ReadFile(path)
   sum := sha256.Sum256(data)
   ```

   This happens after the archive is already built on disk (`154-156`) and before it is streamed again (`269+`). The shared snapshot size ceiling is 100 GiB (`internal/agent/snapshot.go:36`).

   Impact: larger pg_dump-style controller backups can create very large one-shot RSS spikes and GC pressure during backup windows, reducing safe backup concurrency.

   Recommendation: compute the digest as a stream while writing the archive or by reopening it with `io.Copy` into a hash instead of `os.ReadFile`.
