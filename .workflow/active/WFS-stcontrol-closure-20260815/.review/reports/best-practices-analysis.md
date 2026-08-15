# Best-Practices Review

- Review target: `flash` vs `origin/main` in `E:\dshtest\Sillytarvennew\stcontrol`
- Coupling spot-check: `E:\dshtest\Sillytarvennew\Sillytarven-online\src\endpoints\stcontrol.js`, `users-public.js`, `users-admin.js`
- Scope focus: Go/React idioms, middleware and fail-closed behavior, validation/logging consistency, migration/test gate portability

## Summary

- Findings: 3
- Severity: 2 high, 1 medium
- Highest-risk area: new AI supervision/admin surface

## High

### 1. AI admin pagination uses stale React state and does not page correctly

- File: `web/src/pages/Admin.tsx:1546`
- Evidence:

```tsx
adminApi.aiRequests(cursor)
useEffect(() => { load() }, [])
const nextPage = () => { if (nextCursor > 0) { setCursor(nextCursor); setTimeout(load, 0) } }
const previousPage = () => { setCursor(0); setTimeout(load, 0) }
```

- Impact: `下一页/上一页` does not reliably fetch the requested AI request page. The panel can keep reloading the old cursor and `上一页` always jumps to page 1, which undermines manual audit of AI request history.
- Recommendation: follow the existing paginator pattern already used elsewhere in `Admin.tsx`: fetch from `useEffect([cursor])` or pass the target cursor explicitly into `load(nextCursor)`, and keep actual cursor history for backwards navigation.

### 2. AI advisory validation is not EOF-strict after the first JSON object

- File: `internal/ai/validator.go:56`
- Evidence:

```go
dec := json.NewDecoder(strings.NewReader(trimmed))
dec.DisallowUnknownFields()
if err := dec.Decode(&adv); err != nil {
```

- Impact: one valid advisory followed by trailing prose or a second JSON object is still accepted. That contradicts the stated JSON-only fail-closed contract for AI output and can let malformed provider responses reach advisory or auto-adopt evaluation.
- Recommendation: after the first decode, require EOF and add a regression test for trailing text / concatenated JSON cases.

## Medium

### 3. Live-check verification script hardcodes an absolute repository path

- File: `run-live-check.bat:2`
- Evidence:

```bat
cd /d E:\Sillytarvennew\stcontrol
```

- Contrast: `run-live-controller.bat:7` already uses `%~dp0`.
- Impact: in the reviewed flash worktree the repo lives under `E:\dshtest\Sillytarvennew\stcontrol`, so the live-check script starts from the wrong directory and breaks the verification flow before `pg_ctl`/`psql` run.
- Recommendation: switch to `cd /d %~dp0` and keep the script relative-path based.

## Notes

- I spot-checked the direct `Sillytarven-online` coupling points (`src/endpoints/stcontrol.js`, `users-public.js`, `users-admin.js`) and did not find a higher-severity regression than the three issues above in this pass.
- Migration coverage is present for `0048_ai_auto_adopt.sql` (`internal/store/ai_adoption_postgres_integration_test.go`), so I did not raise a migration-test finding.
