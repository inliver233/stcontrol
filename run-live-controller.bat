@echo off
rem Live controller launcher (local test only).
rem Never hardcode the control-plane master key or bootstrap admin password here:
rem if they are committed to git, a leaked secret rotates every agent credential.
rem Provide them via environment or a local, git-ignored secrets file.
setlocal
cd /d %~dp0
if not defined CONTROLLER_SECRET_KEY (
  if exist .live-secrets.cmd call .live-secrets.cmd
)
if not defined CONTROLLER_SECRET_KEY (
  echo [error] CONTROLLER_SECRET_KEY is not set. Create .live-secrets.cmd (git-ignored) with:
  echo   set CONTROLLER_SECRET_KEY=^<base64 32 bytes^>
  echo   set CONTROLLER_BOOTSTRAP_ADMIN_PASSWORD=^<password^>
  exit /b 1
)
if not defined CONTROLLER_BOOTSTRAP_ADMIN_PASSWORD (
  echo [error] CONTROLLER_BOOTSTRAP_ADMIN_PASSWORD is not set.
  exit /b 1
)
go run ./cmd/controller --config controller.livecheck.yaml
endlocal
