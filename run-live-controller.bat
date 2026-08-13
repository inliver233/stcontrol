@echo off
cd /d E:\Sillytarvennew\stcontrol
set CONTROLLER_SECRET_KEY=vYfss0CKN2cbF/IuEGoI19Ix6hVciTz7P/vEA9DdGgM=
set CONTROLLER_BOOTSTRAP_ADMIN_PASSWORD=livecheck-admin-123
go run ./cmd/controller --config controller.livecheck.yaml
