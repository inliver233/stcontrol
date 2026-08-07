@echo off
cd /d E:\Sillytarvennew\stcontrol
set GOPROXY=https://goproxy.cn
set GOSUMDB=sum.golang.google.cn
set CGO_ENABLED=0
echo === build controller (windows) ===
go build -o bin\controller.exe .\cmd\controller 2>&1
echo === build agent (windows) ===
go build -o bin\agent.exe .\cmd\agent 2>&1
echo === build agent (linux amd64) ===
set GOOS=linux
set GOARCH=amd64
go build -o bin\agent-linux-amd64 .\cmd\agent 2>&1
set GOOS=
set GOARCH=
echo === vet ===
go vet .\... 2>&1
echo EXIT=%ERRORLEVEL%
