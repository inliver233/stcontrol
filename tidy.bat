@echo off
cd /d E:\Sillytarvennew\stcontrol
set GOPROXY=https://goproxy.cn
set GOSUMDB=sum.golang.google.cn
go mod tidy 2>&1
echo EXIT=%ERRORLEVEL%
