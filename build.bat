@echo off
cd /d E:\Sillytarvennew\stcontrol
set GOPROXY=https://goproxy.cn
set GOSUMDB=sum.golang.google.cn
go build ./... 2>&1
echo EXIT=%ERRORLEVEL%
