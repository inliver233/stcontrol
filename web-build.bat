@echo off
cd /d E:\Sillytarvennew\stcontrol\web
set NPM_CONFIG_REGISTRY=https://registry.npmmirror.com
call npm run build 2>&1
echo BUILD_EXIT=%ERRORLEVEL%
