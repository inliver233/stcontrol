@echo off
cd /d E:\Sillytarvennew\stcontrol\web
set NPM_CONFIG_REGISTRY=https://registry.npmmirror.com
call npm install --no-audit --no-fund 2>&1
echo INSTALL_EXIT=%ERRORLEVEL%
