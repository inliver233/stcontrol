@echo off
cd /d E:\Sillytarvennew\stcontrol
.test-postgres\runtime\pgsql\bin\pg_ctl.exe -D .test-postgres\data -l .test-postgres\postgres.log -o "-p 55432" start
timeout /t 3 /nobreak >nul
.test-postgres\runtime\pgsql\bin\psql.exe -h 127.0.0.1 -p 55432 -U postgres -d postgres -c "select 1 as pg_up;"
