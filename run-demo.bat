@echo off
setlocal

cd /d "%~dp0"

if not exist certs\pins.json (
  echo Demo certificates are missing. Run "npm run pki" first.
  exit /b 1
)

echo Starting RIC server...
start "Inforsec RIC Server" powershell -NoExit -Command "Set-Location -LiteralPath '%~dp0'; npm run server"

echo Starting UI dev server...
start "Inforsec UI" powershell -NoExit -Command "Set-Location -LiteralPath '%~dp0ui'; npm run dev -- --host 0.0.0.0"

echo.
echo Demo launch requested.
echo Server: http://127.0.0.1:8080
echo UI:     http://localhost:5173
echo.
echo If you need the UI in Docker instead, build it with:
echo   docker build -f ui/Dockerfile -t inforsec-ui .
echo.
endlocal