@echo off
setlocal
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
  echo AgentGuard sanal ortami bulunamadi.
  echo Once README dosyasindaki kurulum adimlarini uygulayin.
  exit /b 1
)

".venv\Scripts\python.exe" -m agentguard --reload
