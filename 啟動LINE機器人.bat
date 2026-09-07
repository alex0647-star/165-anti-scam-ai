@echo off
chcp 65001 >nul
echo ======================================================
echo  正在啟動 165 AI 防詐騙 LINE Bot 伺服器 (FastAPI)...
echo ======================================================
cd /d "%~dp0"
set PYTHONPATH=%~dp0;%PYTHONPATH%
"C:\Users\USER\anaconda3\python.exe" line_bot_server.py
pause
