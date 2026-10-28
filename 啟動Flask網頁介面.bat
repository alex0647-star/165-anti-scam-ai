@echo off
chcp 65001 >nul
title 165 AI 智能多模態防詐騙鑑識工作台 (Flask 高速版)
echo ======================================================================
echo       [165 AI 智能多模態防詐騙鑑識系統] 啟動 Flask 網頁前端工作台
echo ======================================================================
echo.
echo 正在啟動 Flask 伺服器 (http://127.0.0.1:5000) ...
start "" "http://127.0.0.1:5000"
"C:\Users\USER\anaconda3\python.exe" "%~dp0flask_app.py"
pause
