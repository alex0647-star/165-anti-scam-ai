@echo off
chcp 65001 >nul
echo ======================================================
echo  正在啟動 165 AI 防詐騙鑑識工作台 (Streamlit Web)...
echo ======================================================
cd /d "%~dp0"
set PYTHONPATH=%~dp0;%PYTHONPATH%
"C:\Users\USER\anaconda3\Scripts\streamlit.exe" run anti_scam_llm/app.py
pause
