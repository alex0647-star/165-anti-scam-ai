@echo off
chcp 65001 >nul
echo ======================================================
echo  正在執行 20 筆黃金測試集基準評估 (Benchmark)...
echo ======================================================
cd /d "%~dp0"
set PYTHONPATH=%~dp0;%PYTHONPATH%
"C:\Users\USER\anaconda3\python.exe" -m anti_scam_llm.main --benchmark
pause
