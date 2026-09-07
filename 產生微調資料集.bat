@echo off
title 165 AI 防詐大模型 - 產生微調資料集
cd /d "%~dp0"
chcp 65001 >nul
echo ======================================================
echo  正在建構 165 AI 防詐 SFT 領域微調資料集...
echo ======================================================
"C:\Users\USER\anaconda3\python.exe" anti_scam_llm\dataset_generator.py
pause