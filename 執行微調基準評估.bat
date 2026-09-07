@echo off
title 165 AI 防詐大模型 - 基準評估
cd /d "%~dp0"
chcp 65001 >nul
echo ======================================================
echo  正在執行 165 AI 防詐模型測試集基準驗證...
echo ======================================================
"C:\Users\USER\anaconda3\python.exe" finetune\eval_lora.py
pause