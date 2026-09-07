@echo off
title 165 AI 防詐專題 - 一鍵推送到 GitHub
cd /d "%~dp0"
chcp 65001 >nul
echo ================================================================================
echo   165 AI 防詐專題 - GitHub 雲端推送工具
echo ================================================================================
echo.
echo 請先至 https://github.com/new 建立一個名為 165-anti-scam-ai 的倉庫。
echo.
set /p REPO_URL="請貼上您的 GitHub 倉庫網址 (例如: https://github.com/alex0647-star/165-anti-scam-ai.git): "

if "%REPO_URL%"=="" (
    echo [錯誤] 未輸入網址，已取消。
    pause
    exit /b
)

echo.
echo 正在設定遠端倉庫...
git remote remove origin 2>nul
git remote add origin %REPO_URL%
git branch -M main

echo 正在推送程式碼至 GitHub...
git push -u origin main

echo.
echo ================================================================================
echo 推送完成！請回到 Streamlit Cloud 點擊 Deploy 即可！
echo ================================================================================
pause