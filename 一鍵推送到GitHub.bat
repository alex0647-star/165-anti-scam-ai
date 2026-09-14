@echo off
chcp 65001 >nul
cd /d "%~dp0"
"C:\Users\USER\anaconda3\python.exe" push_to_github.py
pause
