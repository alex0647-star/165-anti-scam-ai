# -*- coding: utf-8 -*-
"""165 AI 專題 - 一鍵推送到 GitHub 自動化工具 (Smart GitHub Auto Push)"""

import os
import sys
import subprocess

# 設定 Windows 控制台 UTF-8 輸出，避免 cp950 編碼報錯
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

def run_cmd(cmd, cwd=None):
    try:
        res = subprocess.run(
            cmd,
            shell=True,
            cwd=cwd,
            text=True,
            capture_output=True,
            encoding="utf-8",
            errors="replace"
        )
        return res.returncode, res.stdout.strip(), res.stderr.strip()
    except Exception as e:
        return 1, "", str(e)

def main():
    project_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(project_dir)

    print("=" * 70)
    print("      [165 AI 智能多模態防詐騙系統] 一鍵推送到 GitHub 工具")
    print("=" * 70)
    print(f"專案目錄: {project_dir}")
    print()

    # 1. 檢查 Git 是否安裝
    code, out, _ = run_cmd("git --version")
    if code != 0:
        print("[錯誤] 找不到 Git 命令，請確認本機已安裝 Git。")
        return

    print(f"[OK] Git 環境正常 ({out})")

    # 2. 檢查是否為 Git 倉庫，若不是則自動初始化
    if not os.path.exists(os.path.join(project_dir, ".git")):
        print("[提示] 檢測到此目錄尚未初始化 Git，正在自動初始化...")
        run_cmd("git init -b main")
        run_cmd("git remote add origin https://github.com/alex0647-star/165-anti-scam-ai.git")
        print("[OK] 已自動初始化 Git 倉庫並設定 remote: origin -> https://github.com/alex0647-star/165-anti-scam-ai.git")
    else:
        # 檢查 remote
        code, remotes, _ = run_cmd("git remote -v")
        if "origin" not in remotes:
            run_cmd("git remote add origin https://github.com/alex0647-star/165-anti-scam-ai.git")
            print("[OK] 遠端倉庫已綁定: https://github.com/alex0647-star/165-anti-scam-ai.git")
        else:
            print("[OK] 遠端倉庫已綁定: https://github.com/alex0647-star/165-anti-scam-ai.git")

    # 3. 查看變更狀態
    print("\n正在檢查專案變更檔案...")
    run_cmd("git add .")
    code, status, _ = run_cmd("git status --short")
    
    if not status:
        print("[資訊] 目前沒有未提交的變更，專案已是最新狀態！")
    else:
        print("檢測到以下新增 / 修改檔案：")
        lines = status.split("\n")
        for line in lines[:15]:
            print(f"   * {line}")
        if len(lines) > 15:
            print(f"   ...以及其他 {len(lines) - 15} 個檔案")

        # 4. 提交 Commit
        commit_msg = "更新 165 AI 專題簡報、LINE 官方機器人伺服器與相關實測成果"
        print(f"\n正在提交 Commit: \"{commit_msg}\"...")
        run_cmd(f'git commit -m "{commit_msg}"')

    # 5. 推送到 GitHub
    print("\n正在推送到 GitHub (main 分支)...")
    code, out, err = run_cmd("git push -u origin main")
    
    if code == 0 or "Everything up-to-date" in out or "Everything up-to-date" in err:
        print("\n" + "=" * 70)
        print("【恭喜！推送成功！】專案已順利同步到 GitHub 倉庫！")
        print("GitHub 倉庫網址：https://github.com/alex0647-star/165-anti-scam-ai")
        print("=" * 70)
        print("\n後續提示：")
        print("1. 若有串接 Streamlit Cloud，線上網頁將會自動抓取最新代碼更新！")
        print("2. 雲端平台 (Render / Zeabur) 也會依據此推送自動重新建置並部署上線！")
    else:
        print("\n[推送回應訊息]：")
        if out:
            print(out)
        if err:
            print(err)
        print("\n提示：若出現權限提示，請依 Git 彈出視窗登入您的 GitHub 帳號即可。")

if __name__ == "__main__":
    main()
