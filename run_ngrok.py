"""
啟動 ngrok 外網穿透服務
"""
import sys
import os
import time

try:
    from pyngrok import ngrok
except ImportError:
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pyngrok"])
    from pyngrok import ngrok

print("=" * 65)
print("       165 AI 防詐騙機器人 - ngrok 外網連線服務")
print("=" * 65)
print()
print("💡 提示：若您尚未設定過 Authtoken，請至 https://dashboard.ngrok.com/get-started/your-authtoken 複製。")
print()

token = input("請在此貼上 Authtoken (若已設定過請直接按 Enter): ").strip()
if token:
    try:
        ngrok.set_auth_token(token)
        print("✅ Authtoken 註冊完成！\n")
    except Exception as e:
        print(f"⚠️ Authtoken 設定提示: {e}\n")

print("🚀 正在啟動外網連線隧道 (Port 8000)...")
try:
    tunnel = ngrok.connect(8000, "http")
    public_url = tunnel.public_url.replace("http://", "https://")
    webhook_url = f"{public_url}/callback"

    print()
    print("=" * 65)
    print("🎉 【外網穿透成功！】請複製下方這串網址：")
    print()
    print(f"   {webhook_url}")
    print()
    print("=" * 65)
    print("👉 請將上方這串網址貼到 LINE Developers Console -> Messaging API -> Webhook URL")
    print("👉 然後點擊【Update】，開啟【Use Webhook】，並點擊【Verify】！")
    print("⚠️ 提醒：測試期間請保持此黑底視窗開啟，不要關閉。")
    print("=" * 65)
    print()

    # 保持執行狀態
    while True:
        time.sleep(1)

except KeyboardInterrupt:
    print("\n連線已正常中斷。")
    ngrok.kill()
except Exception as e:
    print(f"\n❌ 連線錯誤: {e}")
    print("\n常見原因：Authtoken 未填或無效。請重新執行並輸入正確的 Authtoken。")
    input("\n按 Enter 鍵關閉視窗...")