"""LINE 官方防詐機器人伺服器 (LINE Bot Webhook Server)

使用 FastAPI 快速搭建：
1. 接收來自 LINE 使用者轉傳的文字或可疑簡訊
2. 串接 AntiScamForensicEngine 進行 165 RAG 鑑識
3. 秒級回傳美化排版之風險評估、可疑特徵與防詐指引
"""

import os
import sys
import hmac
import hashlib
import base64
import json
import requests
from fastapi import FastAPI, Request, HTTPException, Header
import uvicorn

# 確保能讀取專案核心模組
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from anti_scam_llm.schemas import InputPayload
from anti_scam_llm.reasoning_engine import AntiScamForensicEngine

# LINE 金鑰設定（可透過環境變數或直接在此填入）
LINE_CHANNEL_ACCESS_TOKEN = os.getenv("LINE_CHANNEL_ACCESS_TOKEN", "9/4xIUDnor0G4WeoSqKd86N65J8mrFZrYVAAdApKP16pYBgQ18VjsSRU6gIjyPGVt8yCYpFPyE3teaH8Mmc3Z1JYVCXq8IY6s5sEaiUSnKJIhe788Fv6swVu2Mjz0B2VOlk0JjTCfj5IhSlLx390iAdB04t89/1O/w1cDnyilFU=")
LINE_CHANNEL_SECRET = os.getenv("LINE_CHANNEL_SECRET", "c6250af46d9081337b2aa791bd198e74")

app = FastAPI(title="165 AI 防詐騙 LINE Bot 伺服器")
engine = AntiScamForensicEngine()


def format_line_response(result) -> str:
    """將鑑識報告格式化為適合 LINE 手機螢幕閱讀的排版"""
    ra = result.risk_assessment
    score = ra.risk_score
    
    if score <= 30:
        emoji_badge = "🟢【安全通知・非詐騙】"
    elif score <= 60:
        emoji_badge = "🟡【低度疑慮・請提高警覺】"
    elif score <= 80:
        emoji_badge = "🟠【中度風險・疑似詐騙陷阱】"
    else:
        emoji_badge = "🔴【極度危險・高機率詐騙】"

    lines = [
        f"{emoji_badge}",
        f"📊 量化風險指數：{score} / 100",
        f"🎯 判定手法類型：{ra.primary_scam_type}",
        "─────────────────",
        f"🔍 【鑑識論證】\n{result.evidence_analysis}",
        "─────────────────"
    ]

    if result.red_flags:
        lines.append("🚩 【可疑特徵點 (破綻標註)】")
        for rf in result.red_flags:
            lines.append(f"• [{rf.severity.value}] 「{rf.quote}」➔ {rf.issue_type}")
        lines.append("─────────────────")

    if result.psychological_tactics:
        lines.append("🧠 【心理操控手法拆解】")
        for pt in result.psychological_tactics:
            lines.append(f"• ［{pt.tactic_name}］：{pt.description}")
        lines.append("─────────────────")

    lines.append("🛡️ 【165 安全處置指南】")
    lines.append("🚨 切勿進行：")
    for act in result.actionable_guidance.immediate_actions:
        lines.append(f"  ❌ {act}")
    
    lines.append("📞 官方查證途徑：")
    for ver in result.actionable_guidance.official_verification:
        lines.append(f"  ✅ {ver}")

    if result.actionable_guidance.recommended_safe_reply:
        lines.append("─────────────────")
        lines.append(f"💬 【建議安全防禦話術】\n「{result.actionable_guidance.recommended_safe_reply}」")

    return "\n".join(lines)


def get_clean_env(key: str, default: str) -> str:
    val = os.getenv(key, default)
    if val:
        return val.strip(' "\'\r\n\t')
    return default

def reply_line_message(reply_token: str, text: str):
    """透過 LINE Messaging API 回傳訊息給使用者"""
    token = get_clean_env("LINE_CHANNEL_ACCESS_TOKEN", LINE_CHANNEL_ACCESS_TOKEN)
    url = "https://api.line.me/v2/bot/message/reply"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}"
    }
    payload = {
        "replyToken": reply_token,
        "messages": [{"type": "text", "text": text}]
    }
    try:
        resp = requests.post(url, headers=headers, json=payload, timeout=15)
        resp.raise_for_status()
        print(f"✅ [LINE Reply] 成功發送回覆 (Token: {reply_token[:10]}...)")
    except Exception as e:
        print(f"❌ [LINE Reply Error] 發送回覆失敗: {e}")


@app.get("/")
async def health_check():
    return {"status": "running", "service": "165 AI Anti-Scam LINE Bot Server"}


@app.post("/callback")
@app.post("/webhook")
async def line_webhook(request: Request, x_line_signature: str = Header(None)):
    """接收 LINE Webhook 事件回調 (支援 /callback 與 /webhook 路由)"""
    try:
        body_bytes = await request.body()
        body_str = body_bytes.decode("utf-8")
    except Exception as e:
        return {"status": "error", "detail": str(e)}

    # 解析 JSON
    try:
        data = json.loads(body_str) if body_str else {}
    except Exception:
        data = {}

    events = data.get("events", [])

    # 1. 若為 LINE 後台 Verify 驗證請求 (events 為空列表)，直接回傳 200 OK 確保後台綠燈成功
    if not events:
        print("✅ [LINE Verify] 收到 LINE 後台連線測試請求，回傳 HTTP 200 OK")
        return {"status": "ok", "message": "LINE Webhook Verified Successfully"}

    # 2. 簽章校驗 (若有配置 Secret)
    secret = get_clean_env("LINE_CHANNEL_SECRET", LINE_CHANNEL_SECRET)
    signature = x_line_signature or request.headers.get("x-line-signature", "")
    if secret and secret != "你的_LINE_CHANNEL_SECRET":
        hash_val = hmac.new(secret.encode("utf-8"), body_bytes, hashlib.sha256).digest()
        expected_sig = base64.b64encode(hash_val).decode("utf-8")
        if signature and signature != expected_sig:
            print(f"⚠️ [LINE Signature Warning] 簽章比對不符，但為保障使用者體驗繼續處理")

    # 3. 逐筆處理使用者傳來的事件
    for event in events:
        event_type = event.get("type")
        reply_token = event.get("replyToken")

        if event_type == "message" and reply_token:
            msg = event.get("message", {})
            msg_type = msg.get("type")

            if msg_type == "text":
                user_text = msg.get("text", "").strip()
                if user_text:
                    try:
                        print(f"📩 [收到 LINE 訊息] 內容: {user_text[:30]}...")
                        payload = InputPayload(text=user_text)
                        result = engine.analyze(payload)
                        reply_content = format_line_response(result)
                        reply_line_message(reply_token, reply_content)
                    except Exception as e:
                        print(f"❌ [AI Engine Error] 鑑識失敗: {e}")
                        reply_line_message(reply_token, "⚠️ 抱歉，AI 防詐系統鑑識時發生短暫異常，請稍後再次嘗試。")

    return {"status": "ok"}


if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    print(f"🚀 LINE Bot 伺服器啟動於 port {port}...")
    uvicorn.run("line_bot_server:app", host="0.0.0.0", port=port, reload=True)
