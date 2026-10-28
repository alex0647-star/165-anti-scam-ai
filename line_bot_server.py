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
import time
import threading
import tempfile
import requests
from fastapi import FastAPI, Request, HTTPException, Header, UploadFile, File, Form
from fastapi.responses import HTMLResponse, JSONResponse
from jinja2 import Environment, FileSystemLoader
import uvicorn

# 確保能讀取專案核心模組
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from anti_scam_llm.schemas import InputPayload
from anti_scam_llm.reasoning_engine import AntiScamForensicEngine
from anti_scam_llm.knowledge_base import (
    KNOWLEDGE_BASE_ENTRIES,
    sync_from_165_official_api,
    check_165_official_line_id,
)
from anti_scam_llm.dataset import GOLDEN_TEST_DATASET

# LINE 金鑰設定（可透過環境變數或直接在此填入）
LINE_CHANNEL_ACCESS_TOKEN = os.getenv("LINE_CHANNEL_ACCESS_TOKEN", "pxYMYhSgKjTGtDhFcVnnDmWCy5jImABGE6lds8v3H/5v+9Nz6JQbVWEYpIxBHVLL0jjp79/4iMzMOlzWDnTu39WWPb1H8oAUii5ZH2GQTwqybfw+E7APl0wQ/N21dW6UzDG/TUheqsY81hINHXVecgdB04t89/1O/w1cDnyilFU=")
LINE_CHANNEL_SECRET = os.getenv("LINE_CHANNEL_SECRET", "f31f835ea4c677afbea367442cbc01f2")

app = FastAPI(title="165 AI 防詐騙 Web & LINE Bot 伺服器")
engine = AntiScamForensicEngine()
jinja_env = Environment(loader=FileSystemLoader(os.path.join(CURRENT_DIR, "templates")))

# 追蹤最後一次請求時間以偵測雲端休眠喚醒狀態
_LAST_ACTIVE_TIME = time.time()
_IS_FIRST_REQUEST = True


def _start_keep_alive_daemon():
    """背景定時自喚醒執行緒：每 10 分鐘自動 ping 雲端網址，防止 Render 免費容器進入 15 分鐘閒置休眠"""
    def _ping_loop():
        while True:
            time.sleep(540)  # 每 9 分鐘執行一次
            target_url = os.getenv("RENDER_EXTERNAL_URL", "").rstrip("/")
            if target_url:
                try:
                    requests.get(f"{target_url}/health", timeout=10)
                except Exception:
                    pass
    t = threading.Thread(target=_ping_loop, daemon=True)
    t.start()


_start_keep_alive_daemon()


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
    if score <= 30:
        lines.append("✨ 處置建議：")
        for act in result.actionable_guidance.immediate_actions:
            lines.append(f"  🟢 {act}")
    else:
        lines.append("🚨 切勿進行：")
        for act in result.actionable_guidance.immediate_actions:
            lines.append(f"  ❌ {act}")
    
    lines.append("📞 官方查證途徑：")
    for ver in result.actionable_guidance.official_verification:
        lines.append(f"  ✅ {ver}")

    if result.actionable_guidance.recommended_safe_reply and score > 30:
        lines.append("─────────────────")
        lines.append(f"💬 【建議安全防禦話術】\n「{result.actionable_guidance.recommended_safe_reply}」")

    return "\n".join(lines)


def get_clean_env(key: str, default: str) -> str:
    val = os.getenv(key, default)
    if val:
        return val.strip(' "\'\r\n\t')
    return default

def start_line_loading(user_id: str, loading_seconds: int = 25):
    """調用 LINE 官方 Loading Indicator API，在使用者聊天室立即顯示『正在輸入/分析中(...)』動態動畫回饋"""
    if not user_id:
        return
    token = get_clean_env("LINE_CHANNEL_ACCESS_TOKEN", LINE_CHANNEL_ACCESS_TOKEN)
    url = "https://api.line.me/v2/bot/chat/loading/start"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}"
    }
    # LINE 規範 loadingSeconds 需為 5 之倍數 (5 ~ 60)
    sec = max(5, min(60, (loading_seconds // 5) * 5))
    payload = {
        "chatId": user_id,
        "loadingSeconds": sec
    }
    try:
        requests.post(url, headers=headers, json=payload, timeout=3)
        print(f"⏳ [LINE Loading] 已向使用者 ({user_id[:8]}...) 顯示官方分析中動態提示 ({sec}s)")
    except Exception as e:
        print(f"⚠️ [LINE Loading Notice] {e}")


def reply_line_message(reply_token: str, text: str, wakeup_notice: bool = False):
    """透過 LINE Messaging API 回傳訊息給使用者（若剛從雲端休眠喚醒，可附加喚醒完成提示）"""
    token = get_clean_env("LINE_CHANNEL_ACCESS_TOKEN", LINE_CHANNEL_ACCESS_TOKEN)
    url = "https://api.line.me/v2/bot/message/reply"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}"
    }
    messages = []
    if wakeup_notice:
        messages.append({
            "type": "text",
            "text": "⚡【165 AI 雲端鑑識引擎已喚醒】\n感謝您的耐心等候！剛剛雲端主機正從省電模式喚醒並載入 165 防詐資料庫，以下為您的深度鑑識報告 👇"
        })
    messages.append({"type": "text", "text": text[:4900]})
    payload = {
        "replyToken": reply_token,
        "messages": messages
    }
    try:
        resp = requests.post(url, headers=headers, json=payload, timeout=15)
        resp.raise_for_status()
        print(f"✅ [LINE Reply] 成功發送回覆 (Token: {reply_token[:10]}...)")
    except Exception as e:
        print(f"❌ [LINE Reply Error] 發送回覆失敗: {e}")


def download_line_image(message_id: str) -> str:
    """從 LINE Messaging API 下載使用者傳送的截圖圖片並存為暫存檔"""
    token = get_clean_env("LINE_CHANNEL_ACCESS_TOKEN", LINE_CHANNEL_ACCESS_TOKEN)
    url = f"https://api-data.line.me/v2/bot/message/{message_id}/content"
    headers = {"Authorization": f"Bearer {token}"}
    resp = requests.get(url, headers=headers, timeout=15)
    resp.raise_for_status()
    tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".jpg")
    tmp_file.write(resp.content)
    tmp_file.close()
    return tmp_file.name


def download_line_video(message_id: str) -> str:
    """從 LINE Messaging API 下載使用者傳送的短影音 (.mp4) 並存為暫存檔"""
    token = get_clean_env("LINE_CHANNEL_ACCESS_TOKEN", LINE_CHANNEL_ACCESS_TOKEN)
    url = f"https://api-data.line.me/v2/bot/message/{message_id}/content"
    headers = {"Authorization": f"Bearer {token}"}
    resp = requests.get(url, headers=headers, stream=True, timeout=20)
    resp.raise_for_status()
    tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".mp4")
    for chunk in resp.iter_content(chunk_size=65536):
        if chunk:
            tmp_file.write(chunk)
            if tmp_file.tell() > 10 * 1024 * 1024:  # 限制讀取前 10MB 確保秒級抽幀回應
                break
    tmp_file.close()
    return tmp_file.name


def format_line_video_response(vr: dict) -> str:
    """將 AI 深偽影片與短影音鑑識結果格式化為 LINE 手機訊息排版（分兩大部分：1. AI合成率、2. 辨別是否為詐騙）"""
    v_score = vr.get("scam_risk_score", 10)
    df_prob = vr.get("deepfake_probability", 12)
    vm = vr.get("visual_metrics", {})
    lines = [
        f"🎬 【165 影片雙維度鑑識報告】",
        f"📺 來源平台：{vr.get('platform', 'LINE 影片上傳')}",
    ]
    if vr.get("title"):
        lines.append(f"📝 影片標題：{vr['title'][:60]}")
    if vr.get("author_name"):
        ch_tag = " ✅[官方頻道]" if (vr.get("is_official_channel") and v_score <= 30) else " ⚠️[非官方/遭擷取]"
        lines.append(f"👤 發布頻道：{vr['author_name']}{ch_tag}")

    lines.extend([
        "─────────────────",
        f"🤖 【1️⃣ 第一部分：AI 合成率鑑識】",
        f"• AI 合成率：{df_prob}%",
        f"• 判定結果：{vr.get('ai_verdict_label', '')}",
        f"• 頻域指標：人臉/背景紋理比值 {vm.get('skin_smoothing_ratio', 1.0)}x",
        f"• 深偽剖析：{vr.get('ai_synthesis_summary', '')}",
        "─────────────────",
        f"🚨 【2️⃣ 第二部分：辨別是否為詐騙】",
        f"• 詐騙風險指數：{v_score} / 100",
        f"• 判定結果：{vr.get('scam_verdict_label', '')}",
        f"• 防詐剖析：{vr.get('scam_analysis_summary', '')}",
    ])

    if vr.get("scam_flags"):
        lines.append("🚩 偵測到的詐騙破綻：")
        for ff in vr["scam_flags"][:3]:
            lines.append(f"• 「{ff.get('quote')}」➔ {ff.get('issue_type')}")

    lines.append("─────────────────")
    lines.append("🛡️ 【165 防範 AI 深偽詐騙指南】")
    if v_score > 50 or df_prob > 50:
        lines.append("  ❌ 切勿輕信短影音中名人（如黃仁勳、張忠謀、財經專家）推薦飆股或免費贈書！")
        lines.append("  ❌ 切勿點擊影片說明欄連結或加入影片內的私人 LINE ID！")
        lines.append("  ✅ 遇可疑名人投資廣告請撥打 165 反詐騙專線查證。")
    else:
        lines.append("  🟢 未偵測到明顯 AI 換臉冒用名人或假投資引流話術。")
    return "\n".join(lines)


def _serialize_result(result) -> dict:
    ra = result.risk_assessment
    return {
        "analysis_id": result.analysis_id,
        "risk_score": ra.risk_score,
        "risk_level": ra.risk_level.value,
        "primary_scam_type": ra.primary_scam_type,
        "evidence_analysis": result.evidence_analysis,
        "red_flags": [
            {"severity": rf.severity.value, "quote": rf.quote, "issue_type": rf.issue_type}
            for rf in result.red_flags
        ],
        "immediate_actions": result.actionable_guidance.immediate_actions,
        "official_verification": result.actionable_guidance.official_verification,
        "recommended_safe_reply": result.actionable_guidance.recommended_safe_reply,
    }


@app.get("/", response_class=HTMLResponse)
async def web_dashboard():
    """直接於根路由渲染高速無重刷 165 AI 防詐騙鑑識工作台前端頁面"""
    template = jinja_env.get_template("index.html")
    html_content = template.render(kb_entries=KNOWLEDGE_BASE_ENTRIES)
    return HTMLResponse(content=html_content)


@app.get("/health")
async def health_check():
    return {"status": "running", "service": "165 AI Anti-Scam Web & LINE Bot Server"}


@app.post("/api/analyze-text")
async def api_analyze_text(request: Request):
    data = await request.json()
    text = (data.get("text") or "").strip()
    if not text:
        return JSONResponse({"error": "請輸入待鑑識文字"}, status_code=400)
    res = engine.analyze(InputPayload(text=text))
    return JSONResponse(_serialize_result(res))


@app.post("/api/analyze-image")
async def api_analyze_image(image: UploadFile = File(...)):
    ext = os.path.splitext(image.filename or "img.png")[1] or ".png"
    content = await image.read()
    with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as tf:
        tf.write(content)
        tmp_path = tf.name
    try:
        v_res = engine.vision_processor.analyze_image(tmp_path)
        ocr_text = v_res.get("extracted_text", "") if v_res.get("success") else ""
        ocr_source = v_res.get("source", "vision-ocr")
        payload = InputPayload(text=ocr_text, image_path=tmp_path) if ocr_text else InputPayload(image_path=tmp_path)
        res = engine.analyze(payload)
        return JSONResponse({
            "ocr_text": ocr_text,
            "ocr_source": ocr_source,
            "report": _serialize_result(res),
        })
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


@app.post("/api/analyze-video")
async def api_analyze_video(
    video_url: str = Form(""),
    user_context: str = Form(""),
    video_file: UploadFile = File(None),
):
    tmp_vpath = None
    grid_path = None
    try:
        if video_file and video_file.filename:
            v_ext = os.path.splitext(video_file.filename)[1] or ".mp4"
            content = await video_file.read()
            with tempfile.NamedTemporaryFile(delete=False, suffix=v_ext) as tvf:
                tvf.write(content)
                tmp_vpath = tvf.name

        v_res = engine.analyze_video_forensics(
            video_url=video_url.strip() if video_url else None,
            video_path=tmp_vpath,
            user_context_text=user_context.strip() if user_context else "",
        )
        grid_path = v_res.get("grid_image_path")
        grid_b64 = ""
        if grid_path and os.path.exists(grid_path):
            with open(grid_path, "rb") as gf:
                grid_b64 = base64.b64encode(gf.read()).decode("utf-8")
        v_res["grid_image_b64"] = grid_b64
        v_res.pop("grid_image_path", None)
        return JSONResponse(v_res)
    finally:
        for p in [tmp_vpath, grid_path]:
            if p and os.path.exists(p):
                try:
                    os.remove(p)
                except Exception:
                    pass


@app.post("/api/sync-165")
async def api_sync_165():
    return JSONResponse(sync_from_165_official_api(max_items=6))


@app.get("/api/check-line-id")
async def api_check_line_id(line_id: str = ""):
    hit = check_165_official_line_id(line_id.strip()) if line_id.strip() else None
    return JSONResponse({"hit": hit})


@app.post("/api/benchmark")
async def api_benchmark():
    total = len(GOLDEN_TEST_DATASET)
    passed = tp = fn = fp = tn = 0
    for item in GOLDEN_TEST_DATASET:
        res = engine.analyze(InputPayload(text=item["input_text"]))
        pred_scam = res.risk_assessment.risk_score >= 60
        actual_scam = item["expected_is_scam"]
        if pred_scam == actual_scam:
            passed += 1
        if actual_scam and pred_scam:
            tp += 1
        elif actual_scam and not pred_scam:
            fn += 1
        elif not actual_scam and pred_scam:
            fp += 1
        else:
            tn += 1
    acc = round(passed / total * 100, 1) if total else 100.0
    rec = round(tp / (tp + fn) * 100, 1) if (tp + fn) else 100.0
    fpr = round(fp / (fp + tn) * 100, 1) if (fp + tn) else 0.0
    return JSONResponse({"total": total, "passed": passed, "accuracy": acc, "recall": rec, "fpr": fpr})


@app.post("/callback")
@app.post("/webhook")
async def line_webhook(request: Request, x_line_signature: str = Header(None)):
    """接收 LINE Webhook 事件回調 (支援 /callback 與 /webhook 路由)"""
    global _LAST_ACTIVE_TIME, _IS_FIRST_REQUEST
    now_ts = time.time()
    idle_seconds = now_ts - _LAST_ACTIVE_TIME
    was_waking_up = _IS_FIRST_REQUEST or (idle_seconds > 480)
    _LAST_ACTIVE_TIME = now_ts
    _IS_FIRST_REQUEST = False

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
        user_id = event.get("source", {}).get("userId", "")

        # 立即啟動 LINE 官方 Loading 動畫 (...)，讓使用者第一時間看到機器人正在喚醒與分析中！
        if user_id:
            start_line_loading(user_id, loading_seconds=30)

        if event_type == "follow" and reply_token:
            welcome_msg = (
                "🛡️ 歡迎加入【165 AI 智能防詐騙守門員 (@325readm)】！\n"
                "─────────────────\n"
                "您可以隨時直接傳送以下 3 種內容給我：\n"
                "1️⃣ 【可疑簡訊或網址】：直接複製貼上（含短網址與 LINE ID 查驗）\n"
                "2️⃣ 【手機對話截圖】：直接上傳圖片，內建三層 OCR 自動辨識\n"
                "3️⃣ 【可疑短影音或影片連結】：支援貼上 YouTube / Shorts / TikTok / FB 影片網址或直接傳送 MP4 影片，自動檢測是否為 AI 換臉深偽 (Deepfake) 詐騙！\n"
                "─────────────────\n"
                "💡 溫馨提示：若雲端引擎處於省電休眠，首次傳訊後畫面會顯示「分析中 (...)」動畫，約需 5～15 秒喚醒，請稍候片刻！"
            )
            reply_line_message(reply_token, welcome_msg)
            continue

        if event_type == "message" and reply_token:
            msg = event.get("message", {})
            msg_type = msg.get("type")

            if msg_type == "text":
                user_text = msg.get("text", "").strip()
                if user_text:
                    # 若使用者傳送測試或喚醒指令，秒回狀態說明
                    if user_text.lower() in ["你好", "嗨", "hi", "hello", "測試", "喚醒", "在嗎", "help", "說明", "功能"]:
                        guide_msg = (
                            "🟢 【165 AI 鑑識引擎：已在線待命！】\n"
                            "─────────────────\n"
                            "請直接貼上或傳送您想查證的內容：\n"
                            "• 💬 貼上【可疑簡訊 / LINE 對話 / 短網址】\n"
                            "• 📸 傳送【手機截圖圖片】\n"
                            "• 🎬 貼上【YouTube / TikTok / FB 短影音連結】或【傳送影片檔】檢測 AI 深偽換臉詐騙！\n"
                            "─────────────────\n"
                            "⏳ 當您傳送訊息後，聊天室會立即顯示「...」動態讀取動畫，代表 AI 正在為您展開短網址與比對警政署 165 資料庫！"
                        )
                        reply_line_message(reply_token, guide_msg)
                        continue

                    try:
                        print(f"📩 [收到 LINE 訊息] 內容: {user_text[:30]}...")
                        t0 = time.time()
                        payload = InputPayload(text=user_text)
                        result = engine.analyze(payload)
                        elapsed = time.time() - t0
                        reply_content = format_line_response(result)
                        reply_line_message(reply_token, reply_content, wakeup_notice=(was_waking_up or elapsed > 6.0))
                    except Exception as e:
                        print(f"❌ [AI Engine Error] 鑑識失敗: {e}")
                        reply_line_message(reply_token, "⚠️ 抱歉，AI 防詐系統鑑識時發生短暫異常，請稍後再次嘗試。")

            elif msg_type == "image":
                msg_id = msg.get("id", "")
                if msg_id:
                    tmp_path = ""
                    try:
                        print(f"🖼️ [收到 LINE 圖片] Message ID: {msg_id}，啟動多模態截圖 OCR 鑑識...")
                        t0 = time.time()
                        tmp_path = download_line_image(msg_id)
                        payload = InputPayload(image_path=tmp_path)
                        result = engine.analyze(payload)
                        elapsed = time.time() - t0
                        reply_content = format_line_response(result)
                        reply_line_message(reply_token, reply_content, wakeup_notice=(was_waking_up or elapsed > 6.0))
                    except Exception as e:
                        print(f"❌ [LINE Image Analysis Error] 圖片鑑識失敗: {e}")
                        reply_line_message(reply_token, "⚠️ 抱歉，截圖辨識時發生短暫連線異常，請直接將截圖中的網址或對話文字複製貼上，系統將立即為您鑑識！")
                    finally:
                        if tmp_path and os.path.exists(tmp_path):
                            try:
                                os.remove(tmp_path)
                            except Exception:
                                pass

            elif msg_type == "video":
                msg_id = msg.get("id", "")
                if msg_id:
                    tmp_vpath = ""
                    grid_p = ""
                    try:
                        print(f"🎬 [收到 LINE 影片] Message ID: {msg_id}，啟動 AI 深偽影片抽幀與話術鑑識...")
                        t0 = time.time()
                        tmp_vpath = download_line_video(msg_id)
                        v_report = engine.analyze_video_forensics(video_path=tmp_vpath)
                        elapsed = time.time() - t0
                        grid_p = v_report.get("grid_image_path", "")
                        reply_content = format_line_video_response(v_report)
                        reply_line_message(reply_token, reply_content, wakeup_notice=(was_waking_up or elapsed > 6.0))
                    except Exception as e:
                        print(f"❌ [LINE Video Analysis Error] 影片鑑識失敗: {e}")
                        reply_line_message(reply_token, "⚠️ 抱歉，影片抽幀鑑識時發生短暫異常，您可直接貼上該影片的網址（YouTube / Shorts / TikTok / FB Reels）或截圖傳送，系統將立即為您鑑識！")
                    finally:
                        for p in [tmp_vpath, grid_p]:
                            if p and os.path.exists(p):
                                try:
                                    os.remove(p)
                                except Exception:
                                    pass

    return {"status": "ok"}


if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    print(f"🚀 LINE Bot 伺服器啟動於 port {port}...")
    uvicorn.run("line_bot_server:app", host="0.0.0.0", port=port, reload=True)
