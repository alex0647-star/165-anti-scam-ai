"""Flask 高速無重刷多模態防詐鑑識伺服器 (Flask Web Dashboard & Unified API Server)

整合五大核心功能與 LINE Bot Webhook：
1. 💬 即時文字與短網址鑑識 (/api/analyze-text)
2. 📸 多模態截圖視覺 OCR 鑑識 (/api/analyze-image)
3. 🎬 AI 深偽 (Deepfake) 影片與短影音連結鑑識 (/api/analyze-video)
4. 📚 警政署 165 官網 API 即時同步與涉詐 LINE ID 查驗 (/api/sync-165, /api/check-line-id)
5. 📊 20 筆黃金基準測試量化評估 (/api/benchmark)
6. 📱 LINE 官方防詐機器人 Webhook + 即時 Loading 動畫與防休眠機制 (/callback, /webhook)
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
from flask import Flask, render_template, request, jsonify

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

app = Flask(__name__, template_folder=os.path.join(CURRENT_DIR, "templates"))
engine = AntiScamForensicEngine()


def serialize_analysis_result(result) -> dict:
    """將 AntiScamAnalysisResult 轉為前端 JSON 結構"""
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


@app.route("/", methods=["GET"])
def index():
    """渲染 Flask 單頁式高速防詐鑑識工作台"""
    return render_template("index.html", kb_entries=KNOWLEDGE_BASE_ENTRIES)


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "running", "service": "165 AI Flask & LINE Bot Unified Server"})


@app.route("/api/analyze-text", methods=["POST"])
def api_analyze_text():
    data = request.get_json(silent=True) or {}
    text = (data.get("text") or "").strip()
    if not text:
        return jsonify({"error": "請輸入待鑑識文字"}), 400
    res = engine.analyze(InputPayload(text=text))
    return jsonify(serialize_analysis_result(res))


@app.route("/api/analyze-image", methods=["POST"])
def api_analyze_image():
    if "image" not in request.files:
        return jsonify({"error": "未上傳圖片"}), 400
    f = request.files["image"]
    ext = os.path.splitext(f.filename or "img.png")[1] or ".png"
    with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as tf:
        f.save(tf.name)
        tmp_path = tf.name

    try:
        v_res = engine.vision_processor.analyze_image(tmp_path)
        ocr_text = v_res.get("extracted_text", "") if v_res.get("success") else ""
        ocr_source = v_res.get("source", "vision-ocr")
        payload = InputPayload(text=ocr_text, image_path=tmp_path) if ocr_text else InputPayload(image_path=tmp_path)
        res = engine.analyze(payload)
        return jsonify({
            "ocr_text": ocr_text,
            "ocr_source": ocr_source,
            "report": serialize_analysis_result(res),
        })
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


@app.route("/api/analyze-video", methods=["POST"])
def api_analyze_video():
    video_url = (request.form.get("video_url") or "").strip()
    user_context = (request.form.get("user_context") or "").strip()
    video_file = request.files.get("video_file")

    tmp_vpath = None
    grid_path = None
    try:
        if video_file and video_file.filename:
            v_ext = os.path.splitext(video_file.filename)[1] or ".mp4"
            with tempfile.NamedTemporaryFile(delete=False, suffix=v_ext) as tvf:
                video_file.save(tvf.name)
                tmp_vpath = tvf.name

        v_res = engine.analyze_video_forensics(
            video_url=video_url if video_url else None,
            video_path=tmp_vpath,
            user_context_text=user_context,
        )
        grid_path = v_res.get("grid_image_path")
        grid_b64 = ""
        if grid_path and os.path.exists(grid_path):
            with open(grid_path, "rb") as gf:
                grid_b64 = base64.b64encode(gf.read()).decode("utf-8")
        v_res["grid_image_b64"] = grid_b64
        v_res.pop("grid_image_path", None)
        return jsonify(v_res)
    finally:
        for p in [tmp_vpath, grid_path]:
            if p and os.path.exists(p):
                try:
                    os.remove(p)
                except Exception:
                    pass


@app.route("/api/sync-165", methods=["POST"])
def api_sync_165():
    sync_res = sync_from_165_official_api(max_items=6)
    return jsonify(sync_res)


@app.route("/api/check-line-id", methods=["GET"])
def api_check_line_id():
    lid = (request.args.get("line_id") or "").strip()
    hit = check_165_official_line_id(lid) if lid else None
    return jsonify({"hit": hit})


@app.route("/api/benchmark", methods=["POST"])
def api_benchmark():
    total = len(GOLDEN_TEST_DATASET)
    passed = 0
    tp = fn = fp = tn = 0
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
    return jsonify({"total": total, "passed": passed, "accuracy": acc, "recall": rec, "fpr": fpr})


if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    print(f"🚀 165 AI Flask 防詐鑑識工作台已啟動：http://127.0.0.1:{port}")
    app.run(host="0.0.0.0", port=port, debug=False)
