"""多模態影像解析模組 (Vision Processor Module)

處理對話截圖、簡訊截圖與公文圖片，支援：
1. Gemini 1.5 Flash 多模態 OCR 與視覺理解
2. 本地圖片基礎資訊解析與安全例外防護
"""

import os
import base64
from typing import Dict, Any, Optional
import requests
from anti_scam_llm.config import GEMINI_API_KEY, OPENAI_API_KEY


class VisionProcessor:
    """多模態圖片前處理與視覺鑑識器"""

    def __init__(self, api_key: Optional[str] = None):
        self.gemini_key = api_key or os.getenv("GEMINI_API_KEY") or GEMINI_API_KEY
        self.openai_key = os.getenv("OPENAI_API_KEY") or OPENAI_API_KEY

    def encode_image(self, image_path: str) -> str:
        """將圖片轉為 base64 編碼"""
        if not os.path.exists(image_path):
            raise FileNotFoundError(f"找不到指定的圖片檔案: {image_path}")
        with open(image_path, "rb") as img_file:
            return base64.b64encode(img_file.read()).decode("utf-8")

    def analyze_image(self, image_path: str) -> Dict[str, Any]:
        """解析截圖或公文圖片，提取對話與可疑元素"""
        if not os.path.exists(image_path):
            return {
                "success": False,
                "error": f"檔案不存在: {image_path}",
                "extracted_text": "",
                "source": "error"
            }

        # 若有 Gemini API Key，直接調用 Gemini 1.5 Flash 多模態模型
        if self.gemini_key:
            try:
                extracted = self._call_gemini_vision(image_path)
                if extracted and extracted.strip():
                    return {
                        "success": True,
                        "extracted_text": extracted.strip(),
                        "source": "gemini-vision"
                    }
            except Exception as e:
                print(f"[VisionProcessor Warning] Vision API 呼叫失敗: {e}")

        # 若未設定 Key 或 API 失敗，回傳明確標記而非誤導文字
        return {
            "success": True,
            "extracted_text": "",
            "source": "no-api-key",
            "warning": "未設定有效 GEMINI_API_KEY，無法辨識截圖文字。請於 Settings -> Variables and secrets 新增 GEMINI_API_KEY。"
        }

    def _call_gemini_vision(self, image_path: str) -> str:
        """透過 Gemini REST API 進行圖片文字與情境抽取"""
        img_b64 = self.encode_image(image_path)
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={self.gemini_key}"
        
        headers = {"Content-Type": "application/json"}
        payload = {
            "contents": [
                {
                    "parts": [
                        {"text": "請精準讀取並逐字提取這張圖片中的所有文字、對話記錄、發送者、簡訊內容或公文細節。若有網址連結或電話號碼請完整列出。如果圖片中沒有文字，請回答『[未包含文字的非詐騙圖片]』。"},
                        {
                            "inline_data": {
                                "mime_type": "image/jpeg" if image_path.lower().endswith((".jpg", ".jpeg")) else "image/png",
                                "data": img_b64
                            }
                        }
                    ]
                }
            ]
        }
        
        resp = requests.post(url, headers=headers, json=payload, timeout=20)
        resp.raise_for_status()
        data = resp.json()
        return data["candidates"][0]["content"]["parts"][0]["text"]