"""多模態影像解析模組 (Vision Processor Module)

處理對話截圖、簡訊截圖與公文圖片，支援：
1. Gemini 多模態視覺 OCR (支援 gemini-3.6-flash / gemini-flash-latest)
2. 自動模型降級相容機制
"""

import os
import base64
from typing import Dict, Any, Optional
import requests
from anti_scam_llm.config import GEMINI_API_KEY, OPENAI_API_KEY, get_secret


class VisionProcessor:
    """多模態圖片前處理與視覺鑑識器"""

    def __init__(self, api_key: Optional[str] = None):
        self.gemini_key = api_key or get_secret("GEMINI_API_KEY", "") or GEMINI_API_KEY
        self.openai_key = get_secret("OPENAI_API_KEY", "") or OPENAI_API_KEY

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

        # 檢查是否有設定 Key
        current_key = self.gemini_key or get_secret("GEMINI_API_KEY", "")
        if current_key and current_key.strip():
            current_key = current_key.strip()
            # 依序嘗試最新可用的多模態模型
            models_to_try = ["gemini-3.6-flash", "gemini-flash-latest", "gemini-2.5-flash-lite", "gemini-1.5-flash"]
            last_err = ""

            for model_name in models_to_try:
                try:
                    extracted = self._call_gemini_vision(image_path, current_key, model_name)
                    if extracted and extracted.strip():
                        return {
                            "success": True,
                            "extracted_text": extracted.strip(),
                            "source": f"gemini-vision ({model_name})"
                        }
                except Exception as e:
                    last_err = str(e)
                    continue

            return {
                "success": False,
                "extracted_text": "",
                "source": "api-error",
                "error": f"Gemini API 視覺辨識錯誤: {last_err}"
            }

        return {
            "success": False,
            "extracted_text": "",
            "source": "no-key",
            "error": "未設定有效的 GEMINI_API_KEY。請至 Streamlit 右下角「⚙️ 管理應用」➔ Settings ➔ Secrets 填入金鑰。"
        }

    def _call_gemini_vision(self, image_path: str, api_key: str, model_name: str = "gemini-3.6-flash") -> str:
        """透過 Gemini REST API 進行圖片文字與情境抽取"""
        img_b64 = self.encode_image(image_path)
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={api_key}"
        
        headers = {"Content-Type": "application/json"}
        payload = {
            "contents": [
                {
                    "parts": [
                        {"text": "請精準讀取並逐字提取這張圖片中的所有文字、對話記錄、發送者、簡訊內容或公文細節。若有網址連結、金額、抽成比例或電話號碼請完整列出。"},
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
        
        resp = requests.post(url, headers=headers, json=payload, timeout=30)
        if resp.status_code != 200:
            error_detail = ""
            try:
                error_detail = resp.json().get("error", {}).get("message", resp.text)
            except Exception:
                error_detail = resp.text
            raise RuntimeError(f"HTTP {resp.status_code}: {error_detail}")

        data = resp.json()
        return data["candidates"][0]["content"]["parts"][0]["text"]