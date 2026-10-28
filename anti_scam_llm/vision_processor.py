"""多模態影像解析模組 (Vision Processor Module)

處理對話截圖、簡訊截圖與公文圖片，支援三層式高可用視覺辨識架構：
1. Gemini 多模態視覺 OCR (支援多模型自動降級與配額切換)
2. 本地端神經網路 OCR 引擎 (RapidOCR ONNX Runtime) — 免 API 金鑰、零配額限制、永不發生 HTTP 429/503
3. 免金鑰雲端 OCR 自動備援機制 (Cloud OCR Fallback)
"""

import os
import io
import base64
from typing import Dict, Any, Optional
import requests
from PIL import Image
from anti_scam_llm.config import GEMINI_API_KEY, OPENAI_API_KEY, get_secret

# 單例快取本地 RapidOCR 引擎，避免重複載入模型
_LOCAL_RAPID_OCR = None


def _get_local_rapid_ocr():
    global _LOCAL_RAPID_OCR
    if _LOCAL_RAPID_OCR is None:
        from rapidocr_onnxruntime import RapidOCR
        _LOCAL_RAPID_OCR = RapidOCR()
    return _LOCAL_RAPID_OCR


class VisionProcessor:
    """多模態圖片前處理與視覺鑑識器"""

    def __init__(self, api_key: Optional[str] = None):
        self.gemini_key = api_key or get_secret("GEMINI_API_KEY", "") or GEMINI_API_KEY
        self.openai_key = get_secret("OPENAI_API_KEY", "") or OPENAI_API_KEY

    def encode_image(self, image_path: str, max_dim: int = 1000) -> str:
        """自動等比例壓縮並轉為輕量 JPEG base64 編碼，確保秒級傳輸"""
        if not os.path.exists(image_path):
            raise FileNotFoundError(f"找不到指定的圖片檔案: {image_path}")

        try:
            with Image.open(image_path) as img:
                img = img.convert("RGB")
                img.thumbnail((max_dim, max_dim), Image.Resampling.LANCZOS)
                buffer = io.BytesIO()
                img.save(buffer, format="JPEG", quality=85)
                return base64.b64encode(buffer.getvalue()).decode("utf-8")
        except Exception:
            with open(image_path, "rb") as img_file:
                return base64.b64encode(img_file.read()).decode("utf-8")

    def analyze_image(self, image_path: str) -> Dict[str, Any]:
        """解析截圖或公文圖片，提取對話與可疑元素（具備 Gemini Vision + 本地 RapidOCR + 雲端 OCR 三重保障）"""
        if not os.path.exists(image_path):
            return {
                "success": False,
                "error": f"檔案不存在: {image_path}",
                "extracted_text": "",
                "source": "error"
            }

        # 1. 若有設定 GEMINI_API_KEY，嘗試使用 Gemini 多模態視覺模型 (優先使用高配額模型避免 429)
        current_key = self.gemini_key or get_secret("GEMINI_API_KEY", "")
        last_err = ""
        if current_key and current_key.strip():
            current_key = current_key.strip()
            models_to_try = [
                "gemini-2.0-flash",
                "gemini-2.0-flash-lite",
                "gemini-1.5-flash",
                "gemini-2.5-flash",
            ]

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

        # 2. 本地端神經網路 OCR 自動備援 (RapidOCR ONNX Runtime，無配額上限、不受 HTTP 429 / 503 影響)
        try:
            local_text = self._call_local_rapidocr(image_path)
            if local_text and local_text.strip():
                return {
                    "success": True,
                    "extracted_text": local_text.strip(),
                    "source": "local-neural-ocr (RapidOCR)"
                }
        except Exception as e:
            last_err = f"{last_err}; Local RapidOCR Error: {e}".strip("; ")

        # 3. 免金鑰雲端 OCR 自動備援 (第三道防線)
        try:
            ocr_text = self._call_free_cloud_ocr(image_path)
            if ocr_text and ocr_text.strip():
                return {
                    "success": True,
                    "extracted_text": ocr_text.strip(),
                    "source": "cloud-ocr-fallback"
                }
        except Exception as e:
            last_err = f"{last_err}; Cloud OCR Error: {e}".strip("; ")

        return {
            "success": False,
            "extracted_text": "",
            "source": "ocr-failed",
            "error": last_err or "圖片未偵測到有效文字或 OCR 服務暫時無法連線。"
        }

    def _call_local_rapidocr(self, image_path: str) -> str:
        """使用本地端 ONNX 神經網路 OCR (RapidOCR) 進行零延遲、零配額限制的中英文字與網址提取"""
        ocr_engine = _get_local_rapid_ocr()
        result, _ = ocr_engine(image_path)
        if not result:
            return ""
        lines = [item[1].strip() for item in result if len(item) >= 2 and item[1] and item[1].strip()]
        return "\n".join(lines)

    def _call_gemini_vision(self, image_path: str, api_key: str, model_name: str = "gemini-2.0-flash") -> str:
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
                                "mime_type": "image/jpeg",
                                "data": img_b64
                            }
                        }
                    ]
                }
            ]
        }
        
        resp = requests.post(url, headers=headers, json=payload, timeout=15)
        if resp.status_code != 200:
            error_detail = ""
            try:
                error_detail = resp.json().get("error", {}).get("message", resp.text)
            except Exception:
                error_detail = resp.text
            raise RuntimeError(f"HTTP {resp.status_code}: {error_detail}")

        data = resp.json()
        return data["candidates"][0]["content"]["parts"][0]["text"]

    def _call_free_cloud_ocr(self, image_path: str) -> str:
        """免金鑰多語系雲端 OCR 備援引擎 (支援繁體中文與英文網址混合提取)"""
        img_b64 = self.encode_image(image_path, max_dim=1000)
        b64_uri = f"data:image/jpeg;base64,{img_b64}"
        url = "https://api.ocr.space/parse/image"

        for engine_id in ["1", "2"]:
            try:
                resp = requests.post(
                    url,
                    data={
                        "apikey": "helloworld",
                        "base64Image": b64_uri,
                        "language": "cht" if engine_id == "1" else "auto",
                        "OCREngine": engine_id,
                        "scale": "true",
                        "isTable": "false"
                    },
                    timeout=12
                )
                if resp.status_code == 200:
                    data = resp.json()
                    parsed_list = data.get("ParsedResults") or []
                    if parsed_list:
                        text = "\n".join(item.get("ParsedText", "") for item in parsed_list).strip()
                        if text:
                            return text
            except Exception:
                continue
        return ""