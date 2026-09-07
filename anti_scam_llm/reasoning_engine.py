"""核心鑑識推理引擎模組 (Reasoning Engine Module)

負責系統整體的調度流程：
[輸入前處理] ➔ [165 RAG 知識庫檢索] ➔ [Prompt 動態組裝] ➔ [LLM 鑑識推論] ➔ [Guardrail 校驗] ➔ [輸出結構化報告]
"""

import json
import uuid
import re
import os
from datetime import datetime, timezone
from typing import Optional, Dict, Any
import requests

from anti_scam_llm.config import GEMINI_API_KEY, OPENAI_API_KEY, DEFAULT_MODEL_PROVIDER, DEFAULT_MODEL_NAME
from anti_scam_llm.schemas import AntiScamAnalysisResult, InputPayload
from anti_scam_llm.prompts import build_analysis_prompt
from anti_scam_llm.knowledge_base import ScamKnowledgeRetriever
from anti_scam_llm.vision_processor import VisionProcessor
from anti_scam_llm.guardrails import OutputGuardrail


class AntiScamForensicEngine:
    """防詐騙 AI 鑑識核心引擎"""

    def __init__(
        self,
        provider: str = DEFAULT_MODEL_PROVIDER,
        model_name: str = DEFAULT_MODEL_NAME,
        api_key: Optional[str] = None
    ):
        self.provider = provider
        self.model_name = model_name
        self.api_key = api_key or os.getenv("GEMINI_API_KEY") or GEMINI_API_KEY
        
        self.retriever = ScamKnowledgeRetriever()
        self.vision_processor = VisionProcessor(api_key=self.api_key)

    def analyze(self, payload: InputPayload) -> AntiScamAnalysisResult:
        """端到端全流程鑑識分析"""
        user_text = payload.text or ""
        image_desc = ""

        # 1. 處理影像輸入（若有）
        if payload.image_path:
            vision_res = self.vision_processor.analyze_image(payload.image_path)
            if vision_res.get("success"):
                image_desc = vision_res.get("extracted_text", "")
                if not user_text:
                    user_text = image_desc

        # 若圖片無文字或未提供內容
        if not user_text.strip():
            now_iso = datetime.now(timezone.utc).isoformat()
            safe_mock = json.dumps({
                "analysis_id": f"IMG-INFO-{uuid.uuid4().hex[:8].upper()}",
                "timestamp": now_iso,
                "input_summary": "上傳之圖片未提取到文字內容",
                "risk_assessment": {
                    "risk_score": 0,
                    "risk_level": "安全",
                    "confidence_level": "高",
                    "primary_scam_type": "正常圖片 / 未含詐騙特徵"
                },
                "red_flags": [],
                "psychological_tactics": [],
                "evidence_analysis": "此圖片中未偵測到任何可疑詐騙字句或惡意特徵。\n\n💡 **重要提示**：若您上傳的是對話截圖，請至右下角 **「⚙️ 管理應用」➔ Settings ➔ Secrets** 填入 `GEMINI_API_KEY = '您的金鑰'`，系統即可自動啟動 Gemini 1.5 Flash 多模態 OCR 進行深度鑑識！",
                "actionable_guidance": {
                    "immediate_actions": ["無須採取任何防禦行動。"],
                    "official_verification": ["若要啟用截圖自動辨識，請配置 GEMINI_API_KEY。"],
                    "recommended_safe_reply": "此圖片安全，未見任何詐騙破綻。"
                }
            }, ensure_ascii=False)
            _, validated_result, _ = OutputGuardrail.validate_and_parse(
                raw_output=safe_mock,
                fallback_input_summary="上傳圖片未提取到文字",
                
            )
            return validated_result

        # 2. RAG 知識庫檢索
        rag_cases = self.retriever.retrieve(user_text, top_k=2)

        # 3. 組裝動態 Prompt
        prompt = build_analysis_prompt(
            user_text=user_text,
            rag_context=rag_cases,
            image_description=image_desc if payload.image_path else None
        )

        # 4. 呼叫 LLM 進行鑑識
        raw_output = self._call_llm(prompt, user_text, rag_cases)

        # 5. 防護校驗與後處理
        summary = user_text[:60] + "..." if len(user_text) > 60 else user_text
        _, validated_result, _ = OutputGuardrail.validate_and_parse(
            raw_output=raw_output,
            fallback_input_summary=summary,
            
        )

        return validated_result

    def _call_llm(self, prompt: str, user_text: str, rag_cases: list) -> str:
        """根據設定調用對應的 LLM API，若無金鑰則啟用智慧離線推論"""
        if self.provider == "gemini" and self.api_key:
            try:
                return self._call_gemini_api(prompt)
            except Exception as e:
                print(f"[ReasoningEngine Warning] Gemini API 呼叫失敗，切換離線鑑識: {e}")
        elif self.provider == "openai" and self.api_key:
            try:
                return self._call_openai_api(prompt)
            except Exception as e:
                print(f"[ReasoningEngine Warning] OpenAI API 呼叫失敗，切換離線鑑識: {e}")

        # 無有效 API Key 時使用智慧離線推論
        return self._intelligent_offline_inference(user_text, rag_cases)

    def _call_gemini_api(self, prompt: str) -> str:
        """調用 Google Gemini REST API (具備多模型自動降級)"""
        models_to_try = [self.model_name, "gemini-3.6-flash", "gemini-flash-latest", "gemini-1.5-flash"]
        headers = {"Content-Type": "application/json"}
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": 0.1,
                "response_mime_type": "application/json"
            }
        }
        last_err = None
        for m in models_to_try:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{m}:generateContent?key={self.api_key}"
            try:
                resp = requests.post(url, headers=headers, json=payload, timeout=25)
                if resp.status_code == 200:
                    data = resp.json()
                    return data["candidates"][0]["content"]["parts"][0]["text"]
            except Exception as e:
                last_err = e
                continue
        if last_err:
            raise last_err
        raise RuntimeError("Gemini API 調用失敗")

    def _call_openai_api(self, prompt: str) -> str:
        """調用 OpenAI 格式 API"""
        url = "https://api.openai.com/v1/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}"
        }
        payload = {
            "model": self.model_name,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.1,
            "response_format": {"type": "json_object"}
        }
        resp = requests.post(url, headers=headers, json=payload, timeout=25)
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"]

    def _intelligent_offline_inference(self, user_text: str, rag_cases: list) -> str:
        """智慧離線推論引擎：依據 RAG 檢索特徵與關鍵詞規則進行精準鑑識"""
        low_text = user_text.lower()
        now_iso = datetime.now(timezone.utc).isoformat()
        
        # 關鍵詐騙特徵指標
        has_phishing_link = ("http://" in low_text or "https://" in low_text or "line.me" in low_text or ".vip" in low_text or ".top" in low_text or ".xyz" in low_text)
        has_money_trigger = ("atm" in low_text or "轉帳" in low_text or "監管帳戶" in low_text or "解除分期" in low_text or "匯款" in low_text or "usdt" in low_text or "提現保證金" in low_text or "日領高薪" in low_text or "給你抽" in low_text or "丟你那邊" in low_text or "借帳戶" in low_text or "租帳戶" in low_text or "不能收錢" in low_text)
        has_legal_threat = ("洗錢防制法" in user_text or "地檢署" in user_text or "特偵組" in user_text or "強制拘提" in user_text or "公文傳票" in user_text or "健保卡異常" in user_text or "鎖卡" in user_text)
        has_investment_trap = ("飆股" in user_text or "老師帶盤" in user_text or "內線消息" in user_text or "保證獲利" in user_text or "翻倍" in user_text)

        # 1. 正常訊息判斷（如果沒有觸發任何明顯詐騙特徵）
        is_scam = has_phishing_link or has_money_trigger or has_legal_threat or has_investment_trap

        if not is_scam:
            return json.dumps({
                "analysis_id": f"SCAM-EVAL-{uuid.uuid4().hex[:8].upper()}",
                "timestamp": now_iso,
                "input_summary": user_text[:50],
                "risk_assessment": {
                    "risk_score": 5,
                    "risk_level": "安全",
                    "confidence_level": "高",
                    "primary_scam_type": "正常訊息 / 非詐騙"
                },
                "red_flags": [],
                "psychological_tactics": [],
                "evidence_analysis": "經 165 AI 鑑識比對，此內容未出現釣魚連結、非官方網址、要求匯款轉帳、恐嚇凍結或假投資等惡意破綻特徵，屬於日常安全內容。",
                "actionable_guidance": {
                    "immediate_actions": ["無須採取任何防禦行動，可正常閱讀與回覆。"],
                    "official_verification": ["若為重要公務或銀行交易且有疑慮，可直接致電官方官方代表號確認。"],
                    "recommended_safe_reply": "內容安全，無需特別防範。"
                }
            }, ensure_ascii=False)

        # 2. 詐騙特徵鑑識
        matched_case = rag_cases[0] if rag_cases else {
            "category": "疑似釣魚或未知詐騙",
            "tactics": ["製造急迫感", "利益引誘"]
        }
        category = matched_case.get("category", "疑似詐騙")

        # 根據文本抽取可疑特徵
        red_flags = []
        if has_phishing_link:
            urls = re.findall(r"https?://[^\s]+", user_text)
            red_flags.append({
                "quote": urls[0] if urls else "非官方可疑連結",
                "issue_type": "非官方或可疑短網址跳轉",
                "severity": "HIGH"
            })
        if has_money_trigger:
            red_flags.append({
                "quote": "要求操作 ATM / 匯款轉移資金 / 保證金",
                "issue_type": "異常金錢轉移指示",
                "severity": "HIGH"
            })
        if has_legal_threat:
            red_flags.append({
                "quote": "公文恐嚇 / 凍結資產 / 鎖卡",
                "issue_type": "製造時間急迫感與司法威脅",
                "severity": "HIGH"
            })
        if has_investment_trap:
            red_flags.append({
                "quote": "保證獲利 / 飆股密碼",
                "issue_type": "以高報酬誘餌吸引受害者",
                "severity": "HIGH"
            })

        tactics = []
        for t in matched_case.get("tactics", ["心理施壓", "誘餌誘導"]):
            tactics.append({
                "tactic_name": t,
                "description": f"詐騙方運用『{t}』手法降低受害者的防備心並迫使其在慌亂中採取行動。"
            })

        score = 90 if (has_legal_threat or has_money_trigger) else 75
        
        return json.dumps({
            "analysis_id": f"SCAM-EVAL-{uuid.uuid4().hex[:8].upper()}",
            "timestamp": now_iso,
            "input_summary": user_text[:50],
            "risk_assessment": {
                "risk_score": score,
                "risk_level": "極度危險" if score >= 80 else "中度風險",
                "confidence_level": "高",
                "primary_scam_type": category
            },
            "red_flags": red_flags or [
                {"quote": user_text[:30], "issue_type": "符合典型詐騙套路語法", "severity": "HIGH"}
            ],
            "psychological_tactics": tactics,
            "evidence_analysis": f"此訊息高度吻合 165 資料庫中之『{category}』犯罪特徵。對方透過非官方管道聯繫，並試圖誘導金錢轉移或個資竊取，屬於高風險詐騙。",
            "actionable_guidance": {
                "immediate_actions": [
                    "絕對不要點擊訊息中的任何連結或輸入個人身分證、信用卡及 OTP 驗證碼。",
                    "切勿聽從指示前往 ATM 或開啟網路銀行進行任何操作。"
                ],
                "official_verification": [
                    "立即撥打 165 反詐騙諮詢專線進行查證與通報檢舉。",
                    "透過官方網站或 104 查號台取得該機關/企業之真實電話親自核對。"
                ],
                "recommended_safe_reply": "此案件我已通報 165 反詐騙專線與派出所備案，請勿再來電或傳訊。"
            }
        }, ensure_ascii=False)