"""防護校驗與自我修復模組 (Guardrails Module)

負責：
1. 去除 LLM 輸出中的 Markdown 標籤 (```json ... ```)
2. 自動修復毀損或缺漏的 JSON 結構 (Self-Healing)
3. 透過 Pydantic Schema 進行強型別校驗
4. 業務規則一致性校驗（如：分數與中文分級是否一致）
"""

import json
import re
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Tuple
from pydantic import ValidationError

from anti_scam_llm.schemas import AntiScamAnalysisResult, RiskAssessment, RiskLevel, ConfidenceLevel
from anti_scam_llm.config import get_risk_level_from_score


class OutputGuardrail:
    """輸出安全守衛與自動修復器"""

    @staticmethod
    def extract_clean_json_str(raw_text: str) -> str:
        """過濾 markdown 與額外雜訊，純化出 JSON 字串"""
        text = raw_text.strip()
        
        # 移除 ```json 和 ``` 包裹
        if "```json" in text:
            match = re.search(r"```json\s*(.*?)\s*```", text, re.DOTALL)
            if match:
                return match.group(1).strip()
        elif "```" in text:
            match = re.search(r"```\s*(.*?)\s*```", text, re.DOTALL)
            if match:
                return match.group(1).strip()

        # 尋找最外層的 { 與 }
        start_idx = text.find("{")
        end_idx = text.rfind("}")
        if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
            return text[start_idx:end_idx+1].strip()

        return text

    @classmethod
    def validate_and_parse(
        cls,
        raw_output: str,
        fallback_input_summary: str = "未提供摘要"
    ) -> Tuple[bool, AntiScamAnalysisResult, str]:
        """校驗原始 LLM 回傳字串，若格式有誤則自動啟動修復機制"""
        clean_json = cls.extract_clean_json_str(raw_output)
        
        try:
            parsed_dict = json.loads(clean_json)
            
            # 確保必要欄位存在與填補
            if "analysis_id" not in parsed_dict or not parsed_dict["analysis_id"]:
                parsed_dict["analysis_id"] = f"SCAM-EVAL-{uuid.uuid4().hex[:8].upper()}"
            
            if "timestamp" not in parsed_dict or not parsed_dict["timestamp"]:
                parsed_dict["timestamp"] = datetime.now(timezone.utc).isoformat()

            if "input_summary" not in parsed_dict:
                parsed_dict["input_summary"] = fallback_input_summary

            # 校驗與修正風險等級與分數一致性
            if "risk_assessment" in parsed_dict:
                ra = parsed_dict["risk_assessment"]
                score = ra.get("risk_score", 0)
                # 確保分數在 0~100 範圍內
                score = max(0, min(100, int(score)))
                ra["risk_score"] = score
                # 自動校正中文分級，確保與分數邏輯相符
                expected_level = get_risk_level_from_score(score)
                ra["risk_level"] = expected_level

            # 透過 Pydantic 進行嚴格結構檢查
            result = AntiScamAnalysisResult(**parsed_dict)
            return True, result, "Validation Passed"

        except (json.JSONDecodeError, ValidationError, Exception) as err:
            # 啟動 Self-Healing 備用降級安全結構
            healed_result = cls._generate_fallback_safe_result(
                raw_text=raw_output,
                summary=fallback_input_summary,
                error_msg=str(err)
            )
            return False, healed_result, f"Self-Healing Triggered: {str(err)}"

    @classmethod
    def _generate_fallback_safe_result(
        cls,
        raw_text: str,
        summary: str,
        error_msg: str
    ) -> AntiScamAnalysisResult:
        """當 JSON 嚴重毀損時的自動修復降級機制"""
        return AntiScamAnalysisResult(
            analysis_id=f"SCAM-HEALED-{uuid.uuid4().hex[:8].upper()}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            input_summary=summary,
            risk_assessment=RiskAssessment(
                risk_score=50,
                risk_level=RiskLevel.LOW_CONCERN,
                confidence_level=ConfidenceLevel.LOW,
                primary_scam_type="格式異常（已啟動安全保護）"
            ),
            red_flags=[],
            psychological_tactics=[],
            evidence_analysis=f"系統解析模型輸出時發生異常，已啟動防護降級機制。原始錯誤：{error_msg[:100]}",
            actionable_guidance={
                "immediate_actions": ["暫勿進行任何涉及金錢與個人資訊之操作。"],
                "official_verification": ["請直接撥打 165 反詐騙專線進行人工查證。"],
                "recommended_safe_reply": "目前系統繁忙，請稍後再試。"
            }
        )
