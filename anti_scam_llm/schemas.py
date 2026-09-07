"""資料契約與 Pydantic 模組 (Schemas Module)

嚴格定義系統的輸入與結構化輸出資料模型，作為前端、後端與 LLM 之間的溝通契約。
"""

from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    """風險分級枚舉"""
    SAFE = "安全"
    LOW_CONCERN = "低度疑慮"
    MEDIUM_RISK = "中度風險"
    CRITICAL_DANGER = "極度危險"


class ConfidenceLevel(str, Enum):
    """模型置信度"""
    HIGH = "高"
    MEDIUM = "中"
    LOW = "低"


class Severity(str, Enum):
    """特徵嚴重程度"""
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class RedFlagItem(BaseModel):
    """單一可疑特徵點標註"""
    quote: str = Field(..., description="原文中被標記為可疑的字句")
    issue_type: str = Field(..., description="問題特徵類型（如：非官方短網址、急迫感施壓、索取個資）")
    severity: Severity = Field(default=Severity.MEDIUM, description="嚴重等級 (HIGH/MEDIUM/LOW)")


class PsychologicalTactic(BaseModel):
    """心理學操控手法拆解"""
    tactic_name: str = Field(..., description="心理手法名稱（例如：權威施壓、稀缺性誘導、貪婪誘惑、沉沒成本陷阱）")
    description: str = Field(..., description="具體說明該手法如何操作受害者心理")


class ActionableGuidance(BaseModel):
    """防詐處置與行動建議"""
    immediate_actions: List[str] = Field(
        default_factory=list,
        description="當下千萬不可進行的動作（例如：勿點連結、勿操作 ATM、勿匯款）"
    )
    official_verification: List[str] = Field(
        default_factory=list,
        description="官方正當查證管道（例如：撥打 165 專線、至官網親自核對）"
    )
    recommended_safe_reply: Optional[str] = Field(
        default="",
        description="若使用者需回覆對方，建議採用的安全防禦話術（例如：已報警請向警方說明）"
    )


class RiskAssessment(BaseModel):
    """整體風險評估摘要"""
    risk_score: int = Field(..., ge=0, le=100, description="0 到 100 分之量化風險分數")
    risk_level: RiskLevel = Field(..., description="風險等級（安全 / 低度疑慮 / 中度風險 / 極度危險）")
    confidence_level: ConfidenceLevel = Field(default=ConfidenceLevel.HIGH, description="模型分析置信度")
    primary_scam_type: str = Field(..., description="主要詐騙手法名稱，若非詐騙則為 '無 / 正常訊息'")


class AntiScamAnalysisResult(BaseModel):
    """防詐騙鑑識最終完整報告資料模型"""
    analysis_id: str = Field(..., description="鑑識任務唯一識別碼")
    timestamp: str = Field(..., description="鑑識完成時間戳記 (ISO 8601)")
    input_summary: str = Field(..., description="原始輸入訊息之摘要內容")
    risk_assessment: RiskAssessment = Field(..., description="整體風險評估數據")
    red_flags: List[RedFlagItem] = Field(default_factory=list, description="可疑特徵字句標註清單")
    psychological_tactics: List[PsychologicalTactic] = Field(default_factory=list, description="心理操縱手法拆解")
    evidence_analysis: str = Field(..., description="綜合鑑識理由說明（100-200字客觀論證）")
    actionable_guidance: ActionableGuidance = Field(..., description="安全行動處置指南")


class InputPayload(BaseModel):
    """使用者端輸入封包"""
    text: Optional[str] = Field(default=None, description="純文字訊息或對話內容")
    image_path: Optional[str] = Field(default=None, description="對話截圖或檔案路徑")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="其他輔助資訊（如發送管道等）")
