"""系統組態設定模組 (Config Module)

定義 API 金鑰、模型選擇、風險門檻與支援的詐騙類型常數。
"""

import os

# 讀取環境變數 (可搭配 .env 使用)
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")

# 預設使用模型 (支援 gemini-1.5-flash, gpt-4o-mini, mock)
DEFAULT_MODEL_PROVIDER = os.getenv("LLM_PROVIDER", "gemini")  # "gemini" | "openai" | "mock"
DEFAULT_MODEL_NAME = os.getenv("LLM_MODEL", "gemini-1.5-flash")

# 風險分級門檻標準
RISK_THRESHOLDS = {
    "SAFE": (0, 30),        # 0 ~ 30: 安全（正常通知）
    "LOW": (31, 60),        # 31 ~ 60: 低度疑慮
    "MEDIUM": (61, 80),     # 61 ~ 80: 中度風險
    "CRITICAL": (81, 100),  # 81 ~ 100: 極度危險
}

# 165 定義之 8 大主要詐騙分類
SUPPORTED_SCAM_TYPES = [
    "假投資飆股 / 虛擬幣",
    "假解除分期付款 / 電商客服",
    "假檢警與公務機關公文",
    "釣魚簡訊與惡意短網址",
    "假交友徵婚 / 殺豬盤",
    "假求職兼職 / 家庭代工",
    "假中獎通知 / 抽獎活動",
    "假親友借錢 / 盜用帳號",
    "正常訊息 / 非詐騙"
]

def get_risk_level_from_score(score: int) -> str:
    """根據風險分數轉換為對應中文等級"""
    if score <= 30:
        return "安全"
    elif score <= 60:
        return "低度疑慮"
    elif score <= 80:
        return "中度風險"
    else:
        return "極度危險"
