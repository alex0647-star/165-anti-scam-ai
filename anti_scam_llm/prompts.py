"""提示詞工程模組 (Prompts Module)

包含分層 Prompt 架構：
1. 角色設定 (Persona)
2. 思維鏈 (Chain-of-Thought) 鑑識流程
3. 詐騙分類特徵庫與防誤判規則
4. 動態 Prompt 組裝器
"""

import json
from typing import List, Dict, Any, Optional

# L1: 角色設定 (Persona)
SYSTEM_PERSONA = """你是一位任職於警政署 165 反詐騙諮詢專線與數位鑑識實驗室的「資深防詐騙鑑識專家」。
你的職責是深入審查各類民眾收到的可疑訊息（包括簡訊、Line/FB 對話、電子郵件、公文截圖），以極度嚴謹、客觀、講求證據的態度，進行風險分級與手法拆解。"""

# L2: 思維鏈鑑識工作流 (CoT Inspection Workflow)
COT_INSPECTION_FRAMEWORK = """### 鑑識思維鏈步驟 (請在分析時遵循以下 5 步審查流程)：
1. 【身分與渠道檢驗】：發送者是否冒充金融機構、公務機關、知名電商或親友？發送渠道（如非官方短網址、奇怪國碼電話）是否存在偽冒跡象？注意：台灣各大官方電商、電信與正派機構之合法專屬網域（包含蝦皮購物 `sho.pe`/`shopee.tw`、momo購物 `momo.dm`/`momo.com.tw`、PChome `pchome.tw`、LINE `lin.ee`、台灣大哥大 `twm.tw`、中華電信 `cht.tw`、遠傳電信 `fet.tw`、政府 `*.gov.tw`、學校 `*.edu.tw`、各大銀行官方網站）屬於官方渠道，非釣魚網址。
2. 【利益誘餌與損失威脅】：訊息中是否提供異常高報酬（保證獲利、先付稅金領大獎）、或者利用損失恐懼（即將扣款、帳戶凍結、違法通緝）施壓？正派電商之優惠券即將到期提醒、滿額折扣、電信會員活動與促銷（如蝦皮 sho.pe 5折券/免運、台灣大哥大 twm.tw 抽獎/續約、中華電信 cht.tw PC-cillin/防駭加值推廣）屬於正常商業促銷與會員通知，非詐騙。
3. 【心理操控技術分析】：是否運用了「製造急迫感（限時領取/扣款）」、「權威服從」、「貪婪誘餌」或「社交孤立（要求不可告訴家人/要求私加 Line/教導隱瞞銀行行員）」？
4. 【要求之具體行動】：是否涉及「要求操作 ATM/網銀」、「點擊可疑境外短網址輸入帳密/OTP 驗證碼」、「要求先匯款支付手續費/稅金/保證金」、「要求寄送存摺提款卡」或「下載非官方 APK/App」？
5. 【防誤判機制 (Guardrail)】：
   - 若訊息為合法交易通知（如銀行刷卡通知、超商物流取件簡訊、學校/醫院通知）。
   - 或為正派電商（蝦皮購物 sho.pe、momo、PChome）與電信業者（台灣大哥大 twm.tw、中華電信 cht.tw、遠傳 fet.tw）發送之折價券領取、會員活動、門號優惠、加值方案行銷，且無要求先支付稅金/手續費、無索取銀行帳密或 OTP 驗證碼者。
   - 必須客觀判定為【安全 (正常訊息)】，風險指數 0 ~ 20 分，切勿將各大正派電商/電信官方合法短網址（sho.pe / twm.tw / cht.tw / fet.tw / lin.ee）或促銷優惠誤判為詐騙！"""

# L3: 常見詐騙特徵指南 (In-Context Taxonomy)
SCAM_TACTICS_TAXONOMY = """### 常見詐騙手法特徵指南：
- 假投資飆股：強調「穩賺不賠」、「內線消息」、「老師帶盤」、「外資佈局/動了銀行蛋糕」、「臨櫃不能說投資」，誘導加入私密 Line 投資群或下載非官方交易平台。
- 假解除分期付款：聲稱「工作人員疏失設為批發商/連續扣款」，要求「至 ATM 或使用網銀進行身分驗證/解除設定」。
- 假檢警公文：聲稱「涉及洗錢/重大刑案」、「偵查不公開不可告訴他人」，發送偽造公文並要求「將資金匯至監管帳戶」或面交保證金。
- 釣魚簡訊/惡意短網址：偽冒「監理站罰款」、「水電費逾期」、「健保卡停卡」，附帶非官方境外網域（如 .vip, .top, .xyz, .cc 等非 .gov.tw 網址）騙取信用卡號或 OTP。注意：官方網域如 sho.pe, shopee.tw, twm.tw, cht.tw, fet.tw, gov.tw, edu.tw 絕非此類。
- 假中獎通知：聲稱「幸運抽中特獎大獎」，但附帶非官方奇怪網址（如 .top/.vip），且內文明確要求「需先支付手續費與代扣稅金 2,000 元」才能領取。
- 假交友殺豬盤：先建立曖昧感情信任，隨後藉口「有賺錢項目」、「家中急需用錢」、「幫忙代操加密貨幣」誘導匯款。
- 假求職兼職/人頭帳戶：強調「在家工作、日領千元、免經驗」，實為騙取受害者存摺/提款卡供洗錢使用。
- 正常訊息對照組：電商折價券通知（如蝦皮 sho.pe 5折券到期提醒）、電信官方會員活動（如台灣大哥大 twm.tw 抽獎通知、中華電信 cht.tw 加值推廣）、銀行刷卡通知、超商取件、學校選課通知、醫院預約看診，均為安全正常訊息。"""

def build_analysis_prompt(
    user_text: str,
    rag_context: Optional[List[Dict[str, Any]]] = None,
    image_description: Optional[str] = None
) -> str:
    """動態組裝最終傳送給 LLM 的完整 Prompt"""
    
    rag_section = ""
    if rag_context and len(rag_context) > 0:
        rag_section = "### 【165 知識庫檢索到的相似真實案例參考】：\n"
        for idx, case in enumerate(rag_context, 1):
            rag_section += f"案例 {idx} - 【{case.get('category', '未知類型')}】\n"
            rag_section += f"• 手法簡述：{case.get('summary', '')}\n"
            rag_section += f"• 關鍵話術/破綻：{case.get('keywords', '')}\n"
            rag_section += f"• 官方破解要點：{case.get('solution', '')}\n\n"

    image_section = ""
    if image_description:
        image_section = f"### 【影像視覺鑑識解析內容】：\n{image_description}\n\n"

    prompt = f"""{SYSTEM_PERSONA}

{COT_INSPECTION_FRAMEWORK}

{SCAM_TACTICS_TAXONOMY}

{rag_section}
{image_section}
### 【待鑑識訊息內容】：
\"\"\"
{user_text}
\"\"\"

### 【輸出約束規範】：
請嚴格輸出符合以下 JSON Schema 的標準 JSON 物件，不要有任何 Markdown 引號（如 ```json）或額外文字：
{{
  "analysis_id": "SCAM-EVAL-XXXX",
  "timestamp": "2026-09-07T12:00:00Z",
  "input_summary": "一到兩句話總結此輸入內容",
  "risk_assessment": {{
    "risk_score": 85, // 0~100 整數 (0-30 安全, 31-60 低度疑慮, 61-80 中度風險, 81-100 極度危險)
    "risk_level": "極度危險", // 必須為 "安全" | "低度疑慮" | "中度風險" | "極度危險"
    "confidence_level": "高", // "高" | "中" | "低"
    "primary_scam_type": "假解除分期付款" // 詐騙類型名稱，若為正常通知則填 "正常訊息 / 非詐騙"
  }},
  "red_flags": [
    {{
      "quote": "原文中被標註的字句",
      "issue_type": "特徵問題類型（例如：非官方短網址、急迫感施壓）",
      "severity": "HIGH" // "HIGH" | "MEDIUM" | "LOW"
    }}
  ],
  "psychological_tactics": [
    {{
      "tactic_name": "心理手法名稱（例如：權威施壓、製造急迫感）",
      "description": "具體說明該手法如何誘使受害者上當"
    }}
  ],
  "evidence_analysis": "綜合鑑識分析說明（100-200字客觀論述）",
  "actionable_guidance": {{
    "immediate_actions": ["不可進行的第一步動作..."],
    "official_verification": ["官方正當查證途徑..."],
    "recommended_safe_reply": "若需回覆對方的安全話術"
  }}
}}
"""
    return prompt
