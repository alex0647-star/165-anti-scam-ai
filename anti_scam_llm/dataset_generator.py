import sys
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
"""
165 AI 防詐大模型 - SFT 指令微調資料集生成器 (Dataset Generator)

功能：
1. 整合 20 筆標準黃金基準案例 (Golden Test Dataset)
2. 整合 15 類 165 官方詐騙手法知識庫模式 (Knowledge Base Entries)
3. 自動合成擴增多樣化台灣真實情境詐騙對話與多樣化負樣本 (合法正常通知)
4. 匯出為業界通用標準微調格式：
   - Alpaca 格式 (train_alpaca.json / train_alpaca.jsonl)
   - ShareGPT / ChatML 格式 (train_sharegpt.json)
   - 獨立評估驗證集 (test_cases.json)
"""

import os
import sys
import json
import random
from typing import List, Dict, Any

# 確保引用專案核心
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from anti_scam_llm.dataset import GOLDEN_TEST_DATASET
from anti_scam_llm.knowledge_base import KNOWLEDGE_BASE_ENTRIES

SYSTEM_INSTRUCTION = (
    "你是由中華民國警政署 165 反詐騙諮詢專線標準所訓練的「165 AI 智能防詐鑑識專家」。"
    "你的任務是精確剖析使用者輸入的文字訊息、簡訊或對話內容，進行嚴格的防詐鑑識。"
    "請務必輸出嚴謹的 JSON 結構，包含 risk_score (0~100)、primary_scam_type、red_flags (可疑特徵列表)、"
    "evidence_analysis (鑑識論證) 與 actionable_guidance (處置與防禦指引)。"
)

# 額外擴增真實情境案例庫
AUGMENTED_CASES = [
    # 假冒公務機關 / 假執法人員 / 假健保
    {
        "text": "【台北地檢署公文通知】台端涉嫌洗錢防制法案，案件編號 (115) 偵字第 9821 號，請於本日 17:00 前攜帶身分證與名下所有存摺至地檢署說明，或點此 http://tp-prosecutor-gov.top 進行線上資產公證監管，逾期將核發拘票逮捕。",
        "risk_score": 98,
        "scam_type": "假冒公務機關 / 檢警監管帳戶",
        "red_flags": ["非政府 .gov.tw 網址 (使用 .top 可疑頂級域名)", "恐嚇核發拘票並限定時間壓迫", "要求線上資產公證/監管帳戶"],
        "evidence": "檢警司法機關絕不會透過簡訊或通訊軟體傳送公文，更不會要求線上資產公證或監管民眾名下帳戶財產。此為典型假冒檢警詐騙話術。",
        "guidance": "1. 立即掛斷並切勿點擊連結 2. 檢警辦案絕無『監管帳戶』或『線上製作筆錄』機制 3. 撥打 165 反詐專線或向管轄地檢署求證。"
    },
    {
        "text": "【交通違規罰單逾期通知】您有一筆國道超速違規未繳納 (罰款金額 NT$3,000)，最後繳納期限為今天，請立即至監理服務網線上結清以免加罰：http://mvdis-gov-tw.vip/pay",
        "risk_score": 95,
        "scam_type": "冒名官方機構 / 釣魚簡訊",
        "red_flags": ["使用假冒監理站域名 (.vip)", "威脅加重處罰並限制當日繳納", "未提供詳細車牌號碼與違規時間地點"],
        "evidence": "政府監理服務網真實網址為 https://www.mvdis.gov.tw，簡訊中提供的網址為釣魚網站，目的在騙取民眾信用卡號與 OTP 簡訊驗證碼。",
        "guidance": "1. 切勿輸入信用卡卡號及 OTP 驗證碼 2. 查詢違規請自行下載『監理服務 APP』或至官方 .gov.tw 網站查詢。"
    },
    {
        "text": "【台灣自來水公司】親愛的用戶您好，您的水費已逾期未繳（帳單編號 TW-89104，欠費金額 398 元），請於 24 小時內點擊繳費專區結清：http://water-gov.xyz/pay，若未繳納將於明日執行停水作業。",
        "risk_score": 95,
        "scam_type": "冒名公用事業 / 釣魚簡訊",
        "red_flags": ["低額欠費誘使民眾放鬆戒心", "以『立即停水』恐嚇催繳", "可疑外國網域 .xyz"],
        "evidence": "台水公司水費催繳簡訊發送號碼具備特定認證，絕不會提供短網址或 .xyz 網址要求刷卡繳費。此為盜刷信用卡之釣魚簡訊。",
        "guidance": "1. 請至台水官方網站或持實體帳單至超商繳費 2. 若已輸入信用卡資料請立即致電發卡銀行停卡。"
    },
    # 假投資 / 假虛擬幣 / 飆股群組
    {
        "text": "【內部消息】台積電法說會即將公布重大利多，富邦證券資深分析師陳老師帶領內線主力佈局！每日免費分享 1~2 檔必漲飆股，預期獲利 300% 以上，點擊加入 LINE 飆股私密群：https://line.me/ti/g2/fubon-vip888",
        "risk_score": 95,
        "scam_type": "假投資詐騙 / 飆股群組",
        "red_flags": ["保證獲利 300% 超常報酬", "假借知名證券與明星分析師名義", "引導私下加入 LINE 群組操作"],
        "evidence": "正規合法券商與投顧公司絕不會透過私加 LINE 報名牌方式招攬投資，更不可能保證獲利。群組內多數成員為樁腳暗樁。",
        "guidance": "1. 投資應透過合法登記證券商 2. 勿輕信來源不明的 LINE 飆股群組 3. 不聽信保證獲利之投資話術。"
    },
    {
        "text": "哥，我最近在操作一個以太坊量化搬磚套利平台，每天回報率固定 3.5%，提現都是秒到帳！我把我的邀請碼發你，你先儲值 1,000 USDT 試試看，我帶你一起賺買房基金～平台網址：http://eth-arbitrage-pro.cc",
        "risk_score": 96,
        "scam_type": "虛擬貨幣投資 / 殺豬盤",
        "red_flags": ["日報酬 3.5%（換算年化破千）違反常理", "誘導於未受監管的私人野雞交易所註冊儲值", "以情感關係帶領投資降低戒心"],
        "evidence": "此為典型的虛擬貨幣假平台殺豬盤詐騙，初期小額可能讓受害者順利提領，待受害者投入大額資金後便以『洗碼量不足』、『繳納個人所得稅保證金』為由拒絕出金。",
        "guidance": "1. 切勿在非主流合規交易所（如幣安、MAX 等）註冊入金 2. 網友談及投資賺錢均為詐騙。"
    },
    # 假求職 / 假家庭代工 / 租借帳戶
    {
        "text": "【在家兼職・高薪現領】誠徵打字員 / 訂單處理員，工作時間自由，每天只需 1-2 小時，日薪 $2,000 - $5,000 現領！無需經驗、學生家庭主婦皆可，意者請加主管 LINE ID: job_vip99 預約線上面試。",
        "risk_score": 92,
        "scam_type": "假求職 / 兼職詐騙",
        "red_flags": ["工作內容極度簡單卻標榜高薪", "僅透過 LINE 面試溝通無實體公司登記", "後續常要求繳交保證金或提供金融存摺"],
        "evidence": "『低門檻、高薪現領、在家兼職』為假求職常見陷阱。詐團後續會以『購買工作材料保證金』、『設定薪資轉帳帳戶』為由騙取金錢或將受害者帳戶作為洗錢人頭戶。",
        "guidance": "1. 找工作請透過合法立案人力銀行 2. 絕不繳納保證金 3. 絕不寄出或交出個人身分證、存摺及提款卡。"
    },
    {
        "text": "【高價租用薪轉帳戶】因公司擴展外貿業務需要多組帳戶進出，誠租各大銀行正常使用之存摺與提款卡，一本每月租金 30,000 元，簽約即預付三個月！可當面簽訂合法合約，保證安全無風險，意者洽 Telegram: @bank_rent",
        "risk_score": 99,
        "scam_type": "人頭帳戶收購 / 洗錢車手誘捕",
        "red_flags": ["租借/買賣存摺金融卡", "承諾高額被動租金收入", "使用高隱私加密通訊軟體 (Telegram) 聯繫"],
        "evidence": "提供金融帳戶供他人使用已違反《洗錢防制法》第15條之2，將成為詐欺共同正犯並面臨刑事責任及帳戶全面警示凍結。",
        "guidance": "1. 絕不提供金融存摺、提款卡及密碼給任何人 2. 買賣租借帳戶即觸犯刑法洗錢防制法。"
    },
    # 假買家 / 假客服 / 7-11 賣貨便認證
    {
        "text": "【賣家您好】我剛剛在您的 7-11 賣貨便賣場下單了 3 件商品，但是系統顯示『賣家尚未簽署 2026 最新金流保障協議，訂單已凍結』！請您立刻點擊線上客服連結簽署協議，否則我的付款會被扣留：http://myship-7-11-verify.shop/service",
        "risk_score": 96,
        "scam_type": "假買家 / 假金流認證詐騙",
        "red_flags": ["非 7-11 官方 myship.7-11.com.tw 網址", "假冒買家製造訂單被卡住的急迫感", "誘騙賣家點擊假客服連結進行假認證"],
        "evidence": "近期高發之假網拍買家詐騙，假客服會進一步要求賣家操作網銀 ATM 進行『金流帳戶身分驗證』，實質誘騙賣家轉帳匯款。",
        "guidance": "1. 7-11 賣貨便、旋轉拍賣絕不會以『未簽署協議』要求賣家線上操作網銀驗證 2. 勿相信買家傳來的假客服連結。"
    },
    # 正常合法安全訊息 (負樣本)
    {
        "text": "【國泰世華銀行】您於 2026/09/07 20:15 在 PChome 24h 購物刷卡消費 NT$ 1,890 元。如非本人交易請立即致電本行客服專線 (02)2383-1000。",
        "risk_score": 5,
        "scam_type": "非詐騙 / 正常銀行刷卡通知",
        "red_flags": [],
        "evidence": "訊息包含具體消費商家、精確時間與金額，無任何要求點擊的可疑連結，所提供電話為國泰世華銀行官方真實客服號碼。",
        "guidance": "此為標準信用卡消費即時簡訊通知，無需採取額外動作。如確實非本人刷卡，請撥打卡片背面電話與銀行確認。"
    },
    {
        "text": "【7-ELEVEN】包裹取件通知：您訂購之商品 (包裹末三碼 782) 已送達 7-11 鑫鑫門市，請於 7 日內攜帶身分證件並出示取件條碼至門市取件，感謝您的惠顧！",
        "risk_score": 5,
        "scam_type": "非詐騙 / 正常超商物流通知",
        "red_flags": [],
        "evidence": "標準門市取件通知，未附帶可疑釣魚連結，亦未要求先匯款或提供信用卡驗證碼。",
        "guidance": "正常到店取貨通知，請於期限內攜帶證件前往指定超商取件即可。"
    },
    {
        "text": "【Google 安全驗證】您的 Google 帳戶驗證碼為 G-482019。請勿將此代碼分享給任何人。如果不是您本人請求，請忽略此訊息。",
        "risk_score": 0,
        "scam_type": "非詐騙 / 雙重驗證 OTP",
        "red_flags": [],
        "evidence": "標準兩步驟驗證碼簡訊，並明確包含資安警告（請勿分享代碼），無釣魚網址。",
        "guidance": "輸入驗證碼完成登入即可。請牢記切勿將任何 OTP 驗證碼透過電話或通訊軟體告知他人。"
    },
    {
        "text": "【勞動部勞工保險局】提醒您：115 年度勞工保險投保薪資調整通知已寄發至投保單位電子信箱，詳細資訊請投保單位登入勞保局 e 化服務系統 (https://edesk.bli.gov.tw) 查閱。",
        "risk_score": 2,
        "scam_type": "非詐騙 / 官方行政通知",
        "red_flags": [],
        "evidence": "所附連結為真實政府機關 .gov.tw 域名 (https://edesk.bli.gov.tw)，未要求匯款或點擊非官方網站。",
        "guidance": "此為政府勞保局正常業務公告，各事業單位可放心登入官方系統查閱。"
    }
]


def generate_structured_response(case: Dict[str, Any]) -> str:
    """產生標準結構化 JSON 回應字串"""
    response_data = {
        "risk_score": case["risk_score"],
        "primary_scam_type": case["scam_type"],
        "red_flags": case["red_flags"],
        "evidence_analysis": case["evidence"],
        "actionable_guidance": case["guidance"]
    }
    return json.dumps(response_data, ensure_ascii=False, indent=2)


def build_alpaca_sample(input_text: str, structured_output: str) -> Dict[str, str]:
    """轉換為 Alpaca SFT 格式"""
    return {
        "instruction": SYSTEM_INSTRUCTION,
        "input": input_text.strip(),
        "output": structured_output.strip()
    }


def build_sharegpt_sample(input_text: str, structured_output: str) -> Dict[str, Any]:
    """轉換為 ShareGPT / ChatML 多輪對話格式"""
    return {
        "messages": [
            {"role": "system", "content": SYSTEM_INSTRUCTION},
            {"role": "user", "content": f"請對以下內容進行 165 防詐鑑識剖析：\n\n{input_text.strip()}"},
            {"role": "assistant", "content": structured_output.strip()}
        ]
    }


def generate_full_dataset(output_dir: str = "data"):
    """彙整所有案例並導出完整訓練集與測試集"""
    os.makedirs(output_dir, exist_ok=True)
    all_cases = []

    # 1. 導入 Golden Test Dataset 案例
    for g in GOLDEN_TEST_DATASET:
        score = g.get("min_expected_score", 90 if g.get("is_scam") else 5)
        all_cases.append({
            "id": g["id"],
            "text": g["input_text"],
            "risk_score": score,
            "scam_type": g["category"],
            "red_flags": [f"符合「{g['category']}」關鍵破綻特徵"] if g.get("is_scam") else [],
            "evidence": g["description"],
            "guidance": "切勿依循指示操作，如已匯款或提供個資，請立即撥打 165 反詐騙諮詢專線或向管轄派出所報案製作筆錄。" if g.get("is_scam") else "此為常態安全訊息，未見詐騙破綻特徵，請安心。"
        })

    # 2. 導入 15 類知識庫模式特徵轉化為案例
    for pat in KNOWLEDGE_BASE_ENTRIES:
        all_cases.append({
            "id": pat["id"],
            "text": f"【防詐警訊範例】{pat['keywords'][0]}！話術：{pat['summary']}",
            "risk_score": 92,
            "scam_type": pat["category"],
            "red_flags": pat.get("tactics", ["涉及話術操控與誘導"]),
            "evidence": f"本內容觸發 165 知識庫核心防詐特徵【{pat['category']}】。特徵剖析：{pat['summary']}",
            "guidance": pat.get("solution", "請撥打 165 專線查證。")
        })

    # 3. 導入擴增案例
    for idx, aug in enumerate(AUGMENTED_CASES):
        aug_copy = dict(aug)
        aug_copy["id"] = f"AUG_{idx+1:03d}"
        all_cases.append(aug_copy)

    print(f"📊 彙整原始案例庫總計: {len(all_cases)} 筆")

    # 隨機打散並拆分訓練集 (85%) 與 測試集 (15%)
    random.seed(42)
    random.shuffle(all_cases)

    split_idx = max(int(len(all_cases) * 0.85), len(all_cases) - 5)
    train_cases = all_cases[:split_idx]
    test_cases = all_cases[split_idx:]

    # 建立 Alpaca 與 ShareGPT 格式
    alpaca_train = []
    sharegpt_train = []

    for c in train_cases:
        struct_res = generate_structured_response(c)
        alpaca_train.append(build_alpaca_sample(c["text"], struct_res))
        sharegpt_train.append(build_sharegpt_sample(c["text"], struct_res))

    # 輸出檔案路徑
    alpaca_file = os.path.join(output_dir, "train_alpaca.json")
    sharegpt_file = os.path.join(output_dir, "train_sharegpt.json")
    jsonl_file = os.path.join(output_dir, "train_alpaca.jsonl")
    test_file = os.path.join(output_dir, "test_cases.json")

    # 寫入 JSON 檔案
    with open(alpaca_file, "w", encoding="utf-8") as f:
        json.dump(alpaca_train, f, ensure_ascii=False, indent=2)

    with open(sharegpt_file, "w", encoding="utf-8") as f:
        json.dump(sharegpt_train, f, ensure_ascii=False, indent=2)

    with open(jsonl_file, "w", encoding="utf-8") as f:
        for item in alpaca_train:
            f.write(json.dumps(item, ensure_ascii=False) + "\n")

    with open(test_file, "w", encoding="utf-8") as f:
        json.dump(test_cases, f, ensure_ascii=False, indent=2)

    print("=" * 60)
    print("🎉 165 AI 防詐微調資料集生成完畢！")
    print(f"📁 訓練集筆數 (Train Set): {len(train_cases)} 筆")
    print(f"📁 測試集筆數 (Test Set) : {len(test_cases)} 筆")
    print("=" * 60)
    print(f"✅ Alpaca 格式:   {alpaca_file}")
    print(f"✅ ShareGPT 格式: {sharegpt_file}")
    print(f"✅ JSONL 格式:    {jsonl_file}")
    print(f"✅ 測試評估集:    {test_file}")
    print("=" * 60)

    return {
        "train_count": len(train_cases),
        "test_count": len(test_cases),
        "alpaca_file": alpaca_file,
        "test_file": test_file
    }


if __name__ == "__main__":
    generate_full_dataset(os.path.join(PROJECT_ROOT, "data"))