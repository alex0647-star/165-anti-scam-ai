"""黃金評估資料集模組 (Dataset Module)

提供 20 筆標準與對抗性測試案例（包含經典詐騙、對抗變形錯字、新興科技詐騙與正常通知），
每筆資料皆附帶難易度分級、Ground Truth 標籤，用於基準測試與量化評估。
"""

from typing import List, Dict, Any

GOLDEN_TEST_DATASET: List[Dict[str, Any]] = [
    # --- 【標準詐騙樣本 (Standard Scam Cases)】 ---
    {
        "id": "CASE-01",
        "category": "假投資飆股 / 虛擬幣",
        "difficulty": "基礎",
        "is_scam": True,
        "expected_risk_level": "極度危險",
        "min_expected_score": 80,
        "input_text": "【台股實戰學院】張老師親自帶盤！佈局下半年翻倍黑馬飆股，上週帶會員獲利達 45%。免費領取精準進出場點位，名額僅限前 20 名，請點擊連結加助理 Line：https://line.me/ti/p/scam888 領取獲利密碼。",
        "description": "典型的假投資飆股詐騙，使用高回報、名人頭銜與名額限制製造稀缺感。"
    },
    {
        "id": "CASE-02",
        "category": "假解除分期付款 / 電商客服",
        "difficulty": "基礎",
        "is_scam": True,
        "expected_risk_level": "極度危險",
        "min_expected_score": 85,
        "input_text": "您好，這裡是博客來客服。因新進人員系統登錄錯誤，將您的訂單誤設為批發商經銷商，今晚 12 點前將自動從您帳戶扣款 14,800 元。為協助您取消扣款，請配合稍後配合銀行專員來電，並攜帶金融卡至鄰近 ATM 進行身分驗證。",
        "description": "假解除分期付款手法，利用扣款恐懼誘騙受害者前往 ATM 操作。"
    },
    {
        "id": "CASE-03",
        "category": "假檢警與公務機關公文",
        "difficulty": "基礎",
        "is_scam": True,
        "expected_risk_level": "極度危險",
        "min_expected_score": 90,
        "input_text": "台北地檢署特偵組公文通知：受文者經查涉嫌洗錢防制法及重大金融詐欺案，名下所有資產即將凍結。因案件偵查不公開，嚴禁告知親友或律師。請於今日下午三點前將名下存款轉移至國家安全監管指定帳戶，配合資產清查，違者逕行拘提。",
        "description": "假冒檢警詐騙，利用法律名詞、凍結威脅與偵查不公開孤立受害者。"
    },
    {
        "id": "CASE-04",
        "category": "釣魚簡訊與惡意短網址",
        "difficulty": "基礎",
        "is_scam": True,
        "expected_risk_level": "極度危險",
        "min_expected_score": 85,
        "input_text": "【監理服務網】通知：您有一筆交通違規罰款新台幣 900 元已逾期未繳納。請於 24 小時內點擊官方繳費入口 http://mvdis-gov-tw.vip/pay 線上繳納，逾期將加倍開罰並移送強制執行。",
        "description": "釣魚簡訊，假冒監理站並偽造類似 gov.tw 的非官方域名騙取信用卡卡號。"
    },
    {
        "id": "CASE-05",
        "category": "假交友徵婚 / 殺豬盤",
        "difficulty": "中等",
        "is_scam": True,
        "expected_risk_level": "中度風險",
        "min_expected_score": 70,
        "input_text": "親愛的，我叔叔是香港金融高層，他最近發現一個內部套利漏洞，保證穩賺不賠。我已經放了 50 萬進去獲利翻倍了。我希望我們未來生活更好，你先投個 5 萬元試試看，我把內部後台網址發給你，一起為我們的未來努力好嗎？",
        "description": "殺豬盤愛情詐騙，透過情感包裝與內線獲利誘使受害者投入資金。"
    },
    {
        "id": "CASE-06",
        "category": "假求職兼職 / 家庭代工",
        "difficulty": "基礎",
        "is_scam": True,
        "expected_risk_level": "極度危險",
        "min_expected_score": 80,
        "input_text": "【在家兼職】誠徵打字員 / 訂單處理員，免出門、免經驗、時間彈性，每日結算薪資 1,500 - 3,000 元。只需提供名下任一銀行存摺封面與提款卡以供薪資入帳審核，意者加 Line 聯絡陳主管。",
        "description": "假求職詐騙，實為騙取受害者人頭帳戶供詐騙集團洗錢使用。"
    },
    {
        "id": "CASE-07",
        "category": "假中獎通知 / 抽獎活動",
        "difficulty": "基礎",
        "is_scam": True,
        "expected_risk_level": "極度危險",
        "min_expected_score": 75,
        "input_text": "恭喜您！您的門號已被幸運抽中 momo 購物網 20 週年特獎『iPhone 16 Pro 256GB』一台！請於今天下午 5:00 前至領獎連結填寫寄送資料並支付手續費與代扣稅金 2,000 元：http://momo-luckydraw.top/win",
        "description": "假中獎通知，藉由要求先支付稅金/手續費騙取金錢。"
    },

    # --- 【新興科技與變形詐騙 (Emerging Tech & Adversarial Cases)】 ---
    {
        "id": "CASE-08",
        "category": "AI 換臉與聲紋擬真 (Deepfake)",
        "difficulty": "高階",
        "is_scam": True,
        "expected_risk_level": "極度危險",
        "min_expected_score": 85,
        "input_text": "（語音訊息音檔轉譯）爸！是我啦，我跟朋友開車在南部出嚴重車禍撞到人了，對方要十萬塊和解不然要告我。我手機快沒電了，你先不要打電話過來，馬上把錢匯到我朋友這張郵局帳號 0021-xxxx，拜託快點救我！",
        "description": "假冒子女親情詐騙，通常結合 AI 仿聲技術與極端危急情境逼迫匯款。"
    },
    {
        "id": "CASE-09",
        "category": "二手買賣平台假買家 / 假客服協議",
        "difficulty": "中等",
        "is_scam": True,
        "expected_risk_level": "極度危險",
        "min_expected_score": 80,
        "input_text": "賣家你好，我剛剛在 7-11 賣貨便下單你的二手相機，但系統跳出『賣家尚未簽署 2026 數位金流保障協議無法下單』。請你點擊賣貨便線上客服連結 https://myship-7-11-service.xyz 掃描 QR 碼聯繫專員開通，我才能付款喔。",
        "description": "二手交易平台假買家雙簧詐騙，假借平台金流協議要求賣家認證轉帳。"
    },
    {
        "id": "CASE-10",
        "category": "Web3 虛擬幣假空投與授權竊取",
        "difficulty": "高階",
        "is_scam": True,
        "expected_risk_level": "極度危險",
        "min_expected_score": 85,
        "input_text": "🔥【Solana 官方空投季】恭喜您的錢包地址符合 $SOL 生態治理代幣領取資格！前 10,000 名連接錢包並 Claim 即享 500 枚免費代幣。倒數 2 小時截止，請前往官網領取：https://solana-claim-airdrop.cc",
        "description": "Web3 惡意釣魚空投，誘騙連接錢包並簽署惡意資產轉移合約。"
    },
    {
        "id": "CASE-11",
        "category": "假冒台水台電瓦斯欠費催繳",
        "difficulty": "基礎",
        "is_scam": True,
        "expected_risk_level": "極度危險",
        "min_expected_score": 80,
        "input_text": "【台灣自來水公司】重要通知：貴用戶 7-8 月份水費新台幣 382 元已逾期，若未於 24 小時內補繳將於明日上午執行停水。請立即登入繳費中心補繳：https://water-gov-pay.top/tw",
        "description": "利用停水恐懼與小額水費誘導民眾點擊非 gov.tw 釣魚網址。"
    },
    {
        "id": "CASE-12",
        "category": "海外高薪打工度假人口販運",
        "difficulty": "中等",
        "is_scam": True,
        "expected_risk_level": "極度危險",
        "min_expected_score": 85,
        "input_text": "【東南亞跨國企業招募】急徵海外中文客服人員！底薪 12 萬台幣 + 績效獎金，包來回機票、五星級宿舍與專人打理三餐。無經驗、英文不拘，只要會打字即可，名額有限下週直接出發！",
        "description": "海外高薪打工陷阱，實為人口販運與強迫電信詐騙園區。"
    },

    # --- 【對抗變形錯字測試 (Adversarial Typos Cases)】 ---
    {
        "id": "CASE-13",
        "category": "假投資飆股 / 虛擬幣 (變形錯字)",
        "difficulty": "高階對抗",
        "is_scam": True,
        "expected_risk_level": "中度風險",
        "min_expected_score": 70,
        "input_text": "【財經密碼】張老帥親自布局！穩賺不賠翻倍黑馬，上週帶會員獲利40%。免費領取飆股代碼，名額有限『加.賴.』：boss999，跟著老帥一起『投.貲.』財富自由！",
        "description": "詐騙集團透過錯字（老帥、加.賴.、投.貲.）試圖躲避傳統關鍵字審查過濾器。"
    },
    {
        "id": "CASE-14",
        "category": "線上申辦低利貸款騙取存摺",
        "difficulty": "中等",
        "is_scam": True,
        "expected_risk_level": "極度危險",
        "min_expected_score": 80,
        "input_text": "【玉山融資中心】急需週轉不求人！信用不良、小白皆可貸，超低年息 1.5%，當天申請當天撥款 50 萬。因您信用評分偏低，需先將郵局提款卡及存摺寄至本公司作帳戶資金流水認證，認證完成立即返還並撥款。",
        "description": "以美化帳戶流水為名義，詐騙借貸人的人頭帳戶與提款卡。"
    },
    {
        "id": "CASE-15",
        "category": "假買車 / 假租屋訂金詐騙",
        "difficulty": "中等",
        "is_scam": True,
        "expected_risk_level": "中度風險",
        "min_expected_score": 70,
        "input_text": "台北大安區電梯獨立套房，月租只要 9,000 元（含水電網路）！因本人被外派國外急租，目前已有 5 組人在約看房。如果想排第一順位優先簽約，請先匯 3,000 元保留訂金，看房不滿意全額退還。",
        "description": "利用遠低於市價的房屋與排隊心理，騙取未看房訂金。"
    },

    # --- 【正常安全負樣本 (Negative Benign Cases - 避免誤判)】 ---
    {
        "id": "CASE-16",
        "category": "正常訊息 / 銀行刷卡通知",
        "difficulty": "基礎",
        "is_scam": False,
        "expected_risk_level": "安全",
        "max_expected_score": 30,
        "input_text": "國泰世華銀行通知：您於 09/07 18:32 透過信用卡 (末四碼 8821) 於台灣高鐵消費 NT$1,490 元，若非您本人交易請速洽本行客服專線 02-2383-1000。",
        "description": "合法標準交易通知，包含官方正規客服電話，無任何可疑短網址或轉帳要求。"
    },
    {
        "id": "CASE-17",
        "category": "正常訊息 / 物流取件通知",
        "difficulty": "基礎",
        "is_scam": False,
        "expected_risk_level": "安全",
        "max_expected_score": 30,
        "input_text": "【7-ELEVEN 取件通知】您訂購的商品已送達 7-11 鑫欣門市 (取貨編號: 7890123)，請於 09/14 前攜帶與收件人相符之身分證件前往領取。若有疑問請洽購物平台客服。",
        "description": "標準超商取件簡訊，無釣魚連結，僅提醒取貨期限與門市。"
    },
    {
        "id": "CASE-18",
        "category": "正常訊息 / 好友聚會日常聊天",
        "difficulty": "基礎",
        "is_scam": False,
        "expected_risk_level": "安全",
        "max_expected_score": 30,
        "input_text": "小明你明天晚上有空嗎？大家約好 7 點在忠孝復興那間火鍋店聚餐，菜單我傳在群組相簿了，你記得看一下要點什麼湯底喔！",
        "description": "一般好友日常社交對話，無金錢要求與可疑行為。"
    },
    {
        "id": "CASE-19",
        "category": "正常訊息 / 學校註冊與選課提醒",
        "difficulty": "中等",
        "is_scam": False,
        "expected_risk_level": "安全",
        "max_expected_score": 30,
        "input_text": "【教務處通知】115 學年度第一學期初選加退選作業將於明日上午 9:00 開放，請各位同學依規定期限登入校務資訊系統 (portal.ntu.edu.tw) 進行選課確認，逾期不予受理。",
        "description": "正規學校教務處通知，使用標準官方 edu.tw 網域名稱。"
    },
    {
        "id": "CASE-20",
        "category": "正常訊息 / 醫院預約看診提醒",
        "difficulty": "基礎",
        "is_scam": False,
        "expected_risk_level": "安全",
        "max_expected_score": 30,
        "input_text": "【台大醫院提醒】林先生您好，您預約於 09/10 上午 09:30 心臟內科門診 (診號 15 號)，請攜帶健保卡於門診大樓 2 樓報到。若需取消請於前一日致電預約中心 02-2356-2996。",
        "description": "正規醫院看診提醒，包含具體診號與正規代表號，無任何匯款轉帳要求。"
    }
]
