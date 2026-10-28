"""165 反詐騙知識庫與 RAG 檢索模組 (Knowledge Base Module)

擴充至 15 大經典與新興科技詐騙劇本庫（含 Deepfake、二手平台假買家、Web3 釣魚等），
提供混合語意檢索器，作為 LLM 鑑識的客觀知識來源。
"""

import math
import re
from typing import List, Dict, Any, Optional


# 165 官方常見與新興科技詐騙手法特徵庫 (共 15 大手法)
KNOWLEDGE_BASE_ENTRIES: List[Dict[str, Any]] = [
    {
        "id": "KB-001",
        "category": "假投資飆股 / 虛擬幣",
        "summary": "以財經名人或投顧老師為號召，宣稱掌握未上市飆股、內線消息或高頻交易機器人，保證高獲利、低風險，誘導加入私人 Line 投資群或下載山寨交易 App。",
        "keywords": ["飆股", "翻倍", "老師帶盤", "內線消息", "保證獲利", "加助理Line", "投資學院", "虛擬貨幣", "出金困難", "加賴", "投貲"],
        "tactics": ["貪婪誘餌", "權威專家包裝", "飢餓行銷/限時名額"],
        "solution": "金管會與警政署提醒：合法證券投顧業者絕不會以個人 Line 群組或私下轉帳方式招攬會員，凡標榜『穩賺不賠』必為詐騙。"
    },
    {
        "id": "KB-002",
        "category": "假解除分期付款 / 電商客服",
        "summary": "駭客入侵電商資料庫取得受害者購買紀錄，佯裝電商客服稱『系統出錯誤設為連續扣款/批發商』，隨後由假冒銀行專員來電，要求受害者操作 ATM 或網銀『解除設定』，實為將存款轉出。",
        "keywords": ["工作人員疏失", "誤設經銷商", "批發商", "重複扣款", "操作ATM", "身分驗證", "解除分期", "網銀轉帳", "非營業時間來電"],
        "tactics": ["製造損失恐懼", "時間緊迫施壓（即將扣款）", "雙簧偽冒（電商+銀行）"],
        "solution": "ATM 與網路銀行僅有存款與提款轉帳功能，絕對沒有『解除扣款設定』或『驗證身分』之功能。"
    },
    {
        "id": "KB-003",
        "category": "假檢警與公務機關公文",
        "summary": "佯稱戶政事務所、健保局或檢察官，告知個人資料遭冒用涉及洗錢等重大刑案，寄送偽造的法務部公文或傳票，以『偵查不公開』恐嚇不得告知親友，要求將名下資金匯入『國家安全監管帳戶』。",
        "keywords": ["洗錢防制法", "地檢署", "特偵組", "監管帳戶", "資產凍結", "偵查不公開", "強制拘提", "公文傳票", "健保停卡"],
        "tactics": ["司法公權力威脅", "資訊孤立（禁止告知他人）", "嚴重刑責恐嚇"],
        "solution": "司法檢警機關辦案絕不會以電話製作筆錄、不會透過通訊軟體傳送公文傳票，更絕無『監管帳戶』或要求民眾匯款監管之制度。"
    },
    {
        "id": "KB-004",
        "category": "釣魚簡訊與惡意木馬病毒短網址",
        "summary": "發送偽冒監理站、水電公司催繳簡訊（如 t.ly/mvdis.gov.tw、回復 1 啟動連結），或傳送『您有一件包裹簽收單電子憑證請查收（假冒黑貓宅急便）』、『上次聚會的照片，你存檔一下』並附帶 http://goo.gl/... 等公開短網址。一旦點擊將誘導輸入信用卡號，或在手機自動下載惡意 APK 木馬病毒程式，竊取電信小額付費認證碼並讀取通訊錄向親友進行病毒式跳板擴散！",
        "keywords": ["交通違規罰款", "交通違規罰鍰", "交通罰款", "逾期未到案", "逾期未繳", "停水通知", "點數即將到期", "mvdis", "gov-tw", "t.ly", "goo.gl", "包裹簽收單", "電子憑證請查收", "上次聚會的照片", "存檔一下", "回復1", "啟動連結", "vip", "top", "xyz", ".top", ".vip", ".xyz", "線上繳費", "繳納罰鍰"],
        "tactics": ["日常瑣事疏忽（假包裹簽收單/假聚會照片）", "木馬病毒通訊錄跳板直呼姓名裝熟", "短網址隱藏惡意 APK 下載點或釣魚網域"],
        "solution": "黑貓宅急便（官方網域 t-cat.com.tw）等物流業者絕不會以 http://goo.gl 等公開短網址寄送『包裹簽收單電子憑證』，親友更不會用簡訊夾帶不安全的 http 短網址傳送『上次聚會的照片』！切勿點擊連結或安裝不明應用程式，並立即向電信商關閉『小額付費』功能。"
    },
    {
        "id": "KB-005",
        "category": "假交友裝熟引流 / 殺豬盤詐騙",
        "summary": "常先透過 Apple iMessage（使用 @126.com / @163.com / @qq.com 等中國免費信箱）亂槍打鳥群發『Line好友怎麼找不到你了？你是不是把我刪了？有事找你加我 Line：xxxxx』或『有急事找你電話打不通加我賴』。一旦受害者主動加入該 LINE ID，對方即偽裝成帥哥美女稱『認錯人也是緣分』建立曖昧信任（養豬），或直接拉入假投資飆股群組進行詐騙（殺豬）。",
        "keywords": ["親愛的", "為了我們未來", "內部漏洞", "代操", "虛擬貨幣平台", "只賺不賠", "提現保證金", "老公", "老婆", "找不到你了", "把我刪了", "有事找你", "急事找你", "加我Line", "加我賴", "126.com", "163.com"],
        "tactics": ["無頭無尾裝熟激發好奇心", "利用境外信箱 iMessage 免費群發規避電信攔截", "誘導受害者主動搜尋加 LINE 規避官方封號"],
        "solution": "凡收到無具名、使用 @126.com / @163.com 等免費信箱透過 iMessage 傳來『有急事找你、是不是把我刪了、加我 LINE ID』之訊息，100% 為亂槍打鳥引流詐騙！請直接點選『回報垃圾訊息 (Report Junk)』並切勿加入該 LINE 帳號。"
    },
    {
        "id": "KB-006",
        "category": "假求職兼職 / 家庭代工",
        "summary": "在 Facebook、IG 或求職社團刊登『居家打字、免經驗、日領高薪』廣告，要求應徵者寄出銀行存摺正本與提款卡（附密碼）聲稱作『薪資轉帳認證』，實為作為洗錢人頭帳戶，使應徵者淪為詐欺共犯。",
        "keywords": ["在家兼職", "打字員", "家庭代工", "日領高薪", "寄送存摺", "提款卡密碼", "薪資審核", "輕鬆賺錢"],
        "tactics": ["輕鬆賺錢誘惑", "求職若渴心理", "掩飾人頭帳戶本質"],
        "solution": "合法公司錄取員工僅需提供存摺『影本（帳號封面）』，要求寄送存摺正本、提款卡或提供密碼者皆為人頭帳戶陷阱。"
    },
    {
        "id": "KB-007",
        "category": "假中獎通知 / 抽獎活動",
        "summary": "透過簡訊或通訊軟體告知抽中知名電商或品牌之高價獎品（如 iPhone、汽車），要求受害者必須先匯款支付『手續費』、『代扣所得稅』或『海外海關關稅』才能寄出獎品。",
        "keywords": ["恭喜中獎", "特獎iPhone", "幸運抽中", "代扣稅金", "預付手續費", "領獎連結", "幸運得主"],
        "tactics": ["意外橫財心理", "先付小錢領大獎陷阱"],
        "solution": "依稅法規定，機會中獎稅款是由主辦單位在發給獎金時直接扣除，或由得獎者向主辦單位官方帳戶繳納，絕不會要求以個人帳戶匯款。"
    },
    {
        "id": "KB-008",
        "category": "AI 換臉與聲紋擬真 (Deepfake)",
        "summary": "利用 AI 生成技術偽造親友或公司主管的聲音、視訊畫面，進行簡短通話稱『發生車禍急需保釋金』或『臨時有緊急公務款項需代墊』，誘導受害者在慌亂中匯款。",
        "keywords": ["爸媽救我", "出車禍急需用錢", "我是主管", "緊急調度款", "視訊短暫斷線", "聲音一模一樣"],
        "tactics": ["親情與恐懼綁架", "AI擬真技術信任", "時間極度緊迫"],
        "solution": "遇到親友聲音視訊借錢，務必掛斷後透過原有私人管道重新回撥查證，或詢問只有彼此知道的『通關密語』。"
    },
    {
        "id": "KB-009",
        "category": "二手買賣平台假買家 / 假客服協議",
        "summary": "在旋轉拍賣、7-11賣貨便、全家好賣+等平台假裝買家，稱『無法下單、需賣家開通金流保障協議』，傳送假冒客服 QR Code 或連結，要求賣家配合銀行人員操作轉帳簽署協議。",
        "keywords": ["無法下單", "開通金流保障", "賣貨便客服", "簽署協議", "掃描QR Code", "認證帳戶"],
        "tactics": ["交易障礙製造", "假冒官方客服雙簧", "急於成交心理"],
        "solution": "各大超商與二手平台絕不會透過買家私下傳送連結要求賣家簽署金流協議或操作網銀認證。"
    },
    {
        "id": "KB-010",
        "category": "Web3 虛擬幣假空投與授權竊取",
        "summary": "在 Telegram、X (Twitter) 或 Discord 發布免費領取熱門代幣/NFT 資訊，誘導連接加密錢包並簽署『無限額度授權 (Unlimited Approval)』惡意合約，瞬間將錢包內資產全數轉走。",
        "keywords": ["免費空投", "Airdrop", "Claim", "連接錢包", "授權合約", "Unlimited Approval", "轉走代幣"],
        "tactics": ["免費暴利誘惑", "合約代碼晦澀難懂", "錯失恐懼 (FOMO)"],
        "solution": "絕不輕易點擊不明來源的 Claim 空投連結，簽署錢包授權時務必仔細審查授權合約權限。"
    },
    {
        "id": "KB-011",
        "category": "海外高薪打工度假人口販運",
        "summary": "以『海外高薪客服、包吃包住包機票、無門檻月入十萬』為誘餌，吸引年輕人前往柬埔寨、緬甸等特定園區，入境後立即扣押護照並強迫從事跨國電信詐騙。",
        "keywords": ["柬埔寨高薪", "包機票包食宿", "海外文字客服", "底薪十萬", "無經驗可", "園區工作"],
        "tactics": ["高薪夢想包裝", "低門檻陷阱", "人身自由控制"],
        "solution": "出國工作務必透過政府核准之合法仲介，對條件過於優渥且要求即刻出境的工作應高度警惕。"
    },
    {
        "id": "KB-012",
        "category": "假冒台水台電瓦斯欠費催繳",
        "summary": "發送『台電/台灣自來水：您有水電費逾期未繳，即將於明日停止供水供電』簡訊，附上非官方短網址誘導線上繳費並盜刷信用卡。",
        "keywords": ["水費欠繳", "電費逾期", "即將停水", "即將斷電", "台水繳費", "台電通知"],
        "tactics": ["民生基本需求威脅", "時間緊迫（明日停供）", "日常麻痺疏忽"],
        "solution": "台水與台電催繳簡訊發送號碼為專屬政府短碼（如 111），不會隨意使用一般手機門號或附帶非 .gov.tw 網址。"
    },
    {
        "id": "KB-013",
        "category": "假買車 / 假租屋訂金詐騙",
        "summary": "刊登遠低於市價的精美房屋或二手車出租出售資訊，稱『看房/看車人數眾多，需先付 5,000 訂金保留優先權』，匯款後對方隨即封鎖失聯。",
        "keywords": ["先付訂金優先看房", "很多人在排隊", "出國便宜租", "保留資格", "匯款排第一順位"],
        "tactics": ["稀缺性競爭心理", "遠低於市價誘餌", "沉沒成本陷阱"],
        "solution": "在未親眼見到房屋現況、未核對房東身分證與房屋權狀之前，絕不可提前預付任何訂金或押金。"
    },
    {
        "id": "KB-014",
        "category": "假親友比賽拉票釣魚 / LINE 帳號盜用詐騙",
        "summary": "盜取親友 LINE 帳號後，先詢問『有在忙嗎』，接著以『小朋友參加繪畫比賽/寵物比賽/才藝競賽，幫忙投一票（如幫我投14號）』為由，傳送偽裝成投票活動的境外釣魚網站（如 .top / .vip 網域）。一旦點擊投票，網頁會要求輸入 LINE 帳號、密碼與簡訊 OTP 認證碼以盜走受害者的 LINE 帳號，或進一步向通訊錄親友借錢詐騙。",
        "keywords": ["在忙嗎", "有在忙嗎", "可以幫我個忙嗎", "繪畫比賽", "參加繪畫", "幫忙投一票", "幫我投", "創意繪畫", "寵物比賽", "輔助認證", "急需周轉", "明天一定還", "帳號不是我的名字是我朋友的"],
        "tactics": ["親友情誼信任", "人情幫忙拉票降低戒心", "偽造線上投票頁面騙取 LINE 帳密與 OTP 驗證碼"],
        "solution": "凡親友於 LINE 傳送『小朋友繪畫比賽/寵物比賽幫忙投票』連結（常見為 .top / .vip 等亂數網址），或要求進行 LINE 輔助認證、借錢周轉，100% 為帳號遭盜用之釣魚詐騙！絕對不可點擊連結或輸入手機號碼、LINE 密碼與簡訊驗證碼。"
    },
    {
        "id": "KB-015",
        "category": "線上申辦低利貸款騙取存摺",
        "summary": "假冒銀行或代辦貸款公司，聲稱『信用不良亦可貸、超低利率、快速撥款』，隨後稱受害者『流水帳戶資金不足』，要求寄送存摺與提款卡以協助製造假流水，實為騙取人頭帳戶。",
        "keywords": ["免聯徵", "信用瑕疵可貸", "超低利率", "製造資金流水", "寄送提款卡美化帳戶", "快速核貸"],
        "tactics": ["急需資金脆弱心理", "低門檻包裝", "以美化帳戶為名騙取存摺"],
        "solution": "合法銀行辦理貸款絕不會要求寄送存摺正本、提款卡或提供密碼，要求寄送提款卡者必為詐騙。"
    },
    {
        "id": "KB-016",
        "category": "假冒政府「普發現金一萬元 / 補助津貼」釣魚簡訊詐騙 (165官網最新通報)",
        "summary": "【165全民防騙網 #1715/#1701 同步】詐騙集團緊跟時事話題，發送假冒財政部或行政院之『普發現金一萬元開放登記領取』、『防詐補助津貼入帳確認』簡訊，夾帶偽冒政府之短網址或釣魚連結，誘騙民眾輸入身分證字號、銀行帳號密碼、信用卡號與簡訊 OTP 驗證碼進行盜刷或網銀轉帳。",
        "keywords": ["普發現金", "普發萬元", "普發一萬元", "一萬元補助", "現金一萬", "補助津貼", "財政部普發", "線上登記領取", "點擊連結領取"],
        "tactics": ["時事政策熱點誘餌", "假冒政府機關權威", "誘騙輸入信用卡與網銀帳密"],
        "solution": "政府普發現金或各項補助絕不會發送『含短網址之領錢簡訊』，更不會要求輸入信用卡號、網銀密碼或操作 ATM！請認明政府唯一認證簡訊發送碼『111』。"
    },
    {
        "id": "KB-017",
        "category": "社群「一頁式詐騙廣告」與超商幽靈包裹貨到付款詐騙 (165官網最新通報)",
        "summary": "【165全民防騙網 #1739 同步】刑事局追查發現詐騙集團於 Facebook、IG 大量投放『限時一折、專櫃出清、名醫/名人代言、免運貨到付款』之一頁式詐騙廣告，並透過國內代寄物流公司發送超商貨到付款包裹。民眾取貨拆封後才發現是劣質廉價品，或根本沒網購卻收到『幽靈到付包裹』。",
        "keywords": ["一頁式廣告", "一頁式網站", "貨到付款", "限時下殺", "清倉特賣", "幽靈包裹", "代寄物流", "非賣場包裹", "沒買東西卻收到取貨通知"],
        "tactics": ["超低價限時倒數促銷", "標榜超商貨到付款降低戒心", "盜用名人與新聞畫面背書"],
        "solution": "網購若見『網頁僅有一長頁、無公司統編與實體地址、僅提供貨到付款、售價遠低於市價』即為一頁式詐騙！若收到非本人訂購之超商到付包裹切勿領取；若已取貨付款，請立即透過各大超商『爭議包裹退貨退款平台』申請退費。"
    },
    {
        "id": "KB-018",
        "category": "社群「舊衣回收換現金 / 小小體驗營報名」引流加 LINE 詐騙 (165官網最新通報)",
        "summary": "【165全民防騙網 #1480 同步】詐騙集團於臉書地方社團張貼溫馨公益或親子活動貼文，宣稱『舊衣回收/捐二手書即可換取百元超商禮券與現金』或『超商小小店長/小小職人體驗營免費報名』，要求民眾點擊連結私訊主辦方 LINE 客服登記，隨後拉入群組誘導參與『公益認購抽獎、匯款解凍或假投資代操』。",
        "keywords": ["舊衣回收換現金", "舊衣回收領禮券", "小小體驗營", "小小店長體驗營", "親子體驗營報名", "免費報名加LINE", "公益抽獎"],
        "tactics": ["環保公益與親子活動偽裝", "小額超商禮券誘餌", "誘導私訊加 LINE 後轉入投資/刷單群組"],
        "solution": "凡臉書社團張貼『舊衣回收換現金/禮券』或『知名連鎖品牌小小店長體驗營』卻要求私下加個人 LINE 帳號報名者，皆為詐騙引流手法！請直接向該品牌官方網站查證。"
    }
]


def check_165_official_line_id(line_id: str) -> Optional[Dict[str, Any]]:
    """即時連線內政部警政署 165 全民防騙網官方 API，查驗 LINE ID 是否已被通報為詐騙帳號
    API 端點: GET https://165.npa.gov.tw/api/queryLineId/{line_id}
    """
    import requests
    clean_id = (line_id or "").strip().lstrip("@")
    if not clean_id or len(clean_id) < 3:
        return None
    try:
        url = f"https://165.npa.gov.tw/api/queryLineId/{clean_id}"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Accept": "application/json"
        }
        resp = requests.get(url, headers=headers, timeout=3.5)
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, list) and len(data) > 0:
                first_hit = data[0]
                return {
                    "is_reported_scam": True,
                    "line_id": first_hit.get("lineId", clean_id),
                    "alert_time": first_hit.get("alertTime", "近期"),
                    "source": "內政部警政署 165 全民防騙網官方資料庫 (165.npa.gov.tw)"
                }
            return {
                "is_reported_scam": False,
                "line_id": clean_id,
                "source": "內政部警政署 165 全民防騙網官方資料庫 (165.npa.gov.tw)"
            }
    except Exception:
        pass
    return None


def sync_from_165_official_api(max_items: int = 8) -> Dict[str, Any]:
    """即時從警政署 165 全民防騙網 (https://165.npa.gov.tw) 官方 API 抓取最新反詐公告與每日通報涉詐廣告清單，
    並自動轉換注入本系統之 KNOWLEDGE_BASE_ENTRIES 向量檢索知識庫。
    """
    import os
    import json
    import requests

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Accept": "application/json"
    }
    synced_articles = []
    daily_ad_reports = []
    error_msg = ""

    # 1. 抓取 165 最新反詐新聞與手法公告 (list/1)
    try:
        r_list = requests.get("https://165.npa.gov.tw/api/article/list/1", headers=headers, timeout=6)
        if r_list.status_code == 200:
            items = r_list.json()
            if isinstance(items, list):
                for item in items[:max_items]:
                    art_id = item.get("id")
                    title = (item.get("title") or "").strip()
                    pub_date = (item.get("publishDate") or "")[:10]
                    if not title:
                        continue
                    # 嘗試抓取前 3 筆的完整內文摘要
                    content_summary = ""
                    if len(synced_articles) < 3 and art_id:
                        try:
                            r_det = requests.get(f"https://165.npa.gov.tw/api/article/detail/1/{art_id}", headers=headers, timeout=3.5)
                            if r_det.status_code == 200:
                                raw_html = r_det.json().get("content") or ""
                                clean_txt = re.sub(r"<[^>]+>", " ", raw_html)
                                clean_txt = re.sub(r"&nbsp;|\s+", " ", clean_txt).strip()
                                content_summary = clean_txt[:220] + ("..." if len(clean_txt) > 220 else "")
                        except Exception:
                            pass
                    if not content_summary:
                        content_summary = f"警政署 165 全民防騙網於 {pub_date} 發布之最新反詐公告：「{title}」。提醒民眾提高警覺，遇可疑訊息請撥打 165 專線查證。"

                    # 自動抽取標題中之關鍵詞
                    extracted_kws = re.findall(r"「([^」]+)」|【([^】]+)】", title)
                    kw_list = [k[0] or k[1] for k in extracted_kws if (k[0] or k[1])]
                    if not kw_list:
                        kw_list = [w for w in ["一頁式廣告", "普發", "假檢警", "LINE", "投票", "投資", "租屋", "台水", "台電", "郵局", "抽獎"] if w in title]
                    if not kw_list:
                        kw_list = [title[:6]]

                    kb_entry = {
                        "id": f"165-LIVE-{art_id}",
                        "category": f"【165官網同步】{title}",
                        "publish_date": pub_date,
                        "summary": content_summary,
                        "keywords": kw_list,
                        "tactics": ["165官方最新通報態樣", "時事與社交工程誘餌"],
                        "solution": "此為內政部警政署 165 全民防騙網 (https://165.npa.gov.tw) 發布之最新防詐示警，切勿點擊不明連結或依指示匯款，請立即撥打 165 查證。"
                    }
                    synced_articles.append(kb_entry)

                    # 動態注入 KNOWLEDGE_BASE_ENTRIES (避免重複)
                    existing_ids = {e.get("id") for e in KNOWLEDGE_BASE_ENTRIES}
                    if kb_entry["id"] not in existing_ids:
                        KNOWLEDGE_BASE_ENTRIES.append(kb_entry)
    except Exception as e:
        error_msg = str(e)

    # 2. 抓取 165 每日民眾通報社群平臺涉詐廣告清單 (list/9)
    try:
        r_ads = requests.get("https://165.npa.gov.tw/api/article/list/9", headers=headers, timeout=5)
        if r_ads.status_code == 200:
            ad_items = r_ads.json()
            if isinstance(ad_items, list):
                for ad in ad_items[:5]:
                    daily_ad_reports.append({
                        "id": ad.get("id"),
                        "title": ad.get("title", ""),
                        "publish_date": (ad.get("publishDate") or "")[:16].replace("T", " ")
                    })
    except Exception:
        pass

    return {
        "success": len(synced_articles) > 0 or len(daily_ad_reports) > 0,
        "synced_count": len(synced_articles),
        "synced_articles": synced_articles,
        "daily_ad_reports": daily_ad_reports,
        "total_kb_count": len(KNOWLEDGE_BASE_ENTRIES),
        "error": error_msg
    }


class ScamKnowledgeRetriever:
    """反詐騙 RAG 檢索器（結合關鍵字權重與語意比對）"""

    def __init__(self, kb_data: List[Dict[str, Any]] = None):
        self.kb_data = kb_data or KNOWLEDGE_BASE_ENTRIES

    def _tokenize(self, text: str) -> List[str]:
        """簡易中文與英數分詞（支援 2~4 字 n-gram 與關鍵詞抽取）"""
        clean_text = re.sub(r"[^\w\s]", " ", text.lower())
        tokens = clean_text.split()
        
        # 產生中文 2-gram 和 3-gram 增強特徵辨識
        chinese_chars = re.findall(r"[\u4e00-\u9fff]", text)
        for i in range(len(chinese_chars) - 1):
            tokens.append("".join(chinese_chars[i:i+2]))
        for i in range(len(chinese_chars) - 2):
            tokens.append("".join(chinese_chars[i:i+3]))
        return tokens

    def retrieve(self, query: str, top_k: int = 2) -> List[Dict[str, Any]]:
        """檢索與使用者輸入最相關的 165 案例"""
        if not query.strip():
            return []

        query_tokens = set(self._tokenize(query))
        scores = []

        for entry in self.kb_data:
            score = 0.0
            
            # 關鍵字重合權重加權
            for kw in entry.get("keywords", []):
                if kw.lower() in query.lower():
                    score += 3.5  # 關鍵字命中高權重

            # 摘要與手法詞彙比對
            entry_tokens = set(self._tokenize(entry.get("summary", "") + " " + entry.get("category", "")))
            intersection = query_tokens.intersection(entry_tokens)
            score += len(intersection) * 0.5

            if score > 0:
                scores.append((score, entry))

        # 按相關度分數由高到低排序 (僅保留達門檻之相關案例)
        valid_scores = [item for item in scores if item[0] >= 3.0]
        valid_scores.sort(key=lambda x: x[0], reverse=True)
        results = [item[1] for item in valid_scores[:top_k]]
        return results
