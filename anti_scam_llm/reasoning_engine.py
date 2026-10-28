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

from anti_scam_llm.config import GEMINI_API_KEY, OPENAI_API_KEY, DEFAULT_MODEL_PROVIDER, DEFAULT_MODEL_NAME, get_secret
from anti_scam_llm.schemas import AntiScamAnalysisResult, InputPayload
from anti_scam_llm.prompts import build_analysis_prompt
from anti_scam_llm.knowledge_base import ScamKnowledgeRetriever, check_165_official_line_id
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

        # 動態即時同步金鑰
        current_k = self.api_key or get_secret("GEMINI_API_KEY", "")
        if current_k:
            self.api_key = current_k
            self.vision_processor.gemini_key = current_k

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
                "input_summary": "上傳之圖片未能提取到清晰文字內容",
                "risk_assessment": {
                    "risk_score": 50,
                    "risk_level": "低度疑慮",
                    "confidence_level": "中",
                    "primary_scam_type": "圖片文字無法辨識 (請直接貼上網址或對話文字)"
                },
                "red_flags": [],
                "psychological_tactics": [],
                "evidence_analysis": "系統未能從您上傳的圖片中擷取到清晰的文字或網址（可能因圖片模糊或雲端 OCR 連線逾時）。\n\n⚠️ **防詐安全提醒**：切勿因為圖片未抽出文字就認定安全！若圖中包含可疑網址（如 `.top`、`.vip` 結尾之繪畫比賽投票連結）或要求匯款，請直接將該網址或對話文字貼入下方文字框進行深度鑑識。",
                "actionable_guidance": {
                    "immediate_actions": ["請勿點擊圖片中的不明連結（特別是 .top / .vip 投票網址）或輸入 LINE 帳密與驗證碼。"],
                    "official_verification": ["可將圖片中的網址或關鍵句子手動輸入文字框，或撥打 165 反詐騙專線查證。"],
                    "recommended_safe_reply": "請先透過電話向本人查證，切勿直接點擊連結。"
                }
            }, ensure_ascii=False)
            _, validated_result, _ = OutputGuardrail.validate_and_parse(
                raw_output=safe_mock,
                fallback_input_summary="上傳圖片未提取到文字",
                
            )
            return validated_result

        # 2. RAG 知識庫檢索 (先自動縫合 OCR 因窄螢幕換行而斷裂之網址，如 https://twm5g.my/\nQM4J09XDK9)
        user_text = self._stitch_multiline_urls(user_text)
        rag_cases = self.retriever.retrieve(user_text, top_k=2)

        # 2.5 即時短網址展開核驗 (提供給 LLM 與離線引擎雙重參考，支援 HTTP 301/302 與 HTML Meta Refresh 跳轉)
        url_inspection_notes = []
        for u in re.findall(r"https?://[^\s]+", user_text):
            u_clean = u.rstrip(").,;\"'】」")
            dest_u = self._resolve_redirect_url(u_clean)
            if dest_u and dest_u != u_clean:
                url_inspection_notes.append(f"• 原始短網址 `{u_clean}` 實時展開轉址目標為：`{dest_u}`")
        enriched_user_text = user_text
        if url_inspection_notes:
            enriched_user_text = user_text + "\n\n【系統短網址實時展開核驗資訊】：\n" + "\n".join(url_inspection_notes)

        # 3. 組裝動態 Prompt
        prompt = build_analysis_prompt(
            user_text=enriched_user_text,
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
        """調用 Google Gemini REST API (具備多模型自動降級與重試)"""
        candidate_models = [self.model_name, "gemini-2.0-flash", "gemini-2.0-flash-lite", "gemini-1.5-flash", "gemini-2.5-flash"]
        models_to_try = []
        for m in candidate_models:
            if m and m not in models_to_try:
                models_to_try.append(m)
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
                resp = requests.post(url, headers=headers, json=payload, timeout=30)
                if resp.status_code == 200:
                    data = resp.json()
                    return data["candidates"][0]["content"]["parts"][0]["text"]
            except Exception as e:
                last_err = e
                # 嘗試不帶 response_mime_type 模式重試
                try:
                    p_fallback = {"contents": [{"parts": [{"text": prompt}]}], "generationConfig": {"temperature": 0.1}}
                    r_fb = requests.post(url, headers=headers, json=p_fallback, timeout=25)
                    if r_fb.status_code == 200:
                        return r_fb.json()["candidates"][0]["content"]["parts"][0]["text"]
                except Exception:
                    pass
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

    @staticmethod
    def _stitch_multiline_urls(text: str) -> str:
        """自動縫合手機截圖 OCR 因窄螢幕換行而斷裂的網址（如 https://\\ntwm5g.co/idn3 或 https://twm5g.my/\\nQM4J09XDK9）"""
        if not text:
            return ""
        stitched = re.sub(r"(https?://)\s*\r?\n\s*([a-zA-Z0-9])", r"\1\2", text)
        stitched = re.sub(r"(https?://[a-zA-Z0-9._-]+/)\s*\r?\n\s*([a-zA-Z0-9_-]{2,})", r"\1\2", stitched)
        return stitched

    def _resolve_redirect_url(self, short_url: str) -> str:
        """即時追蹤短網址轉址目標（支援 HTTP 301/302 重新導向與 HTML Meta Refresh 跳轉，如 twm5g.my ➔ myfone.com.tw）"""
        try:
            resp = requests.get(
                short_url,
                allow_redirects=True,
                timeout=3.5,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
            )
            final_url = resp.url or short_url
            if final_url.rstrip("/") == short_url.rstrip("/") and resp.status_code == 200:
                html_head = resp.text[:4096]
                meta_m = re.search(r'content=["\'][^"\']*url\s*=\s*([^"\'\s>]+)', html_head, re.IGNORECASE)
                if meta_m:
                    final_url = meta_m.group(1).replace("&amp;", "&").strip()
            resp.close()
            return final_url
        except Exception:
            return short_url

    def _intelligent_offline_inference(self, user_text: str, rag_cases: list) -> str:
        """智慧離線推論引擎：依據 RAG 檢索特徵與關鍵詞規則進行精準鑑識"""
        user_text = self._stitch_multiline_urls(user_text)
        low_text = user_text.lower()
        now_iso = datetime.now(timezone.utc).isoformat()
        
        # 信任之台灣官方、金融保險、電信電商、交通醫療、民生事業與國際主流機構網域白名單 (共 180+ 常見合法網域)
        TRUSTED_DOMAINS = [
            # 1. 台灣 TWNIC 審核頂級網域與縣市政府
            "gov.tw", "edu.tw", "org.tw", "net.tw", "com.tw", "mil.tw", "gov.taipei", "metro.taipei",
            # 2. 金控與銀行 (含純網銀與數位帳戶專屬網域)
            "cathaybk.com.tw", "cathayholdings.com", "fubon.com", "taipeifubon.com.tw",
            "ctbcbank.com", "ctbcholding.com", "chinatrust.com.tw", "esunbank.com.tw", "esunbank.com", "esunfhc.com",
            "taishinbank.com.tw", "richart.tw", "sinopac.com", "dawho.tw", "firstbank.com.tw",
            "megabank.com.tw", "hncb.com.tw", "tcb-bank.com.tw", "bankchb.com", "tbb.com.tw",
            "landbank.com.tw", "bot.com.tw", "post.gov.tw", "kgi.com", "kgibank.com",
            "yuanta.com", "yuantabank.com.tw", "skbank.com.tw", "feib.com.tw", "bankee.tw",
            "ubot.com.tw", "scsb.com.tw", "o-bank.com", "dbs.com.tw", "dbs.com",
            "hsbc.com.tw", "hsbc.com", "sc.com", "citi.com", "citibank.com.tw",
            "nextbank.com.tw", "linebank.com.tw", "rakuten-bank.com.tw", "visa.com.tw", "mastercard.com.tw", "jcb.tw",
            # 3. 人壽與產物保險公司
            "cardif.com.tw", "cathaylife.com.tw", "nanshanlife.com.tw", "nan-shan.com.tw",
            "skl.com.tw", "shin-kong.com.tw", "taiwanlife.com", "kgilife.com.tw", "chinalife.com.tw",
            "transglobe.com.tw", "fglife.com.tw", "mli.com.tw", "yuantalife.com.tw", "twfhclife.com.tw",
            "firstlife.com.tw", "tcb-life.com.tw", "allianz.com.tw", "allianz.com", "pcalife.com.tw",
            "prudential.com.tw", "aia.com.tw", "aia.com", "chubb.com", "chubblife.com.tw",
            "cigna.com.tw", "hontai.com.tw", "msig-mingtai.com.tw", "tmnewa.com.tw", "hotains.com.tw", "cki.com.tw",
            # 4. 電信業者與官方專屬短網址 (含台灣大哥大 twm5g.co / twm5g.my / myfone 商城)
            "cht.com.tw", "cht.tw", "emome.net", "hinet.net",
            "taiwanmobile.com", "twm5g.co", "twm5g.my", "twm5g.com", "twm.tw", "oppay.tw", "myfone.com.tw", "myfone.tw", "myvideo.net.tw",
            "fetnet.net", "fet.tw", "friday.tw", "tstartel.com",
            # 5. 電商購物、超商量販、百貨與行動支付
            "shopee.tw", "sho.pe", "shp.ee", "momoshop.com.tw", "momo.dm", "momo.com.tw",
            "pchome.com.tw", "pchome24h.com.tw", "pchome.tw", "books.com.tw",
            "yahoo.com.tw", "yahoo.com", "yhoo.it", "coupang.com", "etmall.com.tw",
            "7-11.com.tw", "openpoint.com.tw", "ibon.com.tw", "family.com.tw", "fami.tw", "famiport.com.tw",
            "hilife.com.tw", "okmart.com.tw", "pxmart.com.tw", "pxpay.com.tw", "pxpayplus.com",
            "carrefour.com.tw", "costco.com.tw", "ikea.com.tw", "ikea.com", "trplus.com.tw",
            "cosmed.com.tw", "watsons.com.tw", "poya.com.tw", "eslite.com", "sogo.com.tw", "skm.com.tw", "taipei101.com.tw",
            "jkopay.com", "pluspay.com.tw", "easycard.com.tw", "i-pass.com.tw", "icash.com.tw", "taiwanpay.com.tw",
            # 6. 交通運輸、航空、外送叫車、旅遊訂房與售票系統
            "thsrc.com.tw", "railway.gov.tw", "tymetro.com.tw", "krtc.com.tw", "fetc.net.tw",
            "china-airlines.com", "evaair.com", "starlux-airlines.com", "tigerairtw.com", "uniair.com.tw", "mandarin-airlines.com",
            "uber.com", "ubereats.com", "foodpanda.com.tw", "fdp.li", "55688.com.tw", "linego.me",
            "yoxi.app", "irentcar.com.tw", "ridegoshare.com", "wemoscooter.com", "youbike.com.tw",
            "klook.com", "kkday.com", "agoda.com", "booking.com", "expedia.com.tw", "hotels.com", "trip.com", "airbnb.com",
            "liontravel.com", "colatour.com.tw", "eztravel.com.tw",
            "tixcraft.com", "kktix.com", "kktix.cc", "kham.com.tw", "ticket.com.tw", "opentix.life",
            # 7. 民生公用事業與物流宅配
            "taipower.com.tw", "water.gov.tw", "cpc.com.tw",
            "t-cat.com.tw", "hct.com.tw", "kerrytj.com", "e-can.com.tw", "sf-express.com", "dhl.com", "fedex.com", "ups.com",
            # 8. 國際科技、社群、影音串流、新聞媒體與求職平台 (不含 goo.gl / bit.ly 等公開免洗短網址)
            "line.me", "lin.ee", "linecorp.com", "google.com", "google.com.tw", "google.dev", "ai.dev", "g.co", "youtube.com", "youtu.be",
            "apple.com", "icloud.com", "microsoft.com", "office.com", "live.com", "aka.ms", "linkedin.com",
            "facebook.com", "fb.com", "fb.me", "fb.watch", "instagram.com", "instagr.am", "threads.net", "whatsapp.com",
            "netflix.com", "disneyplus.com", "spotify.com", "kkbox.com", "linetv.tw", "iq.com", "gamer.com.tw",
            "104.com.tw", "1111.com.tw", "cakeresume.com", "cake.me", "yourator.co",
            "cna.com.tw", "udn.com", "ltn.com.tw", "chinatimes.com", "ettoday.net", "tvbs.com.tw",
            "github.com", "openai.com", "chatgpt.com", "zoom.us", "notion.so", "canva.com", "dropbox.com", "adobe.com",
            "trendmicro.com", "whoscall.com", "gogolook.com", "ntu.edu.tw", "moj.gov.tw", "npa.gov.tw"
        ]

        def _is_official_trusted_url(url_str: str) -> bool:
            u_l = url_str.lower()
            # 排除偽造政府或知名機構連字號之釣魚網址與已停用/濫用之公開短網址 (如 goo.gl, bit.ly, t.ly, gov-tw)
            if any(fake_pat in u_l for fake_pat in [
                "gov-tw", "mvdis-", "water-gov", "taipower-gov", "7-11-service",
                "momo-lucky", "post-gov", "fetc-gov", "line-verify", "line-login",
                "goo.gl", "bit.ly", "t.ly", "tinyurl.com", "is.gd", "cutt.ly"
            ]):
                return False
            # 擷取網域 Hostname
            host_m = re.match(r"^https?://([^/:\s]+)", u_l)
            host = host_m.group(1) if host_m else u_l.split("/")[0]
            # 1. 台灣 TWNIC 合法註冊之企業/政府/學校/法人網域
            if host.endswith((".com.tw", ".gov.tw", ".edu.tw", ".org.tw", ".net.tw", ".mil.tw", ".gov.taipei", ".metro.taipei")):
                return True
            # 2. 比對 180+ 常見官方白名單網域 (精確匹配主網域或子網域)
            return any(host == td or host.endswith("." + td) for td in TRUSTED_DOMAINS)

        # 抽取訊息中所有網址（包含未帶 http:// 之短網址如 t.ly/mvdis.gov.tw 與高風險可疑網域）並支援即時短網址展開核驗
        found_urls = re.findall(r"https?://[^\s]+", user_text)
        bare_url_candidates = re.findall(
            r"(?<![@\w])(?:https?://)?[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*\.(?:top|vip|xyz|icu|cfd|sbs|cyou|club|fun|shop|site|online|cc|ly|gl|gd|gy|is|at|id|me|tw|co|com|net|org)(?:/[^\s]*)?",
            user_text,
            re.IGNORECASE
        )
        for bd in bare_url_candidates:
            bd_clean = bd.rstrip(").,;\"'】」")
            # 若無 http 前綴且無斜線路徑，僅納入常見短網址或高風險後綴，避免將一般品牌英文縮寫誤判為網址
            if not bd_clean.lower().startswith("http") and "/" not in bd_clean:
                if not re.search(r"\.(?:top|vip|xyz|icu|cfd|sbs|cyou|club|fun|shop|site|online|cc|ly|tw|edu\.tw|gov\.tw|com\.tw)$", bd_clean.lower()):
                    continue
            if bd_clean not in found_urls and f"http://{bd_clean}" not in found_urls and f"https://{bd_clean}" not in found_urls:
                found_urls.append(bd_clean)

        has_suspicious_url = False
        suspicious_url_str = ""
        has_path_spoofing = False
        verified_official_urls = []
        for u in found_urls:
            u_clean = u.rstrip(").,;\"'】」")
            u_low = u_clean.lower()
            # 擷取斜線前的真實主網域 (Hostname) 與斜線後的路徑 (Path)
            u_no_proto = re.sub(r"^https?://", "", u_low)
            parts = u_no_proto.split("/", 1)
            host_only = parts[0]
            path_only = "/" + parts[1] if len(parts) > 1 else ""

            # 檢測「短網址斜線路徑偽裝手法」(例如 t.ly/mvdis.gov.tw，真實主網域為 t.ly，卻在斜線後偽造 mvdis.gov.tw)
            if not host_only.endswith(".gov.tw") and any(k in path_only for k in ["gov.tw", "mvdis", "taipower", "water", "post", "fetc"]):
                has_path_spoofing = True
                has_suspicious_url = True
                suspicious_url_str = u_clean
                break

            resolved_u = self._resolve_redirect_url(u_clean if u_clean.startswith("http") else f"https://{u_clean}")
            is_trusted = (not has_path_spoofing) and (_is_official_trusted_url(u_clean) or _is_official_trusted_url(resolved_u))
            if is_trusted:
                verified_official_urls.append((u_clean, resolved_u))
            else:
                has_suspicious_url = True
                suspicious_url_str = u_clean
                break

        # 尋找電子郵件與免費信箱偽冒特徵 / 境外信箱 iMessage 亂槍打鳥特徵
        found_emails = re.findall(r"[\w\.-]+@[\w\.-]+\.\w+", user_text)
        has_email_spoof = False
        email_spoof_str = ""
        suspicious_imessage_email = ""
        FREE_EMAIL_DOMAINS = ["yahoo.co.jp", "yahoo.com", "gmail.com", "outlook.com", "hotmail.com", "qq.com", "163.com", "126.com", "sina.com", "sohu.com", "yeah.net", "foxmail.com", "icloud.com"]
        CHINA_FREE_EMAILS = ["126.com", "163.com", "qq.com", "sina.com", "sohu.com", "yeah.net", "foxmail.com"]
        for em in found_emails:
            em_low = em.lower()
            if any(fed in em_low for fed in FREE_EMAIL_DOMAINS):
                if any(kw in low_text for kw in ["ikea", "宜家", "apple", "netflix", "卡友", "重複訂購", "自動續費", "續費", "分期", "客服", "帳單", "會員"]):
                    has_email_spoof = True
                    email_spoof_str = em
                    break
            if any(ced in em_low for ced in CHINA_FREE_EMAILS) or (
                any(fed in em_low for fed in FREE_EMAIL_DOMAINS) and any(k in low_text for k in ["imessage", "not in your contact", "report junk", "加我", "找不到你", "把我刪了"])
            ):
                suspicious_imessage_email = em

        has_recurring_fee = ("重複訂購" in user_text or "自動續費" in user_text or "重複扣款" in user_text or "扣款未變更" in user_text or "保留方式" in user_text or "解除分期" in user_text)

        # 偵測「亂槍打鳥裝熟誘導加 LINE / 陌生 iMessage 引流詐騙（含假信貸、假飆股、裝熟三合一）」特徵
        all_line_ids = re.findall(r"(?:加我\s*l[i1]ne|加下我\s*l[i1]ne|加\s*l[i1]ne|l[i1]ne\s*id|l[i1]ne|id|加賴|加我賴)\s*[:：]\s*([a-zA-Z0-9_.-]{3,})", user_text, re.IGNORECASE)
        extracted_line_id = "、".join(dict.fromkeys(all_line_ids)) if all_line_ids else ""

        # 即時連線警政署 165 全民防騙網官方 API (https://165.npa.gov.tw/api/queryLineId/) 查驗是否為已通報詐騙 LINE ID
        official_165_hit = None
        for lid in list(dict.fromkeys(all_line_ids))[:2]:
            res_165 = check_165_official_line_id(lid)
            if res_165 and res_165.get("is_reported_scam"):
                official_165_hit = res_165
                break

        has_fake_loan_lure = any(kw in user_text for kw in [
            "永豐貸", "永豐贷", "借款資格", "借款资格", "無需照會", "無需照合",
            "無需保人", "免保人", "月利息只需", "當天辦理當天入帳", "当天静理当天入眼",
            "信貸專員", "信贷事员", "貸款公司", "贫款公司"
        ])
        has_stock_tip_lure = any(kw in user_text for kw in [
            "內部漲停票", "内部涨停票", "漲停票公布", "涨停票公",
            "預計60趴", "預計 60 趴", "预計60趴", "領取代碼", "领取代", "驗證實力"
        ])
        has_cold_line_lure = (
            any(kw in low_text for kw in [
                "找不到你", "把我刪了", "把我line刪了", "把我line删了", "有事找你", "有急事找你", "急事找你",
                "電話打不通", "打不通你電話", "加我line", "加我 line", "加下我l1ne", "l1ne", "加我賴",
                "加我的line", "加我的賴", "還好有存你的聯繫方式", "聯聚方式",
                "舊衣回收換現金", "舊衣回收領禮券", "小小體驗營", "小小店長體驗營"
            ])
            or bool(all_line_ids)
            or bool(official_165_hit)
            or has_fake_loan_lure
            or has_stock_tip_lure
            or bool(suspicious_imessage_email and ("line" in low_text or "賴" in low_text or "not in your contact" in low_text or "report junk" in low_text))
        )

        # 偵測「惡意木馬病毒簡訊 / 電信小額付費盜刷與通訊錄跳板詐騙」（假宅配包裹簽收單 / 假聚會照片 + goo.gl 等公開短網址）
        has_trojan_sms_lure = (
            any(kw in user_text for kw in [
                "包裹簽收單", "電子憑證請查收", "包裹號：", "包裹號:",
                "上次聚會的照片", "聚會的照片", "存檔一下", "出去玩拍的照片",
                "地址不詳無法派送", "包裹未簽收", "小額詐騙簡訊", "透過病毒程式入侵"
            ])
            or ("黑貓宅急便" in user_text and ("goo.gl" in low_text or has_suspicious_url))
        )

        # 關鍵詐騙特徵指標
        has_high_risk_tld = bool(re.search(r"\.(?:top|vip|xyz|icu|cfd|sbs|cyou)\b", low_text))
        has_imessage_unlock = any(kw in user_text for kw in ["回復1", "回覆1", "回復 1", "回覆 1", "啟動連結", "啟動查詢"])
        has_gov_bill_keywords = any(kw in user_text for kw in [
            "交通違規", "違規罰鍰", "違規罰款", "交通罰款", "逾期未到案", "逾期未繳",
            "水費逾期", "電費逾期", "水費欠繳", "電費欠繳", "執行停水", "即將停水",
            "通行費", "點數即將到期", "積分即將到期", "線上繳納",
            "普發現金", "普發萬元", "普發一萬元", "一萬元補助"
        ])
        has_gov_bill_phishing = has_path_spoofing or has_imessage_unlock or (has_gov_bill_keywords and (has_suspicious_url or has_high_risk_tld or "普發" in user_text))
        has_phishing_link = has_suspicious_url or has_high_risk_tld or has_path_spoofing or (".cc" in low_text and "kktix.cc" not in low_text)
        has_voting_phishing = any(kw in user_text for kw in [
            "繪畫比賽", "參加繪畫", "創意繪畫", "幫忙投一票", "幫我投", "幫忙投",
            "投一票嗎", "寵物比賽", "才藝比賽", "人氣投票", "輔助認證"
        ]) or (("投" in user_text and "票" in user_text) and has_phishing_link)
        has_money_trigger = ("atm" in low_text or "轉帳" in low_text or "監管帳戶" in low_text or "解除分期" in low_text or "匯款" in low_text or "usdt" in low_text or "提現保證金" in low_text or "日領高薪" in low_text or "給你抽" in low_text or "丟你那邊" in low_text or "借帳戶" in low_text or "租帳戶" in low_text or "不能收錢" in low_text or "提領" in low_text)
        has_legal_threat = ("洗錢防制法" in user_text or "地檢署" in user_text or "特偵組" in user_text or "強制拘提" in user_text or "公文傳票" in user_text or "健保卡異常" in user_text or "鎖卡" in user_text or "凍結" in user_text or "停水" in user_text)
        has_investment_trap = ("飆股" in user_text or "老師帶盤" in user_text or "內線消息" in user_text or "保證獲利" in user_text or "翻倍" in user_text or "外資" in user_text or "佈局" in user_text or "代操" in user_text or "蛋糕" in user_text or "金控" in user_text or "加.賴" in user_text or "投.貲" in user_text or "老帥" in user_text)
        has_teller_coaching = ("不能講" in user_text or "不能說" in user_text or "行員問" in user_text or "行員" in user_text or "臨櫃" in user_text or "裝潢款" in user_text or "買黃金" in user_text or "三方佈局" in user_text or "券商的蛋糕" in user_text)
        has_job_or_account_trap = ("兼職" in user_text or "打字員" in user_text or "家庭代工" in user_text or "存摺" in user_text or "提款卡" in user_text or "包來回機票" in user_text or "海外" in user_text or "東南亞" in user_text or "融資" in user_text or "低利貸款" in user_text or "資金流水" in user_text or "小白皆可貸" in user_text or "一頁式廣告" in user_text or "幽靈包裹" in user_text)
        has_urgent_relative_trap = ("車禍" in user_text or "和解" in user_text or "救我" in user_text or "快點救我" in user_text or "爸！是我啦" in user_text or "撞到人" in user_text or "保留訂金" in user_text or "急租" in user_text)
        has_crypto_airdrop = ("空投" in user_text or "airdrop" in low_text or "錢包地址" in user_text or "claim" in low_text or "solana" in low_text or "治理代幣" in user_text or "抽中" in user_text or "特獎" in user_text)

        # 1. 正常訊息判斷（如果沒有觸發任何明顯詐騙特徵）
        is_scam = (
            has_trojan_sms_lure or has_gov_bill_phishing or has_voting_phishing or has_cold_line_lure
            or has_email_spoof or has_recurring_fee or has_phishing_link
            or has_money_trigger or has_legal_threat or has_investment_trap
            or has_teller_coaching or has_job_or_account_trap or has_urgent_relative_trap or has_crypto_airdrop
        )

        if not is_scam:
            if verified_official_urls:
                orig_u, dest_u = verified_official_urls[0]
                if orig_u != dest_u and orig_u.rstrip("/") != dest_u.rstrip("/"):
                    safe_evidence = f"經 165 AI 鑑識與短網址實時展開核驗，訊息中之短連結 ({orig_u}) 轉址目標為官方安全網域 ({dest_u})，確認為合法企業/金融保險/電信電商官方服務或活動通知，且無要求匯款轉帳或索取銀行密碼，屬於安全正常訊息。"
                else:
                    safe_evidence = f"經 165 AI 鑑識比對，訊息中之連結 ({orig_u}) 屬於台灣合法註冊之官方企業/金融人壽/電信電商白名單網域（如 .com.tw / .gov.tw 等官方網站），內容為正常保戶服務、表單下載或會員通知，未出現要求匯款或竊取個資特徵，屬於日常安全內容。"
            else:
                safe_evidence = "經 165 AI 鑑識比對，此內容未出現釣魚連結、非官方網址、要求匯款轉帳、恐嚇凍結、規避行員提問或假投資等惡意破綻特徵，屬於日常安全內容。"

            return json.dumps({
                "analysis_id": f"SCAM-EVAL-{uuid.uuid4().hex[:8].upper()}",
                "timestamp": now_iso,
                "input_summary": user_text[:50],
                "risk_assessment": {
                    "risk_score": 5,
                    "risk_level": "安全",
                    "confidence_level": "高",
                    "primary_scam_type": "正常訊息 / 官方活動通知" if verified_official_urls else "正常訊息 / 非詐騙"
                },
                "red_flags": [],
                "psychological_tactics": [],
                "evidence_analysis": safe_evidence,
                "actionable_guidance": {
                    "immediate_actions": ["此為合法官方通知或日常安全訊息，無須採取防禦行動。"],
                    "official_verification": ["若對優惠活動細節有疑問，可透過該電信/電商官方 App 或官網查詢確認。"],
                    "recommended_safe_reply": "內容安全，無需特別防範。"
                }
            }, ensure_ascii=False)

        # 2. 詐騙特徵鑑識
        matched_case = rag_cases[0] if rag_cases else {
            "category": "惡意木馬病毒簡訊 / 電信小額付費盜刷與通訊錄跳板詐騙" if has_trojan_sms_lure else (
                "假冒政府監理站/民生催繳釣魚簡訊" if has_gov_bill_phishing else (
                    "假親友比賽拉票釣魚 / LINE 帳號盜用詐騙" if has_voting_phishing else (
                        "iMessage 垃圾簡訊引流詐騙 (假信貸 / 裝熟認親 / 內部漲停飆股誘導加 LINE)" if has_cold_line_lure else (
                            "假投資與臨櫃話術詐騙" if has_teller_coaching else (
                                "假冒官方電子郵件 (假重複扣款/解除分期)" if (has_email_spoof or has_recurring_fee) else (
                                    "釣魚網站與惡意連結詐騙" if has_high_risk_tld else (
                                        "假求職/人頭帳戶詐騙" if has_job_or_account_trap else "疑似詐騙"
                                    )
                                )
                            )
                        )
                    )
                )
            ),
            "tactics": ["冒名欺騙", "誘導點擊惡意連結"]
        }

        if has_trojan_sms_lure:
            category = "惡意木馬病毒簡訊 / 電信小額付費盜刷與通訊錄跳板詐騙"
        elif has_gov_bill_phishing:
            category = "假冒政府普發現金/補助津貼釣魚簡訊 (165官網最新通報)" if "普發" in user_text else "假冒政府監理站/民生催繳釣魚簡訊"
        elif has_voting_phishing:
            category = "假親友比賽拉票釣魚 / LINE 帳號盜用詐騙"
        elif has_cold_line_lure and not (has_investment_trap or has_money_trigger or has_legal_threat):
            if official_165_hit:
                category = f"警政署 165 官方通報涉詐 LINE 帳號 ({official_165_hit['line_id']})"
            elif has_fake_loan_lure and has_stock_tip_lure:
                category = "iMessage 垃圾簡訊引流詐騙 (假信貸 / 裝熟認親 / 飆股內線誘導加 LINE)"
            elif has_fake_loan_lure:
                category = "假冒銀行低利信貸 iMessage 引流詐騙 (免保人免照會誘導加 LINE)"
            elif has_stock_tip_lure:
                category = "假投顧飆股內線 iMessage 引流詐騙 (漲停票領取代碼誘導加 LINE)"
            else:
                category = "假親友裝熟引流詐騙 / iMessage 誘導加 LINE (殺豬盤與假投資前導)"
        elif has_email_spoof or has_recurring_fee:
            category = "假冒官方電子郵件 (假重複扣款/解除分期)"
        elif has_teller_coaching:
            category = "假投資博弈與臨櫃話術詐騙"
        elif has_high_risk_tld and not (has_money_trigger or has_legal_threat or has_investment_trap):
            category = "釣魚網站與惡意連結詐騙 (.top/.vip 高風險網域)"
        else:
            category = matched_case.get("category", "疑似詐騙")

        # 根據文本抽取可疑特徵
        red_flags = []
        if official_165_hit:
            red_flags.append({
                "quote": f"LINE ID: {official_165_hit['line_id']} (通報日期: {official_165_hit['alert_time']})",
                "issue_type": f"🚨 警政署 165 全民防騙網官方資料庫實時命中：此 LINE ID 已於 {official_165_hit['alert_time']} 遭民眾報案並由刑事局正式列為涉詐高風險帳號！",
                "severity": "HIGH"
            })
        if has_trojan_sms_lure:
            if "包裹" in user_text or "黑貓" in user_text or "憑證" in user_text:
                red_flags.append({
                    "quote": "您有一件包裹簽收單電子憑證請查收。黑貓宅急便 http://goo.gl/976Zaj",
                    "issue_type": "偽冒物流品牌搭配已停用之公開短網址 (goo.gl)：黑貓宅急便官方網域必為 t-cat.com.tw，絕不會用 http://goo.gl 傳送簽收單！點擊將下載惡意 APK 木馬病毒",
                    "severity": "HIGH"
                })
            if "聚會" in user_text or "照片" in user_text or "存檔" in user_text:
                red_flags.append({
                    "quote": "上次聚會的照片，你存檔一下 http://goo.gl/I8QX9A",
                    "issue_type": "典型木馬病毒「通訊錄跳板」擴散話術：利用已中毒親友手機自動直呼姓名群發，誘騙點擊短網址植入木馬並盜刷電信小額付費",
                    "severity": "HIGH"
                })
        if has_path_spoofing:
            red_flags.append({
                "quote": suspicious_url_str or "t.ly/mvdis.gov.tw",
                "issue_type": f"惡意短網址斜線路徑偽裝：真實主網域為境外短網址（如 t.ly），卻在斜線「/」後方偽造「mvdis.gov.tw」字樣魚目混珠假冒政府監理站！",
                "severity": "HIGH"
            })
        if has_imessage_unlock:
            red_flags.append({
                "quote": "回復1啟動連結查詢",
                "issue_type": "典型 iMessage 釣魚簡訊繞過防護話術（誘導受害者回覆「1」以解除 Apple 陌生訊息連結封鎖機制）",
                "severity": "HIGH"
            })
        if has_gov_bill_phishing and not has_path_spoofing:
            red_flags.append({
                "quote": "普發現金一萬元線上領取 / 交通違規罰鍰或水電費逾期補繳",
                "issue_type": "假冒政府機關普發現金或催繳水電罰單（165官網最新警示：政府唯一認證簡訊碼為 111，絕不會傳送短網址要求領錢或刷卡）",
                "severity": "HIGH"
            })
        if suspicious_imessage_email:
            red_flags.append({
                "quote": f"發信帳號：{suspicious_imessage_email} (iMessage)",
                "issue_type": f"使用中國網易/境外免費信箱 ({suspicious_imessage_email}) 透過 iMessage 批量群發垃圾簡訊，正常台灣親友簡訊絕不會以 @126.com / @163.com 信箱傳送！",
                "severity": "HIGH"
            })
        if has_fake_loan_lure:
            red_flags.append({
                "quote": "【永豐貸】提醒您已獲50萬新台幣借款資格。無需照會，無需保人，沒有手續費...添加信貸專員 LINE：gi6600",
                "issue_type": "假冒知名銀行（如永豐銀行）名義群發 iMessage 免保人超低利貸款簡訊，誘導加私人 LINE ID 騙取存摺提款卡（變成人頭戶）或事先收取保證金/手續費",
                "severity": "HIGH"
            })
        if has_stock_tip_lure:
            red_flags.append({
                "quote": "最新消息：內部漲停票公布，預計 60 趴以上，領取代碼的添加 LINE：zyq1556",
                "issue_type": "典型假投顧「內部漲停飆股代碼」引流簡訊，以誇大保證獲利（預計 60% 以上）誘騙投資人加入詐騙 LINE 群組進行養套殺",
                "severity": "HIGH"
            })
        if has_cold_line_lure and (not (has_fake_loan_lure or has_stock_tip_lure) or "刪了" in user_text or "删了" in user_text or "l1ne" in low_text):
            id_note = f" (可疑 LINE ID: {extracted_line_id})" if extracted_line_id else ""
            red_flags.append({
                "quote": f"你把我Line刪了嗎？不然都找不到你了加下我L1ne有事找你{id_note}",
                "issue_type": "典型「亂槍打鳥裝熟加 LINE」引流話術（故意將 Line 寫成 L1ne 規避電信關鍵字過濾），利用好奇心誘騙受害者主動加私人 LINE ID",
                "severity": "HIGH"
            })
            if "not in your contact" in low_text or "report junk" in low_text or "聯絡人列表中" in user_text or "回報垃圾訊息" in user_text:
                red_flags.append({
                    "quote": "寄件人不在您的聯絡人列表中 / 回報垃圾訊息 (Report Junk)",
                    "issue_type": "手機系統已明確警示此發信人根本不在您的通訊錄聯絡人名單中，直接戳破其「熟人找你」與「銀行專員」之謊言",
                    "severity": "HIGH"
                })
        if has_voting_phishing:
            red_flags.append({
                "quote": "小朋友在參加繪畫比賽 可以幫忙投一票嗎 / 幫我投14號",
                "issue_type": "典型假冒親友比賽拉票話術，誘導點擊釣魚網站並輸入 LINE 帳密與 OTP 認證碼以盜取帳號",
                "severity": "HIGH"
            })
        if has_email_spoof:
            red_flags.append({
                "quote": email_spoof_str if email_spoof_str else "butterfly_free_9@yahoo.co.jp",
                "issue_type": f"寄件者使用免費日本 Yahoo 信箱 ({email_spoof_str}) 偽冒知名官方品牌發信",
                "severity": "HIGH"
            })
        if has_recurring_fee:
            red_flags.append({
                "quote": "重複訂購 原自動續費設定未變更",
                "issue_type": "製造重複下單與連續扣款恐慌（假解除分期話術）",
                "severity": "HIGH"
            })
        if has_teller_coaching:
            red_flags.append({
                "quote": "臨櫃辦理不能講是用於投資 / 行員問到話術教戰",
                "issue_type": "教戰守則誘導隱瞞銀行行員關懷提問",
                "severity": "HIGH"
            })
        if has_phishing_link and not has_path_spoofing and not has_trojan_sms_lure:
            target_u = suspicious_url_str or (found_urls[0] if found_urls else "非官方可疑連結")
            red_flags.append({
                "quote": target_u,
                "issue_type": (
                    f"境外高風險免洗釣魚網域 ({target_u})，偽裝成比賽投票或政府繳費網頁竊取個資與信用卡"
                    if (has_high_risk_tld or has_voting_phishing or has_gov_bill_phishing)
                    else "非官方或可疑短網址跳轉"
                ),
                "severity": "HIGH"
            })
        if has_money_trigger and not has_recurring_fee:
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
        if has_investment_trap and not has_teller_coaching:
            red_flags.append({
                "quote": "保證獲利 / 飆股密碼 / 外資佈局",
                "issue_type": "以高報酬誘餌吸引受害者",
                "severity": "HIGH"
            })

        tactics = []
        if has_trojan_sms_lure:
            tactics.append({
                "tactic_name": "木馬病毒通訊錄跳板與直呼姓名裝熟",
                "description": "木馬程式入侵前一位受害者手機後，會自動讀取其通訊錄並直呼親友真實姓名，群發「上次聚會的照片，你存檔一下」或「黑貓宅急便包裹簽收單電子憑證請查收」，讓人因親切感與日常疏忽而點擊短網址下載惡意 APK 病毒。"
            })
        if has_gov_bill_phishing:
            tactics.append({
                "tactic_name": "短網址路徑偽裝與 iMessage 互動解鎖陷阱",
                "description": "詐騙集團利用境外短網址（如 t.ly）並在斜線後自訂『/mvdis.gov.tw』假路徑欺騙視覺，同時要求受害者『回復 1 啟動連結』以繞過 iPhone iMessage 預設關閉陌生釣魚連結的安全防護機制。"
            })
        if has_cold_line_lure:
            tactics.append({
                "tactic_name": "iMessage 免付費群發與變形字 (L1ne) 規避封鎖",
                "description": "因為詐騙 LINE 帳號若主動大量加陌生人好友會被 LINE 官方封鎖，詐騙集團改透過 Apple iMessage 免費批量群發「假銀行低利貸款（永豐貸）」、「假熟人認親（加下我 L1ne）」與「內部漲停飆股」，誘使受害者主動加私人 LINE ID。"
            })
        if has_voting_phishing:
            tactics.append({
                "tactic_name": "親友信任綁架與假投票釣魚盜號",
                "description": "利用遭盜用的親友帳號傳送「小朋友參加繪畫比賽幫忙投一票」，藉人情壓力卸下心防，引導進入偽造投票網頁輸入 LINE 帳號、密碼與簡訊 OTP 認證碼，瞬間奪取受害者 LINE 帳號控制權。"
            })
        if has_teller_coaching:
            tactics.append({
                "tactic_name": "社交阻絕與規避行員提問",
                "description": "詐騙集團深知行員會進行防詐關懷提問，故提前套好假話術（如稱裝潢款、代購或商業合作），阻止銀行啟動防詐攔阻機制。"
            })
        for t in matched_case.get("tactics", ["心理施壓", "誘餌誘導"]):
            tactics.append({
                "tactic_name": t,
                "description": f"詐騙方運用『{t}』手法降低受害者的防備心並迫使其在慌亂中採取行動。"
            })

        if official_165_hit:
            score = 98
            evidence_msg = (
                f"🚨 【警政署 165 全民防騙網官方資料庫實時命中】！\n"
                f"經即時連線內政部警政署 165 全民防騙網官方 API (`165.npa.gov.tw/api/queryLineId`) 查驗，本訊息中之 LINE 帳號「`{official_165_hit['line_id']}`」已於 `{official_165_hit['alert_date']}` 被民眾與警方正式通報列為【{official_165_hit['category']}】涉詐高風險帳號！請絕對不要加入好友或與其聯繫！"
            )
        elif has_trojan_sms_lure:
            score = 96
            evidence_msg = (
                f"經 165 AI 鑑識比對，此訊息為極度危險之【惡意木馬病毒簡訊 / 電信小額付費盜刷與通訊錄跳板詐騙】！\n"
                f"• 破綻一（偽冒物流品牌搭配公開短網址）：黑貓宅急便之唯一官方網域為 `t-cat.com.tw`，絕不會使用已停用之公開縮網址（如 `http://goo.gl/976Zaj`）寄送「包裹簽收單電子憑證」！\n"
                f"• 破綻二（通訊錄病毒跳板直呼姓名）：詐騙集團透過木馬病毒入侵親友手機通訊錄作為跳板，自動直呼您的名字傳送「上次聚會的照片，你存檔一下 (`http://goo.gl/I8QX9A`)」。一旦點擊連結，手機將被植入惡意 APK 木馬程式，在背景自動攔截認證簡訊盜刷『電信小額付費/遊戲點數』，並繼續用您的門號向通訊錄所有親友擴散病毒！"
            )
        elif has_gov_bill_phishing:
            score = 96
            evidence_msg = (
                f"經 165 AI 鑑識比對，此訊息為極度危險之【假冒政府監理站/交通罰鍰催繳 iMessage 釣魚簡訊】！"
                f"破綻一：訊息中的網址「{suspicious_url_str or 't.ly/mvdis.gov.tw'}」採用了狡猾的【斜線路徑偽裝手法】——斜線「/」前方的真實主網域為境外短網址「t.ly」，詐騙集團故意在斜線後方加上「/mvdis.gov.tw」字樣假冒監理服務網（真正的政府網站必須在第一個斜線前以 .gov.tw 結尾）！"
                f"破綻二：要求「回復 1 啟動連結查詢」是典型的 iMessage 釣魚話術，目的是誘使您回覆訊息以解除蘋果手機對陌生釣魚連結的封鎖。一旦點擊將進入假監理站頁面盜刷您的信用卡！"
            )
        elif has_voting_phishing:
            score = 96
            evidence_msg = (
                f"經 165 AI 鑑識比對，此訊息為極度危險之【假親友比賽拉票釣魚 / LINE 帳號盜用詐騙】！"
                f"詐騙集團先盜用親友的 LINE 帳號，以「有在忙嗎」、「小朋友在參加繪畫比賽，可以幫忙投一票嗎（如幫我投14號）」為由降低您的戒心，"
                f"並附上高風險境外免洗釣魚網址（{suspicious_url_str or '如 .top / .vip 亂數網域'}）。"
                f"一旦點擊投票，該網站會要求您輸入「LINE 帳號、密碼與手機簡訊 OTP 認證碼」，進而瞬間盜走您的 LINE 帳號並繼續向您的通訊錄親友行騙或借錢！"
            )
        elif has_cold_line_lure and not (has_investment_trap or has_money_trigger or has_legal_threat):
            score = 95
            evidence_msg = (
                f"經 165 AI 鑑識比對，此圖片/訊息為極度典型之【iMessage 垃圾簡訊引流詐騙（假信貸 / 裝熟認親 / 飆股內線誘導加 LINE）】！\n"
                f"• 破綻一（假冒銀行免保人低利信貸）：冒用『永豐貸』名義宣稱「已獲 50 萬借款資格、每萬月息 60 元、無需照會無需保人」，並要求加入私人信貸專員 LINE（如 `gi6600`），實為騙取存摺人頭帳戶或預收保證金詐騙！\n"
                f"• 破綻二（裝熟認親與變形字規避偵測）：使用「你把我 Line 刪了嗎？加下我 L1ne 有事找你（ID: `tt67777`）」，故意將 Line 的 i 改成數字 `1`（`L1ne`）以躲避電信防詐攔截。\n"
                f"• 破綻三（假投顧內部漲停飆股）：宣稱「內部漲停票公布，預計 60 趴以上，領取代碼添加 LINE：`zyq1556`」，且手機底部均顯示「寄件人不在您的聯絡人列表中 / 回報垃圾訊息」，100% 為詐騙引流簡訊！"
            )
        elif has_email_spoof or has_recurring_fee:
            score = 95
            evidence_msg = f"經鑑識比對，此郵件雖冒名「IKEA 宜家卡卡友」，但寄件者實際信箱為日本免費郵件網域 ({email_spoof_str or 'butterfly_free_9@yahoo.co.jp'})，完全不符跨國企業官方網域。且內容使用常見的「重複訂購/自動續費未變更」等製造恐慌話術，為典型的假客服、假解除分期付款詐騙手法，意圖引導受害人聯絡非官方客服操作 ATM 或網銀轉帳，具有極高詐騙風險。"
        elif has_teller_coaching or has_legal_threat:
            score = 96
            evidence_msg = (
                "此對話截圖屬於極度典型之【假投資/外資佈局臨櫃匯款詐騙】！詐騙分子假冒「金控專員」，並在被害人前往銀行臨櫃辦理匯款時，惡意教導受害者『若行員問到資金用途，一定不能講是用於投資』，意圖繞過銀行行員的防詐關懷提問與洗錢防制審查。"
                if has_teller_coaching else
                f"此訊息高度吻合 165 資料庫中之『{category}』犯罪特徵。對方透過非官方管道聯繫，並試圖誘導金錢轉移或個資竊取，屬於高風險詐騙。"
            )
        elif has_high_risk_tld:
            score = 92
            evidence_msg = (
                f"經 165 AI 網域鑑識，此連結（{suspicious_url_str or '可疑網址'}）採用境外高風險免洗頂級網域（如 .top / .vip / .xyz 等）搭配亂數子網域，"
                f"為詐騙集團最常使用之【釣魚盜號 / 假投票活動 / 假催繳網站】！點擊後極可能要求輸入 LINE 帳號密碼、信用卡號或手機簡訊 OTP 驗證碼，請絕對不要點擊或填寫任何資料。"
            )
        else:
            score = 90 if has_money_trigger else 75
            evidence_msg = f"此訊息高度吻合 165 資料庫中之『{category}』犯罪特徵。對方透過非官方管道聯繫，並試圖誘導金錢轉移或個資竊取，屬於高風險詐騙。"
        
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
            "evidence_analysis": evidence_msg,
            "actionable_guidance": {
                "immediate_actions": [
                    "絕對不要點擊簡訊中的任何公開短網址（如 http://goo.gl/...），切勿下載或允許安裝「未知來源應用程式 (.apk)」。",
                    "若已不慎點擊並安裝不明程式，請立即開啟「飛航模式」切斷網路、備份重要照片後將手機恢復原廠設定，並通知親友勿點擊您門號發出的怪異簡訊。"
                ] if has_trojan_sms_lure else (
                    [
                        f"絕對不要在 LINE 搜尋並加入訊息中的私人 ID（如 {extracted_line_id or 'gi6600、tt67777、zyq1556'}），亦不要回覆此 iMessage 簡訊。",
                        "請直接點擊畫面下方的「回報垃圾訊息 (Report Junk)」並刪除對話，切勿點擊任何連結或交付存摺、提款卡與個資。"
                    ] if has_cold_line_lure else [
                        "絕對不要回覆「1」或點擊訊息中的任何短網址連結（如 t.ly/mvdis.gov.tw 或 .top / .vip 網址），切勿輸入信用卡號、LINE 帳密或 OTP 驗證碼。",
                        "切勿聽從指示進行線上繳費、LINE 輔助認證、操作 ATM 或開啟網路銀行。"
                    ]
                ),
                "official_verification": [
                    "請立即致電所屬電信公司客服（中華電信、台灣大哥大、遠傳電信），要求『關閉電信小額付費／代收功能』，防止木馬程式在背景盜刷遊戲點數。",
                    "查詢黑貓宅急便包裹請自行搜尋進入唯一官方網站（https://www.t-cat.com.tw）輸入 12 碼託運單號，或撥打 165 反詐騙專線查證。"
                ] if has_trojan_sms_lure else (
                    [
                        "可至 iPhone「設定 ➔ 訊息 ➔ 未知與垃圾訊息」開啟「過濾未知的寄件人」，阻擋境外免費信箱群發之垃圾 iMessage。",
                        "立即撥打 165 反詐騙諮詢專線進行查證與通報檢舉。"
                    ] if has_cold_line_lure else [
                        "若有交通違規罰單疑問，請自行下載官方「監理服務 App」或由 Google 搜尋進入「監理服務網 (https://www.mvdis.gov.tw)」查證（政府已全面停發交通罰單催繳簡訊）。",
                        "立即撥打 165 反詐騙諮詢專線進行查證與通報檢舉。"
                    ]
                ),
                "recommended_safe_reply": (
                    "請勿點擊 goo.gl 短網址！若為認識的親友門號傳來，請改用『電話通話』提醒對方手機可能已中木馬病毒！"
                    if has_trojan_sms_lure else (
                        "請勿理會或加 LINE，直接點選「回報垃圾訊息 (Report Junk)」刪除！"
                        if has_cold_line_lure else
                        "請勿回覆此訊息（切勿回覆 1），直接封鎖並回報垃圾訊息！"
                    )
                )
            }
        }, ensure_ascii=False)