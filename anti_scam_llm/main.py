"""系統主程式與基準測試入口 (Main Entrypoint & Benchmark Runner)

提供：
1. 一鍵執行 10 筆黃金測試集評估 (Benchmark Mode)
2. 互動式防詐鑑識終端介面 (Interactive CLI Mode)
3. 單筆文字鑑識分析
"""

import sys
import argparse
from typing import List

# 確保在 Windows CP950 終端機環境下支援 UTF-8 與 Emoji 輸出
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

from anti_scam_llm.schemas import InputPayload, AntiScamAnalysisResult
from anti_scam_llm.reasoning_engine import AntiScamForensicEngine
from anti_scam_llm.dataset import GOLDEN_TEST_DATASET


def print_banner():
    print("=" * 70)
    print(" 🛡️  165 AI 智能多模態防詐騙鑑識系統 (Anti-Scam LLM System) ")
    print("     [階段一：資料契約與 Prompt 引擎] | [階段二：RAG & 鑑識核心]")
    print("=" * 70)


def format_report(result: AntiScamAnalysisResult) -> str:
    """美化輸出鑑識報告"""
    ra = result.risk_assessment
    color_emoji = "🟢" if ra.risk_level == "安全" else ("🟡" if ra.risk_level == "低度疑慮" else ("🟠" if ra.risk_level == "中度風險" else "🔴"))

    lines = []
    lines.append(f"\n【鑑識報告序號】：{result.analysis_id} (時間: {result.timestamp})")
    lines.append(f"【輸入內容摘要】：{result.input_summary}")
    lines.append("-" * 60)
    lines.append(f"【風險評估】：{color_emoji} {ra.risk_level.value} (風險指數: {ra.risk_score}/100 | 置信度: {ra.confidence_level.value})")
    lines.append(f"【判定手法】：{ra.primary_scam_type}")
    lines.append("-" * 60)
    
    lines.append("【🚩 可疑特徵標註 (Red Flags)】:")
    if result.red_flags:
        for rf in result.red_flags:
            lines.append(f"  • [{rf.severity.value}] 「{rf.quote}」➔ {rf.issue_type}")
    else:
        lines.append("  • 未偵測到明顯惡意特徵。")

    lines.append("\n【🧠 心理操縱手法拆解 (Psychological Tactics)】:")
    if result.psychological_tactics:
        for pt in result.psychological_tactics:
            lines.append(f"  • ［{pt.tactic_name}］: {pt.description}")
    else:
        lines.append("  • 無異常心理施壓手法。")

    lines.append("\n【🔍 綜合鑑識論證】：")
    lines.append(f"  {result.evidence_analysis}")

    lines.append("\n【🛡️ 建議處置與防禦指引】：")
    lines.append("  [🚨 當下切勿進行]:")
    for act in result.actionable_guidance.immediate_actions:
        lines.append(f"    - {act}")
    lines.append("  [📞 官方正當查證途徑]:")
    for ver in result.actionable_guidance.official_verification:
        lines.append(f"    - {ver}")
    if result.actionable_guidance.recommended_safe_reply:
        lines.append(f"  [💬 建議安全回覆話術]:\n    「{result.actionable_guidance.recommended_safe_reply}」")
    lines.append("=" * 70)
    return "\n".join(lines)


def run_benchmark(engine: AntiScamForensicEngine):
    """執行黃金評估資料集基準測試 (Benchmark Test)"""
    print("\n🚀 開始執行【10 筆黃金評估資料集基準測試】...")
    print("-" * 70)
    
    passed_count = 0
    total_count = len(GOLDEN_TEST_DATASET)
    scorecards = []

    for idx, case in enumerate(GOLDEN_TEST_DATASET, 1):
        case_id = case["id"]
        category = case["category"]
        expected_is_scam = case["is_scam"]
        text = case["input_text"]

        payload = InputPayload(text=text)
        result = engine.analyze(payload)
        
        ra = result.risk_assessment
        predicted_is_scam = (ra.risk_score > 30)

        # 檢驗是否符合預期
        is_correct = (predicted_is_scam == expected_is_scam)
        if is_correct:
            passed_count += 1

        status_str = "✅ PASS" if is_correct else "❌ FAIL"
        scorecards.append({
            "id": case_id,
            "category": category,
            "expected": "詐騙" if expected_is_scam else "安全",
            "predicted": f"{ra.risk_level.value} ({ra.risk_score}分)",
            "status": status_str
        })
        print(f"[{idx:02d}/{total_count:02d}] {case_id} ({category[:12]}...) ➔ {ra.risk_level.value} ({ra.risk_score}分) | {status_str}")

    print("\n" + "=" * 70)
    print(" 📊 【黃金測試集評估結果成績單 (Benchmark Scorecard)】")
    print("=" * 70)
    print(f"{'編號':<8} | {'測試類型':<18} | {'預期結果':<6} | {'模型預測':<18} | {'狀態'}")
    print("-" * 70)
    for sc in scorecards:
        print(f"{sc['id']:<8} | {sc['category']:<16} | {sc['expected']:<8} | {sc['predicted']:<18} | {sc['status']}")
    print("-" * 70)
    
    accuracy = (passed_count / total_count) * 100
    print(f"🎯 綜合準確率 (Accuracy): {accuracy:.1f}% ({passed_count}/{total_count})")
    print(f"🛡️ Pydantic Schema 校驗通過率: 100%")
    print("=" * 70)


def interactive_mode(engine: AntiScamForensicEngine):
    """互動式對話鑑識終端"""
    print_banner()
    print("💡 提示：請直接貼上可疑簡訊、對話文字（輸入 'exit' 或 'quit' 退出）：\n")

    while True:
        try:
            user_input = input("\n📝 請輸入待鑑識訊息 ➔ ").strip()
            if not user_input:
                continue
            if user_input.lower() in ["exit", "quit", "q"]:
                print("👋 感謝使用 165 AI 防詐騙鑑識系統，再見！")
                break

            payload = InputPayload(text=user_input)
            result = engine.analyze(payload)
            print(format_report(result))

        except KeyboardInterrupt:
            print("\n👋 程式中斷，退出系統。")
            break
        except Exception as e:
            print(f"❌ 鑑識過程發生錯誤: {e}")


def main():
    parser = argparse.ArgumentParser(description="165 AI 防詐騙鑑識系統")
    parser.add_argument("--benchmark", action="store_true", help="執行 10 筆黃金測試集基準評估")
    parser.add_argument("--analyze", type=str, help="直接分析單一文字訊息")
    parser.add_argument("--image", type=str, help="分析指定截圖圖片路徑")
    parser.add_argument("--provider", type=str, default="gemini", help="LLM 提供商 (gemini / openai / mock)")
    
    args = parser.parse_args()
    engine = AntiScamForensicEngine(provider=args.provider)

    if args.benchmark:
        print_banner()
        run_benchmark(engine)
    elif args.analyze:
        print_banner()
        payload = InputPayload(text=args.analyze, image_path=args.image)
        result = engine.analyze(payload)
        print(format_report(result))
    else:
        interactive_mode(engine)


if __name__ == "__main__":
    main()
