"""
165 AI 防詐大模型 - 權重合併與 GGUF/Ollama 匯出工具 (export_model.py)

功能：
1. 將訓練完成的 LoRA Adapter 權重與基底模型完整合併 (Merge & Unload)
2. 匯出為獨立的完整模型檔案 (支援 FP16 / BF16)
3. 產生 Ollama Modelfile 與 llama.cpp GGUF 量化轉換指引，便於離線邊緣推論
"""

import os
import sys
import torch

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
ADAPTER_PATH = os.path.join(CURRENT_DIR, "outputs", "165-lora-adapter")
MERGED_OUTPUT_DIR = os.path.join(CURRENT_DIR, "outputs", "165-anti-scam-merged-model")


def merge_and_export(
    base_model_name: str = "Qwen/Qwen2.5-7B-Instruct",
    adapter_path: str = ADAPTER_PATH,
    output_dir: str = MERGED_OUTPUT_DIR
):
    print("=" * 65)
    print("       165 AI 防詐大模型 - LoRA 權重合併與匯出工具")
    print("=" * 65)

    if not os.path.exists(adapter_path):
        print(f"❌ 找不到 LoRA Adapter: {adapter_path}")
        print("請先執行 train_lora.py 完成訓練後再執行合併。")
        return

    try:
        from transformers import AutoModelForCausalLM, AutoTokenizer
        from peft import PeftModel
    except ImportError:
        print("❌ 請安裝必要套件: pip install transformers peft torch")
        return

    print(f"📦 正在載入原生基底模型: {base_model_name}...")
    tokenizer = AutoTokenizer.from_pretrained(base_model_name, trust_remote_code=True)
    base_model = AutoModelForCausalLM.from_pretrained(
        base_model_name,
        torch_dtype=torch.float16,
        device_map="auto",
        trust_remote_code=True
    )

    print(f"🔗 正在載入 LoRA Adapter 並執行權重融合: {adapter_path}...")
    model = PeftModel.from_pretrained(base_model, adapter_path)
    merged_model = model.merge_and_unload()

    print(f"💾 正在儲存合併後的完整模型至: {output_dir}...")
    os.makedirs(output_dir, exist_ok=True)
    merged_model.save_pretrained(output_dir)
    tokenizer.save_pretrained(output_dir)

    # 產生 Ollama Modelfile
    modelfile_content = f"""FROM {output_dir}
TEMPLATE \"\"\"<|im_start|>system
你是由中華民國警政署 165 反詐騙諮詢專線標準所訓練的「165 AI 智能防詐鑑識專家」。請精確剖析輸入內容並輸出標準 JSON 鑑識報告。<|im_end|>
<|im_start|>user
{{{{ .Prompt }}}}<|im_end|>
<|im_start|>assistant
\"\"\"
PARAMETER temperature 0.2
PARAMETER top_p 0.95
PARAMETER stop "<|im_end|>"
"""
    modelfile_path = os.path.join(output_dir, "Modelfile")
    with open(modelfile_path, "w", encoding="utf-8") as f:
        f.write(modelfile_content)

    print("=" * 65)
    print("🎉 權重合併與匯出完成！")
    print(f"📁 完整模型儲存路徑: {output_dir}")
    print(f"📁 Ollama Modelfile : {modelfile_path}")
    print("\n💡 提示：您可以使用 Ollama 執行以下指令將其註冊為本地離線防詐模型：")
    print(f"   ollama create 165-anti-scam -f {modelfile_path}")
    print(f"   ollama run 165-anti-scam")
    print("=" * 65)


if __name__ == "__main__":
    merge_and_export()