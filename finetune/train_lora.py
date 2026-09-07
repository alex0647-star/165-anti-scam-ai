"""
165 AI 防詐大模型 - LoRA / QLoRA 領域微調訓練腳本 (train_lora.py)

功能：
1. 支援 Hugging Face transformers + peft + trl SFTTrainer
2. 支援 4-bit QLoRA 低顯存微調 (可在 6GB~8GB GPU 或 Colab T4 16GB 運行)
3. 自動載入 data/train_alpaca.jsonl 資料集並進行指令對齊微調
4. 儲存微調權重 (LoRA Adapter) 至 outputs/165-lora-adapter
"""

import os
import sys
import json
import torch
from dataclasses import dataclass, field
from typing import Optional

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

# 專案路徑設定
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
DATA_PATH = os.path.join(PROJECT_ROOT, "data", "train_alpaca.jsonl")
OUTPUT_DIR = os.path.join(CURRENT_DIR, "outputs", "165-lora-adapter")


def check_environment():
    """檢查 GPU 與相依套件環境"""
    print("=" * 60)
    print("  165 AI 防詐大模型 - LoRA/QLoRA 訓練環境檢查")
    print("=" * 60)
    print(f"PyTorch 版本: {torch.__version__}")
    cuda_available = torch.cuda.is_available()
    print(f"CUDA GPU 可用: {cuda_available}")
    if cuda_available:
        print(f"GPU 型號: {torch.cuda.get_device_name(0)}")
        print(f"GPU 顯存: {torch.cuda.get_device_properties(0).total_memory / (1024**3):.2f} GB")
    else:
        print("⚠️ 提示：未偵測到 CUDA GPU。在 CPU 上訓練速度較慢，建議使用 Google Colab 免費 GPU 進行訓練。")
    print("=" * 60)
    return cuda_available


def train(
    base_model_name: str = "Qwen/Qwen2.5-7B-Instruct",
    data_path: str = DATA_PATH,
    output_dir: str = OUTPUT_DIR,
    num_epochs: int = 3,
    batch_size: int = 2,
    gradient_accumulation_steps: int = 4,
    learning_rate: float = 2e-4,
    lora_r: int = 16,
    lora_alpha: int = 32,
    lora_dropout: float = 0.05,
    max_seq_length: int = 1024
):
    """執行 LoRA 微調流程"""
    cuda_available = check_environment()

    if not os.path.exists(data_path):
        print(f"❌ 錯誤：找不到訓練資料集 {data_path}，請先執行 dataset_generator.py 產生資料。")
        return

    try:
        from datasets import load_dataset
        from transformers import (
            AutoModelForCausalLM,
            AutoTokenizer,
            TrainingArguments,
            BitsAndBytesConfig
        )
        from peft import LoraConfig, get_peft_model, TaskType, prepare_model_for_kbit_training
        from trl import SFTTrainer
    except ImportError:
        print("\n❌ 缺少訓練必要套件。請執行以下指令安裝：")
        print("pip install transformers peft trl datasets bitsandbytes accelerate")
        return

    print(f"\n📦 正在載入訓練資料集: {data_path}")
    dataset = load_dataset("json", data_files=data_path, split="train")
    print(f"✅ 資料集載入完成，共 {len(dataset)} 筆訓練樣本。")

    # 4-bit 量化設定 (QLoRA)
    bnb_config = None
    if cuda_available:
        bnb_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.bfloat16 if torch.cuda.is_bf16_supported() else torch.float16,
            bnb_4bit_use_double_quant=True
        )

    print(f"\n🤖 正在載入基底模型: {base_model_name}")
    tokenizer = AutoTokenizer.from_pretrained(base_model_name, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    device_map = "auto" if cuda_available else "cpu"
    model = AutoModelForCausalLM.from_pretrained(
        base_model_name,
        quantization_config=bnb_config if cuda_available else None,
        device_map=device_map,
        trust_remote_code=True,
        torch_dtype=torch.float16 if cuda_available else torch.float32
    )

    if cuda_available:
        model = prepare_model_for_kbit_training(model)

    # 設定 LoRA 參數
    lora_config = LoraConfig(
        r=lora_r,
        lora_alpha=lora_alpha,
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
        lora_dropout=lora_dropout,
        bias="none",
        task_type=TaskType.CAUSAL_LM
    )

    model = get_peft_model(model, lora_config)
    model.print_trainable_parameters()

    # 格式化 Prompt 函數
    def formatting_prompts_func(example):
        output_texts = []
        for i in range(len(example["instruction"])):
            text = (
                f"<|im_start|>system\n{example['instruction'][i]}<|im_end|>\n"
                f"<|im_start|>user\n{example['input'][i]}<|im_end|>\n"
                f"<|im_start|>assistant\n{example['output'][i]}<|im_end|>"
            )
            output_texts.append(text)
        return output_texts

    # 訓練超參數設定
    training_args = TrainingArguments(
        output_dir=output_dir,
        num_train_epochs=num_epochs,
        per_device_train_batch_size=batch_size,
        gradient_accumulation_steps=gradient_accumulation_steps,
        learning_rate=learning_rate,
        lr_scheduler_type="cosine",
        warmup_ratio=0.05,
        logging_steps=5,
        save_strategy="epoch",
        fp16=cuda_available and not torch.cuda.is_bf16_supported(),
        bf16=cuda_available and torch.cuda.is_bf16_supported(),
        optim="paged_adamw_8bit" if cuda_available else "adamw_torch",
        report_to="none"
    )

    print("\n🚀 開始執行 165 AI 防詐 LoRA 領域微調...")
    trainer = SFTTrainer(
        model=model,
        train_dataset=dataset,
        peft_config=lora_config,
        formatting_func=formatting_prompts_func,
        max_seq_length=max_seq_length,
        tokenizer=tokenizer,
        args=training_args
    )

    trainer.train()

    print(f"\n🎉 訓練完成！正在儲存 LoRA Adapter 至 {output_dir}...")
    model.save_pretrained(output_dir)
    tokenizer.save_pretrained(output_dir)
    print(f"✅ LoRA 權重已儲存完畢：{output_dir}")


if __name__ == "__main__":
    train()