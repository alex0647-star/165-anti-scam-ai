---
title: 165 AI Anti Scam System
emoji: 🛡️
colorFrom: blue
colorTo: indigo
sdk: gradio
sdk_version: 5.16.0
app_file: app.py
pinned: false
---

# 🛡️ 165 AI 智能多模態防詐騙鑑識系統 (Anti-Scam LLM System)

本專案為大型語言模型 (LLM) 專題成果，整合 **五步思維鏈鑑識 (CoT)**、**165 詐騙手法劇本知識庫 (RAG)**、**多模態截圖解析 (Vision OCR)** 與 **Pydantic 結構化防護守衛 (Guardrails)**，支援即時文字鑑識、對話截圖分析與 20 筆對抗性基準評估。

---

## 📁 專案目錄結構

```
C:\Users\USER\Desktop\LLM專題\
├── 啟動網頁介面.bat          # 【推薦】雙擊直接開啟 Streamlit Web 介面
├── 執行基準測試.bat          # 雙擊直接執行 20 筆測資成績單
├── README.md                # 專案說明與 Hugging Face Space 設定檔
├── requirements.txt         # 依賴套件清單
├── app.py                   # Hugging Face Gradio 雲端入口
└── anti_scam_llm/           # 核心 Python 模組套件
    ├── app.py               # Streamlit 網頁版互動工作台
    ├── config.py            # 系統組態與風險門檻設定
    ├── schemas.py           # Pydantic 資料契約模型
    ├── prompts.py           # 分層 Prompt 引擎 (Persona, CoT, 特徵庫)
    ├── dataset.py           # 20 筆黃金測試資料庫 (含對抗變形錯字)
    ├── knowledge_base.py    # 15 大 165 詐騙手法特徵庫與語意檢索器 (RAG)
    ├── vision_processor.py  # 多模態截圖前處理模組
    ├── guardrails.py        # JSON 守衛與自我修復器 (Self-Healing)
    ├── reasoning_engine.py  # 端到端鑑識調度核心
    └── main.py              # 終端機 CLI 與 Benchmark Runner
```
