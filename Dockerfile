FROM python:3.11-slim

WORKDIR /app

# 複製依賴套件清單並安裝
COPY anti_scam_llm/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# 複製專案程式碼
COPY . .

# 設定環境變數確保 Python 路徑正確
ENV PYTHONPATH="/app:${PYTHONPATH}"

# 開放 Streamlit 預設通訊埠 7860 (Hugging Face Spaces 規範埠號)
EXPOSE 7860

# 啟動 Streamlit
CMD ["streamlit", "run", "anti_scam_llm/app.py", "--server.port=7860", "--server.address=0.0.0.0"]
