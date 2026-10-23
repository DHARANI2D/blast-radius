FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV BR_LLM_MODE=offline BR_TOOL_TRANSPORT=mcp PYTHONUNBUFFERED=1
EXPOSE 8501
CMD ["python", "-m", "streamlit", "run", "ui/app.py", "--server.address=0.0.0.0", "--server.port=8501", "--browser.gatherUsageStats=false"]
