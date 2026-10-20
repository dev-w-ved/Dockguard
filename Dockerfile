FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir -r requirements.txt
COPY dockguard ./dockguard
COPY samples ./samples
EXPOSE 8000
CMD ["uvicorn", "dockguard.web:app", "--host", "0.0.0.0", "--port", "8000"]
