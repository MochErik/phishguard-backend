FROM python:3.11-slim

# System deps for pyzbar, libmagic, playwright
RUN apt-get update && apt-get install -y --no-install-recommends \
    libzbar0 libmagic1 libgl1 libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps dulu (layer cache)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Playwright chromium (untuk web scan — opsional di free tier)
# RUN playwright install chromium --with-deps

COPY . .

# Port Railway
EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
