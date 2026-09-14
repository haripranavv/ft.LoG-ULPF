FROM python:3.12-slim

# Install system dependencies (including iproute2, net-tools for network/neighbor discovery)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    iproute2 \
    net-tools \
    procps \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend application source
COPY . .

# Ensure storage directories exist
RUN mkdir -p /data/raw storage/raw

ENV RAW_STORAGE_DIR=/data/raw
ENV DATABASE_URL=postgresql://ulpf:ulpf_dev_password@postgres:5432/ulpf
ENV PYTHONUNBUFFERED=1

EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=5 \
  CMD curl -f http://localhost:8000/api/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
