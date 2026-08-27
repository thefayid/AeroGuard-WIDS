# Stage 1: Build & Dependencies
FROM python:3.11-slim-bookworm AS builder

WORKDIR /app
COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir --user -r requirements.txt

# Stage 2: Production
FROM python:3.11-slim-bookworm

WORKDIR /app

# Install wireless tools and required networking utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
    wireless-tools \
    iw \
    aircrack-ng \
    libpcap0.8 \
    iproute2 \
    systemd \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /root/.local /root/.local
COPY . .

ENV PATH=/root/.local/bin:$PATH
ENV PYTHONUNBUFFERED=1

EXPOSE 8000

CMD ["uvicorn", "backend.app:app", "--host", "0.0.0.0", "--port", "8000"]
