FROM python:3.13-slim

WORKDIR /app

# System deps for psycopg2, Playwright, and network tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev gcc \
    # Playwright browser deps
    libnss3 libnspr4 libdbus-1-3 libatk1.0-0 libatk-bridge2.0-0 \
    libcups2 libdrm2 libxkbcommon0 libatspi2.0-0 libxcomposite1 \
    libxdamage1 libxfixes3 libxrandr2 libgbm1 libpango-1.0-0 \
    libcairo2 libasound2 libwayland-client0 \
    # Network tools for pentest modules (arp, nmap-like)
    net-tools iproute2 dnsutils \
    && rm -rf /var/lib/apt/lists/*

COPY apps/api/requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Install Playwright Chromium browser
RUN python -m playwright install chromium

COPY apps/ apps/
COPY alembic.ini alembic.ini
COPY alembic/ alembic/

RUN mkdir -p /app/data

EXPOSE 8000
CMD ["uvicorn", "apps.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
