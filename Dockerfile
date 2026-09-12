FROM python:3.12-slim

# Unbuffered, real-time logs; skip .pyc files
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# tor: จำเป็นสำหรับการค้น dark web (.onion) ใน /identity, /corporate, /search
# ca-certificates: ให้ requests ตรวจใบรับรอง HTTPS ของเว็บเปิดได้
RUN apt-get update \
    && apt-get install -y --no-install-recommends tor ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install dependencies first so this layer is cached unless requirements.txt changes
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the bot's source code
COPY . .
RUN chmod +x docker-entrypoint.sh

# Run as a non-root user (tor รันเป็น non-root ได้ ใช้ DataDirectory ใน /tmp)
RUN useradd --create-home --uid 1000 modbot \
    && chown -R modbot:modbot /app
USER modbot

# entrypoint สตาร์ท Tor ในคอนเทนเนอร์แล้ว exec app.py (long-polling — ไม่ต้อง expose port)
CMD ["./docker-entrypoint.sh"]
