FROM python:3.12-slim

# Unbuffered, real-time logs; skip .pyc files
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Install dependencies first so this layer is cached unless requirements.txt changes
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the bot's source code
COPY . .

# Run as a non-root user
RUN useradd --create-home --uid 1000 modbot \
    && chown -R modbot:modbot /app
USER modbot

# Long-polling bot (app.run_polling) — no port needs to be exposed
CMD ["python", "bot.py"]