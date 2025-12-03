FROM python:3.12-slim

# Install restic and rclone inside the container
RUN apt-get update && \
    apt-get install -y --no-install-recommends restic rclone ca-certificates tzdata && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# App code
COPY app.py /app/app.py
COPY templates /app/templates

EXPOSE 8080

# Production-ish defaults
ENV FLASK_ENV=production \
    PYTHONUNBUFFERED=1

# Use gunicorn instead of Flask dev server
CMD ["gunicorn", "-b", "0.0.0.0:8080", "--workers", "2", "--threads", "4", "app:app"]
