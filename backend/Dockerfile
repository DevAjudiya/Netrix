# ─────────────────────────────────────────
# Netrix — Backend Dockerfile
# Purpose: Multi-stage Docker build for the FastAPI backend.
# Author: Netrix Development Team
# ─────────────────────────────────────────

FROM python:3.11-slim AS base

# Install system dependencies (nmap, network tools)
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    iputils-ping \
    net-tools \
    curl \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for Docker layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY . .

# Create directories for reports and data
RUN mkdir -p /app/reports /app/data

# Expose the API port
EXPOSE 8000

# Run the application with uvicorn
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
