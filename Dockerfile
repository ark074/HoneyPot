###############################################################################
# AegisTrap - Multi-Service AI-Driven Honeypot Framework
# Dockerfile for the Python honeypot application (Enhanced Edition)
###############################################################################

FROM python:3.11-slim

# Set metadata labels
LABEL maintainer="AegisTrap Project"
LABEL description="AI-driven honeypot framework with advanced threat intelligence"
LABEL version="2.0.0"

# Prevent Python from writing bytecode and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        gcc \
        libffi-dev \
        libssl-dev \
        # YARA dependencies
        libyara-dev \
        yara \
        # Build tools for native extensions
        build-essential \
        # curl for healthchecks
        curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY config.py .
COPY aegistrap/ ./aegistrap/
COPY main.py .

# Create runtime directories
RUN mkdir -p /app/logs /app/data/geoip /app/data/yara_rules

# Expose honeypot service ports + dashboard
EXPOSE 2222 23 80 8080 21 9000

# Health check - verify the dashboard API is responding
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -sf http://localhost:9000/api/v1/status || exit 1

# Run the honeypot application
CMD ["python", "-u", "main.py"]
