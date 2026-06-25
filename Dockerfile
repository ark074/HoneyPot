###############################################################################
# AegisTrap - Multi-Service AI-Driven Honeypot Framework
# Dockerfile for the Python honeypot application
###############################################################################

FROM python:3.11-slim

# Set metadata labels
LABEL maintainer="AegisTrap Project"
LABEL description="AI-driven honeypot framework with multi-service listeners"
LABEL version="1.0.0"

# Prevent Python from writing bytecode and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set working directory
WORKDIR /app

# Install system dependencies needed for AsyncSSH cryptography
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        gcc \
        libffi-dev \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY config.py .
COPY aegistrap/ ./aegistrap/
COPY main.py .

# Create log directory
RUN mkdir -p /app/logs

# Expose honeypot service ports
EXPOSE 2222 23 80 8080 21

# Health check - verify the process is running
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python -c "import socket; s=socket.socket(); s.settimeout(2); s.connect(('localhost', 2222)); s.close()" || exit 1

# Run the honeypot application
CMD ["python", "-u", "main.py"]
