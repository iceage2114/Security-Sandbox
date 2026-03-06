# =============================================================================
# Stage 1: Build the React frontend
# =============================================================================
FROM node:20-slim AS frontend-builder

WORKDIR /app/frontend

# Install dependencies
COPY frontend/package*.json ./
RUN npm ci

# Copy source and build
COPY frontend/ ./
RUN npm run build

# =============================================================================
# Stage 2: Final image — Python + Node.js + supervisord
# =============================================================================
FROM python:3.12-slim

# Install Node.js 20, supervisord, and curl
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        supervisor \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# --- Python dependencies ---
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# --- Python application ---
COPY server.py ./
COPY tools/ ./tools/

# --- Node.js API server ---
COPY frontend/package*.json ./frontend/
RUN cd frontend && npm ci --omit=dev

COPY frontend/api-server.js ./frontend/

# --- Built React static files (from stage 1) ---
COPY --from=frontend-builder /app/frontend/dist ./frontend/dist

# --- Supervisor configuration ---
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# MCP server (8000) + Express API + React UI (3001)
EXPOSE 8000 3001

# Copy .env if it exists (API keys); override at runtime with --env-file
# COPY .env ./

CMD ["/usr/bin/supervisord", "-n", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
