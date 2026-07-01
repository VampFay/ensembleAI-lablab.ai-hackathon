# Ensemble AI — Docker image for Fly.io / Render / Railway
#
# Multi-stage build keeps the final image small (~250 MB).

FROM python:3.11-slim AS base

# System deps for Semgrep (needs libc + libffi) and runtime exploit subprocesses
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl \
        nodejs \
    && rm -rf /var/lib/apt/lists/*

# uv for fast dependency install
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app

# Install Python deps first (better layer caching)
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev

# Copy the rest of the source
COPY . .

# Pre-built frontend is already in frontend/dist/ (committed to repo)
# Ensure runtime dirs exist
RUN mkdir -p scratch waf_rules reports

# Health check — Railway/Render/Fly all support HTTP health probes
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:${PORT:-8501}/health || exit 1

EXPOSE 8501

# Default to web process (override with `flyctl deploy --dockerfile-arg CMD=worker` for the agent swarm)
CMD ["uv", "run", "uvicorn", "app:app", "--host=0.0.0.0", "--port=8501"]
