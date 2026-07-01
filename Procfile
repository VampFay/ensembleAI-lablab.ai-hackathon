# Ensemble AI — Deployment manifest for Railway / Render / Fly.io
#
# Web process serves the FastAPI + WebSocket dashboard.
# Worker process runs the 5-agent CrewAI swarm (long-running, never exits).
#
# Railway: supports both `web` and `worker`
# Render:  paid plan supports `worker`; free tier is `web` only
# Fly.io:  use Dockerfile instead; this Procfile is ignored

web: uv run uvicorn app:app --host=0.0.0.0 --port=${PORT:-8501}
worker: uv run python run_agents.py
