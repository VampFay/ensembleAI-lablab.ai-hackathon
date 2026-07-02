import os
import asyncio
import hmac
import json
import time
from collections import defaultdict
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, HTTPException, Depends, Header
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
import uvicorn
import ensemble_ai.db as db
import ensemble_ai.crypto as crypto

import logging

state_changed_event = asyncio.Event()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

app = FastAPI()

# Initialize Ensemble C2 server
logger.info("Initializing Ensemble C2 server...")
crypto.init_key()  # Initialize encryption key from env (before any DB writes)
db.init_db()
logger.info("SQLite DB initialized")

frontend_dist = os.path.join(os.path.dirname(__file__), "frontend", "dist")
if os.path.exists(frontend_dist):
    app.mount("/assets", StaticFiles(directory=os.path.join(frontend_dist, "assets")), name="assets")
    logger.info(f"Serving frontend from {frontend_dist}")


# OPT:8 — Content-Security-Policy header to prevent XSS even if dangerouslySetInnerHTML is exploited
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "connect-src 'self' ws: wss:; "
        "img-src 'self' data:; "
        "object-src 'none'; "
        "base-uri 'self'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


@app.get("/health")
async def health():
    """Health check endpoint for Railway/Render/Fly.io probes."""
    state = db.get_full_state()
    return {"status": "ok", "active_agent": state.get("active_agent", "IDLE")}


@app.get("/metrics")
async def metrics():
    """Prometheus-format metrics endpoint for monitoring."""
    state = db.get_full_state()
    lines = [
        "# HELP ensemble_swarm_critical_total Total critical vulnerabilities detected",
        "# TYPE ensemble_swarm_critical_total counter",
        f"ensemble_swarm_critical_total {state.get('metrics', {}).get('critical', 0)}",
        "# HELP ensemble_swarm_confidence Current confidence score (0-99)",
        "# TYPE ensemble_swarm_confidence gauge",
        f"ensemble_swarm_confidence {state.get('confidence', 0)}",
        "# HELP ensemble_swarm_mttr_seconds Mean time to recovery in seconds",
        "# TYPE ensemble_swarm_mttr_seconds gauge",
        f"ensemble_swarm_mttr_seconds {state.get('metrics', {}).get('mttr_seconds', 0)}",
        "# HELP ensemble_swarm_awaiting_approval 1 if workflow is paused for human approval",
        "# TYPE ensemble_swarm_awaiting_approval gauge",
        f"ensemble_swarm_awaiting_approval {state.get('awaiting_approval', 0)}",
    ]
    return PlainTextResponse("\n".join(lines) + "\n", media_type="text/plain")


@app.get("/")
async def get_dashboard():
    index_path = os.path.join(frontend_dist, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return HTMLResponse("<h1>Ensemble AI — Frontend not built. Run ./start.sh first.</h1>", status_code=503)


def _check_admin_auth(x_api_key: str = Header(default="", alias="X-API-Key")):
    """vuln:1 fix — require X-API-Key header on admin endpoints (approve/reject).
    Key is set via ENSEMBLE_ADMIN_API_KEY env var. If not set, auth is disabled (dev mode).
    Uses hmac.compare_digest to prevent timing attacks."""
    expected = os.environ.get("ENSEMBLE_ADMIN_API_KEY")
    if expected and not hmac.compare_digest(x_api_key, expected):
        raise HTTPException(status_code=401, detail="unauthorized")


@app.get("/api/vulns")
async def list_vulns(auth=Depends(_check_admin_auth)):
    """List all tracked vulnerabilities (multi-vuln support).
    new-vuln:1 fix — requires admin auth (same as /approve)."""
    return JSONResponse(db.list_vulnerabilities())


@app.get("/api/audit_log")
async def audit_log(limit: int = 50, auth=Depends(_check_admin_auth)):
    """Return recent human actions from the audit log (SOC2 compliance).
    new-vuln:1 fix — requires admin auth."""
    return JSONResponse(db.get_audit_log(limit))


@app.post("/approve")
async def approve(auth=Depends(_check_admin_auth)):
    """Human-in-the-loop: approve the pending WAF deployment."""
    conn = db.get_db_connection()
    conn.execute("UPDATE system_state SET awaiting_approval = 0, approved = 1, deploy_status = 'DEPLOYED' WHERE id = 1")
    conn.commit()
    conn.close()
    db.invalidate_state_cache()  # OPT:3 — cache invalidated by update, but be explicit
    db.log_audit("human", "approved_deployment", details="WAF deployment approved via dashboard")
    state_changed_event.set()
    return {"status": "approved"}


@app.post("/reject")
async def reject(auth=Depends(_check_admin_auth)):
    """Human-in-the-loop: reject the pending WAF deployment."""
    conn = db.get_db_connection()
    conn.execute("UPDATE system_state SET awaiting_approval = 0, approved = 0, deploy_status = 'REJECTED' WHERE id = 1")
    conn.commit()
    conn.close()
    db.invalidate_state_cache()
    db.log_audit("human", "rejected_deployment", details="WAF deployment rejected via dashboard")
    state_changed_event.set()
    return {"status": "rejected"}


@app.post("/api/trigger")
async def trigger_sast(request: Request, auth=Depends(_check_admin_auth)):
    """Receive SAST report from CI/CD pipeline and register findings."""
    try:
        payload = await request.json()
        sast_report = payload.get("sast_report", {})
        findings = sast_report.get("results", [])
        
        from ensemble_ai.cve_mapping import enrich_finding
        from ensemble_ai.tools import update_state
        
        vulnerabilities_created = 0
        for top in findings:
            path = top.get("path", "")
            # relative path normalization
            if path.startswith("/app/"):
                path = path[5:]
            elif path.startswith("./"):
                path = path[2:]
                
            check_id = top.get("check_id", "unknown-rule")
            message = top.get("extra", {}).get("message", "Vulnerability detected")
            
            cwe_info = enrich_finding(check_id)
            vuln_id = db.create_vulnerability(
                target_file=path,
                vuln_class=check_id,
                cwe_id=cwe_info["cwe_id"],
                cvss=cwe_info["cvss"]
            )
            vulnerabilities_created += 1
            
            # Start the swarm cycle in DB telemetry
            update_state(
                "TRIAGE",
                f"CI/CD Ingestion: Found vulnerability in {path} — {message}",
                "INFO",
                step=1,
                target_file=path,
                signature_type=f"ZERO-DAY ({cwe_info['cwe_id']})"
            )
            
        state_changed_event.set()
        return {"status": "triggered", "vulnerabilities_created": vulnerabilities_created}
    except Exception as e:
        logger.error(f"Failed to process trigger: {e}")
        return JSONResponse({"error": f"Failed to process trigger: {str(e)}"}, status_code=400)


# OPT:7 — rate limiting on WebSocket connections (prevent DoS via connection flooding)
_ws_connections_per_ip = defaultdict(int)
_WS_MAX_PER_IP = 5


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    # new-vuln:2 fix — auth on WebSocket (check query param if admin key is set)
    admin_key = os.environ.get("ENSEMBLE_ADMIN_API_KEY")
    if admin_key:
        provided = websocket.query_params.get("api_key", "")
        if not hmac.compare_digest(provided, admin_key):
            await websocket.close(code=4401)  # custom close code for unauthorized
            return

    # OPT:7 — rate limit per IP
    client_ip = websocket.client.host if websocket.client else "unknown"
    if _ws_connections_per_ip[client_ip] >= _WS_MAX_PER_IP:
        logger.warning(f"[WS] Rate limit hit for {client_ip} ({_ws_connections_per_ip[client_ip]} connections)")
        await websocket.close(code=1013)  # try again later
        return

    await websocket.accept()
    _ws_connections_per_ip[client_ip] += 1
    logger.info(f"[WS] C2 client connected ({client_ip}, total: {_ws_connections_per_ip[client_ip]})")

    # OPT:4 — only send state when it changes (hash comparison)
    last_hash = None
    try:
        # Initial push
        state = db.get_full_state()
        if state:
            last_hash = hash(json.dumps(state, sort_keys=True, default=str))
            await websocket.send_json(state)

        while True:
            try:
                await asyncio.wait_for(state_changed_event.wait(), timeout=1.0)
                state_changed_event.clear()
            except asyncio.TimeoutError:
                pass

            state = db.get_full_state()
            if state:
                state_hash = hash(json.dumps(state, sort_keys=True, default=str))
                if state_hash != last_hash:
                    await websocket.send_json(state)
                    last_hash = state_hash
    except WebSocketDisconnect:
        logger.info(f"[WS] C2 client disconnected ({client_ip})")
    finally:
        _ws_connections_per_ip[client_ip] -= 1
        if _ws_connections_per_ip[client_ip] <= 0:
            del _ws_connections_per_ip[client_ip]


if __name__ == "__main__":
    # Platforms (Railway/Render/Fly.io) inject PORT; fall back to 8501 for local dev.
    port = int(os.environ.get("PORT", 8501))
    logger.info(f"ENSEMBLE C2 WebSocket Server starting on port {port}...")
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")
