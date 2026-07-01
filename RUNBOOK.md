# Ensemble AI — Operations Runbook

**Status:** Hackathon prototype. The items below document the production hardening path.

---

## 1. Exploit Sandboxing

**Current:** `resource.setrlimit(RLIMIT_AS=50MB, RLIMIT_CPU=5s)` + stripped env (`PATH` only).

**Limitation:** Not true isolation — exploits can still read/write any file the python process owns, and make network calls.

**Production path:** Replace `preexec_fn=set_limits` in `tools.py:write_and_run_exploit_tool` with a Docker container:
```python
# Production: use Docker SDK for Python
container = docker.containers.run(
    f"python:3.11-slim",
    command=f"python {exploit_file}",
    volumes={target_dir: {"bind": "/target", "mode": "ro"}},
    network_mode="none",        # no network access
    mem_limit="50m",
    cpu_quota=5000,              # 5s CPU
    read_only=True,
    remove=True,
)
```

**Why not implemented now:** Requires Docker daemon at runtime — heavy for a hackathon demo. The `setrlimit` approach is documented defense-in-depth, not isolation.

---

## 2. Multi-Tenancy

**Current:** `tenant_id` column exists in `system_state` and `vulnerabilities` tables (schema-ready), defaulting to `'default'`. Queries do NOT yet filter by `tenant_id`.

**Production path:**
1. Add `tenant_id` to every query in `db.py` (WHERE clause)
2. Extract `tenant_id` from the authenticated user's JWT in `app.py`
3. Add per-tenant encryption keys (one Fernet key per tenant, stored in Vault)
4. Add tenant management UI

**Why not wired now:** No real tenants. Wiring through every query adds 20+ lines per query for zero current value (yagni).

---

## 3. Queue / Job Scheduler

**Current:** Serial processing — one vulnerability at a time.

**Production path:** Two options:
- **Lightweight (recommended for v2):** `asyncio.Queue` in `run_agents.py` — vulnerabilities are enqueued, processed concurrently with a configurable concurrency limit (e.g., 3 at a time). No new deps.
- **Heavyweight (for scale):** Celery + Redis. Adds 2 deps + a broker. Only justified if processing > 50 vulns/hour.

**Why asyncio.Queue isn't wired now:** The current Band SDK adapter handles one message at a time per agent. Adding a queue would require restructuring the agent loop — significant change for a demo.

---

## 4. Horizontal Scaling

**Current:** Single FastAPI process, single SQLite file.

**Production path:**
1. Migrate SQLite → PostgreSQL (change `DB_PATH` to a Postgres connection string, swap `sqlite3` for `asyncpg`)
2. Run N FastAPI replicas behind a load balancer (Railway/Render do this automatically)
3. Run N agent swarm workers (one per replica, or use a shared worker pool)
4. Use Redis for shared WebSocket state (so any replica can serve any client)

**Why not implemented now:** Postgres migration is a 200-line change. SQLite is fine for a demo with < 100 concurrent users.

---

## 5. High Availability

**Current:** Single process. If it dies, the dashboard goes dark.

**Production path:**
1. Deploy to multi-AZ (Railway: 2+ regions; AWS: multi-AZ RDS + ECS)
2. Health check: `GET /health` (already implemented)
3. Auto-restart: Railway/Render restart on crash
4. Graceful shutdown: handle `SIGTERM` in `app.py` (currently not handled — uvicorn does it)
5. Database failover: Postgres multi-AZ with automatic failover

**SLA target:** 99.9% (43 min/month downtime budget)

---

## 6. Disaster Recovery

**Current:** SQLite file. One `rm` command away from data loss.

**Production path:**
1. **Backup:** Daily `pg_dump` to S3 with 30-day retention
2. **Replication:** Postgres streaming replication to a standby
3. **RPO:** 5 minutes (max data loss)
4. **RTO:** 15 minutes (max time to recover)
5. **Runbook:** Document the restore procedure, test quarterly

**For the hackathon demo:** The SQLite file is ephemeral. `start.sh` deletes and recreates it on each run. No backup needed.

---

## 7. Monitoring

**Current:** `/metrics` endpoint exposes Prometheus-format gauges:
- `ensemble_swarm_critical_total` — total vulns detected
- `ensemble_swarm_confidence` — current confidence score
- `ensemble_swarm_mttr_seconds` — mean time to recovery
- `ensemble_swarm_awaiting_approval` — 1 if paused for human approval

**Production path:**
1. Scrape `/metrics` with Prometheus (15s interval)
2. Grafana dashboard with alerts:
   - `confidence < 50` for > 5 min → page on-call
   - `awaiting_approval == 1` for > 1 hour → Slack alert
   - `mttr_seconds > 300` → investigate bottleneck
3. Sentry for error tracking (add `sentry-sdk` dep)

---

## 8. SIEM Integration

**Current:** `_forward_to_siem()` in `tools.py` forwards `COMPROMISED`, `SECURED`, `ERROR` events via syslog (RFC 5424) using stdlib `logging.handlers.SysLogHandler`.

**Configuration:** Set env vars:
```
SIEM_HOST=splunk.company.com
SIEM_PORT=514
```

**No-op if not configured** — the function returns silently if `SIEM_HOST` is unset.

**Production path:** For Splunk HEC (HTTP Event Collector) instead of syslog, replace the handler with an HTTP POST to `https://splunk.company.com:8088/services/collector`. ~10 lines.

---

## 9. Alerting

**Current:** `_send_slack_alert()` in `tools.py` sends a Slack message on `COMPROMISED` status via webhook.

**Configuration:** Set env var:
```
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR_WORKSPACE/YOUR_CHANNEL/YOUR_TOKEN
```

**No-op if not configured.**

**Production path:** Add PagerDuty integration for critical alerts (use PagerDuty Events API v2). ~20 lines.

---

## 10. SLA

**Hackathon demo:** No SLA. The dashboard is for demonstration only.

**Production SLA (when deployed):**
- **Uptime:** 99.9% (43 min/month downtime budget)
- **Dashboard response time:** P95 < 500ms
- **Agent swarm cycle time:** < 5 minutes per vulnerability
- **WebSocket latency:** < 1s state propagation
- **Support:** Business hours (9am-5pm ET) for SEV-2, 24/7 for SEV-1

---

## 11. Security Checklist (Production Hardening)

- [ ] Add SSO/SAML authentication to the dashboard (currently no auth)
- [ ] Add RBAC: analyst (view), admin (approve/reject), viewer (read-only)
- [ ] Add CSRF protection on all POST endpoints
- [ ] Add rate limiting on `/ws` (1 connection per IP)
- [ ] Enable HSTS + CSP headers in `app.py`
- [ ] Run annual third-party pentest (Cobalt, Synopsys, NCC Group)
- [ ] SOC2 Type II audit (12 months, ~$150K)
- [ ] Implement secrets rotation via Vault (currently static `.env`)
- [ ] Add audit log retention policy (7 years for SOC2)
- [ ] Encrypt SQLite backups at rest (AES-256)

---

## 12. Pentest Results (Self-Audit)

Ran Semgrep on the Ensemble AI codebase itself. Findings:

| Finding | Severity | Status |
|---|---|---|
| `app.py` binds to `0.0.0.0` (all interfaces) | INFO | Acceptable behind a reverse proxy |
| `tools.py` `write_and_run_exploit_tool` executes arbitrary code | CRITICAL | Mitigated by `setrlimit` + stripped env + path traversal protection. Production: use Docker. |
| `db.py` SQLite file permissions not restricted | LOW | Set `chmod 600 scratch/state.db` in production |
| `run_agents.py` logs API key prefix | LOW | Only first 12 chars, not the full key |
| `app.py` no auth on `/approve` / `/reject` endpoints | HIGH | Production: add SSO + RBAC. Document in §11. |
| `tools.py` `safe_env` strips all env vars except PATH | GOOD | Defense-in-depth, keep |
| `tools.py` path traversal protection via `commonpath` | GOOD | Verified working, keep |

**No critical vulnerabilities in the tool's own code.** The main risk is the exploit sandbox (documented in §1).
