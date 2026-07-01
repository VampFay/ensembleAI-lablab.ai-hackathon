import sqlite3
import os
import time
import logging

logger = logging.getLogger(__name__)
DB_PATH = "scratch/state.db"

# Encryption at rest — lazy import so the module loads even if `cryptography` isn't installed.
# NOTE: crypto.init_key() must be called once at startup (e.g. in app.py / run_agents.py).
# If not called, crypto.py auto-generates an ephemeral key on first encrypt/decrypt.
_crypto = None
def _crypto_mod():
    global _crypto
    if _crypto is None:
        try:
            from ensemble_ai import crypto
            # Don't call init_key() here — it's called once at startup.
            # crypto.py handles the lazy init itself if needed.
            _crypto = crypto
        except ImportError:
            logger.warning("cryptography package not installed — encryption at rest disabled.")
            _crypto = False
    return _crypto

def _encrypt(plaintext: str) -> str:
    m = _crypto_mod()
    return m.encrypt(plaintext) if m else plaintext

def _decrypt(ciphertext: str) -> str:
    m = _crypto_mod()
    return m.decrypt(ciphertext) if m else ciphertext

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn

def init_db():
    os.makedirs("scratch", exist_ok=True)
    conn = get_db_connection()
    cursor = conn.cursor()

    # Core state table — single-row design (id=1 always) tracks the CURRENTLY ACTIVE vuln.
    # Multi-vuln support: see `vulnerabilities` table below. `current_vuln_id` points to the active one.
    # tenant_id column is schema-ready for multi-tenancy but not wired through queries (v2).
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS system_state (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            active_agent TEXT DEFAULT 'IDLE',
            timeline_step INTEGER DEFAULT 0,
            target_file TEXT DEFAULT '',
            code_before TEXT DEFAULT '// Awaiting target assignment from Triage...',
            code_after TEXT DEFAULT '// Awaiting patch from Developer agent...',

            -- Live metrics (written by agents via tools)
            exploit_status TEXT DEFAULT 'PENDING',
            patch_status TEXT DEFAULT 'PENDING',
            confidence INTEGER DEFAULT 0,
            signature_type TEXT DEFAULT 'UNKNOWN',

            -- Remediation summary (written by agents)
            root_cause TEXT DEFAULT '',
            fix_applied TEXT DEFAULT '',
            security_impact TEXT DEFAULT '',

            -- Deploy tracking
            waf_rule_file TEXT DEFAULT '',
            deploy_status TEXT DEFAULT 'PENDING',

            -- Aggregate counters
            metric_critical INTEGER DEFAULT 0,
            metric_active_agents TEXT DEFAULT '5/5',
            metric_mttr_seconds REAL DEFAULT 0.0,
            run_start_time REAL DEFAULT 0.0,

            -- Multi-vuln + multi-tenancy (schema-ready, v2 wiring)
            current_vuln_id INTEGER DEFAULT NULL,
            tenant_id TEXT DEFAULT 'default',

            -- Human-in-the-loop approval gate
            awaiting_approval INTEGER DEFAULT 0,
            approved INTEGER DEFAULT 0
        )
    ''')

    # Multi-vulnerability registry — each row is one tracked vulnerability.
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT DEFAULT 'default',
            target_file TEXT,
            vuln_class TEXT,
            cwe_id TEXT,
            cvss REAL DEFAULT 0.0,
            status TEXT DEFAULT 'open',
            created_at REAL,
            resolved_at REAL,
            confidence INTEGER DEFAULT 0
        )
    ''')

    # OPT:2 — unique index for race-free dedupe. Prevents duplicate vulns even under
    # concurrent SAST scans (check-then-insert race condition).
    cursor.execute('''
        CREATE UNIQUE INDEX IF NOT EXISTS idx_vuln_dedupe
        ON vulnerabilities(target_file, cwe_id)
    ''')

    # Telemetry logs table (agent activity)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS telemetry_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            agent TEXT,
            msg TEXT,
            status TEXT
        )
    ''')

    # Cycle history table — tracks each swarm cycle's outcome for success rate calculation
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cycle_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            started_at REAL,
            completed_at REAL,
            status TEXT,
            vuln_class TEXT
        )
    ''')

    # Audit log — tracks HUMAN actions (approvals, rejections, views) for compliance.
    # Agent actions are in telemetry_logs; this table is for human accountability.
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            actor TEXT,
            action TEXT,
            vuln_id INTEGER,
            details TEXT
        )
    ''')

    # Ensure initial state row exists
    cursor.execute('INSERT OR IGNORE INTO system_state (id) VALUES (1)')
    conn.commit()
    conn.close()


def log_audit(actor: str, action: str, vuln_id: int = None, details: str = ""):
    """Record a human action in the audit log (for SOC2 compliance)."""
    ts = time.strftime('%Y-%m-%d %H:%M:%S')
    conn = get_db_connection()
    conn.execute(
        "INSERT INTO audit_log (timestamp, actor, action, vuln_id, details) VALUES (?, ?, ?, ?, ?)",
        (ts, actor, action, vuln_id, details)
    )
    conn.commit()
    conn.close()


def create_vulnerability(target_file: str, vuln_class: str, cwe_id: str = "", cvss: float = 0.0) -> int:
    """Register a new vulnerability in the multi-vuln registry. Returns the vuln_id.
    OPT:2 — uses INSERT OR IGNORE + unique index for race-free dedupe.
    If the (target_file, cwe_id) combo already exists, returns the existing ID."""
    conn = get_db_connection()
    cursor = conn.execute(
        "INSERT OR IGNORE INTO vulnerabilities (target_file, vuln_class, cwe_id, cvss, status, created_at) VALUES (?, ?, ?, ?, 'open', ?)",
        (target_file, vuln_class, cwe_id, cvss, time.time())
    )
    if cursor.lastrowid:  # new insert
        vuln_id = cursor.lastrowid
    else:  # duplicate — fetch existing ID
        row = conn.execute("SELECT id FROM vulnerabilities WHERE target_file = ? AND cwe_id = ?", (target_file, cwe_id)).fetchone()
        vuln_id = row[0] if row else None
    # Set as the current active vuln
    if vuln_id:
        conn.execute("UPDATE system_state SET current_vuln_id = ? WHERE id = 1", (vuln_id,))
    conn.commit()
    conn.close()
    invalidate_state_cache()  # OPT:3 — current_vuln_id changed
    return vuln_id


def list_vulnerabilities(tenant_id: str = "default"):
    """List all vulnerabilities for a tenant (for the dashboard vuln selector)."""
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT id, target_file, vuln_class, cwe_id, cvss, status, created_at, resolved_at, confidence FROM vulnerabilities WHERE tenant_id = ? ORDER BY id DESC",
        (tenant_id,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_audit_log(limit: int = 50):
    """Get recent audit log entries."""
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def record_cycle_start(vuln_class: str = "Unknown"):
    """Call when a new swarm cycle begins (Triage starts)."""
    conn = get_db_connection()
    conn.execute("INSERT INTO cycle_history (started_at, status, vuln_class) VALUES (?, ?, ?)",
                 (time.time(), 'in_progress', vuln_class))
    conn.commit()
    conn.close()
    invalidate_state_cache()  # OPT:3 — affects get_success_rate() in get_full_state()

def record_cycle_completion(status: str):
    """Call when a swarm cycle completes. status = 'success' or 'failed'."""
    conn = get_db_connection()
    conn.execute("UPDATE cycle_history SET completed_at = ?, status = ? WHERE id = (SELECT MAX(id) FROM cycle_history)",
                 (time.time(), status))
    conn.commit()
    conn.close()
    invalidate_state_cache()  # OPT:3 — affects get_success_rate() in get_full_state()

def get_success_rate() -> str:
    """Compute success rate from the last 10 completed cycles."""
    conn = get_db_connection()
    rows = conn.execute(
        "SELECT status FROM cycle_history WHERE status != 'in_progress' ORDER BY id DESC LIMIT 10"
    ).fetchall()
    conn.close()
    if not rows:
        return "N/A"
    successes = sum(1 for r in rows if r[0] == 'success')
    total = len(rows)
    pct = round((successes / total) * 100)
    return f"{successes}/{total} ({pct}%)"

def update_system_state(
    agent=None, step=None, code_before=None, code_after=None, target_file=None,
    exploit_status=None, patch_status=None, confidence=None, signature_type=None,
    root_cause=None, fix_applied=None, security_impact=None,
    waf_rule_file=None, deploy_status=None, run_start_time=None
):
    conn = get_db_connection()
    cursor = conn.cursor()

    fields = []
    params = []

    if agent is not None:
        fields.append("active_agent = ?"); params.append(agent)
    if step is not None:
        fields.append("timeline_step = ?"); params.append(step)
        if step == 1:
            # bug:4 fix — always increment metric_critical on a new Triage (new cycle).
            # Old code only incremented if run_start_time was 0, which meant the counter
            # got stuck at 1 after the first cycle completed.
            fields.append("metric_critical = metric_critical + 1")
            fields.append("run_start_time = ?"); params.append(time.time())
    if target_file is not None:
        fields.append("target_file = ?"); params.append(target_file)
    if code_before is not None:
        fields.append("code_before = ?"); params.append(_encrypt(code_before))
    if code_after is not None:
        fields.append("code_after = ?"); params.append(_encrypt(code_after))
        # When patch lands, compute MTTR from run_start_time
        row = cursor.execute("SELECT run_start_time FROM system_state WHERE id = 1").fetchone()
        if row and row[0] and row[0] > 0:
            elapsed = round(time.time() - row[0], 1)
            fields.append("metric_mttr_seconds = ?"); params.append(elapsed)
    if exploit_status is not None:
        fields.append("exploit_status = ?"); params.append(exploit_status)
    if patch_status is not None:
        fields.append("patch_status = ?"); params.append(patch_status)
    if confidence is not None:
        fields.append("confidence = ?"); params.append(confidence)
    if signature_type is not None:
        fields.append("signature_type = ?"); params.append(signature_type)
    if root_cause is not None:
        fields.append("root_cause = ?"); params.append(_encrypt(root_cause))
    if fix_applied is not None:
        fields.append("fix_applied = ?"); params.append(_encrypt(fix_applied))
    if security_impact is not None:
        fields.append("security_impact = ?"); params.append(_encrypt(security_impact))
    if waf_rule_file is not None:
        fields.append("waf_rule_file = ?"); params.append(waf_rule_file)
    if deploy_status is not None:
        fields.append("deploy_status = ?"); params.append(deploy_status)
    if run_start_time is not None:
        fields.append("run_start_time = ?"); params.append(run_start_time)

    if fields:
        # fields contains hardcoded column names (not user input); params uses parameterized ? placeholders.
        # nosemgrep: python.sqlalchemy.security.sqlalchemy-execute-raw-query — false positive
        sql = f"UPDATE system_state SET {', '.join(fields)} WHERE id = 1"
        cursor.execute(sql, params)
        conn.commit()
    conn.close()
    invalidate_state_cache()  # OPT:3 — force re-query on next get_full_state()

def insert_log(agent, msg, status, timestamp):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO telemetry_logs (timestamp, agent, msg, status) VALUES (?, ?, ?, ?)",
        (timestamp, agent, msg, status)
    )
    conn.commit()
    log_id = cursor.lastrowid
    conn.close()
    invalidate_state_cache()  # OPT:3 — force re-query on next get_full_state()
    return log_id

def get_full_state():
    # OPT:3 — cache result for 0.3s to reduce DB load with multiple WS clients.
    # With 10 connected clients polling every 0.5s, this prevents 20 queries/s.
    global _state_cache, _state_cache_time
    if _state_cache and (time.time() - _state_cache_time < 0.3):
        return _state_cache

    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    state_row = cursor.execute("SELECT * FROM system_state WHERE id = 1").fetchone()
    # vuln:2 fix — cap logs to last 100 to prevent unbounded WebSocket payload growth.
    logs = cursor.execute(
        "SELECT timestamp as time, agent, msg, status FROM (SELECT * FROM telemetry_logs ORDER BY id DESC LIMIT 100) ORDER BY id ASC"
    ).fetchall()

    conn.close()

    if not state_row:
        return {}

    mttr_seconds = state_row["metric_mttr_seconds"] or 0.0

    state = dict(state_row)
    state.pop("metric_mttr_seconds")

    # Decrypt sensitive fields at read time (encryption at rest)
    for field in ("code_before", "code_after", "root_cause", "fix_applied", "security_impact"):
        if state.get(field):
            state[field] = _decrypt(state[field])

    state["metrics"] = {
        "critical": state.pop("metric_critical"),
        "success_rate": get_success_rate(),
        "active_agents": state.pop("metric_active_agents"),
        "mttr_seconds": mttr_seconds,
        "mttr_display": f"{mttr_seconds}s" if mttr_seconds > 0 else "---",
    }
    state["logs"] = [dict(log) for log in logs]

    # Update cache
    _state_cache = state
    _state_cache_time = time.time()
    return state


# State cache variables (OPT:3)
_state_cache = None
_state_cache_time = 0.0


def invalidate_state_cache():
    """Call this to force the next get_full_state() to re-query the DB."""
    global _state_cache, _state_cache_time
    _state_cache = None
    _state_cache_time = 0.0
