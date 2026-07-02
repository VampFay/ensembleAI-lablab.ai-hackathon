"""Workflow state transitions shared by the dashboard, replay, and agent tools."""

from __future__ import annotations

import json
import logging
import os
import urllib.request
from datetime import datetime
from typing import Any

import ensemble_ai.db as db
from ensemble_ai.cve_mapping import enrich_finding

logger = logging.getLogger(__name__)


def _forward_to_siem(agent: str, msg: str, status: str) -> None:
    """Forward critical events to SIEM via syslog when configured."""
    siem_host = os.environ.get("SIEM_HOST")
    if not siem_host:
        return
    try:
        import logging.handlers

        siem_logger = logging.getLogger("ensemble_ai.siem")
        if not siem_logger.handlers:
            handler = logging.handlers.SysLogHandler(
                address=(siem_host, int(os.environ.get("SIEM_PORT", 514)))
            )
            siem_logger.addHandler(handler)
            siem_logger.setLevel(logging.INFO)
        siem_logger.info("ensemble-ai agent=%s status=%s msg=%s", agent, status, msg[:200])
    except Exception as exc:
        logger.debug("SIEM forward failed: %s", exc)


def _send_slack_alert(msg: str) -> None:
    """Send a critical alert to Slack via webhook URL when configured."""
    webhook = os.environ.get("SLACK_WEBHOOK_URL")
    if not webhook:
        return
    try:
        data = json.dumps({"text": f"Ensemble AI Alert: {msg}"}).encode()
        req = urllib.request.Request(webhook, data=data, headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=3)
    except Exception as exc:
        logger.debug("Slack alert failed: %s", exc)


def compute_confidence(sast_clean: bool, exploit_verified: bool, patch_applied: bool) -> int:
    """Compute confidence from verification signals instead of hard-coded scores."""
    score = 50
    if sast_clean:
        score += 25
    if exploit_verified:
        score += 20
    if patch_applied:
        score += 5
    return min(99, max(0, score))


def update_state(
    agent: str,
    msg: str,
    status: str = "INFO",
    step: int | None = None,
    code_before: str | None = None,
    code_after: str | None = None,
    target_file: str | None = None,
    exploit_status: str | None = None,
    patch_status: str | None = None,
    confidence: int | None = None,
    signature_type: str | None = None,
    root_cause: str | None = None,
    fix_applied: str | None = None,
    security_impact: str | None = None,
    waf_rule_file: str | None = None,
    deploy_status: str | None = None,
) -> None:
    """Write structured telemetry and agent activity to SQLite."""
    timestamp = datetime.now().strftime("%H:%M:%S")
    db.update_system_state(
        agent=agent,
        step=step,
        code_before=code_before,
        code_after=code_after,
        target_file=target_file,
        exploit_status=exploit_status,
        patch_status=patch_status,
        confidence=confidence,
        signature_type=signature_type,
        root_cause=root_cause,
        fix_applied=fix_applied,
        security_impact=security_impact,
        waf_rule_file=waf_rule_file,
        deploy_status=deploy_status,
    )
    db.insert_log(agent, msg, status, timestamp)

    if status in ("COMPROMISED", "SECURED", "ERROR"):
        _forward_to_siem(agent, msg, status)
    if status == "COMPROMISED":
        _send_slack_alert(f"{agent}: {msg}")

    if step == 1 and agent == "TRIAGE":
        db.record_cycle_start(signature_type or "Unknown")
    elif step == 6 and agent == "RELEASE_MGR" and deploy_status == "DEPLOYED":
        db.record_cycle_completion("success")


def request_approval(vuln_class: str, waf_rule_file: str, summary: str) -> str:
    """Move the workflow into the approval gate."""
    conn = db.get_db_connection()
    conn.execute(
        "UPDATE system_state SET awaiting_approval = 1, approved = 0, deploy_status = 'AWAITING_APPROVAL' "
        "WHERE id = 1"
    )
    conn.commit()
    conn.close()
    db.invalidate_state_cache()

    details = f"Vuln: {vuln_class}, WAF: {waf_rule_file}"
    db.log_audit("swarm", "approval_requested", details=details)
    update_state(
        "RELEASE_MGR",
        f"AWAITING HUMAN APPROVAL: {vuln_class} - {summary}",
        "INFO",
        step=6,
        waf_rule_file=waf_rule_file,
        deploy_status="AWAITING_APPROVAL",
    )
    return (
        "Approval requested. The workflow is paused until a human reviews and approves "
        f"via the dashboard. Vuln: {vuln_class}, WAF: {waf_rule_file}. Summary: {summary}"
    )


def approve_deployment(actor: str = "human", details: str = "WAF deployment approved") -> None:
    """Approve a pending deployment from one canonical code path."""
    conn = db.get_db_connection()
    conn.execute(
        "UPDATE system_state SET awaiting_approval = 0, approved = 1, deploy_status = 'DEPLOYED' WHERE id = 1"
    )
    conn.commit()
    conn.close()
    db.invalidate_state_cache()
    db.log_audit(actor, "approved_deployment", details=details)


def reject_deployment(actor: str = "human", details: str = "WAF deployment rejected") -> None:
    """Reject a pending deployment from one canonical code path."""
    conn = db.get_db_connection()
    conn.execute(
        "UPDATE system_state SET awaiting_approval = 0, approved = 0, deploy_status = 'REJECTED' WHERE id = 1"
    )
    conn.commit()
    conn.close()
    db.invalidate_state_cache()
    db.log_audit(actor, "rejected_deployment", details=details)


def get_approval_status() -> tuple[int, str]:
    """Return the current approval flag and deployment status."""
    conn = db.get_db_connection()
    row = conn.execute("SELECT approved, deploy_status FROM system_state WHERE id = 1").fetchone()
    conn.close()
    if not row:
        return 0, "PENDING"
    return int(row[0] or 0), str(row[1] or "PENDING")


def ingest_sast_report(sast_report: dict[str, Any]) -> int:
    """Register SAST findings and start the triage telemetry cycle."""
    findings = sast_report.get("results", [])
    vulnerabilities_created = 0

    for finding in findings:
        path = finding.get("path", "")
        if path.startswith("/app/"):
            path = path[5:]
        elif path.startswith("./"):
            path = path[2:]

        check_id = finding.get("check_id", "unknown-rule")
        message = finding.get("extra", {}).get("message", "Vulnerability detected")
        cwe_info = enrich_finding(check_id)

        db.create_vulnerability(
            target_file=path,
            vuln_class=check_id,
            cwe_id=cwe_info["cwe_id"],
            cvss=cwe_info["cvss"],
        )
        vulnerabilities_created += 1

        update_state(
            "TRIAGE",
            f"CI/CD Ingestion: Found vulnerability in {path} - {message}",
            "INFO",
            step=1,
            target_file=path,
            signature_type=f"ZERO-DAY ({cwe_info['cwe_id']})",
        )

    return vulnerabilities_created
