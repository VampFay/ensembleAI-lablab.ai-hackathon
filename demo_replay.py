"""Replay a complete Ensemble AI workflow without Band or LLM credentials.

This script is intentionally deterministic. It writes the same telemetry shape
that the live Band agents produce, so the dashboard can be evaluated by a
GitHub reviewer without provisioning five external agents.
"""

from __future__ import annotations

import argparse
import os
import shutil
import time
from dataclasses import dataclass
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent
os.chdir(PROJECT_ROOT)

import ensemble_ai.crypto as crypto  # noqa: E402
import ensemble_ai.db as db  # noqa: E402
from ensemble_ai.tools import update_state  # noqa: E402


@dataclass(frozen=True)
class ReplayScenario:
    name: str
    target_file: str
    vulnerability_class: str
    root_cause: str
    fix_applied: str
    security_impact: str
    exploit_before: str
    exploit_after: str
    waf_rule_file: str
    waf_rule: str


SCENARIOS = {
    "php": ReplayScenario(
        name="Legacy PHP object injection",
        target_file="mock_app/legacy_php/plugin_vulnerable.php",
        vulnerability_class="PHP Object Injection",
        root_cause=(
            "Unauthenticated AJAX input is base64-decoded and passed directly "
            "to unserialize(), allowing attacker-controlled object graphs."
        ),
        fix_applied=(
            "Require a WordPress nonce, validate the request shape, replace "
            "unserialize() with json_decode(), and persist only allow-listed fields."
        ),
        security_impact=(
            "Blocks unauthenticated PHP object injection and removes the RCE-capable "
            "deserialization sink."
        ),
        exploit_before=(
            "[GADGET TRIGGERED] __wakeup executed with attacker-controlled command\n"
            "Result: user_profile_settings overwritten through unauthenticated AJAX"
        ),
        exploit_after=(
            "HTTP 403: nonce validation failed\n"
            "Result: payload rejected before decoding or persistence"
        ),
        waf_rule_file="01_block_php_object_injection.conf",
        waf_rule=(
            'SecRule ARGS:profile_data "@rx ^Tzo|O:[0-9]+:" '
            '"id:1001001,phase:2,deny,status:403,msg:\'Block PHP object injection payload\'"'
        ),
    ),
    "ssrf": ReplayScenario(
        name="Cloud Python SSRF",
        target_file="mock_app/cloud_python/invoice_service.py",
        vulnerability_class="Server-Side Request Forgery",
        root_cause=(
            "The receipt fetch endpoint accepts arbitrary URLs and performs a "
            "server-side request without scheme, host, or private-network validation."
        ),
        fix_applied=(
            "Parse the URL, restrict schemes to HTTPS, resolve the hostname, block "
            "private/link-local ranges, and fetch only approved receipt domains."
        ),
        security_impact=(
            "Prevents access to cloud metadata endpoints, localhost services, and "
            "internal network addresses."
        ),
        exploit_before=(
            "Requested http://169.254.169.254/latest/meta-data/iam/security-credentials/\n"
            "Result: server attempted internal metadata fetch"
        ),
        exploit_after=(
            "HTTP 400: blocked private or link-local destination\n"
            "Result: metadata endpoint never fetched"
        ),
        waf_rule_file="02_block_metadata_ssrf.conf",
        waf_rule=(
            'SecRule ARGS:receipt_url "@contains 169.254.169.254" '
            '"id:1001002,phase:2,deny,status:403,msg:\'Block cloud metadata SSRF\'"'
        ),
    ),
    "bola": ReplayScenario(
        name="Regulated Node BOLA",
        target_file="mock_app/regulated_node/patient_api.js",
        vulnerability_class="Broken Object Level Authorization",
        root_cause=(
            "The route authenticates the caller but does not verify that the "
            "requested medical record belongs to the authenticated user."
        ),
        fix_applied=(
            "Compare record.owner_id with req.user.id before returning the record, "
            "and return 403 for cross-user access attempts."
        ),
        security_impact=(
            "Prevents horizontal privilege escalation and unauthorized disclosure "
            "of patient health data."
        ),
        exploit_before=(
            "Authenticated as user_a\n"
            "GET /api/v1/patient/record/102 -> 200 OK, record belongs to user_b"
        ),
        exploit_after=(
            "Authenticated as user_a\n"
            "GET /api/v1/patient/record/102 -> 403 Forbidden"
        ),
        waf_rule_file="03_block_patient_idor.conf",
        waf_rule=(
            'SecRule REQUEST_URI "@rx /api/v1/patient/record/[0-9]+" '
            '"id:1001003,phase:2,pass,log,msg:\'Patient record access requires app-level owner check\'"'
        ),
    ),
}


PATCHES = {
    "php": (
        "$payload = json_decode($decoded_data, true);\n"
        "if (!is_array($payload)) {\n"
        "    wp_send_json_error(array('message' => 'Invalid profile_data.'), 400);\n"
        "}\n"
        "$profile = array_intersect_key($payload, array_flip(array('display_name', 'timezone')));"
    ),
    "ssrf": (
        "parsed = urllib.parse.urlparse(target_url)\n"
        "if parsed.scheme != 'https':\n"
        "    raise HTTPException(status_code=400, detail='Only HTTPS receipt URLs are allowed')\n"
        "if parsed.hostname in {'localhost', '127.0.0.1', '169.254.169.254'}:\n"
        "    raise HTTPException(status_code=400, detail='Blocked internal destination')"
    ),
    "bola": (
        "if (record.owner_id !== req.user.id) {\n"
        "    return res.status(403).json({ error: 'Forbidden' });\n"
        "}\n"
        "res.json({ status: 'success', data: record });"
    ),
}


def reset_state() -> None:
    scratch_dir = PROJECT_ROOT / "scratch"
    if scratch_dir.exists():
        shutil.rmtree(scratch_dir)
    scratch_dir.mkdir(exist_ok=True)
    crypto.init_key()
    db.init_db()


def read_target(path: str) -> str:
    return (PROJECT_ROOT / path).read_text(encoding="utf-8")


def build_after_code(before: str, scenario_key: str) -> str:
    if scenario_key == "php":
        return before.replace("$profile = unserialize($decoded_data);", PATCHES[scenario_key])
    if scenario_key == "ssrf":
        return before.replace(
            "# VULNERABLE: No checks on target_url (e.g., blocking 169.254.169.254 or localhost)\n"
            "        req = urllib.request.Request(target_url)",
            PATCHES[scenario_key] + "\n        req = urllib.request.Request(target_url)",
        )
    if scenario_key == "bola":
        return before.replace(
            "// MISSING CHECK: if (record.owner_id !== req.user.id) { return 403; }\n\n"
            "    // SINK: Returns sensitive medical data to potentially unauthorized users\n"
            "    res.json({ status: 'success', data: record });",
            "// Authorization guard inserted by Patch Developer\n    " + PATCHES[scenario_key],
        )
    raise ValueError(f"Unknown scenario: {scenario_key}")


def write_artifacts(scenario: ReplayScenario) -> None:
    waf_dir = PROJECT_ROOT / "waf_rules"
    reports_dir = PROJECT_ROOT / "reports"
    waf_dir.mkdir(exist_ok=True)
    reports_dir.mkdir(exist_ok=True)
    (waf_dir / scenario.waf_rule_file).write_text(scenario.waf_rule + "\n", encoding="utf-8")
    (reports_dir / f"demo_report_{scenario.vulnerability_class.lower().replace(' ', '_')}.md").write_text(
        "\n".join(
            [
                "# Ensemble AI Demo Compliance Report",
                "",
                f"Vulnerability: {scenario.vulnerability_class}",
                f"Root cause: {scenario.root_cause}",
                f"Fix: {scenario.fix_applied}",
                f"WAF rule: {scenario.waf_rule_file}",
                "",
                "Before:",
                scenario.exploit_before,
                "",
                "After:",
                scenario.exploit_after,
            ]
        )
        + "\n",
        encoding="utf-8",
    )


def replay(scenario_key: str, delay: float) -> None:
    scenario = SCENARIOS[scenario_key]
    before = read_target(scenario.target_file)
    after = build_after_code(before, scenario_key)

    reset_state()
    print(f"Replaying scenario: {scenario.name}")

    steps = [
        (
            "TRIAGE",
            f"Mapped report to {scenario.target_file}",
            "INFO",
            {
                "step": 1,
                "target_file": scenario.target_file,
                "code_before": before,
                "signature_type": f"ZERO-DAY ({scenario.vulnerability_class})",
            },
        ),
        (
            "RED_TEAM",
            f"Exploit confirmed: {scenario.vulnerability_class}",
            "COMPROMISED",
            {"step": 2, "exploit_status": "ACTIVE", "confidence": 70},
        ),
        (
            "DEVELOPER",
            "Applied secure patch and prepared syntax validation",
            "PATCHING",
            {
                "step": 3,
                "code_after": after,
                "patch_status": "APPLIED",
                "root_cause": scenario.root_cause,
                "fix_applied": scenario.fix_applied,
                "security_impact": scenario.security_impact,
            },
        ),
        (
            "AUDITOR",
            "Static audit passed; requesting adversarial re-verification",
            "VERIFIED",
            {"step": 4, "patch_status": "VERIFIED", "confidence": 82},
        ),
        (
            "RED_TEAM",
            "Exploit replay blocked by the patch",
            "SECURED",
            {"step": 5, "exploit_status": "BLOCKED", "confidence": 95, "deploy_status": "READY"},
        ),
        (
            "RELEASE_MGR",
            "Requesting human sign-off on the WAF deployment",
            "INFO",
            {
                "step": 6,
                "waf_rule_file": scenario.waf_rule_file,
                "deploy_status": "AWAITING_APPROVAL",
                "confidence": 95,
            },
        ),
        (
            "RELEASE_MGR",
            f"Generated WAF rule and demo compliance report: {scenario.waf_rule_file}",
            "SECURED",
            {
                "step": 6,
                "waf_rule_file": scenario.waf_rule_file,
                "deploy_status": "DEPLOYED",
                "confidence": 99,
            },
        ),
    ]

    for agent, message, status, fields in steps:
        update_state(agent, message, status, **fields)
        print(f"[{agent}] {message}")
        
        if fields.get("deploy_status") == "AWAITING_APPROVAL":
            print("\n[INFO] Swarm paused. Awaiting human approval via the dashboard...")
            # update db explicitly
            conn = db.get_db_connection()
            conn.execute("UPDATE system_state SET awaiting_approval = 1, approved = 0 WHERE id = 1")
            conn.commit()
            conn.close()
            
            while True:
                time.sleep(0.5)
                conn = db.get_db_connection()
                row = conn.execute("SELECT approved, deploy_status FROM system_state WHERE id = 1").fetchone()
                conn.close()
                if row and (row[0] == 1 or row[1] == 'DEPLOYED'):
                    print("[RELEASE_MGR] human_approval_granted. Proceeding to WAF deployment...")
                    break
                elif row and row[1] == 'REJECTED':
                    print("[RELEASE_MGR] human_approval_rejected. Terminating replay.")
                    return
        elif delay:
            time.sleep(delay)

    write_artifacts(scenario)
    print("Replay complete. Open http://localhost:8501 to inspect the dashboard.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Replay the Ensemble AI dashboard workflow.")
    parser.add_argument("--scenario", choices=sorted(SCENARIOS), default="php")
    parser.add_argument("--delay", type=float, default=0.8, help="Seconds between timeline steps.")
    args = parser.parse_args()
    replay(args.scenario, args.delay)


if __name__ == "__main__":
    main()
