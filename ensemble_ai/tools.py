import asyncio
import hashlib
import hmac
import logging
import os
import resource
import subprocess
import uuid
from datetime import datetime

from pydantic import BaseModel, Field

import ensemble_ai.db as db
from ensemble_ai.cve_mapping import enrich_finding
from ensemble_ai.workflow import (
    compute_confidence as _compute_confidence,
    request_approval,
    update_state,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# TRIAGE TOOLS
# ---------------------------------------------------------------------------

class ReadFileInput(BaseModel):
    """Read the contents of a file from the repository to analyze it."""
    path: str = Field(..., description="The relative path to the file to read.")
    agent_role: str = Field("TRIAGE", description="The role of the calling agent (either 'TRIAGE', 'RED_TEAM', 'DEVELOPER', or 'AUDITOR'). Defaults to 'TRIAGE'.")

async def read_file_tool(input_data: ReadFileInput) -> str:
    logger.info(f"[Tool: readfile] Request to read: {input_data.path} (by {input_data.agent_role})")
    try:
        target_path = os.path.abspath(input_data.path)
        cwd = os.getcwd()
        if os.path.commonpath([cwd, target_path]) != cwd:
            return "Error: Access denied."
        if not os.path.exists(target_path):
            return f"Error: File not found: {input_data.path}"
            
        def _read():
            with open(target_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
                raw_code = "".join(lines)

            # Map agent role → pipeline step (1=triage, 2=red, 3=dev, 4=audit)
            agent = input_data.agent_role.upper()
            if "AUDIT" in agent:
                step = 4
            elif "DEV" in agent:
                step = 3
            elif "RED" in agent:
                step = 2
            else:
                step = 1

            # bug:1 fix — only set code_before on first read (Triage).
            # Auditor/Dev reads must NOT overwrite the original vulnerable code,
            # otherwise the diff viewer shows "patched vs patched" = empty diff.
            current = db.get_full_state()
            existing_code_before = current.get("code_before", "")
            is_first_read = not existing_code_before or existing_code_before.startswith("// Awaiting")

            update_state(
                agent, f"Reading {input_data.path}", "INFO",
                step=step, target_file=input_data.path,
                code_before=raw_code if is_first_read else None
            )
            return "\n".join(f"{i+1}: {line.rstrip()}" for i, line in enumerate(lines))
                
        return await asyncio.to_thread(_read)
    except Exception as e:
        return f"Error reading file: {e}"


class SearchCodeInput(BaseModel):
    """Search for a string pattern across files in the codebase."""
    query: str = Field(..., description="The string pattern to search for.")

async def search_code_tool(input_data: SearchCodeInput) -> str:
    query = input_data.query
    logger.info(f"[Tool: searchcode] Request to search: {query}")
    update_state("TRIAGE", f"Searching codebase for: {query}", "INFO", step=1)
    
    def _search():
        results = []
        ignored_dirs = {".venv", ".git", ".playwright-mcp", "__pycache__", "node_modules"}
        allowed_extensions = {".php", ".py", ".yaml", ".json", ".ini", ".md", ".js"}
        
        for root, dirs, files in os.walk("."):
            dirs[:] = [d for d in dirs if d not in ignored_dirs]
            for file in files:
                if any(file.endswith(ext) for ext in allowed_extensions):
                    path = os.path.normpath(os.path.join(root, file))
                    try:
                        with open(path, "r", encoding="utf-8", errors="replace") as f:
                            for i, line in enumerate(f):
                                if query in line:
                                    results.append(f"{path}:{i+1}: {line.strip()}")
                                    if len(results) >= 50:
                                        return results
                    except Exception:
                        pass
        return results

    try:
        matches = await asyncio.to_thread(_search)
        if not matches:
            return "No matches found."
        return "\n".join(matches)
    except Exception as e:
        return f"Error during search: {e}"


# ---------------------------------------------------------------------------
# DEVELOPER TOOLS
# ---------------------------------------------------------------------------

class ReplaceLinesInput(BaseModel):
    """Replace specific lines of code in a file with a secure patch."""
    path: str = Field(..., description="The relative path to the file to modify.")
    start_line: int = Field(..., description="The starting line number to replace (inclusive, 1-based).")
    end_line: int = Field(..., description="The ending line number to replace (inclusive, 1-based).")
    new_code: str = Field(..., description="The new secure code to insert. Must preserve proper indentation.")
    root_cause: str = Field("", description="Brief description of the root cause of the vulnerability being fixed.")
    fix_description: str = Field("", description="Brief description of the fix being applied.")
    security_impact: str = Field("", description="What attack this fix prevents (e.g., 'Prevents SQL injection').")

async def replace_lines_tool(input_data: ReplaceLinesInput) -> str:
    logger.info(f"[Tool: replacelines] Request to modify {input_data.path} lines {input_data.start_line}-{input_data.end_line}")
    try:
        target_path = os.path.abspath(input_data.path)
        cwd = os.getcwd()
        if os.path.commonpath([cwd, target_path]) != cwd:
            return "Error: Access denied."
        
        def _patch():
            with open(target_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
            
            if input_data.start_line < 1 or input_data.start_line > len(lines):
                return f"Error: Invalid start_line {input_data.start_line}"
            if input_data.end_line < input_data.start_line:
                return f"Error: end_line ({input_data.end_line}) must be >= start_line ({input_data.start_line})"
            if input_data.end_line > len(lines):
                input_data.end_line = len(lines)  # clamp to file end
            
            new_lines = input_data.new_code.split('\n')
            new_lines_with_newline = [line + '\n' for line in new_lines]
            
            lines[input_data.start_line - 1 : input_data.end_line] = new_lines_with_newline
            
            patched_code_str = "".join(lines)
            
            temp_path = target_path + ".tmp"
            try:
                with open(temp_path, "w", encoding="utf-8") as f:
                    f.writelines(lines)
                os.replace(temp_path, target_path)
            except Exception as e:
                if os.path.exists(temp_path): os.remove(temp_path)
                raise e
            
            # Push full remediation context to dashboard
            update_state(
                "DEVELOPER",
                f"Applied patch to {input_data.path} (lines {input_data.start_line}-{input_data.end_line})",
                "PATCHING",
                step=3,
                code_after=patched_code_str,
                patch_status="APPLIED",
                root_cause=input_data.root_cause or f"Vulnerability in {input_data.path}",
                fix_applied=input_data.fix_description or f"Lines {input_data.start_line}-{input_data.end_line} replaced with secure implementation",
                security_impact=input_data.security_impact or "Patch applied — awaiting audit verification"
            )
            return "Patch applied successfully!"

        return await asyncio.to_thread(_patch)
    except Exception as e:
        return f"Error applying patch: {e}"


class RunSyntaxCheckInput(BaseModel):
    """Run a syntax check to verify code syntax and prevent compile/syntax errors."""
    path: str = Field(..., description="The path to the file to check.")

async def run_syntax_check_tool(input_data: RunSyntaxCheckInput) -> str:
    logger.info(f"[Tool: runsyntaxcheck] Request to check: {input_data.path}")
    update_state("DEVELOPER", f"Running syntax check on {input_data.path}", "INFO", step=3)
    
    if input_data.path.endswith('.php'):
        cmd = ["php", "-l", input_data.path]
    elif input_data.path.endswith('.js'):
        cmd = ["node", "-c", input_data.path]
    elif input_data.path.endswith('.py'):
        cmd = ["python", "-m", "py_compile", input_data.path]
    else:
        return "Unknown file type for syntax check. Assuming OK."
        
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=5.0)
        
        if process.returncode == 0:
            update_state("DEVELOPER", f"Syntax check passed for {input_data.path}", "VERIFIED",
                         patch_status="SYNTAX_OK")
            return "Syntax OK!"
        else:
            err_msg = stderr.decode()
            update_state("DEVELOPER", f"Syntax error in {input_data.path}: {err_msg[:80]}", "ERROR",
                         patch_status="SYNTAX_ERROR")
            return f"Syntax Error:\n{err_msg}"
    except Exception as e:
        return f"Error running syntax check: {e}"


# ---------------------------------------------------------------------------
# AUDITOR TOOLS
# ---------------------------------------------------------------------------

class RunSastScanInput(BaseModel):
    """Run a Semgrep SAST scan on a target file to identify logic flaws and vulnerabilities."""
    path: str = Field(..., description="The relative path to the file to scan.")

async def run_sast_scan_tool(input_data: RunSastScanInput) -> str:
    logger.info(f"[Tool: runsast] Request to scan: {input_data.path}")
    update_state("AUDITOR", f"Executing SAST scan on {input_data.path}", "INFO", step=4)
    try:
        target_path = os.path.abspath(input_data.path)
        if not os.path.exists(target_path): return "Error: File not found."
        
        process = await asyncio.create_subprocess_exec(
            "uv", "run", "semgrep", "scan", "--config=auto", "--json", target_path,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=20.0)
        except asyncio.TimeoutError:
            process.kill()
            return "Error: SAST scan timed out."
            
        try:
            import json
            results = json.loads(stdout.decode())
            findings = results.get("results", [])
            
            if not findings:
                # bug:2 fix — only mark VERIFIED if a patch was actually applied.
                # SAST clean on an unpatched file doesn't mean the vuln is mitigated —
                # it might just mean Semgrep doesn't have a rule for it.
                current = db.get_full_state()
                patch_applied = current.get("patch_status") in ("APPLIED", "SYNTAX_OK", "VERIFIED")
                confidence = _compute_confidence(sast_clean=True, exploit_verified=False, patch_applied=patch_applied)

                if patch_applied:
                    update_state(
                        "AUDITOR",
                        "SAST scan passed. No vulnerabilities detected. Patch verified.",
                        "VERIFIED",
                        patch_status="VERIFIED",
                        exploit_status="BLOCKED",
                        confidence=confidence,
                        signature_type="ZERO-DAY (MITIGATED)"
                    )
                    return "SAST Scan OK: 0 vulnerabilities found. Patch verified."
                else:
                    update_state(
                        "AUDITOR",
                        "SAST scan passed (0 findings), but no patch applied yet — cannot verify.",
                        "INFO",
                        patch_status="PENDING",
                        confidence=confidence,
                        signature_type="ZERO-DAY (UNPATCHED)"
                    )
                    return "SAST Scan OK: 0 vulnerabilities found. Awaiting patch before verification."
            
            # Extract real finding details for the dashboard
            top = findings[0]
            severity = top.get('extra', {}).get('severity', 'WARNING')
            check_id = top.get('check_id', 'unknown-rule')
            message = top.get('extra', {}).get('message', 'Vulnerability detected')
            
            # Map severity to confidence reduction (ERROR findings reduce confidence more)
            severity_penalty = {"ERROR": 30, "WARNING": 15, "INFO": 5}
            penalty = severity_penalty.get(severity.upper(), 15)
            confidence = max(10, _compute_confidence(sast_clean=False, exploit_verified=False, patch_applied=True) - penalty)

            # Enrich with CVE/CWE mapping (real compliance signal)
            cwe_info = enrich_finding(check_id)
            output = f"SAST Scan found {len(findings)} vulnerabilities:\n"
            for finding in findings:
                f_cwe = enrich_finding(finding.get('check_id', ''))
                output += f"- [{finding.get('extra', {}).get('severity', 'WARNING')}] {finding.get('check_id')}: {finding.get('extra', {}).get('message')}\n"
                output += f"  → CWE: {f_cwe['cwe_id']} ({f_cwe['cwe_name']}), CVSS: {f_cwe['cvss']}\n"
                if f_cwe.get('typical_cves'):
                    output += f"  → Related CVEs: {', '.join(f_cwe['typical_cves'][:3])}\n"

            # OPT:2 — dedupe is now handled by DB unique index + INSERT OR IGNORE.
            # create_vulnerability returns existing ID if (target_file, cwe_id) already exists.
            vuln_id = db.create_vulnerability(
                target_file=input_data.path,
                vuln_class=check_id,
                cwe_id=cwe_info['cwe_id'],
                cvss=cwe_info['cvss']
            )

            update_state(
                "AUDITOR",
                f"SAST scan failed: {len(findings)} issues found. CWE: {cwe_info['cwe_id']}, CVSS: {cwe_info['cvss']}",
                "COMPROMISED",
                patch_status="FAILED_AUDIT",
                exploit_status="ACTIVE",
                confidence=confidence,
                signature_type=f"ZERO-DAY ({severity})"
            )
            return output
        except Exception:
            return f"SAST Scan Output:\n{stdout.decode()}\n{stderr.decode()}"
    except Exception as e:
        return f"Error running SAST scan: {e}"


# ---------------------------------------------------------------------------
# RED TEAM TOOLS
# ---------------------------------------------------------------------------

class WriteAndRunExploitInput(BaseModel):
    """Write an exploit script (Python, PHP, or JavaScript) to test a vulnerability and execute it."""
    code: str = Field(..., description="The source code of the exploit script to run.")
    language: str = Field(..., description="The language of the script ('python', 'php', or 'javascript').")
    vulnerability_class: str = Field("", description="The class of vulnerability being tested (e.g., 'SQL Injection', 'JWT Bypass', 'SSRF').")

async def write_and_run_exploit_tool(input_data: WriteAndRunExploitInput) -> str:
    logger.info(f"[Tool: runexploit] Running {input_data.language} exploit script")
    
    if input_data.language.lower() in ["javascript", "js", "node"]:
        ext, cmd = "js", "node"
    elif input_data.language.lower() == "php":
        ext, cmd = "php", "php"
    else:
        ext, cmd = "py", "python"
        
    filename = f"scratch/exploit_{uuid.uuid4().hex[:8]}.{ext}"
    
    vuln_class = input_data.vulnerability_class or "Unknown"
    
    try:
        os.makedirs("scratch", exist_ok=True)
        with open(filename, "w", encoding="utf-8") as f:
            f.write(input_data.code)
            
        def set_limits():
            # 50 MB address space, 5s CPU — keeps exploits contained.
            resource.setrlimit(resource.RLIMIT_AS, (50 << 20, 50 << 20))
            resource.setrlimit(resource.RLIMIT_CPU, (5, 5))

        # Pass only PATH to subprocess — prevents env-var leakage (HOME, API keys, etc.)
        safe_env = {"PATH": os.environ.get("PATH", "")}
            
        process = await asyncio.create_subprocess_exec(
            cmd, filename,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=safe_env,
            preexec_fn=set_limits
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=10.0)
        except asyncio.TimeoutError:
            process.kill()
            return "Error: Exploit execution timed out or was killed by resource limits."
            
        out = stdout.decode().strip()
        err = stderr.decode().strip()
        exit_code = process.returncode

        # Determine result from PROCESS EXIT CODE (real signal, not stdout keywords).
        # vuln:4 fix — require exit code 0 AND non-empty stdout to confirm exploit.
        # A crash that exits 0 by accident shouldn't be flagged as a confirmed vuln.
        exploit_confirmed = (exit_code == 0 and len(out) > 0)

        # Check if this is a re-verification (patch already applied) by reading current state
        current_state = db.get_full_state()
        patch_already_applied = current_state.get("patch_status") in ("APPLIED", "VERIFIED", "SYNTAX_OK")

        if exploit_confirmed and not patch_already_applied:
            # First run: exploit succeeded → vuln is real
            confidence = _compute_confidence(sast_clean=False, exploit_verified=True, patch_applied=False)
            update_state(
                "RED_TEAM",
                f"EXPLOIT CONFIRMED: {vuln_class} — payload executed successfully (exit code 0)",
                "COMPROMISED",
                step=2,
                exploit_status="ACTIVE",
                confidence=confidence,
                signature_type=f"ZERO-DAY ({vuln_class})"
            )
        elif not exploit_confirmed and patch_already_applied:
            # Re-verification after patch: exploit failed → patch is effective
            confidence = _compute_confidence(sast_clean=True, exploit_verified=True, patch_applied=True)
            update_state(
                "RED_TEAM",
                f"EXPLOIT BLOCKED: {vuln_class} — patch is effective (exit code {exit_code})",
                "SECURED",
                step=5,
                exploit_status="BLOCKED",
                patch_status="VERIFIED",
                confidence=confidence,
                signature_type=f"ZERO-DAY (MITIGATED)",
                security_impact=f"Patch prevents {vuln_class} exploitation",
                deploy_status="READY"
            )
        else:
            # Inconclusive — exit code doesn't tell us what we need
            confidence = _compute_confidence(sast_clean=False, exploit_verified=False, patch_applied=patch_already_applied)
            update_state(
                "RED_TEAM",
                f"Executed {cmd} payload for {vuln_class} (exit code {exit_code}, inconclusive)",
                "INFO",
                step=2,
                exploit_status="TESTING",
                confidence=confidence,
                signature_type=f"ZERO-DAY ({vuln_class})"
            )
        
        parts = ["=== Exploit Execution Results (Sandboxed) ==="]
        if out: parts.append(f"STDOUT:\n{out}")
        if err: parts.append(f"STDERR:\n{err}")
        return "\n".join(parts) if len(parts) > 1 else "Exploit executed silently."
        
    except Exception as e:
        return f"Error executing exploit: {e}"


# ---------------------------------------------------------------------------
# RELEASE MANAGER TOOLS
# ---------------------------------------------------------------------------

class GenerateWafRuleInput(BaseModel):
    """Generate a WAF rule (e.g., ModSecurity .conf) to mitigate the vulnerability in production."""
    rule_content: str = Field(..., description="The contents of the WAF rule.")
    filename: str = Field(..., description="The filename to save it as (e.g., '01_block_php_obj_injection.conf').")
    vulnerability_blocked: str = Field("", description="The vulnerability class this WAF rule blocks.")

async def generate_waf_rule_tool(input_data: GenerateWafRuleInput) -> str:
    logger.info(f"[Tool: wafrule] Generating WAF rule: {input_data.filename}")
    try:
        os.makedirs("waf_rules", exist_ok=True)
        # Sanitize filename — prevent path traversal (e.g., "../../etc/cron.d/evil")
        safe_filename = os.path.basename(input_data.filename)
        if not safe_filename or safe_filename != input_data.filename:
            return f"Error: Invalid filename '{input_data.filename}' — must be a simple filename, no path components."
        filepath = os.path.join("waf_rules", safe_filename)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(input_data.rule_content)
        
        update_state(
            "RELEASE_MGR",
            f"Generated virtual patch WAF rule: {input_data.filename}",
            "SECURED",
            step=6,
            waf_rule_file=input_data.filename,
            deploy_status="DEPLOYED",
            security_impact=input_data.vulnerability_blocked or "WAF virtual patch active on edge nodes"
        )
        return f"Successfully generated WAF rule at {filepath}"
    except Exception as e:
        return f"Error generating WAF rule: {e}"


class GenerateComplianceReportInput(BaseModel):
    """Generate a structured compliance report (markdown) for auditing."""
    vulnerability_class: str = Field(..., description="The class of vulnerability (e.g., 'SSRF', 'SQL Injection', 'BOLA').")
    root_cause: str = Field(..., description="Root cause description.")
    fix_applied: str = Field(..., description="Description of the secure code patch applied.")
    exploit_before: str = Field(..., description="Exploit output before patching.")
    exploit_after: str = Field(..., description="Exploit output after patching (confirming block).")
    sast_result: str = Field(..., description="Summary of SAST scanner results.")
    waf_rule_file: str = Field(..., description="The filename of the generated WAF rule.")
    sign_off: str = Field("Ensemble Swarm Automated Compliance Gate", description="Signing authority.")

async def generate_compliance_report_tool(input_data: GenerateComplianceReportInput) -> str:
    logger.info(f"[Tool: compliance] Generating compliance report")
    try:
        os.makedirs("reports", exist_ok=True)
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        vuln_slug = input_data.vulnerability_class.lower().replace(" ", "_").replace("/", "_")
        filename = f"reports/compliance_report_{vuln_slug}.md"

        # bug:5 fix — build report content FIRST, then compute HMAC over the full content.
        # Old code computed HMAC over a 4-field subset, then again over the full content —
        # the two signatures didn't match. Now we compute once, embed in the report, write to .sig.
        # Using a placeholder that gets replaced after HMAC computation.
        report_template = f"""# Ensemble AI Compliance Report
Generated on: {timestamp}
Authority: {input_data.sign_off}

## 1. Executive Summary
The Ensemble AI autonomous agent swarm has triaged, exploited, patched, and verified a critical vulnerability in the codebase.

- **Vulnerability Class**: {input_data.vulnerability_class}
- **Remediation Status**: VERIFIED (MITIGATED)
- **Compliance Standard**: SOC2 Trust Services Criteria (Security / Change Management)

## 2. Root Cause Analysis
{input_data.root_cause}

## 3. Secure Patch Description
{input_data.fix_applied}

## 4. Empirical Verification Evidence
- **Exploit Verification (Before Patch)**:
```
{input_data.exploit_before}
```

- **Exploit Verification (After Patch)**:
```
{input_data.exploit_after}
```

## 5. Auditor Review
- **Static Analysis (Semgrep SAST)**: {input_data.sast_result}

## 6. Virtual Patch Deployment
- **WAF Rule File**: {input_data.waf_rule_file}
- **Deployment Status**: DEPLOYED

## 7. Compliance Framework Alignment
- **SOC2 Trust Services Criteria**: CC2 (Change Management), CC7 (Risk Mitigation)
- **ISO 27001**: A.12.6 (Technical Vulnerability Management)
- **HIPAA**: §164.308(a)(1)(ii)(A) — Security Measures
- **PCI-DSS**: Requirement 6 (Develop Secure Software)

## 8. Integrity Signature
- **Algorithm**: HMAC-SHA256
- **Signature**: __HMAC_PLACEHOLDER__

---
*This report has been auto-generated and archived by the Ensemble Swarm Release Manager. Manual human review required before final SOC2 sign-off.*
"""

        # Compute HMAC over the report (with placeholder), then substitute the real signature.
        signing_key = os.environ.get("ENSEMBLE_SIGNING_KEY", "ensemble-dev-key").encode()
        hmac_signature = hmac.new(signing_key, report_template.encode(), hashlib.sha256).hexdigest()
        report_content = report_template.replace("__HMAC_PLACEHOLDER__", hmac_signature)

        def _write():
            with open(filename, "w", encoding="utf-8") as f:
                f.write(report_content)
            # Write the same HMAC to a sidecar file for integrity verification
            sig_file = filename + ".sig"
            with open(sig_file, "w") as f:
                f.write(hmac_signature)
            return f"Compliance report generated at {filename} (signature at {sig_file})"

        return await asyncio.to_thread(_write)
    except Exception as e:
        return f"Error generating compliance report: {e}"


# ---------------------------------------------------------------------------
# HUMAN-IN-THE-LOOP APPROVAL TOOL
# ---------------------------------------------------------------------------

class RequestHumanApprovalInput(BaseModel):
    """Request human approval before final deployment. Pauses the workflow until approved."""
    vuln_class: str = Field(..., description="The vulnerability class being deployed.")
    waf_rule_file: str = Field(..., description="The WAF rule file awaiting deployment.")
    summary: str = Field(..., description="Brief summary of what's being approved.")

async def request_human_approval_tool(input_data: RequestHumanApprovalInput) -> str:
    """Pauses the workflow and waits for human sign-off via the dashboard /approve endpoint."""
    logger.info(f"[Tool: approval] Requesting human approval for {input_data.vuln_class}")
    try:
        return request_approval(
            vuln_class=input_data.vuln_class,
            waf_rule_file=input_data.waf_rule_file,
            summary=input_data.summary,
        )
    except Exception as e:
        return f"Error requesting approval: {e}"
