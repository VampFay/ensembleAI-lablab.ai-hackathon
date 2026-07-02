# Ensemble AI

Autonomous DevSecOps triage, adversarial patching, and compliance reporting with a 5-agent Band workflow.

Ensemble AI is a portfolio-grade hackathon project built for the Band of Agents Hackathon. It demonstrates how specialized agents can coordinate vulnerability remediation: triage a report, prove exploitability, patch code, audit the fix, re-test the exploit, generate a WAF rule, and produce compliance evidence.

## Why It Exists

Security teams spend too much time moving context between scanners, issue trackers, developers, reviewers, and compliance evidence. Ensemble AI turns that handoff-heavy process into a visible multi-agent workflow where every role has a concrete responsibility and leaves an audit trail.

## Demo Paths

### Option A: No-Credential Dashboard Replay

Use this path for GitHub reviewers, resume readers, and local portfolio demos. It does not require Band credentials or an LLM API key.

```bash
uv sync
uv run python app.py
```

In a second terminal:

```bash
uv run python demo_replay.py --scenario php
```

Open `http://localhost:8501`.

Available scenarios:

```bash
uv run python demo_replay.py --scenario php
uv run python demo_replay.py --scenario ssrf
uv run python demo_replay.py --scenario bola
```

The replay writes the same SQLite telemetry shape used by the live agents, so the dashboard exercises the real WebSocket server, timeline, logs, code diff, WAF artifact, and compliance-report path.

By default, `demo_replay.py` auto-approves the release step so portfolio reviewers are never blocked by a second terminal or a browser click. To demonstrate the human approval gate, run:

```bash
uv run python demo_replay.py --scenario php --interactive-approval
```

Then click Approve or Reject in the dashboard before the approval timeout expires.

### Option B: Full Band Agent Swarm

Use this path when you want the live hackathon workflow.

```bash
cp .env.example .env
cp agent_config.yaml.example agent_config.yaml
```

Then configure:

- `GOOGLE_API_KEY` in `.env`
- five Band External Agent IDs and API keys in `agent_config.yaml`

Run:

```bash
./start.sh
```

Create a Band chat room, invite all five agents, and mention the Triage Agent with one of the prompts in [reproduce.md](reproduce.md).

## Agent Architecture

The live system uses five specialized agents connected through Band:

1. **Triage Agent** maps a vulnerability report to the affected file and code context.
2. **Red Team Agent** writes and runs exploit proofs of concept before and after patching.
3. **Patch Developer** applies targeted code changes and performs syntax validation.
4. **Rigor Auditor** runs SAST and adversarial review before approval.
5. **Release Manager** generates a WAF rule and compliance report for human sign-off.

Band is used as the coordination layer for agent-to-agent handoffs, shared memory, and task state. The local dashboard visualizes the same state through FastAPI, SQLite, and WebSockets.

## Supported Vulnerability Scenarios

| Scenario | Stack | Vulnerability | Target |
| --- | --- | --- | --- |
| Legacy PHP | WordPress-style plugin | PHP object injection via `unserialize()` | `mock_app/legacy_php/plugin_vulnerable.php` |
| Cloud Python | FastAPI service | SSRF to internal metadata endpoints | `mock_app/cloud_python/invoice_service.py` |
| Regulated Node | Express API | BOLA / IDOR on medical records | `mock_app/regulated_node/patient_api.js` |

Run the raw PoCs:

```bash
php scratch/legacy_php/test_deserialization.php
uv run python scratch/cloud_python/poc_ssrf.py
node scratch/regulated_node/poc_bola.js
```

## Technical Highlights

- Band SDK + CrewAI adapter integration for five long-running external agents.
- Deterministic replay mode for reviewers without platform credentials.
- FastAPI dashboard backend with WebSocket state streaming.
- SQLite state store with encrypted sensitive fields.
- Agent tools for code search, file reads, line-based patching, syntax checks, exploit execution, SAST, WAF generation, and compliance reporting.
- Prometheus-compatible `/metrics` endpoint.
- Human approval endpoints for deployment sign-off.
- Dockerfile and Procfile for deployment experiments.

## Repository Layout

```text
.
├── app.py                         # FastAPI dashboard and WebSocket server
├── demo_replay.py                 # Credential-free portfolio replay
├── run_agents.py                  # Live Band/CrewAI agent runner
├── ensemble_ai/
│   ├── agents.py                  # Agent roles, prompts, and tool bindings
│   ├── tools.py                   # Agent tools
│   ├── workflow.py                # Shared telemetry, SAST ingestion, and approval transitions
│   ├── db.py                      # SQLite state, logs, metrics, audit trail
│   ├── crypto.py                  # Fernet encryption helpers
│   └── cve_mapping.py             # CWE/CVSS enrichment helpers
├── frontend/                      # React dashboard
├── mock_app/                      # Vulnerable sample applications
├── scratch/                       # Local PoCs and runtime artifacts
├── waf_rules/                     # Generated virtual patch rules
├── reproduce.md                   # Detailed demo and live-swarm guide
└── RUNBOOK.md                     # Production-hardening notes
```

## Quality Notes

This is a hackathon prototype, but it is structured to be reviewable:

- The no-credential demo keeps the project reproducible after hackathon access expires.
- Live external-service configuration is isolated in `.env` and `agent_config.yaml`, both ignored by git.
- The runbook explicitly separates implemented demo behavior from production hardening work.
- Security-sensitive operations are documented with current limitations, especially exploit sandboxing.

Known production gaps are documented in [RUNBOOK.md](RUNBOOK.md): Docker-based exploit isolation, real multi-tenancy, queueing, Postgres, SSO/RBAC, and high availability.

## Resume Summary

Built a multi-agent DevSecOps remediation prototype using Band, CrewAI, FastAPI, React, SQLite, Semgrep, and WebSockets. The system coordinates five specialized agents to triage vulnerabilities, generate exploit proofs, patch code, audit fixes, verify mitigation, and produce WAF/compliance artifacts across PHP, Python, and Node.js targets.
