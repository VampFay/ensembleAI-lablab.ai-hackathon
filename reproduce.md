# Vulnerability Reproduction & Swarm Execution Guide

This guide covers two paths:

1. A deterministic replay that works without Band or LLM credentials.
2. The full 5-agent Band swarm used for the hackathon prototype.

---

## 1. Setup

Synchronize the project dependencies and Python virtual environment:
```bash
uv sync
```

Ensure your local system has the required runtimes (`php`, `python`, `node`):
```bash
php -v
python --version
node -v
```

---

## 2. No-Credential Dashboard Replay

Start the dashboard:

```bash
uv run python app.py
```

In another terminal, replay one workflow:

```bash
uv run python demo_replay.py --scenario php
uv run python demo_replay.py --scenario ssrf
uv run python demo_replay.py --scenario bola
```

Open `http://localhost:8501`. The replay writes the same SQLite telemetry shape that the live agents write, so the React dashboard, WebSocket updates, code diff, timeline, WAF output, and compliance report path can be inspected without external services.

## 3. Local Vulnerability PoCs

To demonstrate that the Ensemble AI swarm is language and framework agnostic, we have provided three distinct enterprise vulnerability scenarios.

### Scenario A: Legacy PHP (WordPress Object Injection)
*   **Target:** `mock_app/legacy_php/plugin_vulnerable.php`
*   **Vulnerability:** Unauthenticated PHP Object Injection via `unserialize()`.
*   **Run the PoC:** 
    ```bash
    php scratch/legacy_php/test_deserialization.php
    ```
*   **Swarm Prompt:** `@Triage Agent A vulnerability was reported in mock_app/legacy_php/plugin_vulnerable.php. It has an unauthenticated AJAX action update_profile_data that unserializes user inputs. Please investigate and pass to the Red Team.`

### Scenario B: Cloud Python (FastAPI SSRF)
*   **Target:** `mock_app/cloud_python/invoice_service.py`
*   **Vulnerability:** Server-Side Request Forgery (SSRF) allowing internal AWS metadata access.
*   **Run the PoC:** 
    ```bash
    uv run python scratch/cloud_python/poc_ssrf.py
    ```
*   **Swarm Prompt:** `@Triage Agent We received a bug bounty report for mock_app/cloud_python/invoice_service.py. The fetch_receipt endpoint is vulnerable to SSRF. Please investigate and pass to the Red Team.`

### Scenario C: Regulated Node (Express.js BOLA/IDOR)
*   **Target:** `mock_app/regulated_node/patient_api.js`
*   **Vulnerability:** Broken Object Level Authorization (BOLA). Users can access medical records they don't own.
*   **Run the PoC:** 
    ```bash
    node scratch/regulated_node/poc_bola.js
    ```
*   **Swarm Prompt:** `@Triage Agent A critical BOLA vulnerability exists in mock_app/regulated_node/patient_api.js. Users can fetch other patients' records because the owner ID is not verified against the token. Please investigate and pass to the Red Team.`

---

## 4. Running the 5-Agent Band Swarm

### Step A: Configure API Credentials
Create your configuration files from the templates:
```bash
cp .env.example .env
cp agent_config.yaml.example agent_config.yaml
```
1. Add your `GOOGLE_API_KEY` to `.env`.
2. Create **five** External Agents in your [Band Agents Console](https://app.band.ai/agents):
   * **Triage Agent**, **Red Team Agent**, **Patch Developer**, **Rigor Auditor**, **Release Manager**.
3. Paste the Agent UUIDs and API Keys generated into `agent_config.yaml`.

### Step B: Start the Command Center
You can launch the entire stack using the provided bash script. This will sync dependencies, start the agent swarm in the background, and open the visual dashboard:
```bash
./start.sh
```
*(Press `Ctrl+C` to gracefully shut down the agents and the dashboard when you are finished.)*

### Step C: Trigger the Flow
1. Go to the [Band Chats](https://app.band.ai/chats).
2. Create a chat room and invite all **five agents**.
3. Pick one of the **Swarm Prompts** from Section 2 above and mention `@Triage Agent` in the chat.
4. Watch the agents communicate, execute dynamic exploits, apply the patch, generate WAF rules, and perform adversarial review!
