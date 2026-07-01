#!/bin/bash
set -euo pipefail

# ─────────────────────────────────────────────────────────
#  TERMINAL LOG — captures this run's full output
#  Saved to: terminal-logs/run_latest.txt (overwritten each run)
# ─────────────────────────────────────────────────────────
mkdir -p terminal-logs
exec > >(tee terminal-logs/run_latest.txt) 2>&1
echo "[LOG] Session started: $(date '+%Y-%m-%d %H:%M:%S')"
echo "[LOG] Saving terminal output → terminal-logs/run_latest.txt"
echo ""

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

DASHBOARD_PORT=8501
DASHBOARD_URL="http://localhost:${DASHBOARD_PORT}"

# Track all child PIDs for clean shutdown
PIDS=()

cleanup() {
    echo -e "\n${RED}${BOLD}⏹  Shutting down Ensemble AI...${NC}"
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null && echo "  ↳ Killed PID $pid" || true
    done
    echo -e "${GREEN}✅ All processes stopped. Goodbye.${NC}"
    exit 0
}
trap cleanup SIGINT SIGTERM

# ── Banner ────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${BLUE}"
echo "  ███████╗███╗   ██╗███████╗███████╗███╗   ███╗██████╗ ██╗     ███████╗"
echo "  ██╔════╝████╗  ██║██╔════╝██╔════╝████╗ ████║██╔══██╗██║     ██╔════╝"
echo "  █████╗  ██╔██╗ ██║███████╗█████╗  ██╔████╔██║██████╔╝██║     █████╗  "
echo "  ██╔══╝  ██║╚██╗██║╚════██║██╔══╝  ██║╚██╔╝██║██╔══██╗██║     ██╔══╝  "
echo "  ███████╗██║ ╚████║███████║███████╗██║ ╚═╝ ██║██████╔╝███████╗███████╗"
echo "  ╚══════╝╚═╝  ╚═══╝╚══════╝╚══════╝╚═╝     ╚═╝╚═════╝ ╚══════╝╚══════╝"
echo -e "${NC}"
echo -e "  ${BOLD}AUTONOMOUS SWARM COMMAND — Booting...${NC}"
echo -e "  ${BLUE}────────────────────────────────────────────────────────${NC}"
echo ""

# ── STEP 0: Config checks ─────────────────────────────────
echo -e "${YELLOW}[0/5] Checking configuration...${NC}"

if [ ! -f ".env" ]; then
    echo -e "${RED}  [ERROR] .env file not found.${NC}"
    if [ -f ".env.example" ]; then
        echo -e "  Run: ${BOLD}cp .env.example .env${NC} then fill in your keys."
    fi
    exit 1
fi

if [ ! -f "agent_config.yaml" ]; then
    echo -e "${RED}  [ERROR] agent_config.yaml not found.${NC}"
    if [ -f "agent_config.yaml.example" ]; then
        echo -e "  Run: ${BOLD}cp agent_config.yaml.example agent_config.yaml${NC} then add Band agent IDs."
    fi
    exit 1
fi

# Warn if Gemini key is a placeholder
if grep -q "your-google-ai-studio-key-here" .env 2>/dev/null; then
    echo -e "${YELLOW}  [WARNING] GOOGLE_API_KEY in .env is still a placeholder.${NC}"
    echo -e "  Agents will fail to run without a real key."
fi

# Warn if Band agent IDs are placeholders
if grep -q "uuid-from-band\|<YOUR" agent_config.yaml 2>/dev/null; then
    echo -e "${YELLOW}  [WARNING] Band agent IDs in agent_config.yaml look like placeholders.${NC}"
    echo -e "  The agent swarm will connect but fail to receive tasks."
    
    AUTO_APPROVE=false
    if [ ! -t 0 ]; then
        AUTO_APPROVE=true
    fi
    for arg in "$@"; do
        if [ "$arg" = "-y" ] || [ "$arg" = "--yes" ]; then
            AUTO_APPROVE=true
        fi
    done

    if [ "$AUTO_APPROVE" = "true" ]; then
        echo "  [INFO] Non-interactive run or auto-approve enabled. Continuing..."
    else
        echo -ne "  Continue anyway? [y/N]: "
        read -r reply
        if [[ ! "$reply" =~ ^[Yy]$ ]]; then
            echo "Aborting."
            exit 1
        fi
    fi
fi

# Check if port is already occupied (lsof first, ss fallback, python last-resort)
_port_in_use() {
    if command -v lsof &>/dev/null; then
        lsof -Pi ":${DASHBOARD_PORT}" -sTCP:LISTEN -t &>/dev/null
    elif command -v ss &>/dev/null; then
        ss -ltn "sport = :${DASHBOARD_PORT}" 2>/dev/null | grep -q ":${DASHBOARD_PORT}"
    else
        python3 -c "import socket,sys; s=socket.socket(); s.settimeout(0.5); sys.exit(0 if s.connect_ex(('127.0.0.1', ${DASHBOARD_PORT})) == 0 else 1)" 2>/dev/null
    fi
}
if _port_in_use; then
    echo -e "${RED}  [ERROR] Port ${DASHBOARD_PORT} is already in use.${NC}"
    echo "  Kill the existing process or change DASHBOARD_PORT in this script."
    exit 1
fi

echo -e "${GREEN}  ✓ Configuration OK${NC}"

# ── STEP 1: Frontend build ────────────────────────────────
echo ""
echo -e "${YELLOW}[1/5] Building Frontend UI...${NC}"
(
    cd frontend
    if [ ! -d "node_modules" ]; then
        echo -e "  Installing npm dependencies (first run)..."
        npm install --silent
    fi
    npm run build --silent
)
echo -e "${GREEN}  ✓ Frontend built → frontend/dist/${NC}"

# ── STEP 2: Python deps ───────────────────────────────────
echo ""
echo -e "${YELLOW}[2/5] Syncing Python dependencies (uv sync)...${NC}"
uv sync --quiet
echo -e "${GREEN}  ✓ Python environment ready${NC}"

# ── STEP 3: Reset stale DB ────────────────────────────────
echo ""
echo -e "${YELLOW}[3/5] Resetting session state (SQLite DB)...${NC}"
mkdir -p scratch
rm -f scratch/state.db
echo -e "${GREEN}  ✓ Fresh session state initialized${NC}"

# ── STEP 4: Start Agent Swarm ─────────────────────────────
echo ""
echo -e "${YELLOW}[4/5] Starting 5-Agent Swarm (run_agents.py)...${NC}"
PYTHONPATH=. uv run python run_agents.py 2>&1 | tee scratch/agents.log &
AGENT_PID=$!
PIDS+=("$AGENT_PID")
echo -e "${GREEN}  ✓ Agent swarm started (PID: ${AGENT_PID}) — logging to terminal + scratch/agents.log${NC}"

# Brief pause so agents register before the server starts
sleep 2

# ── STEP 5: Start FastAPI WebSocket Server ─────────────────
echo ""
echo -e "${YELLOW}[5/5] Starting FastAPI C2 Server (app.py)...${NC}"
PYTHONPATH=. uv run python app.py 2>&1 | tee scratch/server.log &
SERVER_PID=$!
PIDS+=("$SERVER_PID")
echo -e "${GREEN}  ✓ FastAPI server starting (PID: ${SERVER_PID}) — logging to terminal + scratch/server.log${NC}"

# ── Wait for server to be ready ───────────────────────────
echo ""
echo -ne "  Waiting for server to come up"
MAX_WAIT=15
for i in $(seq 1 $MAX_WAIT); do
    sleep 1
    if curl -sf "${DASHBOARD_URL}" -o /dev/null 2>/dev/null; then
        echo -e " ${GREEN}✓${NC}"
        break
    fi
    echo -n "."
    if [ "$i" -eq "$MAX_WAIT" ]; then
        echo -e " ${YELLOW}(timeout — server may still be starting)${NC}"
    fi
done

# ── Open browser ──────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}${BOLD}║  ✅  ENSEMBLE AI IS LIVE                             ║${NC}"
echo -e "${GREEN}${BOLD}║                                                      ║${NC}"
echo -e "${GREEN}${BOLD}║  Dashboard  →  ${DASHBOARD_URL}               ║${NC}"
echo -e "${GREEN}${BOLD}║  Agents     →  https://app.band.ai/chats             ║${NC}"
echo -e "${GREEN}${BOLD}║  Agent Logs →  scratch/agents.log                   ║${NC}"
echo -e "${GREEN}${BOLD}║  Server Log →  scratch/server.log                   ║${NC}"
echo -e "${GREEN}${BOLD}║                                                      ║${NC}"
echo -e "${GREEN}${BOLD}║  Press Ctrl+C to stop everything.                    ║${NC}"
echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════╝${NC}"
echo ""

# Auto-open browser (macOS / Linux)
if command -v open &>/dev/null; then
    open "${DASHBOARD_URL}"
elif command -v xdg-open &>/dev/null; then
    xdg-open "${DASHBOARD_URL}"
fi

# ── Keep alive until Ctrl+C ───────────────────────────────
wait "${SERVER_PID}"
