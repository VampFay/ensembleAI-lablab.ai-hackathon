import asyncio
import logging
import os
import random
from dotenv import load_dotenv

from band import Agent, AdapterFeatures, Emit, Capability
from band.adapters import CrewAIAdapter
from band.config import load_agent_config

from ensemble_ai.agents import get_agent_configs
import ensemble_ai.crypto as crypto
import ensemble_ai.db as db

# Configure logging
logging.basicConfig(level=logging.INFO)
logging.getLogger("band").setLevel(logging.INFO)
logger = logging.getLogger(__name__)


def _bootstrap_env() -> str:
    """Load .env with override=True so it beats any shell-level vars.
    Supports key rotation: GOOGLE_API_KEY can be comma-separated for round-robin.
    Also removes Ollama/local-LLM base URL overrides that cause LiteLLM to route to localhost.
    """
    load_dotenv(override=True)

    # --- Purge Ollama / local-LLM base URL overrides at the process level ---
    for _var in ("OPENAI_BASE_URL", "OPENAI_API_KEY", "ANTHROPIC_BASE_URL",
                 "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "GOOGLE_GEMINI_BASE_URL"):
        old = os.environ.pop(_var, None)
        if old:
            logger.warning(f"Removed shell-injected override: {_var}={old[:40]!r}")

    # Key rotation: GOOGLE_API_KEY can be "key1,key2,key3" — pick one at random.
    # This spreads load across multiple Gemini projects to avoid 429 storms.
    google_keys = [k.strip() for k in os.getenv("GOOGLE_API_KEY", "").split(",") if k.strip() and not k.strip().startswith("ollama")]
    if google_keys:
        chosen = random.choice(google_keys)
        os.environ["GEMINI_API_KEY"] = chosen
        logger.info(f"Gemini key injected from GOOGLE_API_KEY pool ({len(google_keys)} keys, using {chosen[:12]}...)")
    gemini_key = os.getenv("GEMINI_API_KEY", "")
    if not gemini_key or gemini_key.startswith("ollama"):
        logger.error("No valid GEMINI_API_KEY! Set GOOGLE_API_KEY in .env (comma-separated for rotation).")
        raise SystemExit(1)
    return gemini_key


async def start_agent(config_name: str, role: str, goal: str, backstory: str, custom_section: str, ws_url: str, rest_url: str, additional_tools: list = None, model: str = "gemini/gemini-2.5-flash-lite"):
    max_retries = 3
    retry_delay = 5  # seconds

    for attempt in range(1, max_retries + 1):
        try:
            agent_id, api_key = load_agent_config(config_name)
            if not agent_id or "<" in agent_id or not api_key or "<" in api_key:
                raise ValueError(
                    f"Agent credentials for '{config_name}' are missing or use default placeholders in agent_config.yaml."
                )
        except Exception as e:
            logger.error(f"Failed to load credentials for {config_name}: {e}")
            raise

        adapter = CrewAIAdapter(
            model=model,
            role=role,
            goal=goal,
            backstory=backstory,
            custom_section=custom_section,
            features=AdapterFeatures(
                emit={Emit.EXECUTION},
                capabilities={Capability.MEMORY}
            ),
            additional_tools=additional_tools,
            verbose=True,
        )

        agent = Agent.create(
            adapter=adapter,
            agent_id=agent_id,
            api_key=api_key,
            ws_url=ws_url,
            rest_url=rest_url,
        )

        logger.info(f"Starting agent: {role} ({config_name}) — attempt {attempt}/{max_retries}...")
        try:
            await agent.run()
            return  # exited cleanly
        except Exception as e:
            err_str = str(e)
            # Handle Gemini 429 rate-limit: respect the retry-delay from the API
            if "429" in err_str or "RESOURCE_EXHAUSTED" in err_str:
                logger.warning(f"Rate limited on {role}, backing off {retry_delay}s (attempt {attempt}/{max_retries})")
                await asyncio.sleep(retry_delay)
                retry_delay *= 2  # exponential backoff: 5s, 10s, 20s
                continue
            # Handle WebSocket disconnects: reconnect with backoff
            if "WebSocket" in err_str or "ConnectionClosed" in err_str or "Disconnected" in err_str:
                logger.warning(f"WebSocket dropped for {role}, reconnecting in {retry_delay}s (attempt {attempt}/{max_retries})")
                await asyncio.sleep(retry_delay)
                retry_delay *= 2
                continue
            # Other errors: retry up to max_retries
            if attempt < max_retries:
                logger.error(f"Error in {role} (attempt {attempt}): {e}. Retrying in {retry_delay}s...")
                await asyncio.sleep(retry_delay)
                continue
            logger.error(f"Error in {role} after {max_retries} attempts: {e}")
            raise

async def main():
    _bootstrap_env()
    crypto.init_key()  # Initialize encryption key from env (before any DB writes)
    db.init_db()

    ws_url = os.getenv("BAND_WS_URL", "wss://app.band.ai/api/v1/socket/websocket")
    rest_url = os.getenv("BAND_REST_URL", "https://app.band.ai/")

    logger.info("Initializing Ensemble AI 5-Agent Swarm...")
    
    agent_configs = get_agent_configs()
    tasks = []
    
    for config in agent_configs:
        tasks.append(
            asyncio.create_task(
                start_agent(config.name, config.role, config.goal, config.backstory, config.custom_instructions, ws_url, rest_url, config.tools, config.model)
            )
        )
    
    try:
        await asyncio.gather(*tasks)
    except (asyncio.CancelledError, KeyboardInterrupt):
        logger.info("Shutdown requested. Cancelling agent swarm...")
    except Exception as e:
        logger.error(f"Error occurred in agent swarm: {e}")
        raise
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        logger.info("Agent swarm successfully stopped.")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as e:
        logger.error(f"Fatal error during agent swarm execution: {e}")
        exit(1)
