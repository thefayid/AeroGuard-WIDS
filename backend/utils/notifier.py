import httpx
import asyncio
from backend.utils.logger import get_logger

logger = get_logger(__name__)

WEBHOOK_URL = None # Set this to a Slack/Discord webhook URL if desired

async def send_alert_webhook(title: str, description: str, metadata: dict):
    if not WEBHOOK_URL:
        return
        
    payload = {
        "content": f"**🚨 {title}**\n{description}\n```json\n{metadata}\n```"
    }
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(WEBHOOK_URL, json=payload, timeout=5.0)
            if response.status_code >= 400:
                logger.error(f"Failed to send webhook: {response.text}")
    except Exception as e:
        logger.error(f"Webhook dispatch error: {e}")
