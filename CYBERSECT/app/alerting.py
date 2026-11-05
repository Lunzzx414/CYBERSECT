import logging
from typing import Any

import httpx

from app.config import settings


LOGGER = logging.getLogger(__name__)


def _headers() -> dict[str, str]:
    return {"X-AIR-DS-KEY": settings.API_KEY}


def send_alert(payload: dict[str, Any]) -> None:
    try:
        with httpx.Client(timeout=2.0) as client:
            response = client.post(settings.ALERT_API_URL, headers=_headers(), json=payload)
    except httpx.RequestError:
        LOGGER.exception("Could not deliver a security alert to the AIR-DS API.")
        return
    if not response.is_success:
        LOGGER.error(
            "AIR-DS API rejected a security alert with HTTP %s.",
            response.status_code,
        )


async def send_alert_async(payload: dict[str, Any]) -> None:
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            response = await client.post(
                settings.ALERT_API_URL,
                headers=_headers(),
                json=payload,
            )
    except httpx.RequestError:
        LOGGER.exception("Could not deliver a security alert to the AIR-DS API.")
        return
    if not response.is_success:
        LOGGER.error(
            "AIR-DS API rejected a security alert with HTTP %s.",
            response.status_code,
        )
