import requests
from loguru import logger


def log_response(r: requests.Response, *args, **kwargs):
    logger.debug(f"Url: {r.url}")
    logger.debug(f"Status Code: {r.status_code}")
    logger.debug(f"Elapsed Time: {r.elapsed.total_seconds()}")
    logger.debug(f"Headers: {r.headers}")

    content_type = r.headers.get("Content-Type", "")
    if "application/json" in content_type:
        logger.trace(f"Body: {r.json()}")
    else:
        truncate_chars = 120
        truncated = len(r.content) > truncate_chars
        truncated_content = r.content[:truncate_chars]
        if truncated:
            logger.trace(
                f"Body: {truncated_content}... (truncated, {len(r.content)} bytes total"
            )
        else:
            logger.trace(f"Body: {r.content}")


session = requests.Session()
session.hooks["response"].append(log_response)
