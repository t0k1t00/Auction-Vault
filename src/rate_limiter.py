"""
rate_limiter.py - Rate limiting configuration.

Uses slowapi with memory backend for demo/development.
For production, set RATELIMIT_STORAGE_URI=redis://localhost:6379/0
"""

import os
from slowapi import Limiter
from slowapi.util import get_remote_address

RATELIMIT_STORAGE_URI = os.environ.get("RATELIMIT_STORAGE_URI", "memory://")

limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=RATELIMIT_STORAGE_URI,
    default_limits=[f"{os.environ.get('RATE_LIMIT_REQUESTS_GENERAL', '100')}/minute"],
    enabled=os.environ.get("ENVIRONMENT", "development") != "test",
)

RATE_LIMITS = {
    "login": f"{os.environ.get('RATE_LIMIT_REQUESTS_LOGIN', '5')}/minute",
    "register": f"{os.environ.get('RATE_LIMIT_REQUESTS_REGISTER', '3')}/minute",
    "bid": f"{os.environ.get('RATE_LIMIT_REQUESTS_BID', '30')}/minute",
    "item_create": "10/minute",
    "payment_create": "5/minute",
    "refresh": "10/minute",
    "logout": "20/minute",
    "public_list": "30/minute",
}

def rate_limit(key: str):
    """
    Returns a real slowapi limiter decorator.

    Example:
        @app.post("/login")
        @rate_limit("login")
        async def login(request: Request, ...):
            ...
    """
    return limiter.limit(RATE_LIMITS.get(key, "60/minute"))
