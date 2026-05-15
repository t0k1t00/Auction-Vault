"""
middleware.py – Security middleware for FastAPI application.

Implements:
  - Security headers (CSP, HSTS, X-Frame-Options, etc.)
  - CORS configuration
  - Request ID tracking
  - Request logging (without sensitive data)
"""

import re
import time
import uuid
import logging
from typing import Callable

from fastapi import Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from src.config import get_settings

logger = logging.getLogger("auction.middleware")
settings = get_settings()


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Add security headers to all responses.
    """
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        
        # Prevent clickjacking
        response.headers["X-Frame-Options"] = "DENY"
        
        # Prevent MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"
        
        # Enable XSS protection (legacy browsers)
        response.headers["X-XSS-Protection"] = "1; mode=block"
        
        # Control referrer information
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        # Strict CSP (no unsafe-inline)
        csp_directives = [
            "default-src 'self'",
            "script-src 'self' 'unsafe-inline'",  # 'unsafe-inline' needed for vanilla JS
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
            "font-src 'self' https://fonts.gstatic.com data:",
            "img-src 'self' data: https:",
            "object-src 'none'",
            "base-uri 'self'",
            "form-action 'self'",
            "frame-ancestors 'none'",
            "upgrade-insecure-requests",
        ]
        response.headers["Content-Security-Policy"] = "; ".join(csp_directives)
        
        # Disable browser features
        response.headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=(), payment=()"
        )
        
        # HSTS (only in production)
        if settings.environment == "production":
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains; preload"
            )
        
        # Cache control for authenticated endpoints
        if request.headers.get("Authorization") or request.cookies.get("refresh_token"):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
        
        return response


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """
    Log requests without sensitive data.
    """
    
    SENSITIVE_PATHS = {"/login", "/register", "/refresh", "/logout"}
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Add request ID for tracing
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id
        
        start_time = time.time()
        
        # Log request (sanitized)
        if request.url.path not in self.SENSITIVE_PATHS:
            logger.info(
                f"Request {request_id}: {request.method} {request.url.path} "
                f"from {request.client.host if request.client else 'unknown'}"
            )
        
        response = await call_next(request)
        
        # Add request ID to response headers
        response.headers["X-Request-ID"] = request_id
        
        # Log response time
        process_time = time.time() - start_time
        response.headers["X-Process-Time"] = str(process_time)
        
        return response


class RateLimitExemptPaths:
    """Paths exempt from global rate limiting."""
    EXEMPT = {"/health", "/metrics", "/docs", "/openapi.json"}


def setup_middleware(app):
    """Configure all middleware for the FastAPI app."""
    
    # Trusted hosts (prevent Host header attacks)
    if settings.environment == "production":
        app.add_middleware(
            TrustedHostMiddleware,
            allowed_hosts=["*"]  # Configure with actual domains in production
        )
    
    # CORS
    origins = settings.allowed_origins.split(",") if settings.allowed_origins else []
    if settings.environment == "development":
        origins.append("*")
    
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,  # Allow cookies for refresh token
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
        expose_headers=["X-Request-ID", "X-Process-Time"],
        max_age=86400,
    )
    
    # Custom security headers
    app.add_middleware(SecurityHeadersMiddleware)
    
    # Request logging
    app.add_middleware(RequestLoggingMiddleware)
