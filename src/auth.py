"""
auth.py – Authentication with refresh rotation and reuse detection.
"""

import os
import uuid
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, Tuple

from fastapi import Depends, HTTPException, status, Request, Response
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from sqlalchemy import and_

from src.database import get_db
from src.models import User, TokenBlacklist, AuditLog
from src.config import get_settings

logger = logging.getLogger("auction.auth")
settings = get_settings()

# ─────────────────────────────────────────────────────────────
# Password hashing
# ─────────────────────────────────────────────────────────────

pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__rounds=settings.bcrypt_rounds,
)


def hash_password(plain: str) -> str:
    return pwd_context.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


# ─────────────────────────────────────────────────────────────
# JWT Helpers
# ─────────────────────────────────────────────────────────────

def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _utcnow_aware() -> datetime:
    return datetime.now(timezone.utc)


def _create_token(data: Dict[str, Any], expires_delta: timedelta, token_type: str) -> str:
    """Create a JWT token with standard claims."""
    payload = data.copy()
    now = _utcnow_aware()
    payload.update({
        "iat": int(now.timestamp()),
        "exp": int((now + expires_delta).timestamp()),
        "jti": uuid.uuid4().hex,
        "type": token_type,
    })
    return jwt.encode(payload, settings.secret_key, algorithm=settings.algorithm)


def create_access_token(data: Dict[str, Any]) -> str:
    """Create short-lived access token."""
    return _create_token(
        data,
        timedelta(minutes=settings.access_token_expire_minutes),
        "access"
    )


def create_refresh_token(data: Dict[str, Any]) -> str:
    """Create refresh token."""
    return _create_token(
        data,
        timedelta(days=settings.refresh_token_expire_days),
        "refresh"
    )


def decode_token(token: str) -> Dict[str, Any]:
    """Decode and validate JWT token."""
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        return payload
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )


def revoke_token(jti: str, expires_at_timestamp: int, db: Session) -> None:
    """Add token to blacklist."""
    expires_at = datetime.fromtimestamp(expires_at_timestamp, tz=timezone.utc).replace(tzinfo=None)
    existing = db.query(TokenBlacklist).filter(TokenBlacklist.jti == jti).first()
    if not existing:
        db.add(TokenBlacklist(jti=jti, expires_at=expires_at))
        db.commit()


def is_token_revoked(jti: str, db: Session) -> bool:
    """Check if token is blacklisted."""
    return db.query(TokenBlacklist).filter(TokenBlacklist.jti == jti).first() is not None


def store_refresh_token(user_id: int, jti: str, expires_at: datetime, db: Session) -> None:
    """Store refresh token in database for rotation tracking."""
    from src.models import RefreshToken
    # Delete old refresh tokens for this user
    db.query(RefreshToken).filter(RefreshToken.user_id == user_id).delete()
    db.add(RefreshToken(
        user_id=user_id,
        jti=jti,
        expires_at=expires_at,
        created_at=_utcnow()
    ))
    db.commit()


def validate_refresh_token(jti: str, user_id: int, db: Session) -> bool:
    """Validate that refresh token exists and is valid."""
    from src.models import RefreshToken
    token = db.query(RefreshToken).filter(
        and_(RefreshToken.jti == jti, RefreshToken.user_id == user_id)
    ).first()
    return token is not None and token.expires_at > _utcnow()


def revoke_refresh_token(jti: str, user_id: int, db: Session) -> None:
    """Revoke a specific refresh token."""
    from src.models import RefreshToken
    db.query(RefreshToken).filter(
        and_(RefreshToken.jti == jti, RefreshToken.user_id == user_id)
    ).delete()
    db.commit()


def revoke_all_user_tokens(user_id: int, db: Session) -> None:
    """Revoke all tokens for a user (force logout)."""
    from src.models import RefreshToken
    db.query(RefreshToken).filter(RefreshToken.user_id == user_id).delete()
    db.commit()


# ─────────────────────────────────────────────────────────────
# Account lockout helpers
# ─────────────────────────────────────────────────────────────

def is_account_locked(user: User) -> bool:
    """Check if account is currently locked."""
    if user.locked_until is None:
        return False
    return _utcnow() < user.locked_until


def record_failed_login(user: User, db: Session) -> None:
    """Record failed login attempt."""
    user.login_attempts += 1
    if user.login_attempts >= settings.max_login_attempts:
        user.locked_until = _utcnow() + timedelta(minutes=settings.lockout_duration_minutes)
    db.commit()


def record_successful_login(user: User, db: Session) -> None:
    """Reset failed login attempts on success."""
    user.login_attempts = 0
    user.locked_until = None
    db.commit()


# ─────────────────────────────────────────────────────────────
# Bearer token extraction
# ─────────────────────────────────────────────────────────────

_bearer_scheme = HTTPBearer(auto_error=False)


async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    """Get current user from access token (Authorization header)."""
    token = None
    
    # Try Authorization header first
    if credentials:
        token = credentials.credentials
    
    # Try cookie as fallback (for refresh token operations)
    if not token:
        token = request.cookies.get("access_token")
    
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    payload = decode_token(token)
    
    # Validate token type
    if payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type",
        )
    
    # Check blacklist
    jti = payload.get("jti")
    if jti and is_token_revoked(jti, db):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token revoked",
        )
    
    username = payload.get("sub")
    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )
    
    user = db.query(User).filter(User.username == username).first()
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )
    
    return user


async def get_current_user_optional(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer_scheme),
    db: Session = Depends(get_db),
) -> Optional[User]:
    """Get current user or None if not authenticated."""
    try:
        return await get_current_user(request, credentials, db)
    except HTTPException:
        return None


# ─────────────────────────────────────────────────────────────
# Audit logging
# ─────────────────────────────────────────────────────────────

def audit(
    db: Session,
    event: str,
    user_id: Optional[int] = None,
    detail: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> None:
    """Write security event to audit log."""
    try:
        log = AuditLog(
            event=event,
            user_id=user_id,
            detail=detail[:500] if detail else None,
            ip_address=ip_address[:45] if ip_address else None,
            user_agent=user_agent[:255] if user_agent else None,
        )
        db.add(log)
        db.commit()
    except Exception as e:
        logger.error(f"Failed to write audit log: {e}")


# ─────────────────────────────────────────────────────────────
# Role guards
# ─────────────────────────────────────────────────────────────

async def require_seller(current_user: User = Depends(get_current_user)) -> User:
    """Ensure user is a seller."""
    if current_user.role != "Seller":
        raise HTTPException(status_code=403, detail="Seller access required")
    return current_user


async def require_buyer(current_user: User = Depends(get_current_user)) -> User:
    """Ensure user is a buyer."""
    if current_user.role != "Buyer":
        raise HTTPException(status_code=403, detail="Buyer access required")
    return current_user
