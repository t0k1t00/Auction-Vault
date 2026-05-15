"""
schemas.py – Pydantic v2 request/response models with strict validation.

Security features:
  • extra="forbid" prevents mass-assignment / unexpected fields
  • Strict field length + numeric bounds
  • Password strength enforced at schema level
  • HTML sanitization for user input
  • Username normalization and validation
  • Monetary amounts in DOLLARS (float, 2dp) at API surface
"""

import re
from datetime import datetime
from decimal import Decimal, InvalidOperation
from typing import Literal, Optional

import bleach
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

# ─────────────────────────────────────────────────────────────
# Constants & Whitelists
# ─────────────────────────────────────────────────────────────

PAYMENT_METHODS = Literal["demo_card", "upi_demo", "wallet_demo"]

# Password policy: 10-128 chars, uppercase, lowercase, digit, special char
_PASSWORD_MIN = 10
_PASSWORD_MAX = 128
_PASSWORD_RE = re.compile(
    r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()\-_=+\[\]{}|;:',.<>?/`~]).{10,128}$"
)

# Username policy: 3-30 chars, lowercase letters, digits, underscore only
_USERNAME_RE = re.compile(r"^[a-z0-9_]{3,30}$")


def sanitize_text(value: str) -> str:
    """Remove all HTML tags from user input."""
    if not value:
        return ""
    return bleach.clean(value, tags=[], strip=True).strip()


def validate_two_decimals(value: float) -> float:
    """Ensure monetary value has at most 2 decimal places."""
    try:
        d = Decimal(str(value)).quantize(Decimal("0.01"))
    except (InvalidOperation, TypeError):
        raise ValueError("Invalid monetary amount")
    return float(d)


# ─────────────────────────────────────────────────────────────
# AUTH SCHEMAS
# ─────────────────────────────────────────────────────────────

class UserRegister(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(..., min_length=3, max_length=30)
    password: str = Field(..., min_length=_PASSWORD_MIN, max_length=_PASSWORD_MAX)
    role: Literal["Buyer", "Seller"] = "Buyer"

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        v = v.lower().strip()
        if not _USERNAME_RE.match(v):
            raise ValueError(
                "Username must be 3-30 characters, lowercase letters, digits, or underscores only"
            )
        return v

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        if not _PASSWORD_RE.match(v):
            raise ValueError(
                "Password must be 10-128 characters and include: "
                "uppercase letter, lowercase letter, digit, and special character"
            )
        return v

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str) -> str:
        if v not in ["Buyer", "Seller"]:
            raise ValueError("Role must be 'Buyer' or 'Seller'")
        return v


class UserLogin(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(..., min_length=1, max_length=50)
    password: str = Field(..., min_length=1, max_length=256)

    @field_validator("username")
    @classmethod
    def normalize_username(cls, v: str) -> str:
        return v.lower().strip()


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    role: str
    is_active: bool


class TokenResponse(BaseModel):
    """Response for login and token refresh endpoints."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    role: str
    expires_in: int  # seconds until access token expires


class RefreshTokenResponse(BaseModel):
    """Response for refresh token endpoint."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class RefreshRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    refresh_token: Optional[str] = None


class LogoutRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    refresh_token: Optional[str] = None


# ─────────────────────────────────────────────────────────────
# ITEM SCHEMAS
# ─────────────────────────────────────────────────────────────

class ItemCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(..., min_length=3, max_length=120)
    description: Optional[str] = Field(None, max_length=1000)
    starting_price: float = Field(..., gt=0.0, le=10_000_000.0)
    duration_minutes: int = Field(..., ge=1, le=20_160)  # max 2 weeks
    min_increment: float = Field(default=0.01, gt=0.0, le=100_000.0)

    @field_validator("title")
    @classmethod
    def sanitize_title(cls, v: str) -> str:
        return sanitize_text(v)

    @field_validator("description")
    @classmethod
    def sanitize_description(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        return sanitize_text(v)

    @field_validator("starting_price", "min_increment")
    @classmethod
    def validate_two_decimals(cls, v: float) -> float:
        return validate_two_decimals(v)


class ItemResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    title: str
    description: Optional[str]
    current_price: float
    seller_id: int
    end_time: datetime
    status: str
    highest_bidder_id: Optional[int] = None
    highest_bidder_username: Optional[str] = None
    time_remaining_seconds: float
    min_increment: float
    payment_status: str


# ─────────────────────────────────────────────────────────────
# BID SCHEMAS
# ─────────────────────────────────────────────────────────────

class BidCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    amount: float = Field(..., gt=0.0, le=10_000_000.0)

    @field_validator("amount")
    @classmethod
    def validate_two_decimals(cls, v: float) -> float:
        return validate_two_decimals(v)


class BidResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    amount: float
    bidder_id: int
    bidder_username: str
    item_id: int
    created_at: datetime


# ─────────────────────────────────────────────────────────────
# AUCTION RESULT SCHEMA
# ─────────────────────────────────────────────────────────────

class AuctionResultResponse(BaseModel):
    item_id: int
    title: str
    status: str
    final_price: float
    winner_id: Optional[int] = None
    winner_username: Optional[str] = None
    end_time: datetime
    message: str


# ─────────────────────────────────────────────────────────────
# PAYMENT SCHEMAS
# ─────────────────────────────────────────────────────────────

class PaymentCreate(BaseModel):
    """
    Client provides ONLY the item_id and payment method.
    Amount is NEVER accepted from client – looked up server-side.
    """
    model_config = ConfigDict(extra="forbid")

    item_id: int = Field(..., gt=0)
    method: PAYMENT_METHODS


class PaymentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    item_id: int
    payer_id: int
    amount: float
    status: str
    method: str
    transaction_ref: str
    created_at: datetime
    paid_at: Optional[datetime] = None
    item_title: Optional[str] = None
    payer_username: Optional[str] = None


class CheckoutResponse(BaseModel):
    item_id: int
    title: str
    final_price: float
    winner_username: Optional[str] = None
    payment_status: str
    can_pay: bool
    message: str