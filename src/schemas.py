import re
from datetime import datetime
from typing import Optional, Literal
from pydantic import BaseModel, Field, ConfigDict, field_validator


# ──────────────────────────────────────────────
# AUTH SCHEMAS
# ──────────────────────────────────────────────

class UserRegister(BaseModel):
    username: str = Field(pattern=r"^[a-zA-Z0-9_-]+$", min_length=3, max_length=50)
    password: str = Field(min_length=6)
    role: Literal["Buyer", "Seller"] = "Buyer"


class UserLogin(BaseModel):
    username: str = Field(pattern=r"^[a-zA-Z0-9_-]+$", min_length=3, max_length=50)
    password: str = Field(min_length=1)


class UserResponse(BaseModel):
    id: int
    username: str
    role: str
    model_config = ConfigDict(from_attributes=True)


class Token(BaseModel):
    access_token: str
    token_type: str
    role: str


# ──────────────────────────────────────────────
# ITEM SCHEMAS
# ──────────────────────────────────────────────

class ItemCreate(BaseModel):
    title: str = Field(min_length=1, max_length=100)
    description: str = Field(default="", max_length=500)
    starting_price: float = Field(gt=0)
    duration_minutes: int = Field(gt=0, le=10080)
    min_increment: float = Field(default=0.01, ge=0)

    @field_validator("title", "description")
    @classmethod
    def strip_html(cls, v: str) -> str:
        if re.search(r"<[^>]*>", v):
            raise ValueError("HTML tags are not allowed")
        return v


class ItemResponse(BaseModel):
    id: int
    title: str
    description: str
    current_price: float
    seller_id: int
    end_time: datetime
    status: str
    highest_bidder_id: Optional[int] = None
    highest_bidder_username: Optional[str] = None
    time_remaining_seconds: float
    min_increment: float
    payment_status: str = "unpaid"

    model_config = ConfigDict(from_attributes=True)


# ──────────────────────────────────────────────
# BID SCHEMAS
# ──────────────────────────────────────────────

class BidCreate(BaseModel):
    amount: float = Field(gt=0)


class BidResponse(BaseModel):
    id: int
    amount: float
    bidder_id: int
    bidder_username: str
    item_id: int
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)


# ──────────────────────────────────────────────
# AUCTION RESULT
# ──────────────────────────────────────────────

class AuctionResultResponse(BaseModel):
    item_id: int
    title: str
    status: str
    final_price: float
    winner_id: Optional[int] = None
    winner_username: Optional[str] = None
    end_time: datetime
    message: str


# ──────────────────────────────────────────────
# PAYMENT SCHEMAS  (mock / demo only — never real card data)
# ──────────────────────────────────────────────

PaymentMethod = Literal["demo_card", "upi_demo", "wallet_demo"]

# Block anything that looks like real PII / card data
_FORBIDDEN_FIELDS = re.compile(
    r"(card[_-]?number|cvv|cvc|expiry|exp[_-]?date|pin|password|otp)",
    re.IGNORECASE,
)


class PaymentCreate(BaseModel):
    item_id: int = Field(gt=0)
    method: PaymentMethod
    demo_name: Optional[str] = Field(default=None, max_length=60)
    demo_reference: Optional[str] = Field(default=None, max_length=40)

    @field_validator("demo_name", "demo_reference")
    @classmethod
    def reject_real_payment_data(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        if _FORBIDDEN_FIELDS.search(v):
            raise ValueError("Real payment fields are not accepted")
        # Allow only safe printable chars
        if not re.fullmatch(r"[A-Za-z0-9 _.\-@]*", v):
            raise ValueError("Invalid characters")
        return v.strip()


class PaymentResponse(BaseModel):
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
    model_config = ConfigDict(from_attributes=True)


class CheckoutResponse(BaseModel):
    item_id: int
    title: str
    final_price: float
    winner_username: Optional[str] = None
    payment_status: str
    can_pay: bool
    message: str
