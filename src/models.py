"""
models.py – SQLAlchemy ORM models with security improvements.

Key security improvements:
  • Monetary amounts stored as INTEGER CENTS (not Float) to avoid rounding errors
  • login_attempts + locked_until for brute-force protection
  • AuditLog table for security event tracking
  • TokenBlacklist table for JWT revocation (logout)
  • RefreshToken table for token rotation
  • is_active for soft-delete/ban functionality
"""

from datetime import datetime, timezone
from sqlalchemy import (
    Column, Integer, String, ForeignKey, DateTime, Text, Boolean, BigInteger, Index
)
from sqlalchemy.orm import relationship

from src.database import Base


def _utcnow() -> datetime:
    """Return current UTC time without timezone (stored as naive)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ─────────────────────────────────────────────────────────────
# USER MODEL
# ─────────────────────────────────────────────────────────────
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(10), nullable=False)  # "Buyer" | "Seller"

    # Account lockout (brute-force protection)
    login_attempts = Column(Integer, nullable=False, default=0)
    locked_until = Column(DateTime, nullable=True)

    # Account status
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, nullable=False, default=_utcnow)

    # Relationships
    items_selling = relationship(
        "Item", back_populates="seller", foreign_keys="Item.seller_id"
    )
    bids = relationship("Bid", back_populates="bidder", cascade="all, delete-orphan")
    payments_made = relationship("Payment", back_populates="payer", foreign_keys="Payment.payer_id")
    audit_logs = relationship("AuditLog", back_populates="user")
    refresh_tokens = relationship("RefreshToken", back_populates="user", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<User id={self.id} username={self.username} role={self.role}>"


# ─────────────────────────────────────────────────────────────
# ITEM MODEL (Auction Listing)
# ─────────────────────────────────────────────────────────────
class Item(Base):
    __tablename__ = "items"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(120), nullable=False)
    description = Column(Text, nullable=True)

    # Prices stored in CENTS (integer) – eliminates floating point errors
    current_price_cents = Column(BigInteger, nullable=False)
    min_increment_cents = Column(BigInteger, nullable=False, default=100)  # $1.00 default

    seller_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)

    # Auction timing
    end_time = Column(DateTime, nullable=False)
    status = Column(String(10), nullable=False, default="active")  # "active" | "closed"

    # Winner tracking
    highest_bidder_id = Column(Integer, ForeignKey("users.id"), nullable=True)

    # Payment lifecycle
    payment_status = Column(
        String(12), nullable=False, default="unpaid"
    )  # "unpaid" | "pending" | "processing" | "paid" | "failed" | "refunded"

    created_at = Column(DateTime, nullable=False, default=_utcnow)

    # Relationships
    seller = relationship("User", back_populates="items_selling", foreign_keys=[seller_id])
    highest_bidder = relationship("User", foreign_keys=[highest_bidder_id])
    bids = relationship(
        "Bid", back_populates="item", cascade="all, delete-orphan",
        order_by="Bid.created_at.desc()"
    )
    payments = relationship("Payment", back_populates="item", cascade="all, delete-orphan")

    # Indexes for performance
    __table_args__ = (
        Index("ix_items_status_end_time", "status", "end_time"),
        Index("ix_items_seller_id", "seller_id"),
    )

    @property
    def current_price(self) -> float:
        """Return current price in dollars (for API responses)."""
        return self.current_price_cents / 100.0

    @current_price.setter
    def current_price(self, value: float) -> None:
        """Set current price from dollars (converts to cents)."""
        self.current_price_cents = int(round(value * 100))

    @property
    def min_increment(self) -> float:
        """Return min increment in dollars."""
        return self.min_increment_cents / 100.0

    @min_increment.setter
    def min_increment(self, value: float) -> None:
        """Set min increment from dollars."""
        self.min_increment_cents = int(round(value * 100))

    def __repr__(self) -> str:
        return f"<Item id={self.id} title={self.title[:30]} status={self.status}>"


# ─────────────────────────────────────────────────────────────
# BID MODEL
# ─────────────────────────────────────────────────────────────
class Bid(Base):
    __tablename__ = "bids"

    id = Column(Integer, primary_key=True, index=True)
    amount_cents = Column(BigInteger, nullable=False)
    bidder_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    item_id = Column(Integer, ForeignKey("items.id", ondelete="CASCADE"), nullable=False)
    created_at = Column(DateTime, nullable=False, default=_utcnow)

    # Relationships
    bidder = relationship("User", back_populates="bids")
    item = relationship("Item", back_populates="bids")

    __table_args__ = (
        Index("ix_bids_item_id_created_at", "item_id", "created_at"),
    )

    @property
    def amount(self) -> float:
        """Return amount in dollars."""
        return self.amount_cents / 100.0

    @amount.setter
    def amount(self, value: float) -> None:
        """Set amount from dollars."""
        self.amount_cents = int(round(value * 100))


# ─────────────────────────────────────────────────────────────
# PAYMENT MODEL
# ─────────────────────────────────────────────────────────────
class Payment(Base):
    __tablename__ = "payments"

    id = Column(Integer, primary_key=True, index=True)
    item_id = Column(Integer, ForeignKey("items.id", ondelete="CASCADE"), nullable=False, index=True)
    payer_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)

    amount_cents = Column(BigInteger, nullable=False)
    status = Column(String(12), nullable=False, default="pending")
    # "pending" | "processing" | "paid" | "failed" | "refunded"

    method = Column(String(20), nullable=False)  # "demo_card" | "upi_demo" | "wallet_demo"
    transaction_ref = Column(String(64), unique=True, nullable=False, index=True)

    created_at = Column(DateTime, nullable=False, default=_utcnow)
    paid_at = Column(DateTime, nullable=True)

    # Relationships
    item = relationship("Item", back_populates="payments")
    payer = relationship("User", back_populates="payments_made", foreign_keys=[payer_id])

    @property
    def amount(self) -> float:
        """Return amount in dollars."""
        return self.amount_cents / 100.0

    @amount.setter
    def amount(self, value: float) -> None:
        """Set amount from dollars."""
        self.amount_cents = int(round(value * 100))

    def __repr__(self) -> str:
        return f"<Payment id={self.id} status={self.status} ref={self.transaction_ref[:8]}>"


# ─────────────────────────────────────────────────────────────
# TOKEN BLACKLIST (for logout / token revocation)
# ─────────────────────────────────────────────────────────────
class TokenBlacklist(Base):
    __tablename__ = "token_blacklist"

    id = Column(Integer, primary_key=True, index=True)
    jti = Column(String(64), unique=True, nullable=False, index=True)  # JWT ID claim
    expires_at = Column(DateTime, nullable=False)
    revoked_at = Column(DateTime, nullable=False, default=_utcnow)

    __table_args__ = (
        Index("ix_token_blacklist_expires_at", "expires_at"),
    )


# ─────────────────────────────────────────────────────────────
# REFRESH TOKEN (for rotation tracking)
# ─────────────────────────────────────────────────────────────
class RefreshToken(Base):
    """Stored refresh tokens for rotation detection."""
    __tablename__ = "refresh_tokens"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    jti = Column(String(64), unique=True, nullable=False, index=True)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, nullable=False, default=_utcnow)
    
    # Relationship
    user = relationship("User", back_populates="refresh_tokens", foreign_keys=[user_id])
    
    __table_args__ = (
        Index("ix_refresh_tokens_user_jti", "user_id", "jti"),
    )


# ─────────────────────────────────────────────────────────────
# AUDIT LOG (security event tracking)
# ─────────────────────────────────────────────────────────────
class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    event = Column(String(50), nullable=False, index=True)  # "login", "bid", "payment", etc.
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    detail = Column(Text, nullable=True)  # JSON string – NEVER contains passwords/tokens
    ip_address = Column(String(45), nullable=True)  # IPv6 compatible
    user_agent = Column(String(255), nullable=True)
    created_at = Column(DateTime, nullable=False, default=_utcnow)

    # Relationship
    user = relationship("User", back_populates="audit_logs")

    __table_args__ = (
        Index("ix_audit_logs_created_at", "created_at"),
        Index("ix_audit_logs_event_user", "event", "user_id"),
    )