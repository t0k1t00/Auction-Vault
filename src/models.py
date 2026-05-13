from sqlalchemy import Column, Integer, String, Float, ForeignKey, DateTime
from sqlalchemy.orm import relationship
from datetime import datetime, timezone

from src.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String(10), nullable=False)

    items = relationship("Item", back_populates="seller", foreign_keys="Item.seller_id")
    bids = relationship("Bid", back_populates="bidder")
    payments = relationship("Payment", back_populates="payer")


class Item(Base):
    __tablename__ = "items"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(100), nullable=False)
    description = Column(String(500), nullable=True)
    current_price = Column(Float, nullable=False)
    seller_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    # ── Auction lifecycle fields ──────────────────────
    end_time = Column(DateTime, nullable=False)
    status = Column(String(10), nullable=False, default="active")          # "active" | "closed"
    highest_bidder_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    min_increment = Column(Float, nullable=False, default=0.01)

    # ── Payment tracking ──────────────────────────────
    payment_status = Column(String(10), nullable=False, default="unpaid")  # "unpaid" | "paid"

    # ── Relationships ─────────────────────────────────
    seller = relationship("User", back_populates="items", foreign_keys=[seller_id])
    highest_bidder = relationship("User", foreign_keys=[highest_bidder_id])
    bids = relationship("Bid", back_populates="item", order_by="Bid.created_at.desc()")
    payments = relationship("Payment", back_populates="item")


class Bid(Base):
    __tablename__ = "bids"

    id = Column(Integer, primary_key=True, index=True)
    amount = Column(Float, nullable=False)
    bidder_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    item_id = Column(Integer, ForeignKey("items.id"), nullable=False)
    created_at = Column(
        DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc).replace(tzinfo=None),
    )

    bidder = relationship("User", back_populates="bids")
    item = relationship("Item", back_populates="bids")


class Payment(Base):
    __tablename__ = "payments"

    id = Column(Integer, primary_key=True, index=True)
    item_id = Column(Integer, ForeignKey("items.id"), nullable=False, index=True)
    payer_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    amount = Column(Float, nullable=False)
    status = Column(String(10), nullable=False, default="pending")   # pending | paid | failed
    method = Column(String(20), nullable=False)                      # demo_card | upi_demo | wallet_demo
    transaction_ref = Column(String(64), unique=True, nullable=False)
    created_at = Column(
        DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc).replace(tzinfo=None),
    )
    paid_at = Column(DateTime, nullable=True)

    item = relationship("Item", back_populates="payments")
    payer = relationship("User", back_populates="payments")
