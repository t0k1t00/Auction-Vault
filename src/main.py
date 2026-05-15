"""
main.py – FastAPI application with comprehensive security.
"""

import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta
from typing import List, Optional

from fastapi import FastAPI, Depends, HTTPException, status, Request, Response
from fastapi.staticfiles import StaticFiles
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy import select, update

from src.database import engine, Base, get_db
from src.models import User, Item, Bid, Payment, RefreshToken
from src.schemas import (
    UserRegister, UserLogin, ItemCreate, BidCreate, BidResponse,
    TokenResponse, ItemResponse, AuctionResultResponse,
    PaymentCreate, PaymentResponse, CheckoutResponse,
    RefreshTokenResponse, LogoutRequest,
)
from src.auth import (
    hash_password, verify_password, create_access_token, create_refresh_token,
    get_current_user, get_current_user_optional, require_seller, require_buyer,
    is_account_locked, record_failed_login, record_successful_login,
    revoke_token, revoke_refresh_token, revoke_all_user_tokens,
    decode_token, is_token_revoked, validate_refresh_token,
    store_refresh_token, audit,
)
from src.middleware import setup_middleware
from src.rate_limiter import limiter, rate_limit
from src.config import get_settings
from src.crypto import encrypt_data, decrypt_data

from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

# Load settings
settings = get_settings()

# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────

def get_utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def get_client_ip(request: Request) -> str:
    """Get client IP address from request."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


def build_item_response(item: Item, db: Session) -> ItemResponse:
    """Build item response with computed fields."""
    now = get_utc_now()
    remaining = max(0.0, (item.end_time - now).total_seconds())
    highest_bidder_username = None
    if item.highest_bidder_id:
        highest_bidder = db.query(User).filter(User.id == item.highest_bidder_id).first()
        highest_bidder_username = highest_bidder.username if highest_bidder else None
    
    return ItemResponse(
        id=item.id,
        title=item.title,
        description=item.description,
        current_price=item.current_price,
        seller_id=item.seller_id,
        end_time=item.end_time,
        status=item.status,
        highest_bidder_id=item.highest_bidder_id,
        highest_bidder_username=highest_bidder_username,
        time_remaining_seconds=remaining,
        min_increment=item.min_increment,
        payment_status=item.payment_status,
    )


def close_expired_auction(item: Item, db: Session) -> Item:
    """Close auction if end time has passed."""
    if item.status == "active" and get_utc_now() >= item.end_time:
        item.status = "closed"
        db.commit()
        db.refresh(item)
    return item


def close_expired_auctions(db: Session) -> None:
    """Close all expired auctions."""
    now = get_utc_now()
    expired = db.query(Item).filter(
        Item.status == "active", 
        Item.end_time <= now
    ).all()
    for item in expired:
        item.status = "closed"
    if expired:
        db.commit()


# ─────────────────────────────────────────────────────────────
# App Setup
# ─────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create tables
    Base.metadata.create_all(bind=engine)
    print("Database tables created")
    yield
    # Cleanup if needed


app = FastAPI(
    title="Auction Marketplace API",
    description="Secure auction platform with JWT authentication",
    version="2.0.0",
    lifespan=lifespan,
)

# Setup middleware
setup_middleware(app)

# Add rate limiting middleware
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)


# ─────────────────────────────────────────────────────────────
# Exception Handlers
# ─────────────────────────────────────────────────────────────

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Handle validation errors without leaking details."""
    return JSONResponse(
        status_code=422,
        content={"detail": "Invalid request data"},
    )


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    """Handle rate limit exceeded."""
    return JSONResponse(
        status_code=429,
        content={"detail": "Too many requests. Please try again later."},
    )


# ─────────────────────────────────────────────────────────────
# Health Check
# ─────────────────────────────────────────────────────────────

@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": get_utc_now().isoformat()}


# ─────────────────────────────────────────────────────────────
# Authentication Endpoints
# ─────────────────────────────────────────────────────────────

@app.post("/register")
@limiter.limit(settings.rate_limit_requests_register, "minute")
async def register(
    request: Request,
    user_data: UserRegister,
    db: Session = Depends(get_db),
):
    """Register new user with rate limiting and generic errors."""
    ip = get_client_ip(request)
    user_agent = request.headers.get("User-Agent", "")
    
    # Check if user exists (generic response)
    existing = db.query(User).filter(User.username == user_data.username).first()
    if existing:
        # Generic error to prevent enumeration
        raise HTTPException(
            status_code=400,
            detail="Unable to create account",
        )
    
    # Create user
    new_user = User(
        username=user_data.username,
        hashed_password=hash_password(user_data.password),
        role=user_data.role,
        is_active=True,
        created_at=get_utc_now(),
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    # Audit
    audit(db, "user_registered", new_user.id, ip_address=ip, user_agent=user_agent)
    
    return {"message": "Account created successfully"}


@app.post("/login", response_model=TokenResponse)
@limiter.limit(settings.rate_limit_requests_login, "minute")
async def login(
    request: Request,
    login_data: UserLogin,
    response: Response,
    db: Session = Depends(get_db),
):
    """Authenticate user and return tokens."""
    ip = get_client_ip(request)
    user_agent = request.headers.get("User-Agent", "")
    
    # Find user (generic error)
    user = db.query(User).filter(User.username == login_data.username).first()
    if not user:
        audit(db, "login_failed_user_not_found", None, ip_address=ip, user_agent=user_agent)
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials",
        )
    
    # Check lockout
    if is_account_locked(user):
        audit(db, "login_blocked_locked", user.id, ip_address=ip, user_agent=user_agent)
        raise HTTPException(
            status_code=401,
            detail="Account temporarily locked. Please try again later.",
        )
    
    # Verify password
    if not verify_password(login_data.password, user.hashed_password):
        record_failed_login(user, db)
        audit(db, "login_failed_bad_password", user.id, ip_address=ip, user_agent=user_agent)
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials",
        )
    
    # Check if active
    if not user.is_active:
        audit(db, "login_blocked_inactive", user.id, ip_address=ip, user_agent=user_agent)
        raise HTTPException(
            status_code=401,
            detail="Account disabled",
        )
    
    # Success
    record_successful_login(user, db)
    
    # Create tokens
    token_data = {"sub": user.username, "role": user.role}
    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)
    
    # Store refresh token
    refresh_payload = decode_token(refresh_token)
    expires_at = datetime.fromtimestamp(refresh_payload["exp"], tz=timezone.utc).replace(tzinfo=None)
    store_refresh_token(user.id, refresh_payload["jti"], expires_at, db)
    
    # Set refresh token as HttpOnly cookie
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        max_age=settings.refresh_token_expire_days * 24 * 60 * 60,
        path="/refresh",
    )
    
    # Also set access token cookie for cookie-based auth
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        max_age=settings.access_token_expire_minutes * 60,
        path="/",
    )
    
    audit(db, "login_success", user.id, ip_address=ip, user_agent=user_agent)
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        role=user.role,
        expires_in=settings.access_token_expire_minutes * 60,
    )


@app.post("/refresh", response_model=RefreshTokenResponse)
@limiter.limit("10/minute")
async def refresh_token(
    request: Request,
    response: Response,
    refresh_token: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """Refresh access token using refresh token."""
    ip = get_client_ip(request)
    user_agent = request.headers.get("User-Agent", "")
    
    # Get refresh token from body or cookie
    if not refresh_token:
        refresh_token = request.cookies.get("refresh_token")
    
    if not refresh_token:
        raise HTTPException(
            status_code=401,
            detail="Refresh token required",
        )
    
    # Decode and validate
    try:
        payload = decode_token(refresh_token)
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Invalid token type")
    except HTTPException:
        raise
    
    # Check blacklist
    jti = payload.get("jti")
    if jti and is_token_revoked(jti, db):
        raise HTTPException(status_code=401, detail="Token revoked")
    
    username = payload.get("sub")
    if not username:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    user = db.query(User).filter(User.username == username).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found")
    
    # Validate stored refresh token
    if not validate_refresh_token(jti, user.id, db):
        # Possible token theft - revoke all user tokens
        revoke_all_user_tokens(user.id, db)
        audit(db, "refresh_token_reuse_detected", user.id, ip_address=ip, user_agent=user_agent)
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    
    # Revoke old refresh token (rotation)
    revoke_refresh_token(jti, user.id, db)
    
    # Create new tokens
    token_data = {"sub": user.username, "role": user.role}
    new_access_token = create_access_token(token_data)
    new_refresh_token = create_refresh_token(token_data)
    
    # Store new refresh token
    new_payload = decode_token(new_refresh_token)
    new_expires_at = datetime.fromtimestamp(new_payload["exp"], tz=timezone.utc).replace(tzinfo=None)
    store_refresh_token(user.id, new_payload["jti"], new_expires_at, db)
    
    # Update cookies
    response.set_cookie(
        key="refresh_token",
        value=new_refresh_token,
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        max_age=settings.refresh_token_expire_days * 24 * 60 * 60,
        path="/refresh",
    )
    response.set_cookie(
        key="access_token",
        value=new_access_token,
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        max_age=settings.access_token_expire_minutes * 60,
        path="/",
    )
    
    audit(db, "token_refreshed", user.id, ip_address=ip, user_agent=user_agent)
    
    return RefreshTokenResponse(
        access_token=new_access_token,
        refresh_token=new_refresh_token,
        expires_in=settings.access_token_expire_minutes * 60,
    )


@app.post("/logout")
@limiter.limit("20/minute")
async def logout(
    request: Request,
    response: Response,
    logout_data: Optional[LogoutRequest] = None,
    current_user: Optional[User] = Depends(get_current_user_optional),
    db: Session = Depends(get_db),
):
    """Logout and revoke tokens."""
    ip = get_client_ip(request)
    user_agent = request.headers.get("User-Agent", "")
    
    # Get refresh token from various sources
    refresh_token = None
    if logout_data and logout_data.refresh_token:
        refresh_token = logout_data.refresh_token
    if not refresh_token:
        refresh_token = request.cookies.get("refresh_token")
    
    # Revoke refresh token if provided
    if refresh_token:
        try:
            payload = decode_token(refresh_token)
            jti = payload.get("jti")
            username = payload.get("sub")
            if jti and username:
                user = db.query(User).filter(User.username == username).first()
                if user:
                    revoke_refresh_token(jti, user.id, db)
                    revoke_token(jti, payload["exp"], db)
        except Exception:
            pass
    
    # Clear cookies
    response.delete_cookie("refresh_token", path="/refresh")
    response.delete_cookie("access_token", path="/")
    
    if current_user:
        audit(db, "logout", current_user.id, ip_address=ip, user_agent=user_agent)
    
    return {"message": "Logged out successfully"}


# ─────────────────────────────────────────────────────────────
# Items Endpoints
# ─────────────────────────────────────────────────────────────

@app.get("/items", response_model=List[ItemResponse])
@limiter.limit(settings.rate_limit_requests_general, "minute")
async def get_items(
    request: Request,
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db),
):
    """Get all items with pagination."""
    close_expired_auctions(db)
    
    # Enforce pagination limits
    limit = min(limit, 100)  # Max 100 items per request
    
    items = db.query(Item).order_by(Item.id.desc()).offset(offset).limit(limit).all()
    return [build_item_response(item, db) for item in items]


@app.post("/items", response_model=ItemResponse)
@limiter.limit("10/minute")
async def create_item(
    request: Request,
    item: ItemCreate,
    seller: User = Depends(require_seller),
    db: Session = Depends(get_db),
):
    """Create new auction item (seller only)."""
    ip = get_client_ip(request)
    
    end_time = get_utc_now() + timedelta(minutes=item.duration_minutes)
    new_item = Item(
        title=item.title,
        description=item.description,
        current_price=item.starting_price,
        seller_id=seller.id,
        end_time=end_time,
        status="active",
        min_increment=item.min_increment,
        payment_status="unpaid",
    )
    db.add(new_item)
    db.commit()
    db.refresh(new_item)
    
    audit(db, "item_created", seller.id, detail=f"Item {new_item.id}", ip_address=ip)
    
    return build_item_response(new_item, db)


@app.post("/items/{item_id}/bid")
@limiter.limit(settings.rate_limit_requests_bid, "minute")
async def place_bid(
    request: Request,
    item_id: int,
    bid: BidCreate,
    buyer: User = Depends(require_buyer),
    db: Session = Depends(get_db),
):
    """
    Place a bid on an item with atomic transaction.
    Uses SELECT FOR UPDATE to prevent race conditions.
    """
    ip = get_client_ip(request)
    
    # Start transaction
    try:
        # Lock the item row for update (prevents race conditions)
        # For SQLite, this is a no-op; for PostgreSQL, it works properly
        item = db.query(Item).filter(Item.id == item_id).with_for_update().first()
        
        if not item:
            raise HTTPException(status_code=404, detail="Item not found")
        
        # Close if expired
        item = close_expired_auction(item, db)
        
        # Validate auction state
        if item.status == "closed" or get_utc_now() >= item.end_time:
            raise HTTPException(status_code=400, detail="Auction has ended")
        
        # Prevent self-bidding
        if buyer.id == item.seller_id:
            audit(db, "bid_rejected_self_bid", buyer.id, detail=f"Item {item_id}", ip_address=ip)
            raise HTTPException(status_code=403, detail="Cannot bid on your own item")
        
        # Validate bid amount
        min_valid = item.current_price + item.min_increment
        if bid.amount < min_valid - 0.01:  # Allow small floating point tolerance
            raise HTTPException(
                status_code=400,
                detail=f"Bid must be at least ${min_valid:.2f}",
            )
        
        # Create bid
        new_bid = Bid(
            amount=bid.amount,
            bidder_id=buyer.id,
            item_id=item_id,
            created_at=get_utc_now(),
        )
        db.add(new_bid)
        
        # Update item
        old_price = item.current_price
        item.current_price = bid.amount
        item.highest_bidder_id = buyer.id
        
        db.commit()
        db.refresh(new_bid)
        
        audit(
            db, "bid_placed", buyer.id,
            detail=f"Item {item_id}, amount ${bid.amount:.2f}, previous ${old_price:.2f}",
            ip_address=ip
        )
        
        return {
            "message": "Bid placed successfully",
            "new_price": bid.amount,
            "item_id": item_id,
            "bid_id": new_bid.id,
        }
        
    except HTTPException:
        db.rollback()
        raise
    except Exception as e:
        db.rollback()
        logger.error(f"Bid placement failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to place bid")


@app.get("/items/{item_id}/bids", response_model=List[BidResponse])
@limiter.limit(settings.rate_limit_requests_general, "minute")
async def get_bid_history(
    request: Request,
    item_id: int,
    limit: int = 50,
    db: Session = Depends(get_db),
):
    """Get bid history for an item."""
    item = db.query(Item).filter(Item.id == item_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    
    limit = min(limit, 100)
    bids = db.query(Bid).filter(Bid.item_id == item_id).order_by(Bid.created_at.desc()).limit(limit).all()
    
    return [
        BidResponse(
            id=b.id,
            amount=b.amount,
            bidder_id=b.bidder_id,
            bidder_username=b.bidder.username,
            item_id=b.item_id,
            created_at=b.created_at,
        ) for b in bids
    ]


@app.get("/items/{item_id}/result", response_model=AuctionResultResponse)
async def get_auction_result(
    item_id: int,
    db: Session = Depends(get_db),
):
    """Get auction result (winner, final price)."""
    item = db.query(Item).filter(Item.id == item_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    
    item = close_expired_auction(item, db)
    
    if item.status == "active":
        return AuctionResultResponse(
            item_id=item.id,
            title=item.title,
            status="active",
            final_price=item.current_price,
            winner_id=None,
            winner_username=None,
            end_time=item.end_time,
            message="Auction still active",
        )
    
    if item.highest_bidder_id:
        winner = db.query(User).filter(User.id == item.highest_bidder_id).first()
        return AuctionResultResponse(
            item_id=item.id,
            title=item.title,
            status="closed",
            final_price=item.current_price,
            winner_id=item.highest_bidder_id,
            winner_username=winner.username if winner else None,
            end_time=item.end_time,
            message=f"Won by {winner.username if winner else 'Unknown'} for ${item.current_price:.2f}",
        )
    
    return AuctionResultResponse(
        item_id=item.id,
        title=item.title,
        status="closed",
        final_price=item.current_price,
        winner_id=None,
        winner_username=None,
        end_time=item.end_time,
        message="Auction ended with no bids",
    )


@app.post("/items/{item_id}/close")
async def manual_close_auction(
    item_id: int,
    seller: User = Depends(require_seller),
    db: Session = Depends(get_db),
):
    """Manually close an auction (seller only)."""
    item = db.query(Item).filter(Item.id == item_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    
    if item.seller_id != seller.id:
        raise HTTPException(status_code=403, detail="You can only close your own auctions")
    
    if item.status == "closed":
        raise HTTPException(status_code=400, detail="Auction already closed")
    
    item.status = "closed"
    db.commit()
    db.refresh(item)
    
    winner_name = None
    if item.highest_bidder_id:
        winner = db.query(User).filter(User.id == item.highest_bidder_id).first()
        winner_name = winner.username if winner else None
    
    audit(db, "auction_closed", seller.id, detail=f"Item {item_id}, winner {winner_name}")
    
    return {
        "message": "Auction closed",
        "item_id": item.id,
        "final_price": item.current_price,
        "winner_username": winner_name,
    }


# ─────────────────────────────────────────────────────────────
# Payment Endpoints (same as before, with rate limiting)
# ─────────────────────────────────────────────────────────────

@app.get("/items/{item_id}/checkout", response_model=CheckoutResponse)
@limiter.limit("10/minute")
async def get_checkout(
    request: Request,
    item_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get checkout information for a won item."""
    item = db.query(Item).filter(Item.id == item_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    
    item = close_expired_auction(item, db)
    winner_username = None
    if item.highest_bidder_id:
        winner = db.query(User).filter(User.id == item.highest_bidder_id).first()
        winner_username = winner.username if winner else None
    
    if item.status == "active":
        return CheckoutResponse(
            item_id=item.id,
            title=item.title,
            final_price=item.current_price,
            winner_username=winner_username,
            payment_status=item.payment_status,
            can_pay=False,
            message="Auction still active",
        )
    
    if item.highest_bidder_id is None:
        return CheckoutResponse(
            item_id=item.id,
            title=item.title,
            final_price=item.current_price,
            winner_username=None,
            payment_status=item.payment_status,
            can_pay=False,
            message="No winner",
        )
    
    if current_user.id != item.highest_bidder_id:
        raise HTTPException(status_code=403, detail="Only winner can checkout")
    
    if item.payment_status == "paid":
        return CheckoutResponse(
            item_id=item.id,
            title=item.title,
            final_price=item.current_price,
            winner_username=winner_username,
            payment_status="paid",
            can_pay=False,
            message="Already paid",
        )
    
    return CheckoutResponse(
        item_id=item.id,
        title=item.title,
        final_price=item.current_price,
        winner_username=winner_username,
        payment_status=item.payment_status,
        can_pay=True,
        message="Ready to pay",
    )


@app.post("/payments", response_model=PaymentResponse)
@limiter.limit("5/minute")
async def create_payment(
    request: Request,
    payload: PaymentCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Create a payment for a won auction."""
    ip = get_client_ip(request)
    
    item = db.query(Item).filter(Item.id == payload.item_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    
    item = close_expired_auction(item, db)
    
    # Validate auction state
    if item.status != "closed":
        raise HTTPException(status_code=400, detail="Auction not closed")
    
    if item.highest_bidder_id is None:
        raise HTTPException(status_code=400, detail="No winner")
    
    if current_user.id != item.highest_bidder_id:
        audit(db, "payment_unauthorized_attempt", current_user.id, 
              detail=f"Attempted to pay for item {item.id}", ip_address=ip)
        raise HTTPException(status_code=403, detail="Only winner can pay")
    
    # Check for existing payment
    existing = db.query(Payment).filter(
        Payment.item_id == item.id,
        Payment.status == "paid"
    ).first()
    if existing or item.payment_status == "paid":
        raise HTTPException(status_code=400, detail="Payment already processed")
    
    # Server-authoritative amount
    amount = item.current_price
    
    # Create payment record

    raw_ref = f"DEMO-{uuid.uuid4().hex[:16].upper()}"

    payment = Payment(
        item_id=item.id,
        payer_id=current_user.id,
        amount=amount,
        status="paid",
        method=payload.method,
        transaction_ref=encrypt_data(raw_ref),
        created_at=get_utc_now(),
        paid_at=get_utc_now(),
    )
    db.add(payment)
    item.payment_status = "paid"
    db.commit()
    db.refresh(payment)
    
    audit(db, "payment_completed", current_user.id,
          detail=f"Item {item.id}, amount ${amount:.2f}, ref {payment.transaction_ref}",
          ip_address=ip)
    
    return PaymentResponse(
        id=payment.id,
        item_id=payment.item_id,
        payer_id=payment.payer_id,
        amount=payment.amount,
        status=payment.status,
        method=payment.method,
        transaction_ref=decrypt_data(payment.transaction_ref),
        created_at=payment.created_at,
        paid_at=payment.paid_at,
        item_title=item.title,
        payer_username=current_user.username,
    )


@app.get("/payments/me", response_model=List[PaymentResponse])
async def my_payments(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get current user's payments."""
    payments = db.query(Payment).filter(Payment.payer_id == current_user.id).order_by(Payment.created_at.desc()).all()
    return [
        PaymentResponse(
            id=p.id,
            item_id=p.item_id,
            payer_id=p.payer_id,
            amount=p.amount,
            status=p.status,
            method=p.method,
            transaction_ref=decrypt_data(p.transaction_ref),
            created_at=p.created_at,
            paid_at=p.paid_at,
            item_title=p.item.title if p.item else None,
            payer_username=current_user.username,
        ) for p in payments
    ]


@app.get("/seller/payments", response_model=List[PaymentResponse])
async def seller_payments(
    seller: User = Depends(require_seller),
    db: Session = Depends(get_db),
):
    """Get payments received by seller."""
    payments = db.query(Payment).join(Item).filter(Item.seller_id == seller.id).order_by(Payment.created_at.desc()).all()
    return [
        PaymentResponse(
            id=p.id,
            item_id=p.item_id,
            payer_id=p.payer_id,
            amount=p.amount,
            status=p.status,
            method=p.method,
            transaction_ref=decrypt_data(p.transaction_ref),
            created_at=p.created_at,
            paid_at=p.paid_at,
            item_title=p.item.title if p.item else None,
            payer_username=p.payer.username if p.payer else None,
        ) for p in payments
    ]


# Mount static files
app.mount("/", StaticFiles(directory="static", html=True), name="static")
