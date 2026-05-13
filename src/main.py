import uuid
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.staticfiles import StaticFiles
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
from sqlalchemy.orm import Session
from datetime import datetime, timezone, timedelta
from typing import List

from src.database import engine, Base, get_db
from src.models import User, Item, Bid, Payment
from src.schemas import (
    UserRegister, UserLogin, ItemCreate, BidCreate, BidResponse,
    Token, ItemResponse, UserResponse, AuctionResultResponse,
    PaymentCreate, PaymentResponse, CheckoutResponse,
)
from src.auth import (
    hash_password, verify_password, create_access_token, get_current_user,
)

from dotenv import load_dotenv
load_dotenv()


# ──────────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────────
def get_utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def build_item_response(item: Item) -> ItemResponse:
    now = get_utc_now()
    remaining = max(0.0, (item.end_time - now).total_seconds())
    highest_bidder_username = item.highest_bidder.username if item.highest_bidder else None
    return ItemResponse(
        id=item.id,
        title=item.title,
        description=item.description or "",
        current_price=item.current_price,
        seller_id=item.seller_id,
        end_time=item.end_time,
        status=item.status,
        highest_bidder_id=item.highest_bidder_id,
        highest_bidder_username=highest_bidder_username,
        time_remaining_seconds=remaining,
        min_increment=item.min_increment,
        payment_status=item.payment_status or "unpaid",
    )


def close_expired_auction(item: Item, db: Session) -> Item:
    if item.status == "active" and get_utc_now() >= item.end_time:
        item.status = "closed"
        db.commit()
        db.refresh(item)
    return item


def close_expired_auctions(db: Session) -> None:
    now = get_utc_now()
    expired = db.query(Item).filter(Item.status == "active", Item.end_time <= now).all()
    if expired:
        for item in expired:
            item.status = "closed"
        db.commit()


# ──────────────────────────────────────────────
# APP SETUP
# ──────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    print("Database tables created")
    yield


app = FastAPI(lifespan=lifespan)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
    return JSONResponse(status_code=422, content={"detail": "Restricted."})


@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://unpkg.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self'"
    )
    return response


# ──────────────────────────────────────────────
# ROLE GUARDS
# ──────────────────────────────────────────────
async def is_seller(current_user: User = Depends(get_current_user)) -> User:
    if current_user.role != "Seller":
        raise HTTPException(status_code=403, detail="Only sellers can perform this action")
    return current_user


async def is_buyer(current_user: User = Depends(get_current_user)) -> User:
    if current_user.role != "Buyer":
        raise HTTPException(status_code=403, detail="Only buyers can perform this action")
    return current_user


# ──────────────────────────────────────────────
# AUTH
# ──────────────────────────────────────────────
@app.post("/register")
async def register(user: UserRegister, db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == user.username).first():
        raise HTTPException(status_code=400, detail="Username already registered")
    new_user = User(username=user.username, hashed_password=hash_password(user.password), role=user.role)
    db.add(new_user); db.commit()
    return {"message": "User registered successfully", "role": new_user.role}


@app.post("/login", response_model=Token)
async def login(login: UserLogin, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == login.username).first()
    if not user or not verify_password(login.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token({"sub": user.username, "role": user.role})
    return Token(access_token=token, token_type="bearer", role=user.role)


# ──────────────────────────────────────────────
# ITEMS
# ──────────────────────────────────────────────
@app.get("/items", response_model=List[ItemResponse])
async def get_items(db: Session = Depends(get_db)):
    close_expired_auctions(db)
    items = db.query(Item).all()
    return [build_item_response(i) for i in items]


@app.post("/items", response_model=ItemResponse)
async def create_item(item: ItemCreate, seller: User = Depends(is_seller), db: Session = Depends(get_db)):
    end_time = get_utc_now() + timedelta(minutes=item.duration_minutes)
    new_item = Item(
        title=item.title, description=item.description,
        current_price=item.starting_price, seller_id=seller.id,
        end_time=end_time, status="active", highest_bidder_id=None,
        min_increment=item.min_increment, payment_status="unpaid",
    )
    db.add(new_item); db.commit(); db.refresh(new_item)
    return build_item_response(new_item)


# ──────────────────────────────────────────────
# BIDS
# ──────────────────────────────────────────────
@app.post("/items/{item_id}/bid")
async def place_bid(item_id: int, bid: BidCreate, buyer: User = Depends(is_buyer), db: Session = Depends(get_db)):
    item = db.query(Item).filter(Item.id == item_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    item = close_expired_auction(item, db)
    if item.status == "closed" or get_utc_now() >= item.end_time:
        raise HTTPException(status_code=400, detail="Auction has ended")
    if buyer.id == item.seller_id:
        raise HTTPException(status_code=403, detail="Cannot bid on your own item")
    min_valid = item.current_price + item.min_increment
    if bid.amount < min_valid:
        raise HTTPException(
            status_code=400,
            detail=f"Bid must be at least ${min_valid:.2f} (current price + increment of ${item.min_increment:.2f})",
        )
    new_bid = Bid(amount=bid.amount, bidder_id=buyer.id, item_id=item_id, created_at=get_utc_now())
    db.add(new_bid)
    item.current_price = bid.amount
    item.highest_bidder_id = buyer.id
    db.commit(); db.refresh(new_bid); db.refresh(item)
    return {"message": "Bid placed successfully", "new_price": bid.amount, "item_id": item_id}


@app.get("/items/{item_id}/bids", response_model=List[BidResponse])
async def get_bid_history(item_id: int, db: Session = Depends(get_db)):
    item = db.query(Item).filter(Item.id == item_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    bids = db.query(Bid).filter(Bid.item_id == item_id).order_by(Bid.created_at.desc()).all()
    return [
        BidResponse(
            id=b.id, amount=b.amount, bidder_id=b.bidder_id,
            bidder_username=b.bidder.username, item_id=b.item_id, created_at=b.created_at,
        ) for b in bids
    ]


@app.get("/items/{item_id}/result", response_model=AuctionResultResponse)
async def get_auction_result(item_id: int, db: Session = Depends(get_db)):
    item = db.query(Item).filter(Item.id == item_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    item = close_expired_auction(item, db)
    if item.status == "active":
        return AuctionResultResponse(
            item_id=item.id, title=item.title, status="active",
            final_price=item.current_price, winner_id=None, winner_username=None,
            end_time=item.end_time, message="Auction still active",
        )
    if item.highest_bidder:
        return AuctionResultResponse(
            item_id=item.id, title=item.title, status="closed",
            final_price=item.current_price, winner_id=item.highest_bidder_id,
            winner_username=item.highest_bidder.username, end_time=item.end_time,
            message=f"Auction won by {item.highest_bidder.username} for ${item.current_price:.2f}",
        )
    return AuctionResultResponse(
        item_id=item.id, title=item.title, status="closed",
        final_price=item.current_price, winner_id=None, winner_username=None,
        end_time=item.end_time, message="Auction ended with no bids",
    )


@app.post("/items/{item_id}/close")
async def manual_close_auction(item_id: int, seller: User = Depends(is_seller), db: Session = Depends(get_db)):
    item = db.query(Item).filter(Item.id == item_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    if item.seller_id != seller.id:
        raise HTTPException(status_code=403, detail="You can only close your own auctions")
    if item.status == "closed":
        raise HTTPException(status_code=400, detail="Auction is already closed")
    item.status = "closed"
    db.commit(); db.refresh(item)
    return {
        "message": "Auction closed", "item_id": item.id,
        "final_price": item.current_price,
        "winner_username": item.highest_bidder.username if item.highest_bidder else None,
    }


# ══════════════════════════════════════════════
# PAYMENTS  (mock checkout for auction winners)
# ══════════════════════════════════════════════

@app.get("/items/{item_id}/checkout", response_model=CheckoutResponse)
async def get_checkout(
    item_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    item = db.query(Item).filter(Item.id == item_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    item = close_expired_auction(item, db)

    winner_username = item.highest_bidder.username if item.highest_bidder else None

    if item.status == "active":
        return CheckoutResponse(
            item_id=item.id, title=item.title, final_price=item.current_price,
            winner_username=winner_username, payment_status=item.payment_status,
            can_pay=False, message="Auction is still active",
        )
    if item.highest_bidder_id is None:
        return CheckoutResponse(
            item_id=item.id, title=item.title, final_price=item.current_price,
            winner_username=None, payment_status=item.payment_status,
            can_pay=False, message="Auction ended with no winner",
        )
    if current_user.id != item.highest_bidder_id:
        raise HTTPException(status_code=403, detail="Only the winner can checkout this item")
    if item.payment_status == "paid":
        return CheckoutResponse(
            item_id=item.id, title=item.title, final_price=item.current_price,
            winner_username=winner_username, payment_status="paid",
            can_pay=False, message="Payment already completed",
        )
    return CheckoutResponse(
        item_id=item.id, title=item.title, final_price=item.current_price,
        winner_username=winner_username, payment_status=item.payment_status,
        can_pay=True, message="Ready to pay",
    )


@app.post("/payments", response_model=PaymentResponse)
async def create_payment(
    payload: PaymentCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    item = db.query(Item).filter(Item.id == payload.item_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    item = close_expired_auction(item, db)

    if item.status != "closed":
        raise HTTPException(status_code=400, detail="Auction is still active")
    if item.highest_bidder_id is None:
        raise HTTPException(status_code=400, detail="Auction has no winner")
    if current_user.id != item.highest_bidder_id:
        raise HTTPException(status_code=403, detail="Only the winner can pay")
    if current_user.id == item.seller_id:
        raise HTTPException(status_code=403, detail="Sellers cannot pay for their own auction")

    existing = (
        db.query(Payment)
        .filter(Payment.item_id == item.id, Payment.status == "paid")
        .first()
    )
    if existing or item.payment_status == "paid":
        raise HTTPException(status_code=400, detail="Payment already completed")

    # SERVER-AUTHORITATIVE amount — never trust client
    amount = float(item.current_price)
    now = get_utc_now()
    payment = Payment(
        item_id=item.id,
        payer_id=current_user.id,
        amount=amount,
        status="paid",
        method=payload.method,
        transaction_ref="DEMO-" + uuid.uuid4().hex[:16].upper(),
        created_at=now,
        paid_at=now,
    )
    db.add(payment)
    item.payment_status = "paid"
    db.commit(); db.refresh(payment)

    return PaymentResponse(
        id=payment.id, item_id=payment.item_id, payer_id=payment.payer_id,
        amount=payment.amount, status=payment.status, method=payment.method,
        transaction_ref=payment.transaction_ref,
        created_at=payment.created_at, paid_at=payment.paid_at,
        item_title=item.title, payer_username=current_user.username,
    )


@app.get("/payments/me", response_model=List[PaymentResponse])
async def my_payments(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    rows = (
        db.query(Payment)
        .filter(Payment.payer_id == current_user.id)
        .order_by(Payment.created_at.desc())
        .all()
    )
    return [
        PaymentResponse(
            id=p.id, item_id=p.item_id, payer_id=p.payer_id, amount=p.amount,
            status=p.status, method=p.method, transaction_ref=p.transaction_ref,
            created_at=p.created_at, paid_at=p.paid_at,
            item_title=p.item.title if p.item else None,
            payer_username=current_user.username,
        ) for p in rows
    ]


@app.get("/seller/payments", response_model=List[PaymentResponse])
async def seller_payments(
    seller: User = Depends(is_seller),
    db: Session = Depends(get_db),
):
    rows = (
        db.query(Payment)
        .join(Item, Payment.item_id == Item.id)
        .filter(Item.seller_id == seller.id)
        .order_by(Payment.created_at.desc())
        .all()
    )
    return [
        PaymentResponse(
            id=p.id, item_id=p.item_id, payer_id=p.payer_id, amount=p.amount,
            status=p.status, method=p.method, transaction_ref=p.transaction_ref,
            created_at=p.created_at, paid_at=p.paid_at,
            item_title=p.item.title if p.item else None,
            payer_username=p.payer.username if p.payer else None,
        ) for p in rows
    ]


# Mount static AFTER all API routes
app.mount("/", StaticFiles(directory="static", html=True), name="static")
