# AuctionVault - Secure Auction Platform

## Quick Start
```bash
python -m venv venv
source venv/bin/activate          # Mac/Linux
venv\Scripts\activate             # Windows

pip install -r requirements.txt
uvicorn src.main:app --reload
```

Open **http://localhost:8000**

## Users to Test
- **Seller:** username `seller1`, password `seller123`
- **Buyer:** username `buyer1`, password `buyer123`

## Security Features Implemented

| Attack Vector | Defense | Evidence |
|---|---|---|
| SQL Injection | Pydantic regex validation (`^[a-zA-Z0-9_-]+$`) | Register with `admin'); DROP--` → 422 |
| XSS | Content-Security-Policy header | Script tags in item title → blocked, CSP enforced |
| CSRF | Stateless JWT via Authorization header (no cookies) | DevTools → all requests use `Authorization: Bearer`, no Set-Cookie |
| Clickjacking | X-Frame-Options: DENY | DevTools Network → Response Headers |
| Broken Access Control | FastAPI role-based dependencies (`is_seller`, `is_buyer`) | Buyer POST /items → 403 |
| Self-Bidding | `bidder_id != item.seller_id` check in bid logic | Seller bids own item → 403 |
| Price Manipulation | `bid.amount > current_price` validation | Bid $50 on $500 item → 400 |

## Architecture

**Backend:** FastAPI + SQLAlchemy + SQLite  
**Auth:** JWT (python-jose) + bcrypt (passlib)  
**Frontend:** Vanilla JS SPA with localStorage state  
**Validation:** Pydantic v2 with regex constraints + CSP headers  

## API Endpoints

- `POST /register` - Create account (Buyer or Seller)
- `POST /login` - Get JWT token
- `GET /items` - List all items
- `POST /items` - Create item (Seller only)
- `POST /items/{id}/bid` - Place bid (Buyer only)

## Files
```
secure_auction/
├── src/
│   ├── __init__.py
│   ├── database.py
│   ├── models.py
│   ├── schemas.py
│   ├── auth.py
│   └── main.py
├── static/
│   ├── index.html
│   ├── app.js
│   └── style.css
├── venv/
├── .env
├── .gitignore
├── requirements.txt
└── auction.db
```


## Status

- Security implementation is correct
- Basic auction functionality is complete
- Advanced auction features still need to be implemented, including session management, bid finalization, and other enhancements
