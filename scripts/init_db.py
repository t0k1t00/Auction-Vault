#!/usr/bin/env python
"""
scripts/init_db.py – Initialize database with tables and seed data.
Run: python scripts/init_db.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.database import engine, Base
from src.models import User, Item, Bid, Payment, TokenBlacklist, AuditLog, RefreshToken
from src.auth import hash_password
from datetime import datetime, timedelta


def init_db():
    """Create all tables and seed with demo data."""
    print("Creating tables...")
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    print("Tables created.")
    
    from src.database import SessionLocal
    db = SessionLocal()
    
    try:
        # Create demo users
        print("Creating demo users...")
        seller = User(
            username="seller1",
            hashed_password=hash_password("seller123"),
            role="Seller",
            is_active=True,
        )
        buyer = User(
            username="buyer1",
            hashed_password=hash_password("buyer123"),
            role="Buyer",
            is_active=True,
        )
        db.add_all([seller, buyer])
        db.commit()
        
        # Create demo items
        print("Creating demo items...")
        now = datetime.now()
        
        active_item = Item(
            title="Vintage Camera",
            description="Beautiful vintage film camera in working condition",
            current_price=75.00,
            seller_id=seller.id,
            end_time=now + timedelta(hours=48),
            status="active",
            min_increment=5.00,
            payment_status="unpaid",
        )
        
        closed_item = Item(
            title="Signed Book",
            description="First edition signed by the author",
            current_price=120.00,
            seller_id=seller.id,
            end_time=now - timedelta(hours=1),
            status="closed",
            min_increment=10.00,
            highest_bidder_id=buyer.id,
            payment_status="unpaid",
        )
        
        db.add_all([active_item, closed_item])
        db.commit()
        
        print("Database initialized successfully!")
        print(f"  Seller: username='seller1', password='seller123'")
        print(f"  Buyer:  username='buyer1', password='buyer123'")
        
    except Exception as e:
        print(f"Error initializing database: {e}")
        db.rollback()
    finally:
        db.close()


if __name__ == "__main__":
    init_db()
