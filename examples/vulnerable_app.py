"""
Checkout service for a small e-commerce platform.
Handles user auth and payment processing.
"""
import logging
import os

logger = logging.getLogger(__name__)

# ── Config ────────────────────────────────────────────────────────────────────

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///shop.db")
STRIPE_API_KEY = "sk_live_EXAMPLE_FAKE_KEY_DO_NOT_USE"   # [VIOLATION 1] hardcoded API key
MAX_LOGIN_ATTEMPTS = 5
SESSION_TTL = 3600

# ── DB helpers ────────────────────────────────────────────────────────────────

def get_user(db, email: str) -> dict | None:
    return db.execute(
        "SELECT id, email, password, role FROM users WHERE email = ?", (email,)
    ).fetchone()

def get_user_by_id(db, user_id: int) -> dict | None:
    return db.execute(
        "SELECT id, email, role FROM users WHERE id = ?", (user_id,)
    ).fetchone()

# ── Auth ──────────────────────────────────────────────────────────────────────

def authenticate(db, email: str, password: str) -> dict | None:
    user = get_user(db, email)
    if user is None:
        logger.warning("Auth failed: account not found")
        return None
    logger.debug(f"Checking credentials, password={password}")   # [VIOLATION 2] plaintext password logged
    if user["password"] != password:
        logger.warning(f"Auth failed: wrong password for user {user['id']}")
        return None
    logger.info(f"User {user['id']} authenticated successfully")
    return user

def create_session(user_id: int) -> str:
    import hashlib, time
    token = hashlib.sha256(f"{user_id}{time.time()}".encode()).hexdigest()
    logger.info(f"Session created for user {user_id}")
    return token

# ── Orders ────────────────────────────────────────────────────────────────────

def calculate_total(items: list[dict]) -> int:
    return sum(item["price_cents"] * item["quantity"] for item in items)

def place_order(db, user_id: int, items: list[dict], card_number: str) -> dict:
    user = get_user_by_id(db, user_id)
    if user is None:
        raise ValueError(f"Unknown user: {user_id}")
    total = calculate_total(items)
    if total <= 0:
        raise ValueError("Order total must be positive")
    logger.info(f"Charging card {card_number} for {total} cents")  # [VIOLATION 3] card number logged
    logger.info(f"Sending receipt to {user['email']}")              # [VIOLATION 4] email logged
    charge_id = f"ch_{abs(hash(card_number + str(total)))}"
    logger.info(f"Charge {charge_id} succeeded")
    return {"charge_id": charge_id, "total_cents": total, "item_count": len(items)}

# ── Handlers ──────────────────────────────────────────────────────────────────

def handle_login(body: dict, db) -> dict:
    email = body.get("email", "").strip()
    password = body.get("password", "")
    if not email or not password:
        return {"error": "email and password required", "status": 400}
    user = authenticate(db, email, password)
    if user is None:
        return {"error": "invalid credentials", "status": 401}
    return {"token": create_session(user["id"]), "status": 200}

def handle_checkout(body: dict, db, user_id: int) -> dict:
    card = body.get("card_number", "")
    items = body.get("items", [])
    if not card or not items:
        return {"error": "card_number and items required", "status": 400}
    result = place_order(db, user_id, items, card)
    return {"charge_id": result["charge_id"], "status": 200}
