import os
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, HTTPException, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr
import jwt
from passlib.context import CryptContext
from bson import ObjectId

from database import db, create_document, get_documents
from schemas import User as UserSchema, Product as ProductSchema, Order as OrderSchema, CartItem, WishlistItem, OrderItem

# ----------------------------------------------------------------------------
# App and Security Setup
# ----------------------------------------------------------------------------

JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-change-me")
JWT_ALG = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

app = FastAPI(title="E-commerce API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ----------------------------------------------------------------------------
# Utilities
# ----------------------------------------------------------------------------

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_access_token(subject: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = subject.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALG)


def oid_str(oid) -> str:
    return str(oid) if isinstance(oid, ObjectId) else oid


def doc_to_public(doc: Dict[str, Any]) -> Dict[str, Any]:
    if not doc:
        return doc
    doc = dict(doc)
    if "_id" in doc:
        doc["id"] = oid_str(doc.pop("_id"))
    # hide sensitive fields
    if "password_hash" in doc:
        doc.pop("password_hash", None)
    return doc


async def get_current_user(token: str = Depends(oauth2_scheme)) -> Dict[str, Any]:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        uid = payload.get("sub")
        if not uid:
            raise HTTPException(status_code=401, detail="Invalid token")
        user = db["user"].find_one({"_id": ObjectId(uid)})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid authentication")


async def get_current_admin(user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    if not user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


# ----------------------------------------------------------------------------
# Models (request bodies)
# ----------------------------------------------------------------------------

class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    password: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class ProductCreateRequest(BaseModel):
    title: str
    description: Optional[str] = None
    price: float
    category: str
    stock: int = 0
    images: List[str] = []
    tags: List[str] = []


class ProductUpdateRequest(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    price: Optional[float] = None
    category: Optional[str] = None
    stock: Optional[int] = None
    images: Optional[List[str]] = None
    tags: Optional[List[str]] = None


class AddCartRequest(BaseModel):
    product_id: str
    quantity: int = 1


class AddWishlistRequest(BaseModel):
    product_id: str


class CheckoutRequest(BaseModel):
    shipping_address: Optional[str] = None


# ----------------------------------------------------------------------------
# Auth Endpoints
# ----------------------------------------------------------------------------

@app.post("/auth/register", response_model=TokenResponse)
def register(body: RegisterRequest):
    existing = db["user"].find_one({"email": body.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    user = UserSchema(
        name=body.name,
        email=body.email,
        password_hash=hash_password(body.password),
        is_admin=False,
        is_active=True,
        cart=[],
        wishlist=[],
    )
    uid = db["user"].insert_one({**user.model_dump(), "created_at": datetime.utcnow(), "updated_at": datetime.utcnow()}).inserted_id
    token = create_access_token({"sub": str(uid)})
    return TokenResponse(access_token=token)


@app.post("/auth/login", response_model=TokenResponse)
def login(body: LoginRequest):
    user = db["user"].find_one({"email": body.email})
    if not user or not user.get("password_hash") or not verify_password(body.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token({"sub": str(user["_id"])})
    return TokenResponse(access_token=token)


@app.get("/me")
def me(current=Depends(get_current_user)):
    return doc_to_public(current)


# ----------------------------------------------------------------------------
# Product Endpoints
# ----------------------------------------------------------------------------

@app.get("/products")
def list_products(
    q: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    sort: Optional[str] = Query(None, description="price_asc|price_desc|rating_desc|rating_asc"),
    page: int = 1,
    limit: int = 12,
):
    query: Dict[str, Any] = {}
    if q:
        query["$or"] = [
            {"title": {"$regex": q, "$options": "i"}},
            {"description": {"$regex": q, "$options": "i"}},
            {"tags": {"$regex": q, "$options": "i"}},
        ]
    if category:
        query["category"] = category

    cursor = db["product"].find(query)
    total = cursor.count() if hasattr(cursor, 'count') else db["product"].count_documents(query)

    sort_map = {
        "price_asc": ("price", 1),
        "price_desc": ("price", -1),
        "rating_desc": ("rating", -1),
        "rating_asc": ("rating", 1),
        "newest": ("created_at", -1),
    }
    if sort and sort in sort_map:
        field, direction = sort_map[sort]
        cursor = cursor.sort(field, direction)

    skip = max(0, (page - 1) * limit)
    cursor = cursor.skip(skip).limit(limit)

    items = [doc_to_public(x) for x in cursor]
    categories = db["product"].distinct("category")
    return {"items": items, "total": total, "page": page, "limit": limit, "categories": categories}


@app.get("/products/{product_id}")
def get_product(product_id: str):
    try:
        doc = db["product"].find_one({"_id": ObjectId(product_id)})
    except Exception:
        raise HTTPException(status_code=404, detail="Product not found")
    if not doc:
        raise HTTPException(status_code=404, detail="Product not found")
    return doc_to_public(doc)


# ----------------------------------------------------------------------------
# Admin: Product Management
# ----------------------------------------------------------------------------

@app.post("/admin/products")
def admin_create_product(body: ProductCreateRequest, user=Depends(get_current_admin)):
    product = ProductSchema(
        title=body.title,
        description=body.description,
        price=body.price,
        category=body.category,
        stock=body.stock,
        images=body.images or [],
        tags=body.tags or [],
    )
    pid = db["product"].insert_one({**product.model_dump(), "created_at": datetime.utcnow(), "updated_at": datetime.utcnow()}).inserted_id
    return {"id": str(pid)}


@app.put("/admin/products/{product_id}")
def admin_update_product(product_id: str, body: ProductUpdateRequest, user=Depends(get_current_admin)):
    update = {k: v for k, v in body.model_dump().items() if v is not None}
    update["updated_at"] = datetime.utcnow()
    res = db["product"].update_one({"_id": ObjectId(product_id)}, {"$set": update})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Product not found")
    return {"updated": True}


@app.delete("/admin/products/{product_id}")
def admin_delete_product(product_id: str, user=Depends(get_current_admin)):
    res = db["product"].delete_one({"_id": ObjectId(product_id)})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Product not found")
    return {"deleted": True}


# ----------------------------------------------------------------------------
# Cart & Wishlist
# ----------------------------------------------------------------------------

@app.get("/me/cart")
def get_cart(current=Depends(get_current_user)):
    return current.get("cart", [])


@app.post("/me/cart")
def add_to_cart(body: AddCartRequest, current=Depends(get_current_user)):
    product = db["product"].find_one({"_id": ObjectId(body.product_id)})
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    price = product.get("price", 0.0)
    cart: List[Dict[str, Any]] = current.get("cart", [])
    found = False
    for item in cart:
        if item.get("product_id") == body.product_id:
            item["quantity"] = item.get("quantity", 1) + max(1, body.quantity)
            found = True
            break
    if not found:
        cart.append({"product_id": body.product_id, "quantity": max(1, body.quantity), "price_at_add": price})
    db["user"].update_one({"_id": current["_id"]}, {"$set": {"cart": cart, "updated_at": datetime.utcnow()}})
    return {"ok": True, "cart": cart}


@app.delete("/me/cart/{product_id}")
def remove_from_cart(product_id: str, current=Depends(get_current_user)):
    cart: List[Dict[str, Any]] = current.get("cart", [])
    cart = [c for c in cart if c.get("product_id") != product_id]
    db["user"].update_one({"_id": current["_id"]}, {"$set": {"cart": cart, "updated_at": datetime.utcnow()}})
    return {"ok": True, "cart": cart}


@app.get("/me/wishlist")
def get_wishlist(current=Depends(get_current_user)):
    return current.get("wishlist", [])


@app.post("/me/wishlist")
def add_wishlist(body: AddWishlistRequest, current=Depends(get_current_user)):
    wishlist: List[Dict[str, Any]] = current.get("wishlist", [])
    if not any(w.get("product_id") == body.product_id for w in wishlist):
        wishlist.append({"product_id": body.product_id})
    db["user"].update_one({"_id": current["_id"]}, {"$set": {"wishlist": wishlist, "updated_at": datetime.utcnow()}})
    return {"ok": True, "wishlist": wishlist}


@app.delete("/me/wishlist/{product_id}")
def remove_wishlist(product_id: str, current=Depends(get_current_user)):
    wishlist: List[Dict[str, Any]] = current.get("wishlist", [])
    wishlist = [w for w in wishlist if w.get("product_id") != product_id]
    db["user"].update_one({"_id": current["_id"]}, {"$set": {"wishlist": wishlist, "updated_at": datetime.utcnow()}})
    return {"ok": True, "wishlist": wishlist}


# ----------------------------------------------------------------------------
# Orders (Checkout & Tracking)
# ----------------------------------------------------------------------------

@app.post("/orders/checkout")
def checkout(body: CheckoutRequest, current=Depends(get_current_user)):
    cart: List[Dict[str, Any]] = current.get("cart", [])
    if not cart:
        raise HTTPException(status_code=400, detail="Cart is empty")

    # Build items from current product data
    items: List[OrderItem] = []
    subtotal = 0.0
    for c in cart:
        p = db["product"].find_one({"_id": ObjectId(c["product_id"])})
        if not p:
            raise HTTPException(status_code=400, detail="Product in cart no longer exists")
        qty = int(c.get("quantity", 1))
        price = float(p.get("price", 0))
        subtotal += qty * price
        items.append(OrderItem(product_id=str(p["_id"]), title=p.get("title"), price=price, quantity=qty, image=(p.get("images") or [None])[0]))
        # Decrement stock (not going below zero)
        db["product"].update_one({"_id": p["_id"]}, {"$inc": {"stock": -qty}})

    shipping = 0.0 if subtotal >= 50 else 4.99
    total = round(subtotal + shipping, 2)

    order = OrderSchema(
        user_id=str(current["_id"]),
        items=items,
        subtotal=round(subtotal, 2),
        shipping=round(shipping, 2),
        total=total,
        status="processing",
        shipping_address=body.shipping_address or current.get("address"),
    )
    oid = db["order"].insert_one({**order.model_dump(), "created_at": datetime.utcnow(), "updated_at": datetime.utcnow()}).inserted_id

    # Clear cart
    db["user"].update_one({"_id": current["_id"]}, {"$set": {"cart": [], "updated_at": datetime.utcnow()}})

    return {"id": str(oid), "total": total, "status": "processing"}


@app.get("/orders")
def list_orders(current=Depends(get_current_user)):
    cursor = db["order"].find({"user_id": str(current["_id"])}, sort=[("created_at", -1)])
    return [doc_to_public(o) for o in cursor]


@app.get("/orders/{order_id}")
def get_order(order_id: str, current=Depends(get_current_user)):
    doc = db["order"].find_one({"_id": ObjectId(order_id), "user_id": str(current["_id"])})
    if not doc:
        raise HTTPException(status_code=404, detail="Order not found")
    return doc_to_public(doc)


@app.get("/admin/orders")
def admin_orders(user=Depends(get_current_admin)):
    cursor = db["order"].find({}, sort=[("created_at", -1)])
    return [doc_to_public(o) for o in cursor]


# ----------------------------------------------------------------------------
# Health and Test
# ----------------------------------------------------------------------------

@app.get("/")
def root():
    return {"message": "E-commerce API running"}


@app.get("/test")
def test_database():
    try:
        collections = db.list_collection_names()
        return {"backend": "ok", "db": "ok", "collections": collections}
    except Exception as e:
        return {"backend": "ok", "db": f"error: {e}"}


# ----------------------------------------------------------------------------
# Seed Data (idempotent) and Startup Hook
# ----------------------------------------------------------------------------

SAMPLE_PRODUCTS = [
    {
        "title": "Echo Speaker (3rd Gen)",
        "description": "Smart speaker with immersive sound and Alexa.",
        "price": 39.99,
        "category": "Electronics",
        "stock": 120,
        "images": [
            "https://images.unsplash.com/photo-1518445692141-b4bd9a3bf3f0?q=80&w=1200&auto=format&fit=crop",
        ],
        "rating": 4.5,
        "tags": ["speaker", "smart", "alexa"],
    },
    {
        "title": "Noise-Canceling Headphones",
        "description": "Over-ear wireless headphones with active noise cancellation.",
        "price": 89.0,
        "category": "Electronics",
        "stock": 80,
        "images": [
            "https://images.unsplash.com/photo-1518443895914-6bd2e0def5a6?q=80&w=1200&auto=format&fit=crop",
        ],
        "rating": 4.6,
        "tags": ["audio", "wireless"],
    },
    {
        "title": "Minimal Backpack",
        "description": "Water-resistant backpack for daily carry.",
        "price": 59.5,
        "category": "Accessories",
        "stock": 55,
        "images": [
            "https://images.unsplash.com/photo-1483985988355-763728e1935b?q=80&w=1200&auto=format&fit=crop",
        ],
        "rating": 4.2,
        "tags": ["bag", "travel"],
    },
    {
        "title": "Running Shoes",
        "description": "Breathable, lightweight running shoes for everyday training.",
        "price": 74.99,
        "category": "Footwear",
        "stock": 200,
        "images": [
            "https://images.unsplash.com/photo-1542291026-7eec264c27ff?q=80&w=1200&auto=format&fit=crop",
        ],
        "rating": 4.4,
        "tags": ["shoes", "sport"],
    },
]


def seed_data():
    # Create admin if not exists
    admin_email = "admin@shop.local"
    existing_admin = db["user"].find_one({"email": admin_email})
    if not existing_admin:
        admin = UserSchema(
            name="Admin",
            email=admin_email,
            password_hash=hash_password("admin123"),
            is_admin=True,
            is_active=True,
            cart=[],
            wishlist=[],
        )
        db["user"].insert_one({**admin.model_dump(), "created_at": datetime.utcnow(), "updated_at": datetime.utcnow()})

    # Seed products if collection is empty
    if db["product"].count_documents({}) == 0:
        for p in SAMPLE_PRODUCTS:
            prod = ProductSchema(
                title=p["title"],
                description=p.get("description"),
                price=p["price"],
                category=p["category"],
                stock=p["stock"],
                images=p.get("images", []),
                rating=p.get("rating", 0),
                tags=p.get("tags", []),
            )
            db["product"].insert_one({**prod.model_dump(), "created_at": datetime.utcnow(), "updated_at": datetime.utcnow()})


@app.post("/admin/seed")
def trigger_seed(user=Depends(get_current_admin)):
    seed_data()
    return {"seeded": True}


@app.on_event("startup")
def on_startup():
    try:
        seed_data()
    except Exception:
        # Ignore seeding errors on cold start
        pass


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
