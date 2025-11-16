"""
Database Schemas for E‑commerce App

Each Pydantic model represents a collection in MongoDB.
Collection name is the lowercase of the class name by default.

We store:
- User (includes cart and wishlist for simplicity)
- Product
- Order
"""

from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional
from datetime import datetime


class CartItem(BaseModel):
    product_id: str = Field(..., description="Product id as string")
    quantity: int = Field(1, ge=1, description="Quantity for the product")
    price_at_add: float = Field(..., ge=0, description="Snapshot price when added")


class WishlistItem(BaseModel):
    product_id: str = Field(..., description="Product id as string")


class User(BaseModel):
    """
    Users collection schema
    Collection name: "user"
    """
    name: str = Field(..., description="Full name")
    email: EmailStr = Field(..., description="Email address")

    # Auth fields (stored in DB, but not returned in public responses)
    password_hash: Optional[str] = Field(None, description="Hashed password")

    address: Optional[str] = Field(None, description="Default shipping address")
    is_active: bool = Field(True, description="Whether user is active")
    is_admin: bool = Field(False, description="Admin flag")

    # Embedded simple cart and wishlist for fast access
    cart: List[CartItem] = Field(default_factory=list)
    wishlist: List[WishlistItem] = Field(default_factory=list)


class Product(BaseModel):
    """
    Products collection schema
    Collection name: "product"
    """
    title: str = Field(..., description="Product title")
    description: Optional[str] = Field(None, description="Product description")
    price: float = Field(..., ge=0, description="Price in dollars")
    category: str = Field(..., description="Product category")
    stock: int = Field(0, ge=0, description="Available inventory")
    images: List[str] = Field(default_factory=list, description="Image URLs")
    rating: float = Field(0, ge=0, le=5, description="Average rating 0-5")
    tags: List[str] = Field(default_factory=list, description="Search tags")


class OrderItem(BaseModel):
    product_id: str
    title: str
    price: float
    quantity: int
    image: Optional[str] = None


class Order(BaseModel):
    """
    Orders collection schema
    Collection name: "order"
    """
    user_id: str
    items: List[OrderItem]
    subtotal: float
    shipping: float
    total: float
    status: str = Field("processing", description="processing | shipped | delivered | canceled")
    placed_at: datetime = Field(default_factory=datetime.utcnow)
    shipping_address: Optional[str] = None
