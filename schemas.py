"""
Database Schemas for E-commerce App

Each Pydantic model typically maps to a MongoDB collection named after the
lowercased class name (e.g., User -> "user"). Some embedded models are used
for nested fields (e.g., order items).
"""

from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List, Literal
from datetime import datetime

# ------------ Auth & User ------------
class UserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class User(BaseModel):
    name: str
    email: EmailStr
    password_hash: str
    is_active: bool = True

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

# ------------ Store ------------
class StoreCreate(BaseModel):
    name: str
    slug: str = Field(..., description="URL-safe unique identifier for the store")
    description: Optional[str] = None

class Store(BaseModel):
    name: str
    slug: str
    description: Optional[str] = None
    owner_id: str

# ------------ Products ------------
class ProductCreate(BaseModel):
    title: str
    description: Optional[str] = None
    price: float = Field(..., ge=0)
    stock: int = Field(..., ge=0)
    category: Optional[str] = None
    images: List[str] = []

class ProductUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    price: Optional[float] = Field(None, ge=0)
    stock: Optional[int] = Field(None, ge=0)
    category: Optional[str] = None
    images: Optional[List[str]] = None

class Product(BaseModel):
    store_id: str
    title: str
    description: Optional[str] = None
    price: float
    stock: int
    category: Optional[str] = None
    images: List[str] = []
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

# ------------ Customers ------------
class CustomerCreate(BaseModel):
    name: str
    email: EmailStr
    tags: List[str] = []

class CustomerUpdate(BaseModel):
    name: Optional[str] = None
    email: Optional[EmailStr] = None
    tags: Optional[List[str]] = None

class Customer(BaseModel):
    store_id: str
    name: str
    email: EmailStr
    tags: List[str] = []

# ------------ Orders ------------
class OrderItem(BaseModel):
    product_id: str
    title: str
    price: float
    quantity: int = Field(..., ge=1)

class OrderCreate(BaseModel):
    store_id: str
    customer_id: Optional[str] = None
    email: Optional[EmailStr] = None
    items: List[OrderItem]

class OrderStatusUpdate(BaseModel):
    status: Literal["pending", "paid", "fulfilled", "cancelled"]

class Order(BaseModel):
    store_id: str
    customer_id: Optional[str] = None
    email: Optional[EmailStr] = None
    items: List[OrderItem]
    total: float
    status: Literal["pending", "paid", "fulfilled", "cancelled"] = "pending"
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
