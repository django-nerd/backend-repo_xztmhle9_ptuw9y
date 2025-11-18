import os
from datetime import datetime, timedelta, timezone
import hashlib
import secrets
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Depends, Header, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from bson import ObjectId

from database import db, create_document, get_documents
from schemas import (
    UserCreate, UserLogin, TokenResponse,
    StoreCreate,
    ProductCreate, ProductUpdate,
    CustomerCreate, CustomerUpdate,
    OrderCreate, OrderStatusUpdate
)

app = FastAPI(title="ShopFlow API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------- Helpers --------------------

def to_object_id(id_str: str) -> ObjectId:
    try:
        return ObjectId(id_str)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid id format")


def hash_password(password: str, salt: Optional[str] = None) -> tuple[str, str]:
    if not salt:
        salt = secrets.token_hex(16)
    h = hashlib.sha256((salt + password).encode()).hexdigest()
    return h, salt


def verify_password(password: str, salt: str, expected_hash: str) -> bool:
    h, _ = hash_password(password, salt)
    return h == expected_hash


def doc_to_json(doc: dict) -> dict:
    if not doc:
        return doc
    out = {}
    for k, v in doc.items():
        if isinstance(v, ObjectId):
            out[k] = str(v)
        elif isinstance(v, datetime):
            out[k] = v.isoformat()
        elif isinstance(v, list):
            out[k] = [doc_to_json(x) if isinstance(x, dict) else (str(x) if isinstance(x, ObjectId) else x) for x in v]
        else:
            out[k] = v
    return out


class AuthUser(BaseModel):
    id: str
    email: EmailStr
    name: str


def get_user_by_token(token: str) -> Optional[dict]:
    return db["user"].find_one({"token": token, "token_expires": {"$gt": datetime.now(timezone.utc)}})


async def auth_dependency(authorization: Optional[str] = Header(None)) -> AuthUser:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid authorization header")
    token = authorization.split(" ", 1)[1]
    user = get_user_by_token(token)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return AuthUser(id=str(user["_id"]), email=user["email"], name=user.get("name", ""))


# -------------------- Health & Test --------------------

@app.get("/")
def read_root():
    return {"message": "ShopFlow API is running"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
            response["database_name"] = db.name if hasattr(db, 'name') else "✅ Connected"
            response["connection_status"] = "Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️ Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️ Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"
    return response


# -------------------- Auth --------------------

@app.post("/auth/register", response_model=dict)
def register(payload: UserCreate):
    existing = db["user"].find_one({"email": payload.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    pw_hash, salt = hash_password(payload.password)
    user_doc = {
        "name": payload.name,
        "email": payload.email,
        "password_hash": pw_hash,
        "salt": salt,
        "is_active": True,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    inserted_id = db["user"].insert_one(user_doc).inserted_id
    return {"id": str(inserted_id), "email": payload.email, "name": payload.name}


@app.post("/auth/login", response_model=TokenResponse)
def login(payload: UserLogin):
    user = db["user"].find_one({"email": payload.email})
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not verify_password(payload.password, user.get("salt", ""), user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = secrets.token_urlsafe(32)
    expires = datetime.now(timezone.utc) + timedelta(days=7)
    db["user"].update_one({"_id": user["_id"]}, {"$set": {"token": token, "token_expires": expires}})
    return TokenResponse(access_token=token)


@app.get("/me", response_model=AuthUser)
def me(user: AuthUser = Depends(auth_dependency)):
    return user


# -------------------- Stores --------------------

@app.post("/stores", response_model=dict)
def create_store(payload: StoreCreate, user: AuthUser = Depends(auth_dependency)):
    if db["store"].find_one({"slug": payload.slug}):
        raise HTTPException(status_code=400, detail="Slug already in use")
    store_doc = {
        "name": payload.name,
        "slug": payload.slug,
        "description": payload.description,
        "owner_id": user.id,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    store_id = db["store"].insert_one(store_doc).inserted_id
    return {"id": str(store_id), **payload.model_dump()}


@app.get("/stores", response_model=List[dict])
def list_stores(user: AuthUser = Depends(auth_dependency)):
    stores = db["store"].find({"owner_id": user.id}).sort("created_at", -1)
    return [doc_to_json(s) for s in stores]


@app.get("/stores/{store_id}", response_model=dict)
def get_store(store_id: str, user: AuthUser = Depends(auth_dependency)):
    store = db["store"].find_one({"_id": to_object_id(store_id), "owner_id": user.id})
    if not store:
        raise HTTPException(status_code=404, detail="Store not found")
    return doc_to_json(store)


# -------------------- Products --------------------

@app.post("/stores/{store_id}/products", response_model=dict)
def create_product(store_id: str, payload: ProductCreate, user: AuthUser = Depends(auth_dependency)):
    store = db["store"].find_one({"_id": to_object_id(store_id), "owner_id": user.id})
    if not store:
        raise HTTPException(status_code=404, detail="Store not found")
    prod = {
        "store_id": store_id,
        **payload.model_dump(),
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    pid = db["product"].insert_one(prod).inserted_id
    return {"id": str(pid), **payload.model_dump()}


@app.get("/stores/{store_id}/products", response_model=List[dict])
def list_products(store_id: str, q: Optional[str] = Query(None), user: AuthUser = Depends(auth_dependency)):
    store = db["store"].find_one({"_id": to_object_id(store_id), "owner_id": user.id})
    if not store:
        raise HTTPException(status_code=404, detail="Store not found")
    filter_query = {"store_id": store_id}
    if q:
        filter_query["title"] = {"$regex": q, "$options": "i"}
    products = db["product"].find(filter_query).sort("created_at", -1)
    return [doc_to_json(p) for p in products]


@app.get("/products/{product_id}", response_model=dict)
def get_product(product_id: str, user: AuthUser = Depends(auth_dependency)):
    prod = db["product"].find_one({"_id": to_object_id(product_id)})
    if not prod:
        raise HTTPException(status_code=404, detail="Product not found")
    # ensure owner
    store = db["store"].find_one({"_id": to_object_id(prod.get("store_id"))}) if prod.get("store_id") else None
    if not store or store.get("owner_id") != user.id:
        raise HTTPException(status_code=403, detail="Forbidden")
    return doc_to_json(prod)


@app.patch("/products/{product_id}", response_model=dict)
def update_product(product_id: str, payload: ProductUpdate, user: AuthUser = Depends(auth_dependency)):
    prod = db["product"].find_one({"_id": to_object_id(product_id)})
    if not prod:
        raise HTTPException(status_code=404, detail="Product not found")
    store = db["store"].find_one({"_id": to_object_id(prod.get("store_id"))}) if prod.get("store_id") else None
    if not store or store.get("owner_id") != user.id:
        raise HTTPException(status_code=403, detail="Forbidden")
    update = {k: v for k, v in payload.model_dump().items() if v is not None}
    update["updated_at"] = datetime.now(timezone.utc)
    db["product"].update_one({"_id": prod["_id"]}, {"$set": update})
    new_doc = db["product"].find_one({"_id": prod["_id"]})
    return doc_to_json(new_doc)


@app.delete("/products/{product_id}", response_model=dict)
def delete_product(product_id: str, user: AuthUser = Depends(auth_dependency)):
    prod = db["product"].find_one({"_id": to_object_id(product_id)})
    if not prod:
        raise HTTPException(status_code=404, detail="Product not found")
    store = db["store"].find_one({"_id": to_object_id(prod.get("store_id"))}) if prod.get("store_id") else None
    if not store or store.get("owner_id") != user.id:
        raise HTTPException(status_code=403, detail="Forbidden")
    db["product"].delete_one({"_id": prod["_id"]})
    return {"ok": True}


# -------------------- Customers --------------------

@app.post("/stores/{store_id}/customers", response_model=dict)
def create_customer(store_id: str, payload: CustomerCreate, user: AuthUser = Depends(auth_dependency)):
    store = db["store"].find_one({"_id": to_object_id(store_id), "owner_id": user.id})
    if not store:
        raise HTTPException(status_code=404, detail="Store not found")
    existing = db["customer"].find_one({"store_id": store_id, "email": payload.email})
    if existing:
        raise HTTPException(status_code=400, detail="Customer already exists")
    cust = {
        "store_id": store_id,
        **payload.model_dump(),
        "order_ids": [],
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    cid = db["customer"].insert_one(cust).inserted_id
    return {"id": str(cid), **payload.model_dump()}


@app.get("/stores/{store_id}/customers", response_model=List[dict])
def list_customers(store_id: str, user: AuthUser = Depends(auth_dependency)):
    store = db["store"].find_one({"_id": to_object_id(store_id), "owner_id": user.id})
    if not store:
        raise HTTPException(status_code=404, detail="Store not found")
    customers = db["customer"].find({"store_id": store_id}).sort("created_at", -1)
    return [doc_to_json(c) for c in customers]


@app.get("/customers/{customer_id}", response_model=dict)
def get_customer(customer_id: str, user: AuthUser = Depends(auth_dependency)):
    cust = db["customer"].find_one({"_id": to_object_id(customer_id)})
    if not cust:
        raise HTTPException(status_code=404, detail="Customer not found")
    store = db["store"].find_one({"_id": to_object_id(cust.get("store_id"))}) if cust.get("store_id") else None
    if not store or store.get("owner_id") != user.id:
        raise HTTPException(status_code=403, detail="Forbidden")
    return doc_to_json(cust)


@app.patch("/customers/{customer_id}", response_model=dict)
def update_customer(customer_id: str, payload: CustomerUpdate, user: AuthUser = Depends(auth_dependency)):
    cust = db["customer"].find_one({"_id": to_object_id(customer_id)})
    if not cust:
        raise HTTPException(status_code=404, detail="Customer not found")
    store = db["store"].find_one({"_id": to_object_id(cust.get("store_id"))}) if cust.get("store_id") else None
    if not store or store.get("owner_id") != user.id:
        raise HTTPException(status_code=403, detail="Forbidden")
    update = {k: v for k, v in payload.model_dump().items() if v is not None}
    update["updated_at"] = datetime.now(timezone.utc)
    db["customer"].update_one({"_id": cust["_id"]}, {"$set": update})
    new_doc = db["customer"].find_one({"_id": cust["_id"]})
    return doc_to_json(new_doc)


@app.delete("/customers/{customer_id}", response_model=dict)
def delete_customer(customer_id: str, user: AuthUser = Depends(auth_dependency)):
    cust = db["customer"].find_one({"_id": to_object_id(customer_id)})
    if not cust:
        raise HTTPException(status_code=404, detail="Customer not found")
    store = db["store"].find_one({"_id": to_object_id(cust.get("store_id"))}) if cust.get("store_id") else None
    if not store or store.get("owner_id") != user.id:
        raise HTTPException(status_code=403, detail="Forbidden")
    db["customer"].delete_one({"_id": cust["_id"]})
    return {"ok": True}


# -------------------- Orders --------------------

@app.post("/stores/{store_id}/orders", response_model=dict)
def create_order(store_id: str, payload: OrderCreate, user: AuthUser = Depends(auth_dependency)):
    store = db["store"].find_one({"_id": to_object_id(store_id), "owner_id": user.id})
    if not store:
        raise HTTPException(status_code=404, detail="Store not found")
    # compute total
    total = 0.0
    for item in payload.items:
        total += item.price * item.quantity
    order_doc = {
        "store_id": store_id,
        "customer_id": payload.customer_id,
        "email": payload.email,
        "items": [i.model_dump() for i in payload.items],
        "total": round(total, 2),
        "status": "pending",
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    oid = db["order"].insert_one(order_doc).inserted_id
    if payload.customer_id:
        db["customer"].update_one({"_id": to_object_id(payload.customer_id)}, {"$push": {"order_ids": str(oid)}})
    return {"id": str(oid), **doc_to_json(order_doc)}


@app.get("/stores/{store_id}/orders", response_model=List[dict])
def list_orders(store_id: str, status: Optional[str] = Query(None), user: AuthUser = Depends(auth_dependency)):
    store = db["store"].find_one({"_id": to_object_id(store_id), "owner_id": user.id})
    if not store:
        raise HTTPException(status_code=404, detail="Store not found")
    query = {"store_id": store_id}
    if status:
        query["status"] = status
    orders = db["order"].find(query).sort("created_at", -1)
    return [doc_to_json(o) for o in orders]


@app.get("/orders/{order_id}", response_model=dict)
def get_order(order_id: str, user: AuthUser = Depends(auth_dependency)):
    order = db["order"].find_one({"_id": to_object_id(order_id)})
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    store = db["store"].find_one({"_id": to_object_id(order.get("store_id"))}) if order.get("store_id") else None
    if not store or store.get("owner_id") != user.id:
        raise HTTPException(status_code=403, detail="Forbidden")
    return doc_to_json(order)


@app.patch("/orders/{order_id}/status", response_model=dict)
def update_order_status(order_id: str, payload: OrderStatusUpdate, user: AuthUser = Depends(auth_dependency)):
    order = db["order"].find_one({"_id": to_object_id(order_id)})
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    store = db["store"].find_one({"_id": to_object_id(order.get("store_id"))}) if order.get("store_id") else None
    if not store or store.get("owner_id") != user.id:
        raise HTTPException(status_code=403, detail="Forbidden")
    db["order"].update_one({"_id": order["_id"]}, {"$set": {"status": payload.status, "updated_at": datetime.now(timezone.utc)}})
    new_doc = db["order"].find_one({"_id": order["_id"]})
    return doc_to_json(new_doc)


# -------------------- Metrics --------------------

@app.get("/stores/{store_id}/metrics", response_model=dict)
def store_metrics(store_id: str, user: AuthUser = Depends(auth_dependency)):
    store = db["store"].find_one({"_id": to_object_id(store_id), "owner_id": user.id})
    if not store:
        raise HTTPException(status_code=404, detail="Store not found")
    total_customers = db["customer"].count_documents({"store_id": store_id})
    total_orders = db["order"].count_documents({"store_id": store_id})
    paid_orders = db["order"].find({"store_id": store_id, "status": {"$in": ["paid", "fulfilled"]}})
    total_sales = 0.0
    for o in paid_orders:
        total_sales += float(o.get("total", 0))
    return {
        "total_customers": total_customers,
        "total_orders": total_orders,
        "total_sales": round(total_sales, 2),
    }


# -------------------- Storefront --------------------

@app.get("/s/{slug}/products", response_model=List[dict])
def storefront_products(slug: str, q: Optional[str] = Query(None)):
    store = db["store"].find_one({"slug": slug})
    if not store:
        raise HTTPException(status_code=404, detail="Store not found")
    filter_query = {"store_id": str(store["_id"]) }
    if q:
        filter_query["title"] = {"$regex": q, "$options": "i"}
    products = db["product"].find(filter_query).sort("created_at", -1)
    return [doc_to_json(p) for p in products]


@app.get("/s/{slug}/product/{product_id}", response_model=dict)
def storefront_product(slug: str, product_id: str):
    store = db["store"].find_one({"slug": slug})
    if not store:
        raise HTTPException(status_code=404, detail="Store not found")
    prod = db["product"].find_one({"_id": to_object_id(product_id), "store_id": str(store["_id"])})
    if not prod:
        raise HTTPException(status_code=404, detail="Product not found")
    return doc_to_json(prod)


class CheckoutItem(BaseModel):
    product_id: str
    quantity: int

class CheckoutPayload(BaseModel):
    name: Optional[str] = None
    email: Optional[EmailStr] = None
    items: List[CheckoutItem]
    simulate_payment: bool = True


@app.post("/s/{slug}/checkout", response_model=dict)
def storefront_checkout(slug: str, payload: CheckoutPayload):
    store = db["store"].find_one({"slug": slug})
    if not store:
        raise HTTPException(status_code=404, detail="Store not found")
    store_id = str(store["_id"])
    # Build order items from product ids
    items = []
    total = 0.0
    for ci in payload.items:
        prod = db["product"].find_one({"_id": to_object_id(ci.product_id), "store_id": store_id})
        if not prod:
            raise HTTPException(status_code=400, detail=f"Invalid product {ci.product_id}")
        item = {
            "product_id": str(prod["_id"]),
            "title": prod["title"],
            "price": float(prod["price"]),
            "quantity": ci.quantity,
        }
        items.append(item)
        total += item["price"] * item["quantity"]
    status = "paid" if payload.simulate_payment else "pending"
    customer_id = None
    if payload.email:
        existing = db["customer"].find_one({"store_id": store_id, "email": payload.email})
        if existing:
            customer_id = str(existing["_id"]) 
        else:
            customer_doc = {
                "store_id": store_id,
                "name": payload.name or payload.email.split("@")[0],
                "email": payload.email,
                "tags": [],
                "order_ids": [],
                "created_at": datetime.now(timezone.utc),
                "updated_at": datetime.now(timezone.utc),
            }
            customer_id = str(db["customer"].insert_one(customer_doc).inserted_id)
    order_doc = {
        "store_id": store_id,
        "customer_id": customer_id,
        "email": payload.email,
        "items": items,
        "total": round(total, 2),
        "status": status,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    oid = db["order"].insert_one(order_doc).inserted_id
    if customer_id:
        db["customer"].update_one({"_id": to_object_id(customer_id)}, {"$push": {"order_ids": str(oid)}})
    return {"order_id": str(oid), "status": status, "total": round(total, 2)}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
