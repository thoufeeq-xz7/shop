import json
import os
import uuid
from datetime import datetime
from functools import wraps
from pathlib import Path
from typing import Any, Dict, List, Optional

from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

# ------------------------
# Configuration & paths
# ------------------------
BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
UPLOADS_DIR = BASE_DIR / "static" / "uploads"
ITEMS_FILE = DATA_DIR / "items.json"
USERS_FILE = DATA_DIR / "users.json"
ORDERS_FILE = DATA_DIR / "orders.json"

DATA_DIR.mkdir(exist_ok=True)
UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
# ensure files exist (empty list if new)
for p in (ITEMS_FILE, USERS_FILE, ORDERS_FILE):
    p.touch(exist_ok=True)

# Credentials (override with env vars in production)
ADMIN_USERNAME = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASS", "123")
SESSION_ADMIN_KEY = "admin_logged_in"

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "dev-secret-key")

# Uploads / allowed file types
app.config["UPLOAD_FOLDER"] = str(UPLOADS_DIR)
app.config["MAX_CONTENT_LENGTH"] = 4 * 1024 * 1024  # 4MB
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}

# Session settings
app.config["SESSION_PERMANENT"] = True
app.config["PERMANENT_SESSION_LIFETIME"] = 86400 * 30  # 30 days
app.config["SESSION_COOKIE_SECURE"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# Application constants
ORDER_STATUSES = ["ordered", "paid", "dispatched", "cancelled"]


# ------------------------
# Utility helpers
# ------------------------
def parse_sizes(raw: Optional[str]) -> List[str]:
    return [s.strip() for s in (raw or "").split(",") if s.strip()]


def read_json(path: Path) -> List[Dict[str, Any]]:
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
            return data if isinstance(data, list) else []
    except (json.JSONDecodeError, FileNotFoundError):
        return []


def write_json(path: Path, payload: List[Dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)


def read_items() -> List[Dict[str, Any]]:
    return read_json(ITEMS_FILE)


def write_items(items: List[Dict[str, Any]]) -> None:
    write_json(ITEMS_FILE, items)


def read_users() -> List[Dict[str, Any]]:
    return read_json(USERS_FILE)


def write_users(users: List[Dict[str, Any]]) -> None:
    write_json(USERS_FILE, users)


def read_orders() -> List[Dict[str, Any]]:
    orders = read_json(ORDERS_FILE)
    changed = False
    for o in orders:
        if "status" not in o:
            o["status"] = "ordered"
            changed = True
    if changed:
        write_orders(orders)
    return orders


def write_orders(orders: List[Dict[str, Any]]) -> None:
    write_json(ORDERS_FILE, orders)


def allowed_file(filename: str) -> bool:
    return bool(filename and "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS)


def find_item(item_id: str) -> Optional[Dict[str, Any]]:
    return next((it for it in read_items() if it.get("id") == item_id), None)


def find_order(order_id: str) -> Optional[Dict[str, Any]]:
    return next((o for o in read_orders() if str(o.get("id")) == str(order_id)), None)


def ensure_items_list(order: Dict[str, Any]) -> None:
    """Ensure order['items'] is a list for safe iteration in templates."""
    if not isinstance(order, dict):
        return
    items = order.get("items")
    if isinstance(items, dict):
        order["items"] = list(items.values())
    elif items is None:
        order["items"] = []
    elif isinstance(items, (list, tuple)):
        order["items"] = list(items)
    else:
        order["items"] = [items]


def normalize_item_for_cart(item: Dict[str, Any], quantity: int, size: Optional[str]) -> Dict[str, Any]:
    return {
        "id": item["id"],
        "name": item["name"],
        "price": item["price"],
        "quantity": quantity,
        "size": size or "",
        "image": item.get("image", ""),
        "available_sizes": item.get("sizes", []),
    }


def merge_cart_item(cart: List[Dict[str, Any]], new_item: Dict[str, Any]) -> List[Dict[str, Any]]:
    for existing in cart:
        if existing["id"] == new_item["id"] and existing.get("size", "") == new_item.get("size", ""):
            existing["quantity"] += new_item["quantity"]
            return cart
    cart.append(new_item)
    return cart


def get_cart() -> List[Dict[str, Any]]:
    cart = session.get("cart", [])
    if not cart:
        return cart
    items_lookup = {it["id"]: it for it in read_items()}
    for entry in cart:
        entry.setdefault("available_sizes", items_lookup.get(entry["id"], {}).get("sizes", []) or [])
    return cart


def save_cart(cart: List[Dict[str, Any]]) -> None:
    session["cart"] = cart
    session.modified = True


def cart_summary(cart: List[Dict[str, Any]]) -> Dict[str, Any]:
    total = 0.0
    try:
        total = sum(float(item["price"]) * item["quantity"] for item in cart)
    except Exception:
        total = 0.0
    count = sum(item.get("quantity", 0) for item in cart)
    return {"total": total, "count": count}


@app.context_processor
def inject_cart_meta() -> Dict[str, Any]:
    cart = get_cart()
    return {"cart_count": cart_summary(cart)["count"]}


def admin_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if not session.get(SESSION_ADMIN_KEY):
            flash("Please login as admin to continue.", "warning")
            return redirect(url_for("user_login"))
        return view_func(*args, **kwargs)

    return wrapper


# ------------------------
# Routes
# ------------------------
@app.route("/")
def index():
    q = request.args.get("q", "").strip().lower()
    category = request.args.get("category", "").strip().lower()
    items = read_items()

    if q:
        items = [it for it in items if q in it.get("name", "").lower() or q in it.get("description", "").lower()]

    if category:
        items = [it for it in items if category == it.get("category", "").lower()]

    return render_template("index.html", items=items, q=q, category=category)


# Admin authentication
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if session.get(SESSION_ADMIN_KEY):
        return redirect(url_for("admin_dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session[SESSION_ADMIN_KEY] = True
            flash("Logged in as admin.", "success")
            return redirect(url_for("admin_dashboard"))
        flash("Invalid username or password.", "danger")

    return render_template("admin_login.html")


@app.route("/admin/logout")
def admin_logout():
    session.pop(SESSION_ADMIN_KEY, None)
    flash("You have been logged out.", "info")
    return redirect(url_for("index"))


@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    items = read_items()
    orders = read_orders()
    return render_template("admin_dashboard.html", items=items, orders=orders, order_statuses=ORDER_STATUSES)


# Item management
@app.route("/admin/upload", methods=["GET", "POST"])
@admin_required
def upload_item():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        description = request.form.get("description", "").strip()
        price_raw = request.form.get("price", "").strip()
        category = request.form.get("category", "").strip().lower()
        sizes = parse_sizes(request.form.get("sizes", ""))
        image = request.files.get("image")

        if not name or not price_raw or not category:
            flash("Name, price, and category are required.", "danger")
            return render_template("upload_item.html")

        try:
            price_val = float(price_raw)
        except ValueError:
            flash("Price must be a valid number.", "danger")
            return render_template("upload_item.html")

        image_filename = ""
        if image and image.filename:
            if not allowed_file(image.filename):
                flash("Only png, jpg, jpeg, gif files are allowed.", "danger")
                return render_template("upload_item.html")
            safe_name = secure_filename(image.filename)
            image_filename = f"{uuid.uuid4().hex}_{safe_name}"
            image.save(str(UPLOADS_DIR / image_filename))

        items = read_items()
        new_item = {
            "id": uuid.uuid4().hex[:8],
            "name": name,
            "description": description,
            "price": f"{price_val:.2f}",
            "category": category,
            "sizes": sizes,
            "image": image_filename,
        }
        items.insert(0, new_item)
        write_items(items)
        flash("Item added successfully.", "success")
        return redirect(url_for("admin_dashboard"))

    return render_template("upload_item.html")


@app.route("/admin/items/<item_id>/edit", methods=["GET", "POST"])
@admin_required
def edit_item(item_id: str):
    items = read_items()
    item = next((it for it in items if it.get("id") == item_id), None)
    if not item:
        flash("Item not found.", "warning")
        return redirect(url_for("admin_dashboard"))

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        description = request.form.get("description", "").strip()
        price_raw = request.form.get("price", "").strip()
        category = request.form.get("category", "").strip().lower()
        sizes = parse_sizes(request.form.get("sizes", ""))
        image = request.files.get("image")

        if not name or not price_raw or not category:
            flash("Name, price, and category are required.", "danger")
            return render_template("edit_item.html", item=item)

        try:
            price_val = float(price_raw)
        except ValueError:
            flash("Price must be a valid number.", "danger")
            return render_template("edit_item.html", item=item)

        if image and image.filename:
            if not allowed_file(image.filename):
                flash("Only png, jpg, jpeg, gif files are allowed.", "danger")
                return render_template("edit_item.html", item=item)
            safe_name = secure_filename(image.filename)
            image_filename = f"{uuid.uuid4().hex}_{safe_name}"
            image.save(str(UPLOADS_DIR / image_filename))
            if item.get("image"):
                existing_path = UPLOADS_DIR / item["image"]
                if existing_path.exists():
                    existing_path.unlink()
            item["image"] = image_filename

        item.update({"name": name, "description": description, "price": f"{price_val:.2f}", "category": category, "sizes": sizes})
        write_items(items)
        flash("Item updated successfully.", "success")
        return redirect(url_for("admin_dashboard"))

    item.setdefault("sizes", [])
    return render_template("edit_item.html", item=item)


@app.route("/admin/items/<item_id>/delete", methods=["POST"])
@admin_required
def delete_item(item_id: str):
    items = read_items()
    remaining = [it for it in items if it.get("id") != item_id]
    if len(remaining) == len(items):
        flash("Item not found.", "warning")
        return redirect(url_for("admin_dashboard"))

    removed = next((it for it in items if it.get("id") == item_id), None)
    if removed and removed.get("image"):
        image_path = UPLOADS_DIR / removed["image"]
        if image_path.exists():
            image_path.unlink()

    write_items(remaining)
    flash("Item deleted.", "info")
    return redirect(url_for("admin_dashboard"))


# ------------------------
# Cart & checkout
# ------------------------
@app.route("/cart")
def view_cart():
    cart = get_cart()
    summary = cart_summary(cart)
    return render_template("cart.html", cart=cart, summary=summary)


@app.route("/cart/add", methods=["POST"])
def add_to_cart():
    item_id = request.form.get("item_id", "").strip()
    size = request.form.get("size", "").strip()
    quantity_raw = request.form.get("quantity", "1")
    item = find_item(item_id)
    if not item:
        flash("Item not found.", "danger")
        return redirect(request.referrer or url_for("index"))

    try:
        quantity = max(1, int(quantity_raw))
    except ValueError:
        quantity = 1

    if item.get("sizes") and size and size not in item["sizes"]:
        flash("Invalid size selected.", "danger")
        return redirect(request.referrer or url_for("index"))
    if item.get("sizes") and not size:
        size = item["sizes"][0]

    cart = get_cart()
    cart = merge_cart_item(cart, normalize_item_for_cart(item, quantity, size))
    save_cart(cart)
    flash(f"Added {item['name']} to cart.", "success")
    return redirect(request.referrer or url_for("index"))


@app.route("/cart/update", methods=["POST"])
def update_cart_item():
    item_id = request.form.get("item_id")
    current_size = request.form.get("current_size", "")
    new_size = request.form.get("size", "").strip()
    quantity_raw = request.form.get("quantity", "1")
    try:
        quantity = max(0, int(quantity_raw))
    except ValueError:
        quantity = 1

    cart = get_cart()
    target_index = next((i for i, it in enumerate(cart) if it["id"] == item_id and it.get("size", "") == current_size), None)
    if target_index is None:
        flash("Item not found in cart.", "warning")
        return redirect(url_for("view_cart"))

    target = cart.pop(target_index)
    available_sizes = target.get("available_sizes", [])
    if available_sizes:
        if not new_size:
            new_size = current_size or available_sizes[0]
        if new_size not in available_sizes:
            flash("Invalid size selected.", "danger")
            cart.insert(target_index, target)
            save_cart(cart)
            return redirect(url_for("view_cart"))
    else:
        new_size = ""

    if quantity == 0:
        save_cart(cart)
        flash("Item removed from cart.", "info")
        return redirect(url_for("view_cart"))

    target["quantity"] = quantity
    target["size"] = new_size

    for item in cart:
        if item["id"] == target["id"] and item.get("size", "") == target.get("size", ""):
            item["quantity"] += target["quantity"]
            save_cart(cart)
            flash("Cart updated.", "info")
            return redirect(url_for("view_cart"))

    cart.append(target)
    save_cart(cart)
    flash("Cart updated.", "info")
    return redirect(url_for("view_cart"))


@app.route("/cart/remove", methods=["POST"])
def remove_cart_item():
    item_id = request.form.get("item_id")
    size = request.form.get("size", "")
    cart = get_cart()
    cart = [it for it in cart if not (it["id"] == item_id and it.get("size", "") == size)]
    save_cart(cart)
    flash("Item removed from cart.", "info")
    return redirect(url_for("view_cart"))


@app.route("/checkout", methods=["GET", "POST"])
def checkout():
    cart = get_cart()
    if not cart:
        flash("Your cart is empty.", "warning")
        return redirect(url_for("index"))

    summary = cart_summary(cart)
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()
        address = request.form.get("address", "").strip()
        notes = request.form.get("notes", "").strip()

        if not name or not phone or not email or not address:
            flash("Name, phone, email, and address are required.", "danger")
            return render_template("checkout.html", cart=cart, summary=summary)

        orders = read_orders()
        order = {
            "id": uuid.uuid4().hex[:8],
            "customer": {"name": name, "email": email, "phone": phone, "address": address, "notes": notes},
            "items": cart,
            "total": f"{summary['total']:.2f}",
            "created_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
            "status": "ordered",
        }
        orders.insert(0, order)
        write_orders(orders)
        save_cart([])
        flash("Order placed successfully! We'll contact you soon.", "success")
        return redirect(url_for("index"))

    return render_template("checkout.html", cart=cart, summary=summary)


# ------------------------
# Orders management
# ------------------------
@app.route("/admin/orders/<order_id>/status", methods=["POST"])
@admin_required
def update_order_status(order_id: str):
    new_status = request.form.get("status", "").strip().lower()
    if new_status not in ORDER_STATUSES:
        flash("Invalid status.", "danger")
        return redirect(url_for("admin_dashboard"))

    orders = read_orders()
    for order in orders:
        if str(order.get("id")) == str(order_id):
            order["status"] = new_status
            write_orders(orders)
            flash(f"Order {order_id} updated to {new_status.title()}.", "success")
            break
    else:
        flash("Order not found.", "warning")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/orders/<order_id>/delete", methods=["POST"])
@admin_required
def delete_order(order_id: str):
    orders = read_orders()
    remaining = [o for o in orders if str(o.get("id")) != str(order_id)]
    if len(remaining) == len(orders):
        flash("Order not found.", "warning")
        return redirect(url_for("admin_dashboard"))
    write_orders(remaining)
    flash(f"Order {order_id} deleted.", "info")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/orders")
@admin_required
def recent_orders():
    orders = read_orders()

    def _parse_created(o: Dict[str, Any]):
        val = o.get("created_at") or ""
        try:
            if val.endswith("Z"):
                val = val[:-1]
            return datetime.fromisoformat(val)
        except Exception:
            return datetime.min

    orders_sorted = sorted(orders, key=_parse_created, reverse=True)
    return render_template("recent_orders.html", orders=orders_sorted, order_statuses=ORDER_STATUSES)


# ------------------------
# Login / Registration
# ------------------------
@app.route("/login", methods=["GET", "POST"])
def user_login():
    if request.method == "POST":
        session.permanent = True
        name = request.form.get("name", "").strip()
        identifier = request.form.get("identifier", "").strip()
        password = request.form.get("password", "").strip()

        if not identifier or not password:
            flash("Identifier and password are required.", "danger")
            return render_template("login.html", name=name, identifier=identifier)

        # Admin login by username
        if identifier == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session[SESSION_ADMIN_KEY] = True
            flash("Logged in as admin.", "success")
            return redirect(url_for("admin_dashboard"))

        # User login/registration (email used as identifier)
        if "@" not in identifier:
            flash("Please provide a valid email to sign in as a user.", "danger")
            return render_template("login.html", name=name, identifier=identifier)

        users = read_users()
        user = next((u for u in users if (u.get("email") or "").lower() == identifier.lower()), None)

        # Existing user -> verify password
        if user:
            if user.get("password_hash") and check_password_hash(user["password_hash"], password):
                session["user_email"] = user.get("email")
                session["user_name"] = user.get("name") or name
                flash("Logged in.", "success")
                return redirect(url_for("user_dashboard"))
            flash("Incorrect password for this email.", "danger")
            return render_template("login.html", name=name, identifier=identifier)

        # New user -> register
        password_hash = generate_password_hash(password)
        new_user = {"id": uuid.uuid4().hex[:8], "name": name, "email": identifier.lower(), "password_hash": password_hash}
        users.append(new_user)
        write_users(users)
        session["user_email"] = new_user["email"]
        session["user_name"] = new_user["name"]
        flash("Account created and logged in.", "success")
        return redirect(url_for("user_dashboard"))

    return render_template("login.html")


@app.route("/logout")
def user_logout():
    session.pop("user_email", None)
    session.pop("user_name", None)
    flash("You have been logged out.", "info")
    return redirect(url_for("index"))


# ------------------------
# User dashboard
# ------------------------
@app.route("/user/dashboard")
def user_dashboard():
    user_email = session.get("user_email")
    user_name = session.get("user_name")
    if not user_email:
        flash("Please sign in to view your dashboard.", "warning")
        return redirect(url_for("user_login"))

    orders = read_orders()

    def _parse_created(o: Dict[str, Any]):
        val = o.get("created_at") or ""
        try:
            if val.endswith("Z"):
                val = val[:-1]
            return datetime.fromisoformat(val)
        except Exception:
            return datetime.min

    user_orders = [o for o in orders if (o.get("customer", {}).get("email") or "").lower() == user_email.lower()]
    user_orders_sorted = sorted(user_orders, key=_parse_created, reverse=True)
    return render_template("user_dashboard.html", orders=user_orders_sorted, user_name=user_name)


# ------------------------
# Consolidated order detail (single entry point)
# ------------------------
@app.route("/order/<order_id>")
def order_detail(order_id: str):
    """
    Single route to view an order. Admins may view any order; users may view only their own.
    """
    user_email = session.get("user_email")
    is_admin = session.get(SESSION_ADMIN_KEY)

    if not user_email and not is_admin:
        flash("Please sign in to view this order.", "warning")
        return redirect(url_for("user_login"))

    order = find_order(order_id)
    if not order:
        flash("Order not found.", "warning")
        return redirect(url_for("user_dashboard") if user_email else url_for("recent_orders"))

    # permission check
    if not is_admin:
        cust_email = (order.get("customer", {}).get("email") or "").lower()
        if cust_email != (user_email or "").lower():
            flash("You do not have permission to view this order.", "danger")
            return redirect(url_for("user_dashboard"))

    ensure_items_list(order)
    return render_template("order_detail.html", order=order)


# ------------------------
# Run
# ------------------------

