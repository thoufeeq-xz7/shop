import json
import os
import uuid
from datetime import datetime
from functools import wraps
from pathlib import Path

from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

# --- Paths & configuration -------------------------------------------------
BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
UPLOADS_DIR = BASE_DIR / "static" / "uploads"
DATA_FILE = DATA_DIR / "items.json"
USERS_FILE = DATA_DIR / "users.json"
ORDERS_FILE = DATA_DIR / "orders.json"

DATA_DIR.mkdir(exist_ok=True)
UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
ORDERS_FILE.touch(exist_ok=True)
USERS_FILE.touch(exist_ok=True)

# Admin credential defaults (override with env vars)
ADMIN_USERNAME = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASS", "123")
SESSION_ADMIN_KEY = "admin_logged_in"

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "dev-secret-key")
app.config["UPLOAD_FOLDER"] = str(UPLOADS_DIR)
app.config["MAX_CONTENT_LENGTH"] = 4 * 1024 * 1024  # 4 MB
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}
ORDER_STATUSES = ["ordered", "paid", "dispatched", "cancelled"]

# Session config
app.config["SESSION_PERMANENT"] = True
app.config["PERMANENT_SESSION_LIFETIME"] = 86400 * 30  # 30 days
app.config["SESSION_COOKIE_SECURE"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"


# --- Helpers ---------------------------------------------------------------
def parse_sizes(raw: str) -> list[str]:
    return [size.strip() for size in (raw or "").split(",") if size.strip()]


def read_json(path: Path) -> list:
    if not path.exists():
        return []
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
            return data if isinstance(data, list) else []
    except json.JSONDecodeError:
        return []


def write_json(path: Path, payload: list) -> None:
    with path.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)


def read_items() -> list[dict]:
    return read_json(DATA_FILE)


def write_items(items: list[dict]) -> None:
    write_json(DATA_FILE, items)


def read_users() -> list[dict]:
    return read_json(USERS_FILE)


def write_users(users: list[dict]) -> None:
    write_json(USERS_FILE, users)


def read_orders() -> list[dict]:
    orders = read_json(ORDERS_FILE)
    changed = False
    for order in orders:
        if "status" not in order:
            order["status"] = "ordered"
            changed = True
    if changed:
        write_orders(orders)
    return orders


def write_orders(orders: list[dict]) -> None:
    write_json(ORDERS_FILE, orders)


def allowed_file(filename: str) -> bool:
    return bool(
        filename
        and "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


def get_cart() -> list[dict]:
    cart = session.get("cart", [])
    if not cart:
        return cart
    items_lookup = {item["id"]: item for item in read_items()}
    for entry in cart:
        available = items_lookup.get(entry["id"], {}).get("sizes", [])
        entry.setdefault("available_sizes", available or [])
    return cart


def save_cart(cart: list[dict]) -> None:
    session["cart"] = cart
    session.modified = True


def cart_summary(cart: list[dict]) -> dict:
    try:
        total = sum(float(item["price"]) * item["quantity"] for item in cart)
    except Exception:
        total = 0.0
    count = sum(item["quantity"] for item in cart)
    return {"total": total, "count": count}


@app.context_processor
def inject_cart_meta():
    cart = get_cart()
    summary = cart_summary(cart)
    return {"cart_count": summary["count"]}


def admin_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if not session.get(SESSION_ADMIN_KEY):
            flash("Please login as admin to continue.", "warning")
            return redirect(url_for("user_login"))
        return view_func(*args, **kwargs)

    return wrapper


def find_item(item_id: str):
    return next((it for it in read_items() if it.get("id") == item_id), None)


def find_order(order_id: str):
    orders = read_orders()
    for o in orders:
        if str(o.get("id")) == str(order_id):
            return o
    return None


def ensure_items_list(order: dict) -> None:
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


def normalize_item_for_cart(item: dict, quantity: int, size: str | None):
    return {
        "id": item["id"],
        "name": item["name"],
        "price": item["price"],
        "quantity": quantity,
        "size": size or "",
        "image": item.get("image", ""),
        "available_sizes": item.get("sizes", []),
    }


def merge_cart_item(cart: list[dict], new_item: dict):
    for existing in cart:
        if existing["id"] == new_item["id"] and existing.get("size", "") == new_item.get(
            "size", ""
        ):
            existing["quantity"] += new_item["quantity"]
            return cart
    cart.append(new_item)
    return cart


# --- Routes ----------------------------------------------------------------
@app.route("/")
def index():
    q = request.args.get("q", "").strip().lower()
    category = request.args.get("category", "").strip().lower()
    items = read_items()

    if q:
        items = [
            it
            for it in items
            if q in it.get("name", "").lower()
            or q in it.get("description", "").lower()
        ]

    if category:
        items = [it for it in items if category == it.get("category", "").lower()]

    return render_template("index.html", items=items, q=q, category=category)


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
    return render_template(
        "admin_dashboard.html",
        items=items,
        orders=orders,
        order_statuses=ORDER_STATUSES,
    )


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

        item.update(
            {
                "name": name,
                "description": description,
                "price": f"{price_val:.2f}",
                "category": category,
                "sizes": sizes,
            }
        )
        write_items(items)
        flash("Item updated successfully.", "success")
        return redirect(url_for("admin_dashboard"))

    if "sizes" not in item:
        item["sizes"] = []

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
    target_index = None
    for idx, item in enumerate(cart):
        if item["id"] == item_id and item.get("size", "") == current_size:
            target_index = idx
            break

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
    cart = [
        item
        for item in cart
        if not (item["id"] == item_id and item.get("size", "") == size)
    ]
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
            "customer": {
                "name": name,
                "email": email,
                "phone": phone,
                "address": address,
                "notes": notes,
            },
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


@app.route("/admin/orders/<order_id>/status", methods=["POST"])
@admin_required
def update_order_status(order_id: str):
    new_status = request.form.get("status", "").strip().lower()
    if new_status not in ORDER_STATUSES:
        flash("Invalid status.", "danger")
        return redirect(url_for("admin_dashboard"))

    orders = read_orders()
    for order in orders:
        if order.get("id") == order_id:
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
    remaining = [order for order in orders if order.get("id") != order_id]

    if len(orders) == len(remaining):
        flash("Order not found.", "warning")
        return redirect(url_for("admin_dashboard"))

    write_orders(remaining)
    flash(f"Order {order_id} deleted.", "info")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/orders")
@admin_required
def recent_orders():
    """Render a dedicated Recent Orders admin page (most recent first)."""
    orders = read_orders()

    def _parsed_created(o: dict):
        val = o.get("created_at") or ""
        try:
            if val.endswith("Z"):
                val = val[:-1]
            return datetime.fromisoformat(val)
        except Exception:
            return datetime.min

    orders_sorted = sorted(orders, key=_parsed_created, reverse=True)
    return render_template(
        "recent_orders.html", orders=orders_sorted, order_statuses=ORDER_STATUSES
    )


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

        # Admin login
        if identifier == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session[SESSION_ADMIN_KEY] = True
            flash("Logged in as admin.", "success")
            return redirect(url_for("admin_dashboard"))

        # Regular user login (by email)
        if "@" not in identifier:
            flash("Please provide a valid email to sign in as a user.", "danger")
            return render_template("login.html", name=name, identifier=identifier)

        users = read_users()
        user = next((u for u in users if (u.get("email") or "").lower() == identifier.lower()), None)

        if user:
            # existing user: verify password
            stored_hash = user.get("password_hash", "")
            if stored_hash and check_password_hash(stored_hash, password):
                session["user_email"] = user.get("email")
                session["user_name"] = user.get("name") or name
                flash("Logged in.", "success")
                return redirect(url_for("user_dashboard"))
            else:
                flash("Incorrect password for this email.", "danger")
                return render_template("login.html", name=name, identifier=identifier)

        # New user: register and sign in (simple self-registration)
        password_hash = generate_password_hash(password)
        new_user = {
            "id": uuid.uuid4().hex[:8],
            "name": name,
            "email": identifier.lower(),
            "password_hash": password_hash,
        }
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


@app.route("/user/dashboard")
def user_dashboard():
    user_email = session.get("user_email")
    user_name = session.get("user_name")
    if not user_email:
        flash("Please sign in to view your dashboard.", "warning")
        return redirect(url_for("user_login"))

    orders = read_orders()

    def _parse_created(o: dict):
        val = o.get("created_at") or ""
        try:
            if val.endswith("Z"):
                val = val[:-1]
            return datetime.fromisoformat(val)
        except Exception:
            return datetime.min

    user_orders = [
        o
        for o in orders
        if (o.get("customer", {}).get("email", "") or "").lower() == user_email.lower()
    ]

    user_orders_sorted = sorted(user_orders, key=_parse_created, reverse=True)
    return render_template(
        "user_dashboard.html", orders=user_orders_sorted, user_name=user_name
    )


@app.route("/order/<order_id>")
def view_user_order(order_id):
    """Allow a logged-in user to view their own order, or an admin to ny order."""
    user_email = session.get("user_email")
    if not user_email and not session.get(SESSION_ADMIN_KEY):
        flash("Please sign in to view this order.", "warning")
        return redirect(url_for("user_login"))

    orders = read_orders()
    order = next((o for o in orders if o.get("id") == order_id), None)
    if not order:
        flash("Order not found.", "warning")
        return redirect(url_for("user_dashboard") if user_email else url_for("recent_orders"))

    # Permission: non-admin users can only view their own orders
    if not session.get(SESSION_ADMIN_KEY):
        cust_email = (order.get("customer", {}).get("email") or "").lower()
        if cust_email != (user_email or "").lower():
            flash("You do not have permission to view this order.", "danger")
            return redirect(url_for("user_dashboard"))

    # normalize items (defensive, same as admin view)
    if isinstance(order.get("items"), dict):
        order["items"] = list(order["items"].values())
    elif order.get("items") is None:
        order["items"] = []

    return render_template("order_detail.html", order=order)


# --- Order detail routes (user + admin) -----------------------------------
@app.route("/order/<order_id>")
def order_detail(order_id):
    order = find_order(order_id)
    if not order:
        flash("Order not found.", "warning")
        return redirect(url_for("user_dashboard"))
    ensure_items_list(order)
    return render_template("order_detail.html", order=order)


@app.route("/admin/order/<order_id>")
@admin_required
def admin_order_detail(order_id):
    order = find_order(order_id)
    if not order:
        flash("Order not found.", "warning")
        return redirect(url_for("recent_orders"))
    ensure_items_list(order)
    return render_template("order_detail.html", order=order)


# --- Run -------------------------------------------------------------------
if __name__ == "__main__":
    debug = os.environ.get("FLASK_DEBUG", "").lower() == "true"
    app.run(debug=debug)
