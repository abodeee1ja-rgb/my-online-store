"""سوقنا: سوق مصغّر متعدد البائعين.
كل بائع يفتح متجره ويضيف منتجاته ويستلم طلباته، والزبون يتصفح ويطلب (دفع عند الاستلام).

التشغيل:
    pip install flask
    python app.py
ثم افتح http://127.0.0.1:5000
"""
import os
import secrets
import sqlite3
import uuid
from datetime import datetime
from functools import wraps

from flask import (Flask, abort, flash, g, jsonify, redirect, render_template,
                   request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "market.db")
UPLOAD_DIR = os.path.join(BASE_DIR, "static", "uploads")
ALLOWED_EXT = {"png", "jpg", "jpeg", "webp"}
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 4 * 1024 * 1024  # 4MB لكل صورة


def _load_secret():
    env = os.environ.get("SECRET_KEY")
    if env:
        return env
    path = os.path.join(BASE_DIR, "secret.key")
    if not os.path.exists(path):
        with open(path, "w") as f:
            f.write(secrets.token_hex(32))
    with open(path) as f:
        return f.read().strip()


app.secret_key = _load_secret()

CATEGORIES = [
    "مواد غذائية", "أكل بيتي", "ملابس", "أحذية وحقائب", "إلكترونيات",
    "موبايلات وإكسسوارات", "أثاث ومنزل", "مستحضرات تجميل", "حرف يدوية",
    "ألعاب أطفال", "كتب وقرطاسية", "سيارات وقطع غيار", "أخرى",
]

STATUS_LABELS = {
    "new": "جديد", "confirmed": "مؤكد", "delivered": "تم التسليم",
    "cancelled": "ملغي",
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    phone TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS stores (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL UNIQUE REFERENCES users(id),
    name TEXT NOT NULL,
    description TEXT DEFAULT '',
    phone TEXT DEFAULT '',
    city TEXT DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    store_id INTEGER NOT NULL REFERENCES stores(id),
    name TEXT NOT NULL,
    description TEXT DEFAULT '',
    price REAL NOT NULL,
    stock INTEGER NOT NULL DEFAULT 0,
    category TEXT NOT NULL DEFAULT 'أخرى',
    image TEXT DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    store_id INTEGER NOT NULL REFERENCES stores(id),
    buyer_id INTEGER REFERENCES users(id),
    customer_name TEXT NOT NULL,
    customer_phone TEXT NOT NULL,
    address TEXT NOT NULL,
    note TEXT DEFAULT '',
    total REAL NOT NULL,
    status TEXT NOT NULL DEFAULT 'new',
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS order_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id INTEGER NOT NULL REFERENCES orders(id),
    product_id INTEGER,
    name TEXT NOT NULL,
    price REAL NOT NULL,
    qty INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_products_store ON products(store_id);
CREATE INDEX IF NOT EXISTS idx_orders_store ON orders(store_id);
"""


# ------------------------------------------------------------ قاعدة البيانات
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    with sqlite3.connect(DB_PATH) as db:
        db.executescript(SCHEMA)


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M")


# ------------------------------------------------------------ أدوات مساعدة
_DIGITS = str.maketrans("٠١٢٣٤٥٦٧٨٩٫٬", "0123456789.,")


def num(value, default=0.0):
    try:
        value = str(value).strip().translate(_DIGITS).replace(",", "")
        return float(value) if value else default
    except ValueError:
        return default


def clean_phone(value):
    return "".join(ch for ch in str(value).translate(_DIGITS) if ch.isdigit() or ch == "+")


def safe_next(target):
    if target and target.startswith("/") and not target.startswith("//"):
        return target
    return url_for("index")


def save_image(file_storage):
    """يحفظ الصورة المرفوعة ويرجع اسم الملف، أو None."""
    if not file_storage or not file_storage.filename:
        return None
    ext = file_storage.filename.rsplit(".", 1)[-1].lower() if "." in file_storage.filename else ""
    if ext not in ALLOWED_EXT:
        flash("نوع الصورة غير مدعوم (المسموح: png, jpg, webp)", "error")
        return None
    name = f"{uuid.uuid4().hex}.{ext}"
    file_storage.save(os.path.join(UPLOAD_DIR, name))
    return name


def delete_image(name):
    if name:
        path = os.path.join(UPLOAD_DIR, os.path.basename(name))
        if os.path.exists(path):
            os.remove(path)


@app.template_filter("money")
def money(value):
    return f"{int(round(value or 0)):,}"


# ------------------------------------------------------------ CSRF والجلسة
def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


# global حتى تراه الـ macros المستوردة (ما تشوف سياق القالب)
app.jinja_env.globals["csrf"] = csrf_token


@app.before_request
def load_user():
    g.user = None
    g.store = None
    uid = session.get("uid")
    if uid:
        g.user = get_db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        if g.user is None:
            session.pop("uid", None)
        else:
            g.store = get_db().execute(
                "SELECT * FROM stores WHERE owner_id=?", (uid,)
            ).fetchone()
    if request.method == "POST":
        sent = request.form.get("csrf", "")
        if not sent or not secrets.compare_digest(sent, session.get("csrf", "")):
            abort(400, "انتهت صلاحية الصفحة، أعد تحميلها وحاول مرة ثانية")


@app.context_processor
def inject_globals():
    cart = session.get("cart", {})
    return {
        "csrf": csrf_token,
        "user": g.get("user"),
        "my_store": g.get("store"),
        "cart_count": sum(cart.values()),
        "categories": CATEGORIES,
        "status_labels": STATUS_LABELS,
    }


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            flash("سجّل دخولك أولاً", "error")
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def seller_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            flash("سجّل دخولك أولاً", "error")
            return redirect(url_for("login", next=request.path))
        if g.store is None:
            flash("افتح متجرك أولاً", "error")
            return redirect(url_for("seller_store"))
        return view(*args, **kwargs)
    return wrapped


# ------------------------------------------------------------ تسجيل الدخول
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        phone = clean_phone(request.form.get("phone", ""))
        password = request.form.get("password", "")
        if not name or len(phone) < 7:
            flash("اكتب الاسم ورقم هاتف صحيح", "error")
        elif len(password) < 6:
            flash("كلمة السر لازم تكون 6 أحرف أو أرقام على الأقل", "error")
        else:
            db = get_db()
            if db.execute("SELECT 1 FROM users WHERE phone=?", (phone,)).fetchone():
                flash("هذا الرقم مسجّل مسبقاً، سجّل دخولك", "error")
            else:
                cur = db.execute(
                    "INSERT INTO users (name, phone, password_hash, created_at) VALUES (?,?,?,?)",
                    (name, phone, generate_password_hash(password), now()),
                )
                db.commit()
                session["uid"] = cur.lastrowid
                flash(f"أهلاً {name}، تم إنشاء حسابك", "ok")
                if request.form.get("want_store"):
                    return redirect(url_for("seller_store"))
                return redirect(safe_next(request.args.get("next")))
    return render_template("register.html", want_store=request.args.get("store"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        phone = clean_phone(request.form.get("phone", ""))
        row = get_db().execute("SELECT * FROM users WHERE phone=?", (phone,)).fetchone()
        if row and check_password_hash(row["password_hash"], request.form.get("password", "")):
            session["uid"] = row["id"]
            return redirect(safe_next(request.args.get("next")))
        flash("الرقم أو كلمة السر غير صحيحة", "error")
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.pop("uid", None)
    return redirect(url_for("index"))


@app.route("/account")
@login_required
def account():
    return render_template("account.html")


# ------------------------------------------------------------ PWA
@app.route("/sw.js")
def service_worker():
    """يُخدَم من الجذر حتى يغطي كل الموقع."""
    resp = app.send_static_file("sw.js")
    resp.headers["Service-Worker-Allowed"] = "/"
    resp.headers["Cache-Control"] = "no-cache"
    return resp


# ------------------------------------------------------------ صفحات الزبون
PRODUCT_SELECT = (
    "SELECT p.*, s.name AS store_name, s.city AS store_city FROM products p "
    "JOIN stores s ON s.id = p.store_id "
)


def search_products(q="", category="", store_id=None, limit=60):
    sql, args = PRODUCT_SELECT + "WHERE 1=1 ", []
    if q:
        sql += "AND (p.name LIKE ? OR p.description LIKE ?) "
        args += [f"%{q}%", f"%{q}%"]
    if category:
        sql += "AND p.category = ? "
        args.append(category)
    if store_id:
        sql += "AND p.store_id = ? "
        args.append(store_id)
    sql += "ORDER BY (p.stock > 0) DESC, p.id DESC LIMIT ?"
    args.append(limit)
    return get_db().execute(sql, args).fetchall()


@app.route("/")
def index():
    db = get_db()
    latest = search_products(limit=12)
    stores = db.execute(
        "SELECT s.*, (SELECT COUNT(*) FROM products WHERE store_id = s.id) AS n "
        "FROM stores s ORDER BY s.id DESC LIMIT 8"
    ).fetchall()
    return render_template("index.html", products=latest, stores=stores)


@app.route("/products")
def products():
    q = request.args.get("q", "").strip()
    category = request.args.get("category", "").strip()
    rows = search_products(q, category)
    return render_template("products.html", products=rows, q=q, category=category)


@app.route("/product/<int:pid>")
def product(pid):
    row = get_db().execute(PRODUCT_SELECT + "WHERE p.id=?", (pid,)).fetchone()
    if row is None:
        abort(404)
    store = get_db().execute("SELECT * FROM stores WHERE id=?", (row["store_id"],)).fetchone()
    return render_template("product.html", p=row, store=store)


@app.route("/stores")
def stores():
    rows = get_db().execute(
        "SELECT s.*, (SELECT COUNT(*) FROM products WHERE store_id = s.id) AS n "
        "FROM stores s ORDER BY s.id DESC"
    ).fetchall()
    return render_template("stores.html", stores=rows)


@app.route("/store/<int:sid>")
def store_page(sid):
    store = get_db().execute("SELECT * FROM stores WHERE id=?", (sid,)).fetchone()
    if store is None:
        abort(404)
    rows = search_products(store_id=sid, limit=200)
    return render_template("store.html", store=store, products=rows)


# ------------------------------------------------------------ السلة
def cart_lines():
    """يرجع (قائمة سطور السلة، المجموع) مع تنظيف المنتجات المحذوفة."""
    cart = session.get("cart", {})
    lines, total, changed = [], 0.0, False
    db = get_db()
    for pid, qty in list(cart.items()):
        p = db.execute(PRODUCT_SELECT + "WHERE p.id=?", (int(pid),)).fetchone()
        if p is None or p["stock"] <= 0:
            cart.pop(pid)
            changed = True
            continue
        if qty > p["stock"]:
            qty = cart[pid] = p["stock"]
            changed = True
        lines.append({"p": p, "qty": qty, "sub": p["price"] * qty})
        total += p["price"] * qty
    if changed:
        session["cart"] = cart
    return lines, total


@app.route("/cart")
def cart():
    lines, total = cart_lines()
    return render_template("cart.html", lines=lines, total=total)


@app.route("/cart/add/<int:pid>", methods=["POST"])
def cart_add(pid):
    p = get_db().execute("SELECT * FROM products WHERE id=?", (pid,)).fetchone()
    if p is None:
        abort(404)
    qty = max(int(num(request.form.get("qty"), 1)), 1)
    cart_ = session.get("cart", {})
    new_qty = cart_.get(str(pid), 0) + qty
    if new_qty > p["stock"]:
        flash(f"المتوفر من هذا المنتج {p['stock']} فقط", "error")
    else:
        cart_[str(pid)] = new_qty
        session["cart"] = cart_
        flash("تمت الإضافة للسلة", "ok")
    if request.form.get("buy_now") and new_qty <= p["stock"]:
        return redirect(url_for("cart"))
    return redirect(request.referrer or url_for("product", pid=pid))


@app.route("/cart/update/<int:pid>", methods=["POST"])
def cart_update(pid):
    cart_ = session.get("cart", {})
    qty = 0 if request.form.get("remove") else int(num(request.form.get("qty")))
    if qty <= 0:
        cart_.pop(str(pid), None)
    elif str(pid) in cart_:
        cart_[str(pid)] = qty
    session["cart"] = cart_
    return redirect(url_for("cart"))


# ------------------------------------------------------------ إتمام الطلب
@app.route("/checkout", methods=["GET", "POST"])
def checkout():
    lines, total = cart_lines()
    if not lines:
        flash("سلتك فارغة", "error")
        return redirect(url_for("cart"))

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        phone = clean_phone(request.form.get("phone", ""))
        address = request.form.get("address", "").strip()
        note = request.form.get("note", "").strip()
        if not name or len(phone) < 7 or not address:
            flash("اكتب الاسم ورقم الهاتف والعنوان", "error")
            return render_template("checkout.html", lines=lines, total=total, form=request.form)

        db = get_db()
        by_store = {}
        for line in lines:
            by_store.setdefault(line["p"]["store_id"], []).append(line)

        order_ids = []
        try:
            db.execute("BEGIN IMMEDIATE")
            # تحقق نهائي من المخزون داخل المعاملة
            for line in lines:
                stock = db.execute(
                    "SELECT stock FROM products WHERE id=?", (line["p"]["id"],)
                ).fetchone()
                if stock is None or stock["stock"] < line["qty"]:
                    raise ValueError(f"«{line['p']['name']}» نفدت كميته")
            for store_id, items in by_store.items():
                sub = sum(i["sub"] for i in items)
                cur = db.execute(
                    "INSERT INTO orders (store_id, buyer_id, customer_name, customer_phone, "
                    "address, note, total, created_at) VALUES (?,?,?,?,?,?,?,?)",
                    (store_id, g.user["id"] if g.user else None, name, phone,
                     address, note, sub, now()),
                )
                oid = cur.lastrowid
                order_ids.append(oid)
                for i in items:
                    db.execute(
                        "INSERT INTO order_items (order_id, product_id, name, price, qty) "
                        "VALUES (?,?,?,?,?)",
                        (oid, i["p"]["id"], i["p"]["name"], i["p"]["price"], i["qty"]),
                    )
                    db.execute("UPDATE products SET stock = stock - ? WHERE id=?",
                               (i["qty"], i["p"]["id"]))
            db.commit()
        except ValueError as exc:
            db.rollback()
            flash(str(exc), "error")
            return redirect(url_for("cart"))
        except Exception:
            db.rollback()
            raise

        session["cart"] = {}
        session["last_orders"] = order_ids
        return redirect(url_for("thanks"))

    form = {}
    if g.user:
        form = {"name": g.user["name"], "phone": g.user["phone"]}
    return render_template("checkout.html", lines=lines, total=total, form=form)


@app.route("/thanks")
def thanks():
    ids = session.get("last_orders", [])
    orders = []
    for oid in ids:
        o = get_db().execute(
            "SELECT o.*, s.name AS store_name, s.phone AS store_phone FROM orders o "
            "JOIN stores s ON s.id = o.store_id WHERE o.id=?", (oid,)
        ).fetchone()
        if o:
            orders.append(o)
    return render_template("thanks.html", orders=orders)


@app.route("/my-orders")
@login_required
def my_orders():
    db = get_db()
    orders = db.execute(
        "SELECT o.*, s.name AS store_name, s.phone AS store_phone FROM orders o "
        "JOIN stores s ON s.id = o.store_id WHERE o.buyer_id=? ORDER BY o.id DESC",
        (g.user["id"],),
    ).fetchall()
    items = {o["id"]: db.execute(
        "SELECT * FROM order_items WHERE order_id=?", (o["id"],)).fetchall() for o in orders}
    return render_template("my_orders.html", orders=orders, items=items)


# ------------------------------------------------------------ لوحة البائع
@app.route("/seller/store", methods=["GET", "POST"])
@login_required
def seller_store():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        if not name:
            flash("اكتب اسم المتجر", "error")
            return render_template("seller_store.html", form=request.form)
        vals = (name, request.form.get("description", "").strip(),
                clean_phone(request.form.get("phone", "")) or g.user["phone"],
                request.form.get("city", "").strip())
        db = get_db()
        if g.store:
            db.execute("UPDATE stores SET name=?, description=?, phone=?, city=? WHERE id=?",
                       vals + (g.store["id"],))
            flash("تم حفظ بيانات المتجر", "ok")
        else:
            db.execute("INSERT INTO stores (owner_id, name, description, phone, city, created_at) "
                       "VALUES (?,?,?,?,?,?)", (g.user["id"],) + vals + (now(),))
            flash("مبروك! تم فتح متجرك، أضف أول منتج", "ok")
        db.commit()
        return redirect(url_for("seller_dashboard") if g.store else url_for("seller_products"))
    return render_template("seller_store.html", form=dict(g.store) if g.store else {})


@app.route("/seller")
@seller_required
def seller_dashboard():
    db = get_db()
    sid = g.store["id"]
    stats = {
        "products": db.execute("SELECT COUNT(*) FROM products WHERE store_id=?", (sid,)).fetchone()[0],
        "new_orders": db.execute(
            "SELECT COUNT(*) FROM orders WHERE store_id=? AND status='new'", (sid,)).fetchone()[0],
        "sales": db.execute(
            "SELECT COALESCE(SUM(total),0) FROM orders WHERE store_id=? AND status='delivered'",
            (sid,)).fetchone()[0],
        "pending": db.execute(
            "SELECT COALESCE(SUM(total),0) FROM orders WHERE store_id=? AND status IN ('new','confirmed')",
            (sid,)).fetchone()[0],
    }
    low = db.execute(
        "SELECT * FROM products WHERE store_id=? AND stock <= 3 ORDER BY stock LIMIT 8", (sid,)
    ).fetchall()
    return render_template("seller_dashboard.html", stats=stats, low=low)


@app.route("/seller/products")
@seller_required
def seller_products():
    rows = get_db().execute(
        "SELECT * FROM products WHERE store_id=? ORDER BY id DESC", (g.store["id"],)
    ).fetchall()
    return render_template("seller_products.html", products=rows)


def _product_form_values():
    return (request.form.get("name", "").strip(),
            request.form.get("description", "").strip(),
            num(request.form.get("price")),
            max(int(num(request.form.get("stock"))), 0),
            request.form.get("category") if request.form.get("category") in CATEGORIES else "أخرى")


@app.route("/seller/products/new", methods=["GET", "POST"])
@seller_required
def seller_product_new():
    if request.method == "POST":
        name, desc, price, stock, category = _product_form_values()
        if not name or price <= 0:
            flash("اكتب اسم المنتج وسعر أكبر من صفر", "error")
            return render_template("seller_product_form.html", p=request.form)
        image = save_image(request.files.get("image")) or ""
        db = get_db()
        db.execute(
            "INSERT INTO products (store_id, name, description, price, stock, category, image, created_at) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (g.store["id"], name, desc, price, stock, category, image, now()),
        )
        db.commit()
        flash("تمت إضافة المنتج", "ok")
        return redirect(url_for("seller_products"))
    return render_template("seller_product_form.html", p={})


def _own_product(pid):
    row = get_db().execute(
        "SELECT * FROM products WHERE id=? AND store_id=?", (pid, g.store["id"])
    ).fetchone()
    if row is None:
        abort(404)
    return row


@app.route("/seller/products/<int:pid>/edit", methods=["GET", "POST"])
@seller_required
def seller_product_edit(pid):
    p = _own_product(pid)
    if request.method == "POST":
        name, desc, price, stock, category = _product_form_values()
        if not name or price <= 0:
            flash("اكتب اسم المنتج وسعر أكبر من صفر", "error")
            return render_template("seller_product_form.html", p=dict(p), editing=True)
        image = p["image"]
        new_image = save_image(request.files.get("image"))
        if new_image:
            delete_image(image)
            image = new_image
        db = get_db()
        db.execute(
            "UPDATE products SET name=?, description=?, price=?, stock=?, category=?, image=? WHERE id=?",
            (name, desc, price, stock, category, image, pid),
        )
        db.commit()
        flash("تم حفظ التعديل", "ok")
        return redirect(url_for("seller_products"))
    return render_template("seller_product_form.html", p=dict(p), editing=True)


@app.route("/seller/products/<int:pid>/delete", methods=["POST"])
@seller_required
def seller_product_delete(pid):
    p = _own_product(pid)
    delete_image(p["image"])
    db = get_db()
    db.execute("DELETE FROM products WHERE id=?", (pid,))
    db.commit()
    flash("تم حذف المنتج", "ok")
    return redirect(url_for("seller_products"))


@app.route("/seller/orders")
@seller_required
def seller_orders():
    db = get_db()
    status = request.args.get("status", "")
    sql, args = "SELECT * FROM orders WHERE store_id=? ", [g.store["id"]]
    if status in STATUS_LABELS:
        sql += "AND status=? "
        args.append(status)
    orders = db.execute(sql + "ORDER BY id DESC LIMIT 200", args).fetchall()
    items = {o["id"]: db.execute(
        "SELECT * FROM order_items WHERE order_id=?", (o["id"],)).fetchall() for o in orders}
    return render_template("seller_orders.html", orders=orders, items=items, status=status)


@app.route("/seller/orders/<int:oid>/status", methods=["POST"])
@seller_required
def seller_order_status(oid):
    db = get_db()
    order = db.execute("SELECT * FROM orders WHERE id=? AND store_id=?",
                       (oid, g.store["id"])).fetchone()
    if order is None:
        abort(404)
    new = request.form.get("status")
    allowed = {"new": {"confirmed", "cancelled"},
               "confirmed": {"delivered", "cancelled"}}
    if new not in allowed.get(order["status"], set()):
        flash("لا يمكن تغيير الحالة بهذا الشكل", "error")
        return redirect(url_for("seller_orders"))
    if new == "cancelled":  # رجّع الكميات للمخزون
        for it in db.execute("SELECT * FROM order_items WHERE order_id=?", (oid,)).fetchall():
            db.execute("UPDATE products SET stock = stock + ? WHERE id=?", (it["qty"], it["product_id"]))
    db.execute("UPDATE orders SET status=? WHERE id=?", (new, oid))
    db.commit()
    flash(f"تم تغيير حالة الطلب #{oid} إلى «{STATUS_LABELS[new]}»", "ok")
    return redirect(request.referrer or url_for("seller_orders"))


# ------------------------------------------------------------ API (للتطبيق لاحقاً)
def _product_json(p):
    return {
        "id": p["id"], "name": p["name"], "description": p["description"],
        "price": p["price"], "stock": p["stock"], "category": p["category"],
        "image": url_for("static", filename="uploads/" + p["image"], _external=True) if p["image"] else None,
        "store": {"id": p["store_id"], "name": p["store_name"], "city": p["store_city"]},
    }


@app.route("/api/products")
def api_products():
    rows = search_products(
        request.args.get("q", "").strip(), request.args.get("category", "").strip(),
        request.args.get("store", type=int), limit=min(request.args.get("limit", 60, type=int), 200),
    )
    return jsonify([_product_json(p) for p in rows])


@app.route("/api/products/<int:pid>")
def api_product(pid):
    p = get_db().execute(PRODUCT_SELECT + "WHERE p.id=?", (pid,)).fetchone()
    if p is None:
        return jsonify({"error": "not found"}), 404
    return jsonify(_product_json(p))


@app.route("/api/stores")
def api_stores():
    rows = get_db().execute("SELECT id, name, description, phone, city FROM stores ORDER BY id DESC").fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/categories")
def api_categories():
    return jsonify(CATEGORIES)


@app.errorhandler(404)
def not_found(_e):
    return render_template("error.html", code=404, message="الصفحة غير موجودة"), 404


@app.errorhandler(400)
def bad_request(e):
    return render_template("error.html", code=400, message=getattr(e, "description", "طلب غير صحيح")), 400


@app.errorhandler(413)
def too_large(_e):
    return render_template("error.html", code=413, message="حجم الصورة كبير (الحد الأقصى 4 ميغا)"), 413


init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
