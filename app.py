"""
سپر کد (CodeShield AI) — Main Flask Application
"""
import json
import os
import re
import secrets
import requests as http_requests

from datetime import datetime
from flask import (Flask, flash, jsonify, redirect, render_template,
                   request, session, url_for)
from flask_login import (LoginManager, current_user, login_required,
                         login_user, logout_user)
from dotenv import load_dotenv

from database import Scan, User, db
from scanner import scan_code
from ai_fixer import get_offline_fix

load_dotenv()

# ──────────────────────────────────────────────
#  App Configuration
# ──────────────────────────────────────────────
app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", secrets.token_hex(32)),
    SQLALCHEMY_DATABASE_URI="sqlite:///codeshield.db",
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

db.init_app(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "لطفاً ابتدا وارد شوید."
login_manager.login_message_category = "warning"


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# ──────────────────────────────────────────────
#  Demo code samples
# ──────────────────────────────────────────────
DEMO_SAMPLES = {
    "php_vulnerable": {
        "label": "کد آسیب‌پذیر PHP (SQL Injection + XSS)",
        "language": "php",
        "code": """<?php
// ⚠️ کد آسیب‌پذیر - برای نمایش آموزشی
$conn = mysqli_connect("localhost", "root", "admin123", "myDB");
$id = $_GET['id'];
$result = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $id);
$row = mysqli_fetch_array($result);

// XSS آسیب‌پذیری
echo "خوش آمدید " . $_GET['name'];
echo "<p>ایمیل: " . $row['email'] . "</p>";

// پسورد هاردکد شده
$admin_password = "supersecret123";
$api_key = "AIzaSyXXXXXXXXXXXXXX";

if (md5($password) == $row['pass']) {
    echo "ورود موفق";
}
?>""",
    },
    "python_vulnerable": {
        "label": "کد آسیب‌پذیر Python (پسورد + eval خطرناک)",
        "language": "python",
        "code": """from flask import Flask, request
import hashlib, os

app = Flask(__name__)

# اطلاعات حساس هاردکد شده
password = "admin123"
secret = "my-super-secret-key"
api_key = "sk-abc123xyzDEFGHIJ"

@app.route('/calculate')
def calculate():
    expr = request.args.get('expr', '')
    # eval بسیار خطرناک!
    result = eval(expr)
    return str(result)

@app.route('/login', methods=['POST'])
def login():
    pwd = request.form['password']
    # MD5 الگوریتم ضعیف
    hashed = hashlib.md5(pwd.encode()).hexdigest()
    if hashed == hashlib.md5(password.encode()).hexdigest():
        return "ورود موفق"
    return "خطا"

if __name__ == '__main__':
    # حالت دیباگ در production
    app.run(debug=True)
""",
    },
    "javascript_vulnerable": {
        "label": "کد آسیب‌پذیر JavaScript (XSS + توکن امنیتی)",
        "language": "javascript",
        "code": """// ⚠️ کد آسیب‌پذیر JavaScript
const API_TOKEN = "bearer_token_xyz_123456789";
const SECRET_KEY = "mysupersecretkey";

function showUserProfile(userData) {
    // XSS آسیب‌پذیری - innerHTML خطرناک
    document.getElementById('profile').innerHTML = userData.bio;
    document.getElementById('name').innerHTML = userData.name;
    document.write('<p>' + userData.message + '</p>');
}

// eval خطرناک
function processInput(userInput) {
    return eval(userInput);
}

// توکن در URL
fetch('/api/data?token=' + API_TOKEN)
    .then(r => r.json())
    .then(data => {
        document.getElementById('output').innerHTML = data.content;
    });
""",
    },
    "secure_code": {
        "label": "کد کاملاً امن و استاندارد (امتیاز ۱۰۰)",
        "language": "python",
        "code": """import os
import secrets
import logging
from flask import Flask, request, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get('SECRET_KEY', secrets.token_hex(32)),
    SQLALCHEMY_DATABASE_URI=os.environ.get('DATABASE_URL', 'sqlite:///app.db'),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
)

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(
            password, method='pbkdf2:sha256:600000')

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

@app.route('/api/users/<int:user_id>')
def get_user(user_id: int):
    user = db.session.get(User, user_id)
    if not user:
        abort(404)
    return jsonify({'id': user.id, 'username': user.username})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='127.0.0.1', port=5000)
""",
    },
}


# ──────────────────────────────────────────────
#  Auth Routes
# ──────────────────────────────────────────────
@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        action = request.form.get("action", "login")
        if action == "demo":
            demo_user = User.query.filter_by(username="داور").first()
            if not demo_user:
                demo_user = User(username="داور", email="judge@demo.local", is_demo=True)
                demo_user.set_password("demo1234")
                db.session.add(demo_user)
                db.session.commit()
            login_user(demo_user)
            flash("خوش آمدید! وارد حساب داور شدید.", "success")
            return redirect(url_for("dashboard"))

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash(f"خوش آمدید، {user.username}!", "success")
            return redirect(url_for("dashboard"))
        flash("نام کاربری یا رمز عبور اشتباه است.", "danger")
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        if not username or not email or not password:
            flash("تمام فیلدها را پر کنید.", "danger")
            return render_template("register.html")
        if len(password) < 8:
            flash("رمز عبور باید حداقل ۸ کاراکتر باشد.", "danger")
            return render_template("register.html")
        if User.query.filter_by(username=username).first():
            flash("این نام کاربری قبلاً ثبت شده است.", "danger")
            return render_template("register.html")
        if User.query.filter_by(email=email).first():
            flash("این ایمیل قبلاً ثبت شده است.", "danger")
            return render_template("register.html")

        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        flash("ثبت‌نام موفق! به سپر کد خوش آمدید.", "success")
        return redirect(url_for("dashboard"))
    return render_template("register.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("با موفقیت خارج شدید.", "info")
    return redirect(url_for("login"))


# ──────────────────────────────────────────────
#  Main Dashboard
# ──────────────────────────────────────────────
@app.route("/dashboard")
@login_required
def dashboard():
    recent_scans = (
        Scan.query.filter_by(user_id=current_user.id)
        .order_by(Scan.timestamp.desc())
        .limit(10)
        .all()
    )
    return render_template(
        "dashboard.html",
        demo_samples=DEMO_SAMPLES,
        recent_scans=recent_scans,
    )


@app.route("/history")
@login_required
def history():
    scans = (
        Scan.query.filter_by(user_id=current_user.id)
        .order_by(Scan.timestamp.desc())
        .all()
    )
    return render_template("history.html", scans=scans)


# ──────────────────────────────────────────────
#  API Endpoints
# ──────────────────────────────────────────────
@app.route("/api/scan", methods=["POST"])
@login_required
def api_scan():
    data = request.get_json()
    if not data:
        return jsonify({"error": "داده‌ای ارسال نشد"}), 400
    code = data.get("code", "").strip()
    language = data.get("language", "python").lower()
    if not code:
        return jsonify({"error": "کدی برای اسکن ارسال نشد"}), 400

    result = scan_code(code, language)

    # Save to DB
    snippet = code[:500] + ("..." if len(code) > 500 else "")
    scan = Scan(
        user_id=current_user.id,
        language=language,
        code_snippet=snippet,
        score=result["score"],
        issues_count=result["issues_count"],
        issues_json=json.dumps(result["issues"], ensure_ascii=False),
    )
    db.session.add(scan)
    db.session.commit()

    result["scan_id"] = scan.id
    return jsonify(result)


@app.route("/api/ai-fix", methods=["POST"])
@login_required
def api_ai_fix():
    data = request.get_json()
    if not data:
        return jsonify({"error": "داده‌ای ارسال نشد"}), 400

    code = data.get("code", "").strip()
    language = data.get("language", "python").lower()
    issues = data.get("issues", [])
    api_key = session.get("gemini_api_key", "") or os.environ.get("GEMINI_API_KEY", "")

    if not code:
        return jsonify({"error": "کدی ارسال نشد"}), 400

    # Try Gemini API
    if api_key:
        try:
            result = call_gemini_api(code, language, issues, api_key)
            if result:
                return jsonify(result)
        except Exception as e:
            app.logger.warning(f"Gemini API failed: {e}. Using offline fallback.")

    # Offline fallback
    fallback = get_offline_fix(code, language, issues)
    fallback["message"] = (
        "⚠️ از حالت آفلاین استفاده می‌شود. برای دریافت اصلاح هوشمند واقعی، کلید Gemini API را در تنظیمات وارد کنید."
        if not api_key
        else "⚠️ اتصال به API ناموفق بود. از نمونه آفلاین استفاده می‌شود."
    )
    return jsonify(fallback)


def call_gemini_api(code: str, language: str, issues: list, api_key: str) -> dict | None:
    """Call Google Gemini API to fix vulnerable code."""
    issues_text = "\n".join(
        [f"- {i.get('title','')}: {i.get('description','')} (خطوط: {i.get('lines',[])})" for i in issues]
    )
    prompt = f"""شما یک متخصص امنیت نرم‌افزار هستید. کد {language} زیر دارای آسیب‌پذیری‌های امنیتی است.

آسیب‌پذیری‌های شناسایی‌شده:
{issues_text}

کد آسیب‌پذیر:
```{language}
{code}
```

لطفاً:
1. کد را کاملاً بازنویسی کنید و تمام آسیب‌پذیری‌ها را رفع کنید.
2. توضیح فارسی کوتاهی برای هر اصلاح بنویسید.

پاسخ را دقیقاً با این فرمت JSON برگردانید:
{{
  "fixed_code": "کد امن‌سازی‌شده اینجا",
  "explanation": "توضیح فارسی اصلاحات اینجا"
}}"""

    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={api_key}"
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.2, "maxOutputTokens": 4096},
    }
    resp = http_requests.post(url, json=payload, timeout=30)
    resp.raise_for_status()
    content = resp.json()

    # Safe extraction with proper error handling
    candidates = content.get("candidates", [])
    if not candidates:
        app.logger.warning("Gemini API returned no candidates")
        return None

    parts = candidates[0].get("content", {}).get("parts", [])
    if not parts:
        app.logger.warning("Gemini API returned empty parts")
        return None

    text = parts[0].get("text", "")
    if not text:
        return None

    # Use non-greedy JSON extraction to avoid matching multiple objects
    json_match = re.search(r'\{[\s\S]*?"fixed_code"[\s\S]*?"explanation"[\s\S]*?\}', text)
    if not json_match:
        # Fallback: try to find any JSON block
        json_match = re.search(r'```json\s*(\{[\s\S]*?\})\s*```', text)
        if json_match:
            json_str = json_match.group(1)
        else:
            return None
    else:
        json_str = json_match.group()

    try:
        parsed = json.loads(json_str)
        return {
            "fixed_code": parsed.get("fixed_code", ""),
            "explanation": parsed.get("explanation", ""),
            "source": "gemini",
        }
    except json.JSONDecodeError:
        app.logger.warning("Failed to parse Gemini API JSON response")
        return None


@app.route("/api/samples")
@login_required
def api_samples():
    return jsonify(DEMO_SAMPLES)


@app.route("/api/settings", methods=["POST"])
@login_required
def api_settings():
    data = request.get_json()
    api_key = data.get("api_key", "").strip()
    if api_key:
        session["gemini_api_key"] = api_key
    else:
        session.pop("gemini_api_key", None)
    return jsonify({"success": True, "message": "تنظیمات ذخیره شد"})


# ──────────────────────────────────────────────
#  App Init
# ──────────────────────────────────────────────
def init_db():
    with app.app_context():
        db.create_all()
        # Create demo user if not exists
        if not User.query.filter_by(username="داور").first():
            demo = User(username="داور", email="judge@demo.local", is_demo=True)
            demo.set_password("demo1234")
            db.session.add(demo)
            db.session.commit()
            print("[OK] Demo user created: username='daavar', password='demo1234'")


if __name__ == "__main__":
    import sys
    sys.stdout.reconfigure(encoding='utf-8')
    init_db()
    print("[OK] CodeShield AI is running at http://127.0.0.1:5000")
    app.run(debug=True, host="127.0.0.1", port=5000)
