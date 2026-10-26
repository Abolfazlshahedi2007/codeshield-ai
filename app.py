"""
سپر کد (CodeShield AI) — Main Flask Application
"""
import json
import os
import re
import secrets
from urllib.parse import urlparse
from datetime import datetime, timedelta
import requests as http_requests

from flask import (Flask, flash, jsonify, redirect, render_template,
                   request, session, url_for)
from flask_login import (LoginManager, current_user, login_required,
                         login_user, logout_user)
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from dotenv import load_dotenv

from database import Scan, User, db
from scanner import scan_code
from ai_fixer import get_offline_fix

load_dotenv()

# ──────────────────────────────────────────────
#  App Configuration
# ──────────────────────────────────────────────
app = Flask(__name__)

secret_key = os.environ.get("SECRET_KEY")
if not secret_key:
    secret_key = "codeshield-dev-session-secret-key-stable"

app.config.update(
    SECRET_KEY=secret_key,
    SQLALCHEMY_DATABASE_URI="sqlite:///codeshield.db",
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
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
$id =$_GET['id'];
$result = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $id);
$row = mysqli_fetch_array($result);

// XSS آسیب‌پذیری
echo "خوش آمدید " . $_GET['name'];
echo "<p>ایمیل: " . $row['email'] . "</p>";

// پسورد هاردکد شده
$admin_password = "supersecret123";
$api_key = "AIzaSyXXXXXXXXXXXXXX";

if (md5($password) ==$row['pass']) {
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
    "python_logic_perf": {
        "label": "کد دارای باگ منطقی و پرفورمنس (Python AST)",
        "language": "python",
        "code": """import time

# ۱. باگ منطقی حافظه مشترک (Mutable Default Argument)
def add_audit_log(event, logs=[]):
    logs.append(event)
    
    # ۲. نشت منابع سیستم (فایل باز رها شده بدون بلاک with)
    f = open("audit.log", "a")
    f.write(str(event) + "\\n")
    
    # ۳. مقایسه غیردقیق با None
    if event == None:
        return logs
        # ۴. کد مرده و غیرقابل دسترس (Unreachable Code)
        print("این خط هرگز اجرا نخواهد شد!")
    return logs

# ۵. گلوگاه پرفورمنس: کوئری داخل حلقه (N+1) و پیچیدگی O(n³)
def sync_users_report(users, db_cursor):
    try:
        for u in users:
            db_cursor.execute("SELECT score FROM stats WHERE uid = ?", (u,))
            time.sleep(1)  # قفل کردن ترد اصلی سرور
            for i in users:
                for j in users:
                    pass
    except:
        # ۶. بلعیدن خطا به صورت خاموش (Silent Failure)
        pass
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


EMAIL_REGEX = re.compile(r"^[\w\.-]+@[\w\.-]+\.\w+$")
USERNAME_REGEX = re.compile(r"^[\w\u0600-\u06FF\s.-]{3,50}$")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        action = request.form.get("action", "login")
        if action == "demo":
            demo_user = User.query.filter_by(username="داور").first()
            if not demo_user:
                try:
                    demo_user = User(username="داور", email="judge@demo.local", is_demo=True)
                    demo_user.set_password("demo1234")
                    db.session.add(demo_user)
                    db.session.commit()
                except IntegrityError:
                    db.session.rollback()
                    demo_user = User.query.filter_by(username="داور").first()
                except SQLAlchemyError:
                    db.session.rollback()
                    flash("خطای پایگاه داده هنگام ورود داور.", "danger")
                    return redirect(url_for("login"))
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
        if not USERNAME_REGEX.match(username):
            flash("نام کاربری باید بین ۳ تا ۵۰ کاراکتر باشد.", "danger")
            return render_template("register.html")
        if not EMAIL_REGEX.match(email) or len(email) > 120:
            flash("فرمت ایمیل نامعتبر است.", "danger")
            return render_template("register.html")
        if len(password) < 8 or len(password) > 128:
            flash("رمز عبور باید حداقل ۸ کاراکتر باشد.", "danger")
            return render_template("register.html")

        if User.query.filter_by(username=username).first():
            flash("این نام کاربری قبلاً ثبت شده است.", "danger")
            return render_template("register.html")
        if User.query.filter_by(email=email).first():
            flash("این ایمیل قبلاً ثبت شده است.", "danger")
            return render_template("register.html")

        try:
            user = User(username=username, email=email)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            login_user(user)
            flash("ثبت‌نام موفق! به سپر کد خوش آمدید.", "success")
            return redirect(url_for("dashboard"))
        except IntegrityError:
            db.session.rollback()
            flash("نام کاربری یا ایمیل از قبل ثبت شده است.", "danger")
            return render_template("register.html")
        except SQLAlchemyError:
            db.session.rollback()
            flash("خطای سرور در ثبت اطلاعات. لطفاً دوباره تلاش کنید.", "danger")
            return render_template("register.html")
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
        .limit(100)
        .all()
    )
    return render_template("history.html", scans=scans)


# ──────────────────────────────────────────────
#  API Endpoints
# ──────────────────────────────────────────────
@app.route("/api/scan", methods=["POST"])
@login_required
def api_scan():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "فرمت داده ارسالی باید JSON باشد"}), 400

    raw_code = data.get("code")
    if not isinstance(raw_code, str) or not raw_code.strip():
        return jsonify({"error": "کدی برای اسکن ارسال نشد"}), 400

    if len(raw_code) > 100_000:
        return jsonify({"error": "حجم کد ارسالی بیش از حد مجاز است (حداکثر ۱۰۰ کیلوبایت)"}), 400

    raw_lang = data.get("language", "python")
    language = raw_lang.lower().strip() if isinstance(raw_lang, str) else "python"
    if language not in ("php", "python", "javascript"):
        language = "python"

    code = raw_code.strip()
    result = scan_code(code, language)

    # Save to DB
    try:
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
    except SQLAlchemyError as e:
        db.session.rollback()
        app.logger.warning(f"Failed to save scan record: {e}")
        result["scan_id"] = None

    return jsonify(result)


@app.route("/api/ai-fix", methods=["POST"])
@login_required
def api_ai_fix():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "فرمت داده ارسالی باید JSON باشد"}), 400

    raw_code = data.get("code")
    if not isinstance(raw_code, str) or not raw_code.strip():
        return jsonify({"error": "کدی ارسال نشد"}), 400

    if len(raw_code) > 100_000:
        return jsonify({"error": "حجم کد ارسالی بیش از حد مجاز است (حداکثر ۱۰۰ کیلوبایت)"}), 400

    code = raw_code.strip()
    raw_lang = data.get("language", "python")
    language = raw_lang.lower().strip() if isinstance(raw_lang, str) else "python"
    issues = data.get("issues", [])
    if not isinstance(issues, list):
        issues = []

    mode = data.get("mode", "ai")
    raw_key = data.get("api_key")
    api_key = (raw_key.strip() if isinstance(raw_key, str) and raw_key.strip() else None) or session.get("gemini_api_key", "") or os.environ.get("GEMINI_API_KEY", "")
    if api_key and not session.get("gemini_api_key"):
        session["gemini_api_key"] = api_key

    # Mode 1: Explicit Offline Fix (No API key needed)
    if mode == "offline":
        fallback = get_offline_fix(code, language, issues)
        fallback["source"] = "offline"
        fallback["source_label"] = "⚡ موتور امن‌ساز آفلاین (الگوی امن دمو)"
        # Automated security verification
        verification = scan_code(fallback.get("fixed_code", ""), language)
        fallback["verified_score"] = verification.get("score", 100)
        fallback["verified_issues_count"] = verification.get("issues_count", 0)
        return jsonify(fallback)

    # Mode 2: AI-Powered Fix via Gemini
    if not api_key:
        return jsonify({
            "error": "کلید Gemini API وارد نشده است. لطفاً از آیکن تنظیمات ⚙️ در بالای صفحه کلید خود را وارد کنید، یا از دکمه «⚡ اصلاح آفلاین» استفاده نمایید."
        }), 400

    try:
        result = call_gemini_api(code, language, issues, api_key)
        if result:
            # Automated security verification
            verification = scan_code(result.get("fixed_code", ""), language)
            result["verified_score"] = verification.get("score", 100)
            result["verified_issues_count"] = verification.get("issues_count", 0)
            return jsonify(result)
        return jsonify({
            "error": "پاسخی از هوش مصنوعی دریافت نشد. لطفاً اعتبار کلید API یا اتصال اینترنت را بررسی کنید."
        }), 502
    except Exception as e:
        app.logger.warning(f"Gemini API invocation error: {e}")
        return jsonify({"error": f"خطا در ارتباط با هوش مصنوعی: {str(e)}"}), 500


@app.route("/api/fetch-github", methods=["POST"])
@login_required
def api_fetch_github():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "داده نامعتبر است"}), 400

    raw_url = data.get("url", "").strip()
    if not raw_url:
        return jsonify({"error": "لطفاً آدرس فایل گیت‌هاب را وارد کنید"}), 400

    target_url = raw_url
    # Support GitHub web URLs: https://github.com/owner/repo/blob/main/file.ext
    if "github.com" in raw_url and "/blob/" in raw_url:
        target_url = raw_url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")

    # Strict SSRF protection: only allow official GitHub hostnames over HTTPS/HTTP
    parsed = urlparse(target_url)
    if parsed.scheme not in ("http", "https"):
        return jsonify({"error": "آدرس لینک باید با http یا https آغاز شود"}), 400

    hostname = (parsed.hostname or "").lower()
    allowed_domains = {"github.com", "raw.githubusercontent.com", "gist.githubusercontent.com"}
    if hostname not in allowed_domains:
        return jsonify({"error": "فقط دریافت فایل از دامنه‌های رسمی گیت‌هاب مجاز است."}), 400

    try:
        resp = http_requests.get(target_url, timeout=12, headers={"User-Agent": "CodeShield-AI-Fetcher"})
        if resp.status_code == 404:
            return jsonify({"error": "فایل در گیت‌هاب یافت نشد (404). لطفاً از صحت آدرس و پابلیک بودن مخزن اطمینان حاصل کنید."}), 404
        if resp.status_code != 200:
            return jsonify({"error": f"خطا در دریافت از گیت‌هاب (کد وضعیت: {resp.status_code})"}), 400

        content = resp.text
        if len(content) > 300_000:
            return jsonify({"error": "حجم فایل بیش از ۳۰۰ کیلوبایت است."}), 400

        # Auto-detect language
        clean_path = target_url.split("?")[0].lower()
        lang = "python"
        if clean_path.endswith(".php"):
            lang = "php"
        elif clean_path.endswith((".js", ".jsx", ".ts", ".tsx", ".mjs")):
            lang = "javascript"
        elif clean_path.endswith(".py"):
            lang = "python"

        filename = clean_path.split("/")[-1] or "file"

        return jsonify({
            "code": content,
            "language": lang,
            "filename": filename
        })
    except Exception as e:
        return jsonify({"error": f"خطا در برقراری ارتباط با گیت‌هاب: {str(e)}"}), 500


def call_gemini_api(code: str, language: str, issues: list, api_key: str) -> dict | None:
    """Call Google Gemini API with native JSON response mode and secure headers."""
    issues_list = []
    if isinstance(issues, list):
        for i in issues:
            if isinstance(i, dict):
                issues_list.append(f"- {i.get('title','')}: {i.get('description','')} (خطوط: {i.get('lines',[])})")
    issues_text = "\n".join(issues_list) if issues_list else "موردی ثبت نشده است."

    prompt = f"""شما یک متخصص ارشد امنیت نرم‌افزار و بهینه‌سازی کامپایلر هستید. کد {language} زیر دارای مشکلات امنیتی، باگ‌های منطقی یا گلوگاه‌های پرفورمنس است.

موارد شناسایی‌شده:
{issues_text}

کد فعلی:

{code}


وظایف شما:
1. کد را کاملاً بازنویسی کنید تا تمام آسیب‌پذیری‌های امنیتی، باگ‌های منطقی و گلوگاه‌های پرفورمنس/منابع رفع شوند.
2. توضیح فارسی کاملی از اصلاحات امنیتی، منطقی و بهینه‌سازی پرفورمنس ارائه دهید.

خروجی باید منحصراً یک شیء JSON با ساختار زیر باشد:
{{
  "fixed_code": "کد اصلاح و بهینه‌شده",
  "explanation": "توضیح فارسی"
}}"""

    models = ["gemini-flash-lite-latest", "gemini-3.5-flash", "gemini-flash-latest"]
    headers = {
        "Content-Type": "application/json",
        "x-goog-api-key": api_key,
    }
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.2,
            "maxOutputTokens": 4096,
            "responseMimeType": "application/json",
        },
    }

    for model in models:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
        try:
            resp = http_requests.post(url, headers=headers, json=payload, timeout=20)
            if resp.status_code != 200:
                app.logger.warning(f"Model {model} returned HTTP {resp.status_code}: {resp.text[:150]}")
                continue

            content = resp.json()
            candidates = content.get("candidates", [])
            if not candidates:
                continue

            parts = candidates[0].get("content", {}).get("parts", [])
            if not parts:
                continue

            text = parts[0].get("text", "").strip()
            if not text:
                continue

            # Strip code block markers if present
            if text.startswith("```"):
                text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
                text = re.sub(r"\s*```$", "", text)

            try:
                parsed = json.loads(text)
                if isinstance(parsed, dict) and "fixed_code" in parsed:
                    return {
                        "fixed_code": str(parsed.get("fixed_code", "")),
                        "explanation": str(parsed.get("explanation", "")),
                        "source": "gemini",
                        "source_label": f"✨ هوش مصنوعی Gemini ({model})",
                    }
            except json.JSONDecodeError:
                app.logger.warning("Failed to decode JSON from Gemini API response.")
                continue
        except Exception as e:
            app.logger.warning(f"Gemini API request failed for model {model}: {e}")
            continue

    return None


@app.route("/api/samples")
@login_required
def api_samples():
    return jsonify(DEMO_SAMPLES)


@app.route("/api/settings", methods=["POST"])
@login_required
def api_settings():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "فرمت داده نامعتبر است"}), 400

    api_key = data.get("api_key")
    if isinstance(api_key, str) and api_key.strip():
        clean_key = api_key.strip()
        if len(clean_key) > 120:
            return jsonify({"error": "طول کلید نامعتبر است"}), 400
        session["gemini_api_key"] = clean_key
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
    print("[OK] CodeShield AI is running at [http://127.0.0.1:5000](http://127.0.0.1:5000)")
    app.run(debug=True, host="127.0.0.1", port=5000)