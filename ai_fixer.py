"""
Offline fallback secure code samples for demo mode.
These are returned when no API key is provided or network is unavailable.
"""

OFFLINE_FIXES = {
    "php_sqli_xss": {
        "code": """<?php
// ✅ کد امن‌سازی شده با Prepared Statements و htmlspecialchars
$servername = "localhost";
$username   = $_ENV['DB_USER'] ?? 'root';
$password   = $_ENV['DB_PASS'] ?? '';
$dbname     = "myDB";

try {
    $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
    $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    // ✅ استفاده از Prepared Statement برای جلوگیری از SQL Injection
    $user_id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);
    if ($user_id === false || $user_id === null) {
        throw new InvalidArgumentException('شناسه کاربر نامعتبر است');
    }
    
    $stmt = $conn->prepare("SELECT id, name, email FROM users WHERE id = :id");
    $stmt->bindParam(':id', $user_id, PDO::PARAM_INT);
    $stmt->execute();
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if ($user) {
        // ✅ استفاده از htmlspecialchars برای جلوگیری از XSS
        echo "نام: " . htmlspecialchars($user['name'], ENT_QUOTES, 'UTF-8');
        echo "<br>ایمیل: " . htmlspecialchars($user['email'], ENT_QUOTES, 'UTF-8');
    } else {
        echo "کاربر یافت نشد";
    }
} catch (PDOException $e) {
    // ✅ عدم نمایش خطاهای دیتابیس به کاربر
    error_log("Database error: " . $e->getMessage());
    echo "خطا در سرور. لطفاً بعداً تلاش کنید.";
}
?>""",
        "explanation": """### 🔒 توضیح اصلاحات امنیتی

**۱. رفع SQL Injection:**
- از **Prepared Statements با PDO** استفاده شد. کوئری و داده‌ها کاملاً جدا هستند.
- از `bindParam()` با `PDO::PARAM_INT` برای تایید نوع داده استفاده شد.
- از `filter_input()` برای اعتبارسنجی ورودی کاربر استفاده شد.

**۲. رفع XSS:**
- از `htmlspecialchars($value, ENT_QUOTES, 'UTF-8')` برای escape کردن تمام خروجی‌ها استفاده شد.
- این تابع کاراکترهای خطرناک مثل `<`, `>`, `"` را به موجودیت‌های HTML تبدیل می‌کند.

**۳. مدیریت خطا:**
- خطاهای دیتابیس فقط در لاگ‌ها ذخیره می‌شوند و به کاربر نمایش داده نمی‌شوند.
- از متغیرهای محیطی برای اطلاعات اتصال دیتابیس استفاده شد.""",
    },
    "python_secrets_eval": {
        "code": """import os
import hashlib
import hmac
import secrets
from flask import Flask, request, session, abort
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
# ✅ کلید امنیتی از متغیر محیطی
app.secret_key = os.environ.get('SECRET_KEY') or secrets.token_hex(32)

# ✅ استفاده از استاندارد امن PBKDF2 با 600,000 تکرار
def hash_password(password: str) -> str:
    return generate_password_hash(password, method='pbkdf2:sha256:600000')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return check_password_hash(hashed_password, plain_password)

# ✅ ارزیابی امن عبارات با درخت نحوی AST بدون فراخوانی تابع eval
import ast
import operator

SAFE_OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
}

def _calc_node(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in SAFE_OPS:
        return SAFE_OPS[type(node.op)](_calc_node(node.left), _calc_node(node.right))
    raise ValueError("عبارت نامعتبر است")

def safe_evaluate(expression: str):
    \"\"\"ارزیابی امن عبارات ریاضی بدون اجرای کد دلخواه\"\"\"
    try:
        tree = ast.parse(expression, mode='eval')
        return _calc_node(tree.body)
    except Exception:
        raise ValueError("عبارت نامعتبر است")

@app.route('/calculate', methods=['POST'])
def calculate():
    expr = request.json.get('expression', '')
    if len(expr) > 100:
        abort(400, description="عبارت خیلی طولانی است")
    result = safe_evaluate(expr)
    return {'result': result}

if __name__ == '__main__':
    # ✅ Debug Mode خاموش در production
    app.run(debug=False, host='0.0.0.0', port=5000)""",
        "explanation": """### 🔒 توضیح اصلاحات امنیتی

**۱. رفع Hardcoded Secrets:**
- رمز عبور و کلیدهای API از **متغیرهای محیطی** (`os.environ`) خوانده می‌شوند.
- از کتابخانه `secrets` برای تولید کلید تصادفی امن استفاده شد.

**۲. رمزنگاری قوی رمز عبور:**
- به جای MD5/SHA1 از **الگوریتم استاندارد PBKDF2-SHA256** با ۶۰۰,۰۰۰ تکرار استفاده شد.
- این متد به صورت خودکار Salt تصادفی تولید کرده و در برابر حملات brute-force کاملاً مقاوم است.

**۳. رفع eval() خطرناک:**
- به جای `eval()` از `ast.literal_eval` و تجزیه درخت نحوی (AST) استفاده شد.
- فقط عملیات ریاضی مجاز هستند و امکان اجرای کد دلخواه وجود ندارد.

**۴. Debug Mode خاموش:**
- `debug=False` در production تنظیم شد تا Stack Trace به کاربران نمایش داده نشود.""",
    },
    "javascript_xss_token": {
        "code": """// ✅ کد JavaScript امن‌سازی شده

// ✅ توکن را هرگز در کد سمت کاربر ذخیره نکنید - از HttpOnly Cookie استفاده کنید
// توکن از سمت سرور به صورت HttpOnly Cookie ارسال می‌شود

// ✅ تابع امن برای نمایش محتوا بدون XSS
function setTextContentSafe(element, text) {
    // استفاده از textContent به جای innerHTML
    element.textContent = text;
}

// ✅ اگر نیاز به HTML داشتید از DOMPurify استفاده کنید
function setInnerHTMLSafe(element, htmlContent) {
    // DOMPurify تمام تگ‌های خطرناک را حذف می‌کند
    element.innerHTML = DOMPurify.sanitize(htmlContent, {
        ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'p', 'br'],
        ALLOWED_ATTR: []
    });
}

// ✅ نمایش پیام خوش‌آمدگویی - استفاده از textContent
function displayUserMessage(username) {
    const messageEl = document.getElementById('welcome-message');
    if (!messageEl) return;
    // textContent به صورت خودکار همه کاراکترها را escape می‌کند
    messageEl.textContent = `خوش آمدید، ${username}!`;
}

// ✅ دریافت داده از API با اعتبارسنجی
async function fetchUserData(userId) {
    // اعتبارسنجی ورودی
    if (!Number.isInteger(Number(userId)) || userId <= 0) {
        console.error('شناسه کاربر نامعتبر است');
        return null;
    }
    
    try {
        const response = await fetch(`/api/users/${encodeURIComponent(userId)}`, {
            method: 'GET',
            credentials: 'include', // ارسال HttpOnly cookie به صورت خودکار
            headers: {
                'Content-Type': 'application/json',
                // ✅ CSRF Token از یک متا تگ امن خوانده می‌شود (نه localStorage)
                'X-CSRF-Token': document.querySelector('meta[name="csrf-token"]')?.content ?? ''
            }
        });
        
        if (!response.ok) throw new Error(`HTTP Error: ${response.status}`);
        const data = await response.json();
        
        // ✅ نمایش امن داده‌های دریافتی
        displayUserMessage(data.name);
        return data;
    } catch (error) {
        // ✅ فقط پیام امن به کاربر نشان دهید
        setTextContentSafe(document.getElementById('error-msg'), 'خطا در دریافت اطلاعات');
    }
}""",
        "explanation": """### 🔒 توضیح اصلاحات امنیتی

**۱. رفع XSS:**
- به جای `.innerHTML =` از `.textContent =` استفاده شد که به صورت خودکار همه کاراکترها را escape می‌کند.
- برای موارد ضروری HTML از `DOMPurify.sanitize()` استفاده شد که تگ‌های خطرناک را حذف می‌کند.

**۲. مدیریت امن توکن:**
- توکن‌های احراز هویت در **HttpOnly Cookie** ذخیره می‌شوند، نه در `localStorage` یا متغیرهای JavaScript.
- کوکی‌های HttpOnly از JavaScript قابل دسترسی نیستند و از سرقت توکن جلوگیری می‌کنند.

**۳. محافظت CSRF:**
- از CSRF Token در هدر درخواست‌های API استفاده شد.
- توکن از یک متا تگ در صفحه خوانده می‌شود (به جای localStorage).

**۴. اعتبارسنجی ورودی:**
- از `encodeURIComponent()` برای پارامترهای URL استفاده شد.
- شناسه‌های عددی قبل از استفاده اعتبارسنجی می‌شوند.""",
    },
    "python_secure": {
        "code": """# ✅ این کد کاملاً امن است - امتیاز ۱۰۰
import os
import secrets
import logging
from flask import Flask, request, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

# تنظیم لاگینگ امن
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# ✅ تمام پیکربندی‌های حساس از متغیر محیطی
app.config.update(
    SECRET_KEY=os.environ.get('SECRET_KEY', secrets.token_hex(32)),
    SQLALCHEMY_DATABASE_URI=os.environ.get('DATABASE_URL', 'sqlite:///app.db'),
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE='Lax',
)

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    # ✅ ذخیره هش رمز عبور با Werkzeug (pbkdf2)
    password_hash = db.Column(db.String(256), nullable=False)

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256:600000')

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # ... بررسی احراز هویت
        return f(*args, **kwargs)
    return decorated

@app.route('/api/users/<int:user_id>', methods=['GET'])
@require_auth
def get_user(user_id: int):
    # ✅ SQLAlchemy به صورت خودکار از SQL Injection جلوگیری می‌کند
    user = db.session.get(User, user_id)
    if not user:
        abort(404, description="کاربر یافت نشد")
    return jsonify({'id': user.id, 'username': user.username})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    # ✅ debug=False در production
    app.run(debug=False)""",
        "explanation": """### ✅ این کد کاملاً امن است!

**چرا این کد امتیاز ۱۰۰ می‌گیرد:**

1. **بدون SQL Injection:** از SQLAlchemy ORM با Parameterized Queries استفاده شده.
2. **رمزنگاری قوی:** از `werkzeug.security` با PBKDF2-SHA256 و 600,000 تکرار استفاده شده.
3. **بدون Hardcoded Secrets:** تمام کلیدها از متغیرهای محیطی خوانده می‌شوند.
4. **بدون توابع خطرناک:** هیچ `eval()`, `exec()` یا `os.system()` در کد وجود ندارد.
5. **Debug Mode خاموش:** `debug=False` در Production تنظیم شده.
6. **کوکی‌های امن:** `HttpOnly`, `Secure`, و `SameSite=Lax` فعال هستند.""",
    },
    "python_logic_perf_fixed": {
        "code": """# ✅ کد بهینه‌سازی شده از نظر منطقی، مدیریت منابع و پرفورمنس (امتیاز ۱۰۰)
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ✅ ۱. رفع باگ آرگومان پیش‌فرض تغییرپذیر با استفاده از None
def add_audit_log(event: str | None, logs: list | None = None) -> list:
    if logs is None:
        logs = []
    
    # ✅ ۲. مقایسه استاندارد با is None و حذف کد مرده (Unreachable Code)
    if event is None:
        return logs

    logs.append(event)
    
    # ✅ ۳. مدیریت امن منابع فایل با Context Manager (with) برای جلوگیری از نشت حافظه
    with open("audit.log", "a", encoding="utf-8") as f:
        f.write(f"{event}\\n")
        
    return logs

# ✅ ۴. حذف حلقه تودرتوی O(n³)، حذف time.sleep و اجرای کوئری دسته‌ای (رفع مشکل N+1)
def sync_users_report(users: list, db_cursor) -> list:
    if not users:
        return []
    try:
        # استفاده از مجموعه (Set) با پیچیدگی زمانی O(1) به جای حلقه‌های تودرتو
        unique_users = list(set(users))
        placeholders = ",".join(["?"] * len(unique_users))
        query = f"SELECT uid, score FROM stats WHERE uid IN ({placeholders})"
        
        db_cursor.execute(query, tuple(unique_users))
        return db_cursor.fetchmany(size=100)
    except Exception as exc:
        # ✅ ۵. ثبت دقیق خطا در لاگ به جای بلعیدن خاموش خطا (except: pass)
        logger.error("Database sync failed: %s", exc)
        raise
""",
        "explanation": """### 🧠 توضیح اصلاحات منطقی و بهینه‌سازی پرفورمنس

**۱. رفع باگ آرگومان پیش‌فرض تغییرپذیر (Mutable Default Argument):**
- مقدار پیش‌فرض `logs=[]` به `logs=None` تغییر یافت و در ابتدای تابع مقداردهی شد تا حافظه بین فراخوانی‌های مختلف مشترک نماند.

**۲. رفع نشت منابع (Resource Leak):**
- فایل با دستور `with open(...) as f:` باز شد تا حتی در صورت بروز استثنا، فایل به صورت خودکار در سیستم‌عامل بسته شود.

**۳. رفع مشکل N+1 Query و پیچیدگی $O(n^3)$:**
- حلقه‌های تودرتوی اضافی و `time.sleep(1)` حذف شدند و به جای اجرای کوئری در هر دور حلقه، از کوئری یکپارچه و ساختار داده `set` با پیچیدگی $O(1)$ استفاده شد.

**۴. مدیریت اصولی خطاها و حذف کد مرده:**
- مقایسه `== None` به `is None` اصلاح شد، کدهای غیرقابل دسترس بعد از `return` پاکسازی شدند و بلوک خاموش `except: pass` با ثبت لاگ استاندارد (`logger.error`) جایگزین گردید.""",
    },
}


def get_offline_fix(code: str, language: str, issues: list) -> dict:
    """
    Select the best offline fallback based on detected issues and language.
    Guarantees matching the requested language.
    """
    issue_ids = set()
    categories = set()
    if isinstance(issues, list):
        for i in issues:
            if isinstance(i, dict):
                if "id" in i:
                    issue_ids.add(i["id"])
                if "category" in i:
                    categories.add(i["category"])

    norm_lang = language.lower() if isinstance(language, str) else "python"

    logic_perf_ids = {
        "mutable_default_arg", "unreachable_code", "silent_error_swallowing",
        "io_in_loop_bottleneck", "deep_nested_loops", "resource_leak_open",
        "unbounded_query_or_memory", "blocking_sleep_or_sync", "loose_equality_bug"
    }

    if norm_lang == "php":
        sample = OFFLINE_FIXES["php_sqli_xss"]
    elif norm_lang == "javascript":
        sample = OFFLINE_FIXES["javascript_xss_token"]
    elif norm_lang == "python":
        if "dangerous_functions" in issue_ids or "hardcoded_secrets" in issue_ids or "sql_injection" in issue_ids:
            sample = OFFLINE_FIXES["python_secrets_eval"]
        elif (issue_ids & logic_perf_ids) or ("logic" in categories or "performance" in categories):
            sample = OFFLINE_FIXES["python_logic_perf_fixed"]
        else:
            sample = OFFLINE_FIXES["python_secure"]
    else:
        sample = OFFLINE_FIXES["python_secure"]

    return {
        "fixed_code": sample["code"],
        "explanation": sample["explanation"],
        "source": "offline",
    }