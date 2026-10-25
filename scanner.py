import re
import ast

# ─────────────────────────────────────────────
#  Rule definitions (Security, Logic & Performance)
# ─────────────────────────────────────────────
RULES = [
    # ═════════════════════════════════════════
    #  ۱. قوانین امنیتی (Security Rules)
    # ═════════════════════════════════════════
    {
        "id": "sql_injection",
        "category": "security",
        "title": "تزریق SQL",
        "title_en": "SQL Injection",
        "severity": "critical",
        "deduction": 35,
        "description": "کد آسیب‌پذیر به تزریق SQL است. اطلاعات ورودی کاربر بدون اعتبارسنجی مستقیماً در کوئری SQL استفاده می‌شود.",
        "hint": "💡 پیشنهاد کامپایلر: هرگز متغیرها را با + یا f-string داخل کوئری نچسبانید. از Prepared Statements یا پارامترهای ? و :id استفاده کنید.",
        "patterns": {
            "php": [
                r'(SELECT|INSERT|UPDATE|DELETE).*\$_(GET|POST|REQUEST|COOKIE)',
                r'mysql_query\s*\(.*\$_(GET|POST|REQUEST)',
                r'mysqli.*query\s*\(.*\$_(GET|POST|REQUEST)',
                r'".*\s*(SELECT|INSERT|UPDATE|DELETE)\s+.*"\s*\.\s*\$',
                r"'.*\s*(SELECT|INSERT|UPDATE|DELETE)\s+.*'\s*\.\s*\$",
                r'\bquery\s*\(\s*["\'].*?(SELECT|INSERT|UPDATE|DELETE).*?["\']\s*\.\s*\$',
            ],
            "python": [
                r'execute\s*\(\s*[f"\'].*?(SELECT|INSERT|UPDATE|DELETE).*?%s.*?[f"\']\s*%',
                r'execute\s*\(\s*f["\'].*?(SELECT|INSERT|UPDATE|DELETE).*?\{.*?\}',
                r'execute\s*\(\s*f["\'].*?\{.*?\}.*?(SELECT|INSERT|UPDATE|DELETE)',
                r'cursor\.execute\s*\(\s*["\'].*?\+',
                r'(SELECT|INSERT|UPDATE|DELETE).*?["\']\s*%\s*\(',
                r'(SELECT|INSERT|UPDATE|DELETE).*?["\']\s*\+\s*\w+',
            ],
            "javascript": [
                r'query\s*\(\s*`.*?(SELECT|INSERT|UPDATE|DELETE).*?\$\{.*?\}',
                r'query\s*\(\s*`.*?\$\{.*?\}.*?(SELECT|INSERT|UPDATE|DELETE)',
                r'query\s*\(\s*["\'].*?(SELECT|INSERT|UPDATE|DELETE).*?["\']\s*\+',
            ],
        },
    },
    {
        "id": "xss",
        "category": "security",
        "title": "اسکریپت‌نویسی بین‌سایتی (XSS)",
        "title_en": "Cross-Site Scripting (XSS)",
        "severity": "high",
        "deduction": 25,
        "description": "خروجی داده‌های کاربر بدون فیلتر یا escape کردن در صفحه نمایش داده می‌شود که منجر به حمله XSS می‌گردد.",
        "hint": "💡 پیشنهاد کامپایلر: در JS از textContent یا DOMPurify، در PHP از htmlspecialchars() و در Flask از قالب‌های استاندارد Jinja2 استفاده کنید.",
        "patterns": {
            "php": [
                r'(echo|print)\s*(\(|\s).*?\$_(GET|POST|REQUEST|COOKIE)',
                r'(echo|print)\s*\(?\s*\$_(GET|POST|REQUEST|COOKIE)',
                r'echo\s+.*\$_(GET|POST|REQUEST|COOKIE)',
                r'<\?=\s*.*\$_(GET|POST|REQUEST|COOKIE)',
            ],
            "python": [
                r'return\s+.*request\.(args|form|values|json)',
                r'render_template_string\s*\(.*request\.',
            ],
            "javascript": [
                r'\.innerHTML\s*=\s*(?!["\'][\w\s<>/]*["\'])(?!.*DOMPurify).*\b\w+',
                r'\.innerHTML\s*=\s*`.*?\$\{.*?\}',
                r'document\.write\s*\(',
                r'\.outerHTML\s*=\s*(?!["\'][\w\s<>/]*["\'])(?!.*DOMPurify).*\b\w+',
                r'insertAdjacentHTML\s*\(\s*["\'][^"\']+["\']\s*,\s*(?!.*DOMPurify).*\b\w+',
            ],
        },
    },
    {
        "id": "hardcoded_secrets",
        "category": "security",
        "title": "اسرار و رمزهای هاردکد شده",
        "title_en": "Hardcoded Secrets/Passwords",
        "severity": "high",
        "deduction": 25,
        "description": "رمز عبور، کلید API یا توکن‌های امنیتی مستقیماً در کد درج شده‌اند که خطر لو رفتن اطلاعات حساس را دارد.",
        "hint": "💡 پیشنهاد کامپایلر: مقادیر حساس را به فایل .env منتقل کرده و با os.environ.get() یا $_ENV بخوانید.",
        "patterns": {
            "php": [
                r'(\$password|\$passwd|\$pwd|PASSWORD|PASS)\s*=\s*["\'][^"\']+["\']',
                r'(\$api_key|\$secret|\$token|API_KEY|SECRET|TOKEN)\s*=\s*["\'][^"\']{4,}["\']',
            ],
            "python": [
                r'^\s*(password|passwd|pwd|api_key|secret_key|token|auth_token)\s*=\s*["\'][^"\']{4,}["\']',
                r'\b(api_key|secret|token)\s*=\s*["\'][a-zA-Z0-9_\-]{8,}["\']',
            ],
            "javascript": [
                r'^\s*(const|let|var)\s+(password|api_key|apiKey|secret|token|SECRET)\s*=\s*["\'][^"\']{4,}["\']',
                r'const\s+(API_TOKEN|SECRET_KEY|API_KEY)\s*=\s*["\'][^"\']+["\']',
            ],
        },
    },
    {
        "id": "dangerous_functions",
        "category": "security",
        "title": "توابع خطرناک اجرای کد",
        "title_en": "Dangerous Execution Functions",
        "severity": "critical",
        "deduction": 35,
        "description": "توابع خطرناکی مانند eval() یا exec() استفاده شده که اجازه اجرای کد دلخواه را می‌دهند.",
        "hint": "💡 پیشنهاد کامپایلر: استفاده از eval/exec را حذف کنید. برای پارس داده از JSON.parse() یا ast.literal_eval() استفاده نمایید.",
        "patterns": {
            "php": [
                r'\beval\s*\(',
                r'\bexec\s*\(',
                r'\bsystem\s*\(',
                r'\bshell_exec\s*\(',
                r'\bpassthru\s*\(',
                r'\bpopen\s*\(',
            ],
            "python": [
                r'\beval\s*\(',
                r'\bexec\s*\(',
                r'\bos\.system\s*\(',
                r'\bsubprocess\.(call|run|Popen)\s*\(.*?shell\s*=\s*(True|1)',
                r'\b__import__\s*\(',
            ],
            "javascript": [
                r'\beval\s*\(',
                r'new\s+Function\s*\(',
                r'setTimeout\s*\(\s*["\']',
                r'setInterval\s*\(\s*["\']',
            ],
        },
    },
    {
        "id": "weak_crypto",
        "category": "security",
        "title": "رمزنگاری ضعیف",
        "title_en": "Weak Cryptography",
        "severity": "medium",
        "deduction": 15,
        "description": "از الگوریتم‌های رمزنگاری قدیمی و ضعیف مانند MD5 یا SHA1 برای هش کردن استفاده شده است.",
        "hint": "💡 پیشنهاد کامپایلر: برای هش کردن رمز عبور از الگوریتم‌های مدرن مانند PBKDF2، Argon2 یا bcrypt استفاده کنید.",
        "patterns": {
            "php": [
                r'\bmd5\s*\(',
                r'\bsha1\s*\(',
                r'\bcrc32\s*\(',
            ],
            "python": [
                r'hashlib\.md5\s*\(',
                r'hashlib\.sha1\s*\(',
                r"hashlib\.new\s*\(\s*['\"]md5['\"]",
                r"hashlib\.new\s*\(\s*['\"]sha1['\"]",
            ],
            "javascript": [
                r'crypto\.createHash\s*\(\s*["\']md5["\']',
                r'crypto\.createHash\s*\(\s*["\']sha1["\']',
            ],
        },
    },
    {
        "id": "debug_mode",
        "category": "security",
        "title": "حالت دیباگ فعال",
        "title_en": "Debug Mode Left On",
        "severity": "low",
        "deduction": 10,
        "description": "حالت Debug در محیط production فعال مانده که اطلاعات حساس سیستم را در معرض دید قرار می‌دهد.",
        "hint": "💡 پیشنهاد کامپایلر: در محیط عملیاتی (Production) مقدار debug=False تنظیم شود و نمایش خطاها به کاربر بسته شود.",
        "patterns": {
            "php": [
                r'display_errors\s*=\s*On',
                r'error_reporting\s*\(\s*E_ALL\s*\)',
                r'ini_set\s*\(\s*["\']display_errors["\']\s*,\s*["\']1["\']\s*\)',
            ],
            "python": [
                r'debug\s*=\s*True',
                r'DEBUG\s*=\s*True',
                r'app\.run\s*\(.*debug\s*=\s*True',
            ],
            "javascript": [
                r'\bdebugger\b',
            ],
        },
    },

    # ═════════════════════════════════════════
    #  ۲. قوانین پرفورمنس و مصرف منابع (Performance & Resource Rules)
    # ═════════════════════════════════════════
    {
        "id": "unbounded_query_or_memory",
        "category": "performance",
        "title": "واکشی سنگین داده و مصرف بی‌رویه رم",
        "title_en": "Unbounded Query / High Memory Usage",
        "severity": "medium",
        "deduction": 10,
        "description": "واکشی کل رکوردهای جدول یا خواندن کل فایل‌های حجیم به صورت یکجا در حافظه (RAM) می‌تواند باعث کندی شدید یا کرش سرور (Out Of Memory) شود.",
        "hint": "💡 پیشنهاد کامپایلر: در کوئری‌های SELECT از LIMIT و نام ستون‌های مشخص استفاده کنید، و فایل‌های بزرگ را خط‌به‌خط (Generator/Stream) بخوانید.",
        "patterns": {
            "php": [
                r'file_get_contents\s*\(\s*\$_(FILES|POST|GET)',
                r'SELECT\s+\*\s+FROM\s+\w+\s*;',
            ],
            "python": [
                r'\.fetchall\s*\(\s*\)',
                r'\.readlines\s*\(\s*\)',
            ],
            "javascript": [
                r'fs\.readFileSync\s*\(',
            ],
        },
    },
    {
        "id": "blocking_sleep_or_sync",
        "category": "performance",
        "title": "مسدودسازی نخ پردازشی (Thread Blocking)",
        "title_en": "Blocking Execution / Sync Bottleneck",
        "severity": "medium",
        "deduction": 12,
        "description": "استفاده از توابع متوقف‌کننده (Sleep یا عملیات همگام سنگین) در مسیر اصلی پردازش وب، کل ترد سرور را قفل کرده و زمان پاسخ‌دهی به سایر کاربران را به شدت افزایش می‌دهد.",
        "hint": "💡 پیشنهاد کامپایلر: از توابع غیرهمگام (Async/Await)، صف‌های پردازش پس‌زمینه (Celery/Queues) یا Web Workers استفاده کنید.",
        "patterns": {
            "php": [
                r'\bsleep\s*\(\s*\d+\s*\)',
                r'\busleep\s*\(\s*\d+\s*\)',
            ],
            "python": [
                r'\btime\.sleep\s*\(\s*[1-9]\d*\s*\)',
            ],
            "javascript": [
                r'while\s*\(\s*true\s*\)',
                r'execSync\s*\(',
            ],
        },
    },

    # ═════════════════════════════════════════
    #  ۳. قوانین منطقی و پایداری کد (Logic & Reliability Rules)
    # ═════════════════════════════════════════
    {
        "id": "silent_error_swallowing",
        "category": "logic",
        "title": "بلعیدن خطاها و استثناهای خاموش (Silent Failure)",
        "title_en": "Bare Except / Empty Catch Block",
        "severity": "medium",
        "deduction": 12,
        "description": "گرفتن تمام خطاها بدون مشخص کردن نوع خطا یا خالی گذاشتن بلوک catch باعث می‌شود باگ‌های منطقی در زمان اجرا پنهان بمانند و عیب‌یابی سیستم غیرممکن شود.",
        "hint": "💡 پیشنهاد کامپایلر: همیشه نوع دقیق خطا (مثلاً ValueError) را مشخص کنید و حداقل خطا را در لاگ سیستم (logging.error) ثبت نمایید.",
        "patterns": {
            "php": [
                r'catch\s*\([^)]+\)\s*\{\s*\}',
                r'@\s*(mysqli_|file_|fopen|unlink|include|require)',
            ],
            "python": [
                r'^\s*except\s*:\s*$',
            ],
            "javascript": [
                r'catch\s*\([^)]*\)\s*\{\s*\}',
                r'\.catch\s*\(\s*\(\s*\)\s*=>\s*\{\s*\}\s*\)',
            ],
        },
    },
    {
        "id": "loose_equality_bug",
        "category": "logic",
        "title": "مقایسه منطقی غیردقیق (خطای تبدیل نوع ضمنی)",
        "title_en": "Loose Equality / Singleton Comparison Bug",
        "severity": "low",
        "deduction": 8,
        "description": "استفاده از عملگرهای مقایسه غیردقیق باعث تبدیل خودکار نوع داده‌ها (Type Coercion) شده و در شرایط مرزی (مثل 0، رشته خالی یا null) رفتار منطقی غیرمنتظره ایجاد می‌کند.",
        "hint": "💡 پیشنهاد کامپایلر: در پایتون برای مقایسه با None یا بولین از `is None` استفاده کنید. در JS و PHP همیشه از `===` و `!==` استفاده نمایید.",
        "patterns": {
            "php": [
                r'if\s*\(.*?\b(strpos|stripos)\s*\(.*?\)\s*==\s*(false|true|0)',
            ],
            "python": [
                r'[!=]=\s*None\b',
                r'[!=]=\s*(True|False)\b',
            ],
            "javascript": [
                r'[^=!<>]==[^=]',
                r'!=[^=]',
            ],
        },
    },
]

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# Pre-compile regular expressions module-wide for high-throughput scanning
COMPILED_RULES = {}
for rule in RULES:
    COMPILED_RULES[rule["id"]] = {}
    for lang, patterns in rule["patterns"].items():
        COMPILED_RULES[rule["id"]][lang] = [re.compile(p, re.IGNORECASE) for p in patterns]


# ─────────────────────────────────────────────
#  Python AST Static Analyzer (Rust-Clippy Style)
# ─────────────────────────────────────────────
def _ast_scan_python(code: str) -> list:
    """
    Analyze Python code using Abstract Syntax Tree (AST) to detect deep
    logical bugs, resource leaks, and performance bottlenecks.
    """
    ast_issues = []
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        lineno = getattr(e, "lineno", 1) or 1
        return [{
            "id": "syntax_error",
            "category": "logic",
            "title": "خطای نحوی (Syntax Error) در کامپایل کد",
            "title_en": "Python Syntax Error",
            "severity": "high",
            "deduction": 20,
            "description": f"کد پایتون دارای خطای سینتکس در خط {lineno} است و در زمان اجرا کرش خواهد کرد: {e.msg}",
            "hint": "💡 پیشنهاد کامپایلر: پرانتزها، تورفتگی‌ها (Indentation) و دو‌نقطه‌های انتهای دستورات را در خط اشاره‌شده بررسی کنید.",
            "lines": [lineno],
        }]
    except Exception:
        return []

    mutable_arg_lines = []
    unreachable_lines = []
    silent_except_lines = []
    nested_loop_lines = []
    io_in_loop_lines = []
    open_call_lines = set()
    with_open_lines = set()

    IO_CALL_NAMES = {
        "execute", "executemany", "get", "post", "put", "delete",
        "urlopen", "sleep", "connect", "read_sql", "find", "find_one"
    }

    for node in ast.walk(tree):
        # ۱. تشخیص آرگومان پیش‌فرض تغییرپذیر (Mutable Default Argument: list/dict/set)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for default in node.args.defaults + node.args.kw_defaults:
                if default is not None and isinstance(default, (ast.List, ast.Dict, ast.Set)):
                    if node.lineno not in mutable_arg_lines:
                        mutable_arg_lines.append(node.lineno)

        # ۲. تشخیص کد غیرقابل دسترس (Unreachable / Dead Code بعد از return/raise/break/continue)
        for attr in ("body", "orelse", "finalbody"):
            stmts = getattr(node, attr, None)
            if isinstance(stmts, list):
                for idx, stmt in enumerate(stmts):
                    if isinstance(stmt, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
                        if idx + 1 < len(stmts):
                            next_line = getattr(stmts[idx + 1], "lineno", stmt.lineno)
                            if next_line not in unreachable_lines:
                                unreachable_lines.append(next_line)
                        break

        # ۳. تشخیص بلعیدن خطا در except: pass
        if isinstance(node, ast.ExceptHandler):
            if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
                if node.lineno not in silent_except_lines:
                    silent_except_lines.append(node.lineno)

        # ۴. تحلیل حلقه‌ها: حلقه‌های تودرتوی سنگین O(n²) و عملیات شبکه/دیتابیس داخل حلقه (N+1)
        if isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
            for child in ast.walk(node):
                if child is not node and isinstance(child, (ast.For, ast.AsyncFor, ast.While)):
                    # بررسی حلقه سطح سوم یا حلقه تودرتو
                    for grand in ast.walk(child):
                        if grand is not child and isinstance(grand, (ast.For, ast.AsyncFor, ast.While)):
                            if node.lineno not in nested_loop_lines:
                                nested_loop_lines.append(node.lineno)
                if isinstance(child, ast.Call):
                    func_name = ""
                    if isinstance(child.func, ast.Attribute):
                        func_name = child.func.attr
                    elif isinstance(child.func, ast.Name):
                        func_name = child.func.id
                    if func_name in IO_CALL_NAMES:
                        if child.lineno not in io_in_loop_lines:
                            io_in_loop_lines.append(child.lineno)

        # ۵. تشخیص نشت منابع فایل (باز کردن فایل با open بدون بلاک with)
        if isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                ctx = item.context_expr
                if isinstance(ctx, ast.Call) and isinstance(ctx.func, ast.Name) and ctx.func.id == "open":
                    with_open_lines.add(ctx.lineno)
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id == "open":
                open_call_lines.add(node.lineno)

    leaked_open_lines = sorted(open_call_lines - with_open_lines)

    if mutable_arg_lines:
        ast_issues.append({
            "id": "mutable_default_arg",
            "category": "logic",
            "title": "آرگومان پیش‌فرض تغییرپذیر (باگ منطقی حافظه مشترک)",
            "title_en": "Mutable Default Argument",
            "severity": "high",
            "deduction": 15,
            "description": "استفاده از لیست `[]` یا دیکشنری `{}` به عنوان مقدار پیش‌فرض تابع در پایتون باعث می‌شود یک شیء واحد در حافظه بین تمام فراخوانی‌های بعدی تابع مشترک بماند و داده‌ها قاطی شوند.",
            "hint": "💡 پیشنهاد کامپایلر: مقدار پیش‌فرض را `None` بگذارید (مثلاً `def fn(items=None):`) و در خط اول تابع بنویسید: `if items is None: items = []`.",
            "lines": sorted(mutable_arg_lines),
        })

    if unreachable_lines:
        ast_issues.append({
            "id": "unreachable_code",
            "category": "logic",
            "title": "کد مرده و غیرقابل دسترس (Unreachable Code)",
            "title_en": "Unreachable / Dead Code",
            "severity": "medium",
            "deduction": 10,
            "description": "دستوراتی پس از `return`، `break` یا `raise` نوشته شده‌اند که جریان اجرای برنامه هرگز به آن‌ها نمی‌رسد و نشان‌دهنده خطای منطقی در الگوریتم است.",
            "hint": "💡 پیشنهاد کامپایلر: کدهای بعد از دستور خروج را حذف کنید یا شرط (if/else) قبل از return را بررسی نمایید.",
            "lines": sorted(unreachable_lines),
        })

    if silent_except_lines:
        ast_issues.append({
            "id": "silent_error_swallowing",
            "category": "logic",
            "title": "بلعیدن خطا با بلوک except: pass",
            "title_en": "Silent Exception Pass",
            "severity": "medium",
            "deduction": 12,
            "description": "استفاده از `pass` در بلوک `except` باعث می‌شود خطاهای زمان اجرا کاملاً نادیده گرفته شوند و برنامه با داده‌های ناقص به کار ادامه دهد.",
            "hint": "💡 پیشنهاد کامپایلر: به جای `pass`، خطا را لاگ کنید یا خطای مشخصی را مدیریت نمایید.",
            "lines": sorted(silent_except_lines),
        })

    if io_in_loop_lines:
        ast_issues.append({
            "id": "io_in_loop_bottleneck",
            "category": "performance",
            "title": "گلوگاه شدید پرفورمنس: فراخوانی I/O یا کوئری داخل حلقه (N+1)",
            "title_en": "I/O or Database Query Inside Loop",
            "severity": "high",
            "deduction": 18,
            "description": "اجرای کوئری دیتابیس، درخواست شبکه یا توقف زمان در هر دور از حلقه باعث افت نمایی سرعت (N+1 Problem) و مصرف شدید منابع سرور می‌شود.",
            "hint": "💡 پیشنهاد کامپایلر: کوئری‌ها را به صورت دسته‌ای (Batch / WHERE IN) خارج از حلقه اجرا کنید یا از درخواست‌های ناهمگام (asyncio.gather) بهره ببرید.",
            "lines": sorted(io_in_loop_lines),
        })

    if nested_loop_lines:
        ast_issues.append({
            "id": "deep_nested_loops",
            "category": "performance",
            "title": "پیچیدگی زمانی بالا: حلقه‌های تودرتوی عمیق O(n³)",
            "title_en": "High Time Complexity (Deep Nested Loops)",
            "severity": "medium",
            "deduction": 15,
            "description": "وجود ۳ سطح یا بیشتر حلقه تودرتو باعث می‌شود با افزایش حجم ورودی، مصرف CPU به صورت تصاعدی بالا رفته و پردازش قفل شود.",
            "hint": "💡 پیشنهاد کامپایلر: برای جستجوی سریع‌تر، داده‌های حلقه داخلی را به دیکشنری (Hash Map) یا مجموعه (set) با پیچیدگی O(1) تبدیل کنید.",
            "lines": sorted(nested_loop_lines),
        })

    if leaked_open_lines:
        ast_issues.append({
            "id": "resource_leak_open",
            "category": "performance",
            "title": "نشت منابع سیستم (فایل باز رها شده بدون with)",
            "title_en": "Unclosed File Resource Leak",
            "severity": "medium",
            "deduction": 12,
            "description": "فراخوانی `open()` بدون استفاده از Context Manager (`with`) باعث می‌شود در صورت بروز خطا، فایل در سیستم‌عامل باز بماند و File Descriptor نشت کند.",
            "hint": "💡 پیشنهاد کامپایلر: همیشه فایل‌ها را با ساختار `with open(...) as f:` باز کنید تا به صورت خودکار و امن بسته شوند.",
            "lines": leaked_open_lines,
        })

    return ast_issues


def scan_code(code: str, language: str) -> dict:
    """
    Scan code for security vulnerabilities, logical bugs, and performance bottlenecks.
    Returns a dict with score, category sub-scores, issues list, and summary.
    """
    if not isinstance(code, str) or not code.strip():
        return {
            "score": 0,
            "security_score": 0,
            "quality_score": 0,
            "issues": [{
                "id": "empty_code",
                "category": "logic",
                "title": "کدی ارسال نشده است",
                "title_en": "Empty Code",
                "severity": "low",
                "deduction": 0,
                "description": "هیچ کدی برای تحلیل ارسال نشده است.",
                "hint": "لطفاً کد خود را در ویرایشگر وارد کنید.",
                "lines": [],
            }],
            "issues_count": 0,
            "category_counts": {"security": 0, "logic": 0, "performance": 0},
            "total_deduction": 0,
            "language": language if isinstance(language, str) else "python",
        }

    language = language.lower() if isinstance(language, str) else "python"
    if language not in ("php", "python", "javascript"):
        language = "python"

    lines = code.splitlines()
    issues = []
    total_deduction = 0
    seen_rule_ids = set()

    # ۱. اجرای قوانین مبتنی بر الگو (Regex)
    for rule in RULES:
        compiled_patterns = COMPILED_RULES.get(rule["id"], {}).get(language, [])
        if not compiled_patterns:
            continue

        matched_lines = []
        for compiled in compiled_patterns:
            for line_no, raw_line in enumerate(lines, start=1):
                stripped = raw_line.strip()
                # Skip comments to prevent false positives
                if stripped.startswith(("#", "//", "/*", "*")):
                    continue
                if compiled.search(raw_line):
                    if line_no not in matched_lines:
                        matched_lines.append(line_no)

        if matched_lines and rule["id"] not in seen_rule_ids:
            seen_rule_ids.add(rule["id"])
            total_deduction += rule["deduction"]
            issues.append(
                {
                    "id": rule["id"],
                    "category": rule.get("category", "security"),
                    "title": rule["title"],
                    "title_en": rule["title_en"],
                    "severity": rule["severity"],
                    "deduction": rule["deduction"],
                    "description": rule["description"],
                    "hint": rule.get("hint", ""),
                    "lines": sorted(matched_lines),
                }
            )

    # ۲. اجرای تحلیلگر درخت نحوی (AST) برای پایتون
    if language == "python":
        for ast_issue in _ast_scan_python(code):
            if ast_issue["id"] not in seen_rule_ids:
                seen_rule_ids.add(ast_issue["id"])
                total_deduction += ast_issue["deduction"]
                issues.append(ast_issue)

    issues.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 99))
    score = max(0, min(100, 100 - total_deduction))

    # محاسبه آمار تفکیکی برای نمایش در داشبورد
    category_counts = {"security": 0, "logic": 0, "performance": 0}
    sec_deduction = 0
    qual_deduction = 0

    for item in issues:
        cat = item.get("category", "security")
        if cat in category_counts:
            category_counts[cat] += 1
        if cat == "security":
            sec_deduction += item.get("deduction", 0)
        else:
            qual_deduction += item.get("deduction", 0)

    security_score = max(0, min(100, 100 - sec_deduction))
    quality_score = max(0, min(100, 100 - qual_deduction))

    return {
        "score": score,
        "security_score": security_score,
        "quality_score": quality_score,
        "issues": issues,
        "issues_count": len(issues),
        "category_counts": category_counts,
        "total_deduction": total_deduction,
        "language": language,
    }