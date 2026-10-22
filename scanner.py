import re

# ─────────────────────────────────────────────
#  Rule definitions
# ─────────────────────────────────────────────
RULES = [
    {
        "id": "sql_injection",
        "title": "تزریق SQL",
        "title_en": "SQL Injection",
        "severity": "critical",
        "deduction": 35,
        "description": "کد آسیب‌پذیر به تزریق SQL است. اطلاعات ورودی کاربر بدون اعتبارسنجی مستقیماً در کوئری SQL استفاده می‌شود.",
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
        "title": "اسکریپت‌نویسی بین‌سایتی (XSS)",
        "title_en": "Cross-Site Scripting (XSS)",
        "severity": "high",
        "deduction": 25,
        "description": "خروجی داده‌های کاربر بدون فیلتر یا escape کردن در صفحه نمایش داده می‌شود که منجر به حمله XSS می‌گردد.",
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
        "title": "اسرار و رمزهای هاردکد شده",
        "title_en": "Hardcoded Secrets/Passwords",
        "severity": "high",
        "deduction": 25,
        "description": "رمز عبور، کلید API یا توکن‌های امنیتی مستقیماً در کد درج شده‌اند که خطر لو رفتن اطلاعات حساس را دارد.",
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
        "title": "توابع خطرناک اجرای کد",
        "title_en": "Dangerous Execution Functions",
        "severity": "critical",
        "deduction": 35,
        "description": "توابع خطرناکی مانند eval() یا exec() استفاده شده که اجازه اجرای کد دلخواه را می‌دهند.",
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
        "title": "رمزنگاری ضعیف",
        "title_en": "Weak Cryptography",
        "severity": "medium",
        "deduction": 15,
        "description": "از الگوریتم‌های رمزنگاری قدیمی و ضعیف مانند MD5 یا SHA1 برای هش کردن استفاده شده است.",
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
        "title": "حالت دیباگ فعال",
        "title_en": "Debug Mode Left On",
        "severity": "low",
        "deduction": 10,
        "description": "حالت Debug در محیط production فعال مانده که اطلاعات حساس سیستم را در معرض دید قرار می‌دهد.",
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
]

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# Pre-compile regular expressions module-wide for high-throughput scanning
COMPILED_RULES = {}
for rule in RULES:
    COMPILED_RULES[rule["id"]] = {}
    for lang, patterns in rule["patterns"].items():
        COMPILED_RULES[rule["id"]][lang] = [re.compile(p, re.IGNORECASE) for p in patterns]


def scan_code(code: str, language: str) -> dict:
    """
    Scan code for security vulnerabilities.
    Returns a dict with score, issues list, and summary.
    """
    if not isinstance(code, str) or not code.strip():
        return {
            "score": 0,
            "issues": [{
                "id": "empty_code",
                "title": "کدی ارسال نشده است",
                "title_en": "Empty Code",
                "severity": "low",
                "deduction": 0,
                "description": "هیچ کدی برای تحلیل ارسال نشده است.",
                "lines": [],
            }],
            "issues_count": 0,
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
                    "title": rule["title"],
                    "title_en": rule["title_en"],
                    "severity": rule["severity"],
                    "deduction": rule["deduction"],
                    "description": rule["description"],
                    "lines": matched_lines,
                }
            )

    issues.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 99))
    score = max(0, min(100, 100 - total_deduction))

    return {
        "score": score,
        "issues": issues,
        "issues_count": len(issues),
        "total_deduction": total_deduction,
        "language": language,
    }
