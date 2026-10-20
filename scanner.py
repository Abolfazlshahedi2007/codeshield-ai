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
            ],
            "python": [
                r'execute\s*\(\s*[f"\'].*SELECT.*%s.*[f"\']\s*%',
                r'execute\s*\(\s*f["\'].*\{.*\}.*SELECT',
                r'execute\s*\(\s*f["\'].*(SELECT|INSERT|UPDATE|DELETE)',
                r'cursor\.execute\s*\(\s*".*\+',
                r'cursor\.execute\s*\(\s*\'.*\+',
            ],
            "javascript": [
                r'query\s*\(\s*`.*\$\{.*\}.*SELECT',
                r'query\s*\(\s*["\'].*SELECT.*["\'].*\+',
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
                r'echo\s+\$_(GET|POST|REQUEST|COOKIE)',
                r'print\s+\$_(GET|POST|REQUEST|COOKIE)',
                r'echo\s+.*\$_(GET|POST|REQUEST|COOKIE)',
            ],
            "python": [
                r'return\s+.*request\.(args|form|values|json)',
                r'render_template_string\s*\(.*request\.',
            ],
            "javascript": [
                r'\.innerHTML\s*=\s*(?!.*DOMPurify)',
                r'document\.write\s*\(',
                r'\.outerHTML\s*=',
                r'insertAdjacentHTML\s*\(',
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
                r'(?<!os\.environ\.get\()(?<!secrets\.)\b(password|passwd|pwd|api_key|secret_key|SECRET_KEY)\s*=\s*["\'][^"\']+["\']',
                r'\b(api_key|token)\s*=\s*["\'][^"\']{6,}["\']',
            ],
            "javascript": [
                r'(password|passwd|api_key|apiKey|secret|token|SECRET)\s*=\s*["\'][^"\']+["\']',
                r'const\s+(password|api_key|secret|token)\s*=\s*["\']',
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
                r'\bsubprocess\.call\s*\(.*shell\s*=\s*True',
                r'\bsubprocess\.run\s*\(.*shell\s*=\s*True',
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
                r'debugger\s*;',
            ],
        },
    },
]

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def scan_code(code: str, language: str) -> dict:
    """
    Scan code for security vulnerabilities.
    Returns a dict with score, issues list, and summary.
    """
    language = language.lower()
    if language not in ("php", "python", "javascript"):
        language = "python"

    lines = code.splitlines()
    issues = []
    total_deduction = 0
    seen_rule_ids = set()

    for rule in RULES:
        patterns = rule["patterns"].get(language, [])
        if not patterns:
            continue

        matched_lines = []
        for pattern in patterns:
            for line_no, line in enumerate(lines, start=1):
                if re.search(pattern, line, re.IGNORECASE):
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

    # Sort by severity
    issues.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 99))

    score = max(0, 100 - total_deduction)

    return {
        "score": score,
        "issues": issues,
        "issues_count": len(issues),
        "total_deduction": total_deduction,
        "language": language,
    }
