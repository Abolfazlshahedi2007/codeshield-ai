# 🛡️ سپر کد — CodeShield AI

> **سامانه هوشمند تحلیل امنیت و بازبینی کد**  
> پروژه مسابقه دانشگاهی | Hybrid Code Security & Quality Auditor

---

## ✨ ویژگی‌ها

| ویژگی | توضیح |
|---|---|
| 🔍 **اسکن آفلاین** | تحلیل فوری کد بدون نیاز به اینترنت با موتور Regex/AST |
| 🤖 **اصلاح هوشمند AI** | بازنویسی خودکار کد آسیب‌پذیر با Gemini API |
| 🌙 **Dark/Light Mode** | تم تاریک سایبری + تم روشن |
| 📊 **امتیاز امنیتی** | نمودار دایره‌ای ۰ تا ۱۰۰ با رنگ‌بندی |
| 🐘🐍⚡ **سه زبان** | PHP، Python، JavaScript |
| 📋 **تاریخچه اسکن** | ذخیره‌سازی تمام اسکن‌ها در SQLite |
| ⚡ **ورود داور** | یک‌کلیکی برای ارزیابان مسابقه |

---

## 🚀 نصب و راه‌اندازی

```bash
# ۱. کلون پروژه
git clone https://github.com/Abolfazlshahedi2007/codeshield-ai.git
cd codeshield-ai

# ۲. نصب وابستگی‌ها
pip install -r requirements.txt

# ۳. اجرای سرور
python app.py
```

سپس مرورگر را روی **http://127.0.0.1:5000** باز کنید.

---

## 🔒 آسیب‌پذیری‌های قابل شناسایی

| نوع | شدت | کسر امتیاز |
|---|---|---|
| SQL Injection | 🔴 بحرانی | ۳۵ |
| Cross-Site Scripting (XSS) | 🟠 بالا | ۲۵ |
| Hardcoded Secrets | 🟠 بالا | ۲۵ |
| Dangerous Functions (eval/exec) | 🔴 بحرانی | ۳۵ |
| Weak Cryptography (MD5/SHA1) | 🟡 متوسط | ۱۵ |
| Debug Mode On | 🔵 پایین | ۱۰ |

---

## ⚙️ تنظیم Gemini API (اختیاری)

در داشبورد روی آیکن ⚙️ کلیک کنید و کلید API خود را وارد کنید.  
بدون کلید API، از حالت **آفلاین** با نمونه‌های آماده استفاده می‌شود.

---

## 🛠️ تکنولوژی‌ها

- **Backend:** Python + Flask + SQLAlchemy
- **Database:** SQLite
- **Frontend:** HTML5 + CSS3 + Vanilla JS + TailwindCSS
- **Editor:** CodeMirror 5
- **Charts:** Chart.js
- **AI:** Google Gemini API
- **Font:** Vazirmatn (فارسی RTL)

---

## 👤 ورود داور

در صفحه ورود روی دکمه قرمز **«ورود به عنوان داور»** کلیک کنید.

---

*ساخته شده با ❤️ برای مسابقه دانشگاهی*
