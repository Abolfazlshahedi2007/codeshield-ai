import unittest
import json
from app import app, db, User, Scan


class TestApiAndSecurityRoutes(unittest.TestCase):
    """Integration & security tests for Flask routes."""

    @classmethod
    def setUpClass(cls):
        app.config.update(
            TESTING=True,
            SQLALCHEMY_DATABASE_URI="sqlite:///:memory:",
            WTF_CSRF_ENABLED=False
        )
        with app.app_context():
            db.create_all()
            demo = User.query.filter_by(username="داور").first()
            if not demo:
                demo = User(username="داور", email="judge@demo.local", is_demo=True)
                demo.set_password("demo1234")
                db.session.add(demo)
                db.session.commit()

    def setUp(self):
        self.client = app.test_client()
        # Login demo judge user
        with self.client.session_transaction() as sess:
            with app.app_context():
                user = User.query.filter_by(username="داور").first()
                sess["_user_id"] = str(user.id)
                sess["_fresh"] = True

    def test_dashboard_access_authenticated(self):
        resp = self.client.get("/dashboard")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("سپر کد".encode("utf-8"), resp.data)

    def test_api_scan_success(self):
        payload = {
            "code": "import os\neval(input())",
            "language": "python"
        }
        resp = self.client.post("/api/scan", json=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("score", data)
        self.assertIn("issues", data)
        self.assertLess(data["score"], 100)

    def test_api_scan_payload_too_large(self):
        huge_code = "a = 1\n" * 50_000  # > 100KB
        resp = self.client.post("/api/scan", json={"code": huge_code, "language": "python"})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("حجم کد ارسالی بیش از حد مجاز است", resp.get_json().get("error", ""))

    def test_api_ai_fix_offline_mode_returns_verification(self):
        payload = {
            "code": "query = 'SELECT * FROM users WHERE id = ' + uid",
            "language": "python",
            "issues": [{"id": "sql_injection"}],
            "mode": "offline"
        }
        resp = self.client.post("/api/ai-fix", json=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["source"], "offline")
        self.assertEqual(data["verified_score"], 100)
        self.assertEqual(data["verified_issues_count"], 0)

    def test_api_fetch_github_ssrf_protection(self):
        # 1. Attempt to scan local server / loopback
        resp_local = self.client.post("/api/fetch-github", json={"url": "http://127.0.0.1:5000/dashboard"})
        self.assertEqual(resp_local.status_code, 400)
        self.assertIn("فقط دریافت فایل از دامنه‌های رسمی گیت‌هاب مجاز است", resp_local.get_json().get("error", ""))

        # 2. Attempt to reach internal metadata endpoint
        resp_meta = self.client.post("/api/fetch-github", json={"url": "http://169.254.169.254/latest/meta-data"})
        self.assertEqual(resp_meta.status_code, 400)

        # 3. Attempt arbitrary external non-github site
        resp_ext = self.client.post("/api/fetch-github", json={"url": "https://example.com/malicious.py"})
        self.assertEqual(resp_ext.status_code, 400)

        # 4. Empty URL
        resp_empty = self.client.post("/api/fetch-github", json={"url": ""})
        self.assertEqual(resp_empty.status_code, 400)

    def test_history_endpoint_limits(self):
        resp = self.client.get("/history")
        self.assertEqual(resp.status_code, 200)


if __name__ == "__main__":
    unittest.main()
