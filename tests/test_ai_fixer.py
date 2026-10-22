import unittest
from ai_fixer import get_offline_fix, OFFLINE_FIXES
from scanner import scan_code


class TestAiFixerAndFallbacks(unittest.TestCase):
    """Unit tests for offline fallback templates and repairs."""

    def test_all_fallback_templates_exist(self):
        expected_keys = ["php_sqli_xss", "python_secrets_eval", "javascript_xss_token", "python_secure"]
        for key in expected_keys:
            self.assertIn(key, OFFLINE_FIXES)
            self.assertTrue(len(OFFLINE_FIXES[key]["code"]) > 50)
            self.assertTrue(len(OFFLINE_FIXES[key]["explanation"]) > 50)

    def test_python_secrets_eval_does_not_use_bcrypt(self):
        code = OFFLINE_FIXES["python_secrets_eval"]["code"]
        self.assertNotIn("import bcrypt", code)
        self.assertIn("werkzeug.security", code)

    def test_offline_fixes_scan_cleanly_with_zero_vulnerabilities(self):
        # Python secure
        res_py = scan_code(OFFLINE_FIXES["python_secure"]["code"], "python")
        self.assertEqual(res_py["score"], 100, f"Python secure template scored {res_py['score']} instead of 100")
        self.assertEqual(res_py["issues_count"], 0)

        # Python secrets eval
        res_py_eval = scan_code(OFFLINE_FIXES["python_secrets_eval"]["code"], "python")
        self.assertEqual(res_py_eval["score"], 100, f"Python secrets eval template scored {res_py_eval['score']}")
        self.assertEqual(res_py_eval["issues_count"], 0)

        # PHP PDO
        res_php = scan_code(OFFLINE_FIXES["php_sqli_xss"]["code"], "php")
        self.assertEqual(res_php["score"], 100, f"PHP template scored {res_php['score']}")
        self.assertEqual(res_php["issues_count"], 0)

        # JS safe DOM
        res_js = scan_code(OFFLINE_FIXES["javascript_xss_token"]["code"], "javascript")
        self.assertEqual(res_js["score"], 100, f"JS template scored {res_js['score']}")
        self.assertEqual(res_js["issues_count"], 0)

    def test_get_offline_fix_dispatcher(self):
        # PHP dispatch
        res_php = get_offline_fix("some code", "php", [])
        self.assertEqual(res_php["source"], "offline")
        self.assertIn("PDO", res_php["fixed_code"])

        # JS dispatch
        res_js = get_offline_fix("some code", "javascript", [])
        self.assertEqual(res_js["source"], "offline")
        self.assertIn("textContent", res_js["fixed_code"])

        # Python with dangerous function issue
        res_py = get_offline_fix("some code", "python", [{"id": "dangerous_functions"}])
        self.assertEqual(res_py["source"], "offline")
        self.assertIn("safe_evaluate", res_py["fixed_code"])


if __name__ == "__main__":
    unittest.main()
