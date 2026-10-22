import unittest
from scanner import scan_code, RULES, COMPILED_RULES


class TestScannerRules(unittest.TestCase):
    """Unit tests for CodeShield AI security scanner."""

    def test_empty_code_handling(self):
        result = scan_code("", "python")
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["issues_count"], 0)

        result_whitespace = scan_code("   \n\t  ", "python")
        self.assertEqual(result_whitespace["score"], 0)

    def test_sql_injection_detection_php(self):
        code = '$res = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $_GET["id"]);'
        result = scan_code(code, "php")
        issue_ids = [i["id"] for i in result["issues"]]
        self.assertIn("sql_injection", issue_ids)
        self.assertLess(result["score"], 100)

    def test_sql_injection_detection_python(self):
        code = 'cursor.execute(f"SELECT * FROM users WHERE username = \'{user}\'")'
        result = scan_code(code, "python")
        issue_ids = [i["id"] for i in result["issues"]]
        self.assertIn("sql_injection", issue_ids)
        self.assertLess(result["score"], 100)

    def test_sql_injection_detection_javascript(self):
        code = 'db.query(`SELECT * FROM accounts WHERE id = ${accountId}`);'
        result = scan_code(code, "javascript")
        issue_ids = [i["id"] for i in result["issues"]]
        self.assertIn("sql_injection", issue_ids)
        self.assertLess(result["score"], 100)

    def test_xss_detection_php_with_and_without_space(self):
        # Traditional with space
        code_with_space = 'echo $_GET["name"];'
        res1 = scan_code(code_with_space, "php")
        self.assertIn("xss", [i["id"] for i in res1["issues"]])

        # Compact syntax without space (reproduced and verified AI-AN-001)
        code_without_space = 'echo($_GET["name"]);'
        res2 = scan_code(code_without_space, "php")
        self.assertIn("xss", [i["id"] for i in res2["issues"]])

        # Short tag
        code_short_tag = '<?=$row["name"] . $_GET["q"]?>'
        res3 = scan_code(code_short_tag, "php")
        self.assertIn("xss", [i["id"] for i in res3["issues"]])

    def test_hardcoded_secrets_detection(self):
        code = 'api_key = "AIzaSyD-example123456789"\npassword = "supersecretpassword123"'
        result = scan_code(code, "python")
        issue_ids = [i["id"] for i in result["issues"]]
        self.assertIn("hardcoded_secrets", issue_ids)

    def test_dangerous_functions_eval_exec(self):
        code_python = 'user_expr = request.args.get("e")\nres = eval(user_expr)'
        res_py = scan_code(code_python, "python")
        self.assertIn("dangerous_functions", [i["id"] for i in res_py["issues"]])

        code_js = 'const result = eval(userRawInput);'
        res_js = scan_code(code_js, "javascript")
        self.assertIn("dangerous_functions", [i["id"] for i in res_js["issues"]])

    def test_weak_crypto_md5_sha1(self):
        code_py = 'import hashlib\nh = hashlib.md5(pwd.encode()).hexdigest()'
        res_py = scan_code(code_py, "python")
        self.assertIn("weak_crypto", [i["id"] for i in res_py["issues"]])

        code_php = 'if (md5($password) == $db_pass) { echo "ok"; }'
        res_php = scan_code(code_php, "php")
        self.assertIn("weak_crypto", [i["id"] for i in res_php["issues"]])

    def test_debug_mode_detection(self):
        code = 'app.run(debug=True, host="0.0.0.0")'
        result = scan_code(code, "python")
        self.assertIn("debug_mode", [i["id"] for i in result["issues"]])

    def test_secure_code_achieves_perfect_score(self):
        secure_code = '''
import os
import secrets
from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

@app.route("/user/<int:user_id>")
def get_user(user_id):
    return jsonify({"id": user_id})

if __name__ == "__main__":
    app.run(debug=False)
'''
        result = scan_code(secure_code, "python")
        self.assertEqual(result["score"], 100)
        self.assertEqual(result["issues_count"], 0)

    def test_precompiled_rules_loaded(self):
        self.assertGreater(len(COMPILED_RULES), 0)
        for r_id, lang_dict in COMPILED_RULES.items():
            self.assertIn("python", lang_dict)


if __name__ == "__main__":
    unittest.main()
