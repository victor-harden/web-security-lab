import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import app as lab


class LabTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        lab.DB_PATH = Path(self.tmp.name) / "lab.db"
        lab.init_db()
        lab.app.config.update(TESTING=True, SECRET_KEY="test")
        self.client = lab.app.test_client()

    def tearDown(self):
        self.tmp.cleanup()

    # ---- vulnerable endpoints: the flaws are documented by tests
    def test_vuln_login_is_bypassable_with_sql_injection(self):
        resp = self.client.post("/vuln/login", data={"username": "' OR 1=1 --", "password": "x"})
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"logged in as alice", resp.data)

    def test_vuln_search_reflects_markup(self):
        resp = self.client.get("/vuln/search?q=<script>alert(1)</script>")
        self.assertIn(b"<script>alert(1)</script>", resp.data)

    def test_vuln_profile_exposes_other_users(self):
        resp = self.client.get("/vuln/profile/1")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["username"], "alice")

    # ---- hardened endpoints: same payloads are rejected
    def test_safe_login_rejects_sql_injection(self):
        resp = self.client.post("/safe/login", data={"username": "' OR 1=1 --", "password": "x"})
        self.assertEqual(resp.status_code, 401)
        self.assertIn(b"invalid credentials", resp.data)

    def test_safe_login_accepts_valid_credentials(self):
        resp = self.client.post(
            "/safe/login", data={"username": "alice", "password": "alice-password"}
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"logged in as alice", resp.data)

    def test_safe_search_escapes_markup(self):
        resp = self.client.get("/safe/search?q=<script>alert(1)</script>")
        self.assertNotIn(b"<script>", resp.data)
        self.assertIn(b"&lt;script&gt;", resp.data)

    def test_safe_profile_requires_authentication(self):
        self.assertEqual(self.client.get("/safe/profile/1").status_code, 401)

    def test_safe_profile_blocks_other_users(self):
        with self.client.session_transaction() as sess:
            sess["uid"] = 2
        resp = self.client.get("/safe/profile/1")
        self.assertEqual(resp.status_code, 403)

    def test_safe_profile_allows_owner(self):
        with self.client.session_transaction() as sess:
            sess["uid"] = 1
        resp = self.client.get("/safe/profile/1")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["username"], "alice")


if __name__ == "__main__":
    unittest.main()
