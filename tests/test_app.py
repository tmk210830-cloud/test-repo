import base64
import hashlib
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import app


class RegisterUserTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "users.db"
        self.db_patch = patch.object(app, "DATABASE_PATH", self.db_path)
        self.db_patch.start()

    def tearDown(self):
        self.db_patch.stop()
        self.temp_dir.cleanup()

    def test_register_user_creates_database_and_returns_id(self):
        user_id = app.register_user(
            " alice ",
            " Alice@Example.COM ",
            "correct horse battery staple",
        )

        self.assertEqual(user_id, 1)
        self.assertTrue(self.db_path.exists())
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT username, email, password_hash, created_at FROM users"
            ).fetchone()

        self.assertEqual(row[0], "alice")
        self.assertEqual(row[1], "alice@example.com")
        self.assertNotIn("correct horse battery staple", row[2])
        self.assertIsNotNone(row[3])

    def test_stored_password_hash_can_be_recomputed(self):
        password = "correct horse battery staple"
        user_id = app.register_user("alice", "alice@example.com", password)
        password_hash = app.get_user(user_id)[3]
        algorithm, iterations, encoded_salt, encoded_digest = password_hash.split("$")

        actual_digest = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            base64.b64decode(encoded_salt),
            int(iterations),
            dklen=32,
        )

        self.assertEqual(algorithm, "pbkdf2_sha256")
        self.assertEqual(int(iterations), app.PBKDF2_ITERATIONS)
        self.assertEqual(actual_digest, base64.b64decode(encoded_digest))

    def test_same_password_produces_different_hashes(self):
        password = "correct horse battery staple"
        first_id = app.register_user("alice", "alice@example.com", password)
        second_id = app.register_user("bob", "bob@example.com", password)

        self.assertNotEqual(app.get_user(first_id)[3], app.get_user(second_id)[3])

    def test_duplicate_username_is_rejected_case_insensitively(self):
        app.register_user("Alice", "first@example.com", "long enough password")

        with self.assertRaisesRegex(ValueError, "already exists"):
            app.register_user("alice", "second@example.com", "long enough password")

    def test_duplicate_email_is_rejected_case_insensitively(self):
        app.register_user("alice", "User@Example.com", "long enough password")

        with self.assertRaisesRegex(ValueError, "already exists"):
            app.register_user("bob", "user@example.COM", "long enough password")

    def test_invalid_values_are_rejected_without_creating_database(self):
        invalid_registrations = [
            ("ab", "user@example.com", "long enough password"),
            ("invalid user", "user@example.com", "long enough password"),
            ("alice", "not-an-email", "long enough password"),
            ("alice", "user@example.com", "short"),
            (None, "user@example.com", "long enough password"),
        ]

        for values in invalid_registrations:
            with self.subTest(values=values):
                with self.assertRaises(ValueError):
                    app.register_user(*values)

        self.assertFalse(self.db_path.exists())

    def test_sql_input_does_not_change_the_schema(self):
        app.register_user(
            "alice",
            "quote'@example.com",
            "correct horse battery staple",
        )

        with sqlite3.connect(self.db_path) as conn:
            count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]

        self.assertEqual(count, 1)


class ExistingFunctionTests(unittest.TestCase):
    def test_calculate_total(self):
        items = [{"price": 100, "qty": 2}, {"price": 50, "qty": 3}]
        self.assertEqual(app.calculate_total(items), 350)

    def test_calculate_total_for_empty_list(self):
        self.assertEqual(app.calculate_total([]), 0)


if __name__ == "__main__":
    unittest.main()
