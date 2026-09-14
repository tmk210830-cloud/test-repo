"""ユーザー管理と金額計算のサンプル機能。"""
"""2026-09-15 feature/test"""
import base64
import hashlib
import re
import secrets
import sqlite3


DATABASE_PATH = "users.db"
PBKDF2_ITERATIONS = 600_000
_USERNAME_PATTERN = re.compile(r"[A-Za-z0-9_.-]{3,50}")
_EMAIL_PATTERN = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")


def _initialize_database(conn):
    """ユーザー登録に必要なテーブルを作成する。"""
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL COLLATE NOCASE UNIQUE,
            email TEXT NOT NULL COLLATE NOCASE UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )


def _validate_registration(username, email, password):
    """登録値を検証し、保存用に正規化した値を返す。"""
    if not isinstance(username, str):
        raise ValueError("username must be a string")
    normalized_username = username.strip()
    if _USERNAME_PATTERN.fullmatch(normalized_username) is None:
        raise ValueError(
            "username must be 3 to 50 characters and contain only "
            "letters, numbers, underscores, periods, or hyphens"
        )

    if not isinstance(email, str):
        raise ValueError("email must be a string")
    normalized_email = email.strip().lower()
    if len(normalized_email) > 254 or _EMAIL_PATTERN.fullmatch(normalized_email) is None:
        raise ValueError("email must be a valid email address")

    if not isinstance(password, str):
        raise ValueError("password must be a string")
    if not 12 <= len(password) <= 1024:
        raise ValueError("password must be between 12 and 1024 characters")

    return normalized_username, normalized_email, password


def _hash_password(password):
    """パスワードをsalt付きPBKDF2-SHA256ハッシュへ変換する。"""
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
        dklen=32,
    )
    encoded_salt = base64.b64encode(salt).decode("ascii")
    encoded_digest = base64.b64encode(digest).decode("ascii")
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${encoded_salt}${encoded_digest}"


def register_user(username, email, password):
    """ユーザーを検証・登録し、新しく割り当てられたIDを返す。"""
    username, email, password = _validate_registration(username, email, password)
    password_hash = _hash_password(password)

    try:
        with sqlite3.connect(DATABASE_PATH) as conn:
            _initialize_database(conn)
            cursor = conn.execute(
                """
                INSERT INTO users (username, email, password_hash)
                VALUES (?, ?, ?)
                """,
                (username, email, password_hash),
            )
            return cursor.lastrowid
    except sqlite3.IntegrityError as exc:
        raise ValueError("username or email already exists") from exc


def get_user(user_id):
    """指定されたIDのユーザーを取得し、存在しなければNoneを返す。"""
    with sqlite3.connect(DATABASE_PATH) as conn:
        cursor = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        return cursor.fetchone()


def calculate_total(items):
    """商品の価格と数量から合計金額を計算する。"""
    return sum([item["price"] * item["qty"] for item in items])
