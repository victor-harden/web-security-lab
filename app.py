"""Intentionally vulnerable Flask lab for authorized, local practice.

Never deploy this application. Bind to 127.0.0.1 only.
"""
from __future__ import annotations

import hashlib
import os
import sqlite3
from pathlib import Path

from flask import Flask, jsonify, render_template_string, request, session

DB_PATH = Path(__file__).with_name("lab.db")
app = Flask(__name__)
app.secret_key = os.environ.get("LAB_SECRET", "dev-only-change-me")


def sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = get_db()
    conn.executescript(
        """
        DROP TABLE IF EXISTS users;
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_sha256 TEXT NOT NULL,
            role TEXT NOT NULL
        );
        """
    )
    conn.executemany(
        "INSERT INTO users (username, password_sha256, role) VALUES (?, ?, ?)",
        [
            ("alice", sha256("alice-password"), "admin"),
            ("bob", sha256("bob-password"), "user"),
        ],
    )
    conn.commit()
    conn.close()


@app.get("/")
def index():
    return (
        "web-security-lab\n\n"
        "vulnerable: /vuln/login /vuln/search /vuln/profile/<id>\n"
        "hardened:   /safe/login /safe/search /safe/profile/<id>\n"
    )


# ---------------------------------------------------------------- vulnerable
@app.post("/vuln/login")
def vuln_login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    conn = get_db()
    # VULNERABLE ON PURPOSE: user input interpolated into SQL.
    query = (
        "SELECT id, username, role FROM users "
        f"WHERE username = '{username}' AND password_sha256 = '{sha256(password)}'"
    )
    row = conn.execute(query).fetchone()
    conn.close()
    if row is None:
        return "invalid credentials", 401
    return f"logged in as {row['username']} ({row['role']})"


@app.get("/vuln/search")
def vuln_search():
    term = request.args.get("q", "")
    # VULNERABLE ON PURPOSE: reflected input without escaping.
    return render_template_string("<h1>Results for " + term + "</h1>")


@app.get("/vuln/profile/<int:user_id>")
def vuln_profile(user_id: int):
    conn = get_db()
    row = conn.execute(
        "SELECT id, username, role FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    conn.close()
    # VULNERABLE ON PURPOSE: no ownership check (IDOR).
    if row is None:
        return jsonify({"error": "not found"}), 404
    return jsonify(dict(row))


# ---------------------------------------------------------------- hardened
@app.post("/safe/login")
def safe_login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    conn = get_db()
    row = conn.execute(
        "SELECT id, username, role FROM users WHERE username = ? AND password_sha256 = ?",
        (username, sha256(password)),
    ).fetchone()
    conn.close()
    if row is None:
        return "invalid credentials", 401
    session["uid"] = row["id"]
    return f"logged in as {row['username']} ({row['role']})"


@app.get("/safe/search")
def safe_search():
    term = request.args.get("q", "")
    # Escaped by the template engine.
    return render_template_string("<h1>Results for {{ q }}</h1>", q=term)


@app.get("/safe/profile/<int:user_id>")
def safe_profile(user_id: int):
    if "uid" not in session:
        return jsonify({"error": "authentication required"}), 401
    if session["uid"] != user_id:
        return jsonify({"error": "forbidden"}), 403
    conn = get_db()
    row = conn.execute(
        "SELECT id, username, role FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    conn.close()
    if row is None:
        return jsonify({"error": "not found"}), 404
    return jsonify(dict(row))


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=False)
