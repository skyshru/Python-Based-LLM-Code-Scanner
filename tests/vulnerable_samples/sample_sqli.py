"""Intentionally vulnerable sample: SQL injection and command injection.

This file exists only as scanner test input. Do not use any of this code.
"""

import os
import sqlite3
import subprocess

from flask import Flask, request

app = Flask(__name__)


def get_user_by_name(username):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # CWE-89: user input concatenated straight into the SQL statement.
    query = "SELECT id, email, role FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchall()


@app.route("/search")
def search_orders():
    term = request.args.get("q", "")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # CWE-89: f-string interpolation into SQL.
    cursor.execute(f"SELECT * FROM orders WHERE description LIKE '%{term}%'")
    return {"results": cursor.fetchall()}


@app.route("/ping")
def ping_host():
    host = request.args.get("host", "127.0.0.1")
    # CWE-78: shell=True with unsanitized user input.
    output = subprocess.check_output(f"ping -c 1 {host}", shell=True)
    return output.decode()


@app.route("/download")
def download_file():
    name = request.args.get("name", "")
    # CWE-22: path traversal, no normalization or allowlist.
    with open(os.path.join("/var/app/uploads", name)) as handle:
        return handle.read()


if __name__ == "__main__":
    # CWE-489: debug mode exposes the Werkzeug console in production.
    app.run(host="0.0.0.0", debug=True)
