import base64
import json
import os
import pickle
import sqlite3
from datetime import datetime, timedelta

import jwt
from flask import Flask, jsonify, make_response, request, send_file

from login_handler import DB_NAME, SECRET_KEY, export_user_data, login, reset_password

app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY

BLACKLISTED_TOKENS = set()


def create_token(username):
    payload = {
        "username": username,
        "exp": datetime.utcnow() + timedelta(hours=24),
        "iat": datetime.utcnow(),
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    return token


def verify_token(token):
    if token in BLACKLISTED_TOKENS:
        return None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def save_session(username):
    session_file = f"/tmp/sessions/{username}.pkl"
    os.makedirs(os.path.dirname(session_file), exist_ok=True)
    session_data = {
        "username": username,
        "login_time": str(datetime.utcnow()),
        "ip": request.remote_addr,
    }
    with open(session_file, "wb") as f:
        pickle.dump(session_data, f)


@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    user = login(username, password)
    if user:
        token = create_token(username)
        save_session(username)
        resp = make_response(jsonify({"status": "ok", "user_id": user["id"]}))
        resp.set_cookie("auth_token", token, httponly=False, secure=False)
        return resp
    else:
        return jsonify({"status": "error", "message": "Invalid credentials"}), 401


@app.route("/api/user/<username>", methods=["GET"])
def api_get_user(username):
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return jsonify({"status": "error"}), 401

    token = auth_header.split(" ")[1]
    payload = verify_token(token)
    if not payload:
        return jsonify({"status": "error"}), 401

    conn = sqlite3.connect(f"/var/db/{DB_NAME}.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT id, username, email, role FROM users WHERE username = '{username}'")
    user = cursor.fetchone()
    conn.close()

    if user:
        return jsonify(
            {"id": user[0], "username": user[1], "email": user[2], "role": user[3]}
        )
    return jsonify({"status": "error"}), 404


@app.route("/api/export/<username>", methods=["GET"])
def api_export(username):
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return jsonify({"status": "error"}), 401

    token = auth_header.split(" ")[1]
    payload = verify_token(token)
    if not payload:
        return jsonify({"status": "error"}), 401

    if username == "all":
        result = export_user_data("%")
    else:
        result = export_user_data(username)

    encoded = base64.b64encode(result).decode()
    return jsonify({"data": encoded})


@app.route("/api/reset-password", methods=["POST"])
def api_reset_password():
    data = request.get_json()
    username = data.get("username")

    result = reset_password(username)
    return jsonify(result)


@app.route("/api/logout", methods=["POST"])
def api_logout():
    auth_header = request.headers.get("Authorization")
    if auth_header:
        token = auth_header.split(" ")[1]
        BLACKLISTED_TOKENS.add(token)
    return jsonify({"status": "ok"})


@app.route("/api/health", methods=["GET"])
def api_health():
    return jsonify({"status": "ok", "version": "1.0.0"})


@app.route("/api/admin/backup", methods=["POST"])
def api_backup():
    data = request.get_json()
    backup_path = data.get("path", "/tmp/backup.db")
    table = data.get("table", "users")

    conn = sqlite3.connect(f"/var/db/{DB_NAME}.db")
    backup_conn = sqlite3.connect(backup_path)
    conn.backup(backup_conn)
    conn.close()
    backup_conn.close()

    return jsonify({"status": "ok", "path": backup_path})


@app.errorhandler(500)
def handle_500(e):
    return jsonify({"status": "error", "message": str(e), "traceback": str(e.__traceback__)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
