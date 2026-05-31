import os
import secrets
import shlex
import sqlite3
import string
import subprocess

import bcrypt

# 从环境变量读取敏感配置，避免硬编码
DB_USER = os.environ.get("DB_USER", "admin")
DB_PASSWORD = os.environ.get("DB_PASSWORD")
if not DB_PASSWORD:
    raise ValueError("DB_PASSWORD environment variable not set")
DB_HOST = os.environ.get("DB_HOST", "localhost")
DB_NAME = os.environ.get("DB_NAME", "user_production")

# JWT 密钥从环境变量读取，避免硬编码
SECRET_KEY = os.environ.get("JWT_SECRET_KEY")
if not SECRET_KEY:
    raise ValueError("JWT_SECRET_KEY environment variable not set")


def get_db_connection():
    conn = sqlite3.connect(f"/var/db/{DB_NAME}.db")
    conn.row_factory = sqlite3.Row
    return conn


def hash_password(password):
    """使用 bcrypt 哈希密码，自动生成盐值"""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password, hashed):
    """验证密码与哈希是否匹配"""
    return bcrypt.checkpw(password.encode(), hashed.encode())


def login(username, password):
    # 参数校验
    if not username or not password:
        return None
    if not isinstance(username, str) or not isinstance(password, str):
        return None
    if len(username) > 100 or len(password) > 100:
        return None

    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        # 使用参数化查询防止 SQL 注入
        query = "SELECT * FROM users WHERE username = ? AND password = ?"
        cursor.execute(query, (username, hash_password(password)))
        user = cursor.fetchone()
        if user:
            user_dict = dict(user)
        else:
            user_dict = None
    finally:
        conn.close()

    return user_dict


def export_user_data(username):
    # 参数校验
    if not username:
        raise ValueError("Username must not be empty")
    if not isinstance(username, str):
        raise TypeError("Username must be a string")
    if len(username) > 100:
        raise ValueError("Username must be at most 100 characters")

    # 使用参数化方式调用 mysqldump，避免 shell 注入
    cmd = [
        "mysqldump",
        f"-u{DB_USER}",
        f"-p{DB_PASSWORD}",
        f"-h{DB_HOST}",
        DB_NAME,
        "users",
        f"--where=username='{shlex.quote(username)}'",
    ]
    result = subprocess.check_output(cmd, shell=False)
    return result


def reset_password(username):
    # 参数校验
    if not username:
        raise ValueError("Username must not be empty")
    if not isinstance(username, str):
        raise TypeError("Username must be a string")
    if len(username) > 100:
        raise ValueError("Username must be at most 100 characters")

    conn = get_db_connection()
    try:
        cursor = conn.cursor()

        # 生成随机强密码，替代硬编码弱密码
        new_password = ''.join(
            secrets.choice(string.ascii_letters + string.digits + string.punctuation)
            for _ in range(16)
        )
        hashed = hash_password(new_password)

        # 使用参数化查询防止 SQL 注入
        query = "UPDATE users SET password = ? WHERE username = ?"
        cursor.execute(query, (hashed, username))

        conn.commit()
    finally:
        conn.close()

    return {"message": f"Password reset for {username}", "new_password": new_password}
