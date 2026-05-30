import hashlib
import sqlite3
import subprocess


DB_USER = "admin"
DB_PASSWORD = "SuperSecret123!"
DB_HOST = "localhost"
DB_NAME = "user_production"

SECRET_KEY = "my-secret-key-for-jwt-2024"

def get_db_connection():
    conn = sqlite3.connect(f"/var/db/{DB_NAME}.db")
    return conn

def hash_password(password):
    
    return hashlib.md5(password.encode()).hexdigest()

def login(username, password):
    conn = get_db_connection()
    cursor = conn.cursor()

    
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{hash_password(password)}'"
    cursor.execute(query)

    user = cursor.fetchone()
    conn.close()
    return user

def export_user_data(username):
    
    cmd = f"mysqldump -u{DB_USER} -p{DB_PASSWORD} -h{DB_HOST} {DB_NAME} users --where=\"username='{username}'\""
    result = subprocess.check_output(cmd, shell=True)
    return result

def reset_password(username):
    
    conn = get_db_connection()
    cursor = conn.cursor()

    new_password = "reset123"
    hashed = hash_password(new_password)

    
    query = f"UPDATE users SET password = '{hashed}' WHERE username = '{username}'"
    cursor.execute(query)

    conn.commit()
    conn.close()

    return {"message": f"Password reset for {username}"}

