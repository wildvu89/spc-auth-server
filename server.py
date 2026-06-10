import os
import sys
import time
import sqlite3
import random
import string
import smtplib
from email.mime.text import MIMEText
from email.header import Header
from typing import Optional
from fastapi import FastAPI, HTTPException, Header as RequestHeader, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="SPC Central Auth Server")

# Enable CORS for development and cross-app communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_PATH = os.environ.get(
    "SPC_DB_PATH",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "auth.db")
)


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # Users table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        referral_code TEXT NOT NULL,
        is_admin INTEGER DEFAULT 0,
        status TEXT DEFAULT 'pending'
    )
    """)
    # Add status column if DB already exists without it
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN status TEXT DEFAULT 'pending'")
    except Exception:
        pass
        
    # Add expiry_date column if DB already exists without it
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN expiry_date REAL DEFAULT NULL")
    except Exception:
        pass
        
    # Devices table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        uuid TEXT NOT NULL,
        cpu TEXT,
        ram TEXT,
        ip TEXT,
        last_login REAL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)
    conn.commit()

    # Seed default admin if table empty or no admin
    cursor.execute("SELECT COUNT(*) FROM users WHERE username = 'admin'")
    if cursor.fetchone()[0] == 0:
        cursor.execute("""
        INSERT INTO users (name, email, username, password, referral_code, is_admin, status)
        VALUES ('Administrator', 'admin@spc.com', 'admin', 'spcadmin123', 'ADMIN', 1, 'active')
        """)
        conn.commit()
        print("[*] Seeded default admin account (username: admin, password: spcadmin123)")
    else:
        cursor.execute("UPDATE users SET status = 'active' WHERE username = 'admin'")
        conn.commit()
    conn.close()

init_db()

# ── Keep-alive: ping self every 14 min so Render free tier never sleeps ──
import threading
import urllib.request as _urllib_req

def _keep_alive():
    import time
    port = os.environ.get("PORT", "8000")
    url  = f"http://0.0.0.0:{port}/health"
    # Also ping the public URL if available
    public_url = os.environ.get("RENDER_EXTERNAL_URL", "")
    while True:
        time.sleep(14 * 60)   # 14 minutes
        for target in ([url] + ([public_url + "/health"] if public_url else [])):
            try:
                _urllib_req.urlopen(target, timeout=10)
            except Exception:
                pass

threading.Thread(target=_keep_alive, daemon=True).start()


class RegisterRequest(BaseModel):
    name: str
    email: str
    username: str
    password: str
    referral_code: str

class LoginRequest(BaseModel):
    username: str
    password: str
    uuid: str
    cpu: str
    ram: str
    ip: str

class ForgotPasswordRequest(BaseModel):
    identity: str

class ResetDeviceRequest(BaseModel):
    admin_user: str
    admin_pass: str
    target_username: str

class DeleteUserRequest(BaseModel):
    admin_user: str
    admin_pass: str
    target_username: str

class ActivateUserRequest(BaseModel):
    admin_user: str
    admin_pass: str
    target_username: str
    status: str

class SetExpiryRequest(BaseModel):
    admin_user: str
    admin_pass: str
    target_username: str
    duration_days: int

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def send_password_reset_email(to_email: str, new_password: str) -> bool:
    subject = "Team SPC - Cấp lại mật khẩu"
    body = f"""Team SPC Xin chào!
Mật khẩu mới của bạn là: {new_password}
Vui lòng không chia sẻ để bảo mật dữ liệu cá nhân"""

    smtp_email = os.environ.get("SMTP_EMAIL", "")
    smtp_pwd = os.environ.get("SMTP_PASSWORD", "")
    smtp_server = os.environ.get("SMTP_SERVER", "smtp.gmail.com")
    smtp_port_str = os.environ.get("SMTP_PORT", "587")
    try:
        smtp_port = int(smtp_port_str)
    except ValueError:
        smtp_port = 587

    # Log file fallback
    log_dir = os.path.dirname(__file__) if os.path.dirname(__file__) else "."
    log_path = os.path.join(log_dir, "email_log.txt")
    
    if not smtp_email or not smtp_pwd:
        print("[!] SMTP not configured. Writing to local email log instead.")
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(f"\n--- MAIL SENT: {time.strftime('%Y-%m-%d %H:%M:%S')} to {to_email} ---\n{body}\n---------------------------------------\n")
        return True

    try:
        msg = MIMEText(body, 'plain', 'utf-8')
        msg['Subject'] = Header(subject, 'utf-8')
        msg['From'] = smtp_email
        msg['To'] = to_email

        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(smtp_email, smtp_pwd)
        server.sendmail(smtp_email, [to_email], msg.as_string())
        server.quit()
        return True
    except Exception as e:
        print(f"[-] SMTP failed to send mail: {e}. Writing to fallback log.")
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(f"\n--- MAIL FAILED SMTP: {time.strftime('%Y-%m-%d %H:%M:%S')} to {to_email} ---\n{body}\n---------------------------------------\n")
        return False

@app.get("/health")
def health_check():
    return {"status": "ok"}

@app.post("/api/auth/register")

def register(req: RegisterRequest):
    username = req.username.strip().lower()
    email = req.email.strip().lower()
    name = req.name.strip()
    referral_code = req.referral_code.strip()

    if not username or not email or not name or not req.password or not referral_code:
        raise HTTPException(status_code=400, detail="Vui lòng điền đầy đủ tất cả thông tin.")

    # Referral code validation: must be uppercase (no spaces, len >= 3)
    if not referral_code.isupper() or len(referral_code) < 3 or " " in referral_code:
        raise HTTPException(status_code=400, detail="Mã giới thiệu không hợp lệ. Mã giới thiệu phải viết hoa (Ví dụ: NGOCTHANG) và không có khoảng trắng.")

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Check if username exists
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            raise HTTPException(status_code=400, detail="Tên đăng nhập đã tồn tại trong hệ thống.")

        # Check if email exists
        cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
        if cursor.fetchone():
            raise HTTPException(status_code=400, detail="Gmail này đã được đăng ký tài khoản.")

        # Insert user
        cursor.execute("""
        INSERT INTO users (name, email, username, password, referral_code, is_admin, status)
        VALUES (?, ?, ?, ?, ?, 0, 'pending')
        """, (name, email, username, req.password, referral_code))
        conn.commit()
    finally:
        conn.close()

    return {"status": "ok", "message": "Đăng ký tài khoản thành công!"}

@app.post("/api/auth/login")
def login(req: LoginRequest):
    username = req.username.strip().lower()
    password = req.password

    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        if not user or user["password"] != password:
            raise HTTPException(status_code=401, detail="Tên đăng nhập hoặc mật khẩu không chính xác.")

        user_id = user["id"]
        is_admin = bool(user["is_admin"])
        status = user["status"] if "status" in user.keys() else "pending"

        # Non-admin users must be activated
        if not is_admin and status == 'pending':
            raise HTTPException(
                status_code=403, 
                detail="Tài khoản của bạn chưa được kích hoạt. Vui lòng liên hệ Admin hoặc người bán để kích hoạt sử dụng ứng dụng."
            )

        # Check license expiration for non-admin users
        if not is_admin:
            expiry_date = user["expiry_date"] if "expiry_date" in user.keys() else None
            if expiry_date is not None:
                if time.time() > expiry_date:
                    raise HTTPException(
                        status_code=403, 
                        detail="Tài khoản của bạn đã hết hạn sử dụng. Vui lòng liên hệ Admin hoặc người bán để gia hạn."
                    )

        # Admin bypasses device locking checks
        if is_admin:
            return {
                "status": "ok",
                "user": {
                    "username": user["username"],
                    "name": user["name"],
                    "email": user["email"],
                    "is_admin": True
                }
            }

        # Check device UUID lock
        uuid = req.uuid.strip()
        if not uuid or uuid == "UNKNOWN_UUID":
            raise HTTPException(status_code=400, detail="Không thể xác thực thông số phần cứng thiết bị này.")

        # See if device is already registered
        cursor.execute("SELECT id FROM devices WHERE user_id = ? AND uuid = ?", (user_id, uuid))
        device_row = cursor.fetchone()

        if device_row:
            # Device exists, update details
            cursor.execute("""
            UPDATE devices 
            SET cpu = ?, ram = ?, ip = ?, last_login = ? 
            WHERE user_id = ? AND uuid = ?
            """, (req.cpu, req.ram, req.ip, time.time(), user_id, uuid))
            conn.commit()
        else:
            # New device. Check device count
            cursor.execute("SELECT COUNT(*) FROM devices WHERE user_id = ?", (user_id,))
            device_count = cursor.fetchone()[0]

            if device_count >= 2:
                raise HTTPException(
                    status_code=403, 
                    detail="Tài khoản đã đăng nhập tối đa 2 thiết bị. Vui lòng liên hệ Admin của SPC để được cấp quyền hoặc reset lại thiết bị."
                )

            # Register device
            cursor.execute("""
            INSERT INTO devices (user_id, uuid, cpu, ram, ip, last_login)
            VALUES (?, ?, ?, ?, ?, ?)
            """, (user_id, uuid, req.cpu, req.ram, req.ip, time.time()))
            conn.commit()
    finally:
        conn.close()

    return {
        "status": "ok",
        "user": {
            "username": user["username"],
            "name": user["name"],
            "email": user["email"],
            "is_admin": False
        }
    }

@app.post("/api/auth/forgot_password")
def forgot_password(req: ForgotPasswordRequest):
    identity = req.identity.strip().lower()

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT id, email, username FROM users WHERE username = ? OR email = ?", (identity, identity))
        user = cursor.fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="Không tìm thấy tài khoản tương ứng với thông tin đã nhập.")

        user_id = user["id"]
        to_email = user["email"]

        # Generate random password
        chars = string.ascii_letters + string.digits
        new_password = "".join(random.choice(chars) for _ in range(8))

        # Update database
        cursor.execute("UPDATE users SET password = ? WHERE id = ?", (new_password, user_id))
        conn.commit()

        # Send email
        sent = send_password_reset_email(to_email, new_password)
        if not sent:
            raise HTTPException(status_code=500, detail="Không thể gửi email thông báo. Vui lòng thử lại sau.")
    finally:
        conn.close()

    return {"status": "ok", "message": "Mật khẩu mới đã được gửi về Gmail của bạn thành công!"}

@app.get("/api/admin/users")
def admin_list_users(admin_user: str = Query(...), admin_pass: str = Query(...)):
    # Validate admin credentials
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT id FROM users WHERE username = ? AND password = ? AND is_admin = 1", (admin_user, admin_pass))
        if not cursor.fetchone():
            raise HTTPException(status_code=401, detail="Bạn không có quyền quản trị viên.")

        # Fetch users
        cursor.execute("SELECT * FROM users")
        users = cursor.fetchall()
        
        user_list = []
        for u in users:
            # Fetch devices for this user
            cursor.execute("SELECT * FROM devices WHERE user_id = ?", (u["id"],))
            devices = cursor.fetchall()
            
            dev_list = []
            for d in devices:
                dev_list.append({
                    "uuid": d["uuid"],
                    "cpu": d["cpu"],
                    "ram": d["ram"],
                    "ip": d["ip"],
                    "last_login": d["last_login"]
                })
                
            user_list.append({
                "name": u["name"],
                "email": u["email"],
                "username": u["username"],
                "password": u["password"], # Admin can view passwords as requested
                "referral_code": u["referral_code"],
                "is_admin": bool(u["is_admin"]),
                "status": u["status"] if "status" in u.keys() else "pending",
                "expiry_date": u["expiry_date"] if "expiry_date" in u.keys() else None,
                "devices": dev_list
            })
    finally:
        conn.close()

    return user_list

@app.post("/api/admin/reset_device")
def admin_reset_device(req: ResetDeviceRequest):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Validate admin
        cursor.execute("SELECT id FROM users WHERE username = ? AND password = ? AND is_admin = 1", (req.admin_user, req.admin_pass))
        if not cursor.fetchone():
            raise HTTPException(status_code=401, detail="Bạn không có quyền quản trị viên.")

        # Get target user id
        cursor.execute("SELECT id FROM users WHERE username = ?", (req.target_username,))
        target = cursor.fetchone()
        if not target:
            raise HTTPException(status_code=404, detail="Không tìm thấy người dùng cần reset thiết bị.")

        target_id = target["id"]
        # Delete user's device mappings
        cursor.execute("DELETE FROM devices WHERE user_id = ?", (target_id,))
        conn.commit()
    finally:
        conn.close()

    return {"status": "ok", "message": f"Đã reset danh sách thiết bị của tài khoản '{req.target_username}' thành công."}

@app.post("/api/admin/delete_user")
def admin_delete_user(req: DeleteUserRequest):
    if req.target_username == "admin":
        raise HTTPException(status_code=400, detail="Không thể xóa tài khoản Admin hệ thống.")

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Validate admin
        cursor.execute("SELECT id FROM users WHERE username = ? AND password = ? AND is_admin = 1", (req.admin_user, req.admin_pass))
        if not cursor.fetchone():
            raise HTTPException(status_code=401, detail="Bạn không có quyền quản trị viên.")

        # Get target user id
        cursor.execute("SELECT id FROM users WHERE username = ?", (req.target_username,))
        target = cursor.fetchone()
        if not target:
            raise HTTPException(status_code=404, detail="Không tìm thấy người dùng cần xóa.")

        target_id = target["id"]
        # Delete devices first
        cursor.execute("DELETE FROM devices WHERE user_id = ?", (target_id,))
        # Delete user
        cursor.execute("DELETE FROM users WHERE id = ?", (target_id,))
        conn.commit()
    finally:
        conn.close()

    return {"status": "ok", "message": f"Đã xóa tài khoản '{req.target_username}' thành công."}

@app.post("/api/admin/activate_user")
def admin_activate_user(req: ActivateUserRequest):
    if req.target_username == "admin":
        raise HTTPException(status_code=400, detail="Không thể khóa tài khoản Admin hệ thống.")

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Validate admin
        cursor.execute("SELECT id FROM users WHERE username = ? AND password = ? AND is_admin = 1", (req.admin_user, req.admin_pass))
        if not cursor.fetchone():
            raise HTTPException(status_code=401, detail="Bạn không có quyền quản trị viên.")

        cursor.execute("UPDATE users SET status = ? WHERE username = ?", (req.status, req.target_username))
        conn.commit()
    finally:
        conn.close()

    msg = f"Đã kích hoạt tài khoản '{req.target_username}' thành công." if req.status == 'active' else f"Đã khóa/hủy kích hoạt tài khoản '{req.target_username}'."
    return {"status": "ok", "message": msg}

@app.post("/api/admin/set_expiry")
def admin_set_expiry(req: SetExpiryRequest):
    if req.target_username == "admin":
        raise HTTPException(status_code=400, detail="Không thể đặt thời hạn cho tài khoản Admin hệ thống.")

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Validate admin
        cursor.execute("SELECT id FROM users WHERE username = ? AND password = ? AND is_admin = 1", (req.admin_user, req.admin_pass))
        if not cursor.fetchone():
            raise HTTPException(status_code=401, detail="Bạn không có quyền quản trị viên.")

        if req.duration_days <= 0:
            expiry_date = None
            msg = f"Đã cập nhật thời hạn tài khoản '{req.target_username}' thành Vô thời hạn."
        else:
            import datetime
            expiry_date = time.time() + req.duration_days * 86400
            date_str = datetime.datetime.fromtimestamp(expiry_date).strftime('%d/%m/%Y')
            msg = f"Đã cập nhật thời hạn tài khoản '{req.target_username}' đến ngày {date_str}."

        cursor.execute("UPDATE users SET expiry_date = ? WHERE username = ?", (expiry_date, req.target_username))
        conn.commit()
    finally:
        conn.close()

    return {"status": "ok", "message": msg}
