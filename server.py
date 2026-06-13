import os
import sys
import time
import random
import string
import secrets
import smtplib
import threading
import urllib.request as _urllib_req
from email.mime.text import MIMEText
from email.header import Header
from typing import Optional
from fastapi import FastAPI, HTTPException, Header as RequestHeader, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import hashlib
import re

# Password hashing helpers
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def is_sha256(s: str) -> bool:
    return bool(re.match(r'^[0-9a-f]{64}$', s))

def verify_password(stored: str, input_val: str) -> bool:
    if is_sha256(stored):
        return stored == hash_password(input_val)
    else:
        # Backward compatibility for plain text passwords
        return stored == input_val

# Rate limiting for forgot password
forgot_password_rate_limit = {}

app = FastAPI(title="SPC Central Auth Server")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Database setup (PostgreSQL if DATABASE_URL is set, else SQLite) ──────────
DATABASE_URL = os.environ.get("DATABASE_URL", "")
DB_PATH = os.environ.get(
    "SPC_DB_PATH",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "auth.db")
)

IS_PG = bool(DATABASE_URL)
PH    = "%s" if IS_PG else "?"   # SQL placeholder token

if IS_PG:
    import psycopg2
    import psycopg2.extras

    def get_db_connection():
        conn = psycopg2.connect(DATABASE_URL)
        return conn

    def get_cursor(conn):
        return conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
else:
    import sqlite3

    def get_db_connection():
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        return conn

    def get_cursor(conn):
        return conn.cursor()


def q(sql: str) -> str:
    """Replace ? with the correct placeholder for the active database."""
    return sql.replace("?", PH) if IS_PG else sql


def row_get(row, key, default=None):
    """Safe column access that works for both sqlite3.Row and psycopg2 RealDictRow."""
    try:
        return row[key]
    except (KeyError, IndexError):
        return default


# ── Schema init ──────────────────────────────────────────────────────────────
def init_db():
    conn = get_db_connection()
    cur  = get_cursor(conn)
    try:
        if IS_PG:
            cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id             SERIAL PRIMARY KEY,
                name           TEXT NOT NULL,
                email          TEXT NOT NULL,
                username       TEXT UNIQUE NOT NULL,
                password       TEXT NOT NULL,
                referral_code  TEXT NOT NULL,
                is_admin       INTEGER DEFAULT 0,
                status         TEXT DEFAULT 'pending',
                expiry_date    DOUBLE PRECISION DEFAULT NULL,
                selected_package TEXT DEFAULT NULL
            )
            """)
            for col_sql in [
                "ALTER TABLE users ADD COLUMN status TEXT DEFAULT 'pending'",
                "ALTER TABLE users ADD COLUMN expiry_date DOUBLE PRECISION DEFAULT NULL",
                "ALTER TABLE users ADD COLUMN selected_package TEXT DEFAULT NULL",
            ]:
                try:
                    cur.execute(col_sql)
                except Exception:
                    pass
            cur.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                id          SERIAL PRIMARY KEY,
                user_id     INTEGER NOT NULL REFERENCES users(id),
                uuid        TEXT NOT NULL,
                cpu         TEXT,
                ram         TEXT,
                ip          TEXT,
                last_login  DOUBLE PRECISION
            )
            """)
        else:
            cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                name          TEXT NOT NULL,
                email         TEXT NOT NULL,
                username      TEXT UNIQUE NOT NULL,
                password      TEXT NOT NULL,
                referral_code TEXT NOT NULL,
                is_admin      INTEGER DEFAULT 0,
                status        TEXT DEFAULT 'pending',
                selected_package TEXT DEFAULT NULL
            )
            """)
            for col_sql in [
                "ALTER TABLE users ADD COLUMN status TEXT DEFAULT 'pending'",
                "ALTER TABLE users ADD COLUMN expiry_date REAL DEFAULT NULL",
                "ALTER TABLE users ADD COLUMN selected_package TEXT DEFAULT NULL",
            ]:
                try:
                    cur.execute(col_sql)
                except Exception:
                    pass
            cur.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id    INTEGER NOT NULL,
                uuid       TEXT NOT NULL,
                cpu        TEXT,
                ram        TEXT,
                ip         TEXT,
                last_login REAL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
            """)

        conn.commit()

        # Seed admin account (always ensure it exists and is active)
        admin_pass = os.environ.get("SPC_ADMIN_PASSWORD", "spcadmin123")
        cur.execute(q("SELECT COUNT(*) as cnt FROM users WHERE username = ?"), ("admin",))
        count = cur.fetchone()["cnt"]
        if count == 0:
            hashed_admin_pass = hash_password(admin_pass)
            cur.execute(
                q("""INSERT INTO users (name, email, username, password, referral_code, is_admin, status)
                     VALUES (?, ?, ?, ?, ?, 1, 'active')"""),
                ("Administrator", "admin@spc.com", "admin", hashed_admin_pass, "ADMIN")
            )
            conn.commit()
            print(f"[*] Admin account seeded (username: admin, password: {admin_pass} [HASHED])")
        else:
            cur.execute(q("UPDATE users SET status = 'active' WHERE username = ?"), ("admin",))
            conn.commit()
    finally:
        cur.close()
        conn.close()


init_db()


# ── Keep-alive (prevent Render free tier sleep) ──────────────────────────────
def _keep_alive():
    public_url = os.environ.get("RENDER_EXTERNAL_URL", "https://spc-auth-server.onrender.com")
    while True:
        time.sleep(14 * 60)
        try:
            _urllib_req.urlopen(public_url + "/health", timeout=10)
        except Exception:
            pass

threading.Thread(target=_keep_alive, daemon=True).start()


# ── Pydantic models ───────────────────────────────────────────────────────────
class RegisterRequest(BaseModel):
    name: str
    email: str
    username: str
    password: str
    referral_code: str
    selected_package: str = None

class LoginRequest(BaseModel):
    username: str
    password: str
    uuid: str
    cpu: str
    ram: str
    ip: str

class ForgotPasswordRequest(BaseModel):
    identity: str

class ListUsersRequest(BaseModel):
    admin_user: str
    admin_pass: str

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

class ChangePasswordRequest(BaseModel):
    admin_user: str
    admin_pass: str
    target_username: str
    new_password: str


# ── Helpers ───────────────────────────────────────────────────────────────────
def send_password_reset_email(to_email: str, new_password: str) -> bool:
    subject = "Team SPC - Cấp lại mật khẩu"
    body = (
        f"Team SPC Xin chào!\n"
        f"Mật khẩu mới của bạn là: {new_password}\n"
        f"Vui lòng không chia sẻ để bảo mật dữ liệu cá nhân"
    )

    smtp_email  = os.environ.get("SMTP_EMAIL", "")
    smtp_pwd    = os.environ.get("SMTP_PASSWORD", "")
    smtp_server = os.environ.get("SMTP_SERVER", "smtp.gmail.com")
    smtp_port   = int(os.environ.get("SMTP_PORT", "587"))

    log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "email_log.txt")

    if not smtp_email or not smtp_pwd:
        print("[!] SMTP not configured. Writing to local email log instead.")
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(f"\n--- MAIL SENT: {time.strftime('%Y-%m-%d %H:%M:%S')} to {to_email} ---\n{body}\n---\n")
        return True

    try:
        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = Header(subject, "utf-8")
        msg["From"]    = smtp_email
        msg["To"]      = to_email
        srv = smtplib.SMTP(smtp_server, smtp_port)
        srv.starttls()
        srv.login(smtp_email, smtp_pwd)
        srv.sendmail(smtp_email, [to_email], msg.as_string())
        srv.quit()
        return True
    except Exception as e:
        print(f"[-] SMTP failed: {e}")
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(f"\n--- MAIL FAILED: {time.strftime('%Y-%m-%d %H:%M:%S')} to {to_email} ---\n{body}\n---\n")
        return False


# ── Routes ────────────────────────────────────────────────────────────────────
@app.get("/health")
def health_check():
    return {"status": "ok"}


@app.post("/api/auth/register")
def register(req: RegisterRequest):
    username      = req.username.strip().lower()
    email         = req.email.strip().lower()
    name          = req.name.strip()
    referral_code = req.referral_code.strip().upper()

    if not username or not email or not name or not req.password or not referral_code:
        raise HTTPException(status_code=400, detail="Vui lòng điền đầy đủ tất cả thông tin.")

    if referral_code not in ["NGOCTHANG", "ADMIN"]:
        raise HTTPException(status_code=400, detail="Mã giảm giá không hợp lệ. Vui lòng nhập NGOCTHANG hoặc ADMIN.")

    conn = get_db_connection()
    cur  = get_cursor(conn)
    try:
        cur.execute(q("SELECT id FROM users WHERE username = ?"), (username,))
        if cur.fetchone():
            raise HTTPException(status_code=400, detail="Tên đăng nhập đã tồn tại trong hệ thống.")

        cur.execute(q("SELECT id FROM users WHERE email = ?"), (email,))
        if cur.fetchone():
            raise HTTPException(status_code=400, detail="Gmail này đã được đăng ký tài khoản.")

        # Calculate expiry date based on package
        now = time.time()
        duration_days = 0
        package = req.selected_package
        if package:
            package_clean = package.strip().lower()
            if "tuần" in package_clean or "week" in package_clean:
                duration_days = 7
            elif "6 tháng" in package_clean or "6 months" in package_clean:
                duration_days = 180
            elif "1 năm" in package_clean or "1 year" in package_clean:
                duration_days = 365
            elif "5 năm" in package_clean or "5 years" in package_clean:
                duration_days = 1825

        expiry_date = now + duration_days * 86400 if duration_days > 0 else None

        cur.execute(
            q("INSERT INTO users (name, email, username, password, referral_code, is_admin, status, selected_package, expiry_date) VALUES (?, ?, ?, ?, ?, 0, 'pending', ?, ?)"),
            (name, email, username, req.password, referral_code, req.selected_package, expiry_date)
        )
        conn.commit()
    finally:
        cur.close()
        conn.close()

    return {"status": "ok", "message": "Đăng ký tài khoản thành công!"}


@app.post("/api/auth/login")
def login(req: LoginRequest):
    username = req.username.strip().lower()

    conn = get_db_connection()
    cur  = get_cursor(conn)
    try:
        cur.execute(q("SELECT * FROM users WHERE username = ?"), (username,))
        user = cur.fetchone()
        if not user or not verify_password(row_get(user, "password"), req.password):
            raise HTTPException(status_code=401, detail="Tên đăng nhập hoặc mật khẩu không chính xác.")

        user_id  = row_get(user, "id")
        is_admin = bool(row_get(user, "is_admin", 0))
        status   = row_get(user, "status", "pending")

        if not is_admin and status == "pending":
            raise HTTPException(status_code=403, detail="Tài khoản của bạn chưa được kích hoạt. Vui lòng liên hệ Admin hoặc người bán để kích hoạt sử dụng ứng dụng.")

        if not is_admin:
            expiry_date = row_get(user, "expiry_date")
            if expiry_date is not None and time.time() > expiry_date:
                raise HTTPException(status_code=403, detail="Tài khoản của bạn đã hết hạn sử dụng. Vui lòng liên hệ Admin hoặc người bán để gia hạn.")

        if is_admin:
            return {"status": "ok", "user": {"username": row_get(user, "username"), "name": row_get(user, "name"), "email": row_get(user, "email"), "is_admin": True}}

        uuid = req.uuid.strip()
        if not uuid or uuid == "UNKNOWN_UUID":
            raise HTTPException(status_code=400, detail="Không thể xác thực thông số phần cứng thiết bị này.")

        cur.execute(q("SELECT id FROM devices WHERE user_id = ? AND uuid = ?"), (user_id, uuid))
        device_row = cur.fetchone()

        if device_row:
            cur.execute(
                q("UPDATE devices SET cpu = ?, ram = ?, ip = ?, last_login = ? WHERE user_id = ? AND uuid = ?"),
                (req.cpu, req.ram, req.ip, time.time(), user_id, uuid)
            )
        else:
            cur.execute(q("SELECT COUNT(*) as cnt FROM devices WHERE user_id = ?"), (user_id,))
            if cur.fetchone()["cnt"] >= 2:
                raise HTTPException(status_code=403, detail="Tài khoản đã đăng nhập tối đa 2 thiết bị. Vui lòng liên hệ Admin của SPC để được cấp quyền hoặc reset lại thiết bị.")
            cur.execute(
                q("INSERT INTO devices (user_id, uuid, cpu, ram, ip, last_login) VALUES (?, ?, ?, ?, ?, ?)"),
                (user_id, uuid, req.cpu, req.ram, req.ip, time.time())
            )
        conn.commit()
    finally:
        cur.close()
        conn.close()

    return {"status": "ok", "user": {"username": row_get(user, "username"), "name": row_get(user, "name"), "email": row_get(user, "email"), "is_admin": False}}


@app.post("/api/auth/forgot_password")
def forgot_password(req: ForgotPasswordRequest, request: Request):
    identity = req.identity.strip().lower()
    client_ip = request.client.host if request.client else "unknown"

    now = time.time()
    cooldown = 60.0
    for key in (identity, client_ip):
        if key in forgot_password_rate_limit:
            last_time = forgot_password_rate_limit[key]
            if now - last_time < cooldown:
                remaining = int(cooldown - (now - last_time))
                raise HTTPException(
                    status_code=429,
                    detail=f"Vui lòng đợi {remaining} giây trước khi gửi lại yêu cầu cấp lại mật khẩu."
                )

    conn = get_db_connection()
    cur  = get_cursor(conn)
    try:
        cur.execute(q("SELECT id, email, username FROM users WHERE username = ? OR email = ?"), (identity, identity))
        user = cur.fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="Không tìm thấy tài khoản tương ứng với thông tin đã nhập.")

        # Rate limit verified user
        forgot_password_rate_limit[identity] = now
        forgot_password_rate_limit[client_ip] = now

        new_password = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(8))
        cur.execute(q("UPDATE users SET password = ? WHERE id = ?"), (new_password, row_get(user, "id")))
        conn.commit()

        sent = send_password_reset_email(row_get(user, "email"), new_password)
        if not sent:
            raise HTTPException(status_code=500, detail="Không thể gửi email thông báo. Vui lòng thử lại sau.")
    finally:
        cur.close()
        conn.close()

    return {"status": "ok", "message": "Mật khẩu mới đã được gửi về Gmail của bạn thành công!"}


@app.post("/api/admin/users")
def admin_list_users(req: ListUsersRequest):
    conn = get_db_connection()
    cur  = get_cursor(conn)
    try:
        cur.execute(q("SELECT password FROM users WHERE username = ? AND is_admin = 1"), (req.admin_user,))
        admin = cur.fetchone()
        if not admin or not verify_password(row_get(admin, "password"), req.admin_pass):
            raise HTTPException(status_code=401, detail="Bạn không có quyền quản trị viên.")

        cur.execute("SELECT * FROM users")
        users = cur.fetchall()

        user_list = []
        for u in users:
            cur.execute(q("SELECT * FROM devices WHERE user_id = ?"), (row_get(u, "id"),))
            devices = cur.fetchall()
            dev_list = [{"uuid": row_get(d,"uuid"), "cpu": row_get(d,"cpu"), "ram": row_get(d,"ram"), "ip": row_get(d,"ip"), "last_login": row_get(d,"last_login")} for d in devices]
            pwd_val = row_get(u, "password")
            if is_sha256(pwd_val):
                pwd_val = "********"
            user_list.append({
                "name":             row_get(u, "name"),
                "email":            row_get(u, "email"),
                "username":         row_get(u, "username"),
                "password":         pwd_val,
                "referral_code":    row_get(u, "referral_code"),
                "is_admin":         bool(row_get(u, "is_admin", 0)),
                "status":           row_get(u, "status", "pending"),
                "expiry_date":      row_get(u, "expiry_date"),
                "selected_package": row_get(u, "selected_package"),
                "devices":          dev_list,
            })
    finally:
        cur.close()
        conn.close()

    return user_list


@app.post("/api/admin/reset_device")
def admin_reset_device(req: ResetDeviceRequest):
    conn = get_db_connection()
    cur  = get_cursor(conn)
    try:
        cur.execute(q("SELECT password FROM users WHERE username = ? AND is_admin = 1"), (req.admin_user,))
        admin = cur.fetchone()
        if not admin or not verify_password(row_get(admin, "password"), req.admin_pass):
            raise HTTPException(status_code=401, detail="Bạn không có quyền quản trị viên.")

        cur.execute(q("SELECT id FROM users WHERE username = ?"), (req.target_username,))
        target = cur.fetchone()
        if not target:
            raise HTTPException(status_code=404, detail="Không tìm thấy người dùng cần reset thiết bị.")

        cur.execute(q("DELETE FROM devices WHERE user_id = ?"), (row_get(target, "id"),))
        conn.commit()
    finally:
        cur.close()
        conn.close()

    return {"status": "ok", "message": f"Đã reset danh sách thiết bị của tài khoản '{req.target_username}' thành công."}


@app.post("/api/admin/delete_user")
def admin_delete_user(req: DeleteUserRequest):
    if req.target_username == "admin":
        raise HTTPException(status_code=400, detail="Không thể xóa tài khoản Admin hệ thống.")

    conn = get_db_connection()
    cur  = get_cursor(conn)
    try:
        cur.execute(q("SELECT password FROM users WHERE username = ? AND is_admin = 1"), (req.admin_user,))
        admin = cur.fetchone()
        if not admin or not verify_password(row_get(admin, "password"), req.admin_pass):
            raise HTTPException(status_code=401, detail="Bạn không có quyền quản trị viên.")

        cur.execute(q("SELECT id FROM users WHERE username = ?"), (req.target_username,))
        target = cur.fetchone()
        if not target:
            raise HTTPException(status_code=404, detail="Không tìm thấy người dùng cần xóa.")

        tid = row_get(target, "id")
        cur.execute(q("DELETE FROM devices WHERE user_id = ?"), (tid,))
        cur.execute(q("DELETE FROM users WHERE id = ?"), (tid,))
        conn.commit()
    finally:
        cur.close()
        conn.close()

    return {"status": "ok", "message": f"Đã xóa tài khoản '{req.target_username}' thành công."}


@app.post("/api/admin/activate_user")
def admin_activate_user(req: ActivateUserRequest):
    if req.target_username == "admin":
        raise HTTPException(status_code=400, detail="Không thể khóa tài khoản Admin hệ thống.")

    conn = get_db_connection()
    cur  = get_cursor(conn)
    try:
        cur.execute(q("SELECT password FROM users WHERE username = ? AND is_admin = 1"), (req.admin_user,))
        admin = cur.fetchone()
        if not admin or not verify_password(row_get(admin, "password"), req.admin_pass):
            raise HTTPException(status_code=401, detail="Bạn không có quyền quản trị viên.")

        cur.execute(q("UPDATE users SET status = ? WHERE username = ?"), (req.status, req.target_username))
        conn.commit()
    finally:
        cur.close()
        conn.close()

    msg = f"Đã kích hoạt tài khoản '{req.target_username}' thành công." if req.status == "active" else f"Đã khóa/hủy kích hoạt tài khoản '{req.target_username}'."
    return {"status": "ok", "message": msg}


@app.post("/api/admin/set_expiry")
def admin_set_expiry(req: SetExpiryRequest):
    if req.target_username == "admin":
        raise HTTPException(status_code=400, detail="Không thể đặt thời hạn cho tài khoản Admin hệ thống.")

    conn = get_db_connection()
    cur  = get_cursor(conn)
    try:
        cur.execute(q("SELECT password FROM users WHERE username = ? AND is_admin = 1"), (req.admin_user,))
        admin = cur.fetchone()
        if not admin or not verify_password(row_get(admin, "password"), req.admin_pass):
            raise HTTPException(status_code=401, detail="Bạn không có quyền quản trị viên.")

        package_name = None
        if req.duration_days <= 0:
            expiry_date = None
            package_name = "Vĩnh viễn"
            msg = f"Đã cập nhật thời hạn tài khoản '{req.target_username}' thành Vô thời hạn."
        else:
            import datetime
            expiry_date = time.time() + req.duration_days * 86400
            date_str    = datetime.datetime.fromtimestamp(expiry_date).strftime("%d/%m/%Y")
            msg         = f"Đã cập nhật thời hạn tài khoản '{req.target_username}' đến ngày {date_str}."
            
            if req.duration_days == 7:
                package_name = "Dùng thử 1 tuần"
            elif req.duration_days == 30:
                package_name = "1 tháng"
            elif req.duration_days == 90:
                package_name = "3 tháng"
            elif req.duration_days == 180:
                package_name = "6 tháng"
            elif req.duration_days == 365:
                package_name = "1 năm"
            elif req.duration_days == 1825:
                package_name = "5 năm"
            else:
                package_name = f"Gia hạn {req.duration_days} ngày"

        cur.execute(
            q("UPDATE users SET expiry_date = ?, selected_package = ? WHERE username = ?"),
            (expiry_date, package_name, req.target_username)
        )
        conn.commit()
    finally:
        cur.close()
        conn.close()

    return {"status": "ok", "message": msg}


@app.post("/api/admin/change_password")
def admin_change_password(req: ChangePasswordRequest):
    if req.target_username == "admin":
        raise HTTPException(status_code=400, detail="Không thể đổi mật khẩu Admin hệ thống từ đây.")

    conn = get_db_connection()
    cur  = get_cursor(conn)
    try:
        cur.execute(q("SELECT password FROM users WHERE username = ? AND is_admin = 1"), (req.admin_user,))
        admin = cur.fetchone()
        if not admin or not verify_password(row_get(admin, "password"), req.admin_pass):
            raise HTTPException(status_code=401, detail="Bạn không có quyền quản trị viên.")

        cur.execute(q("UPDATE users SET password = ? WHERE username = ?"), (req.new_password, req.target_username))
        conn.commit()
    finally:
        cur.close()
        conn.close()

    return {"status": "ok", "message": f"Đã đổi mật khẩu của tài khoản '{req.target_username}' thành công."}

