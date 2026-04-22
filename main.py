import os
import tempfile
import threading
import time
from pathlib import Path
from urllib.parse import urlencode

import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from starlette.background import BackgroundTask

from crypto import CHECKIN_TIMEOUT, KEY_DIR, VAULT_DIR, CryptoManager
from session_manager import RateLimiter, SessionStore
from audit_logger import AuditEvent, log_event

# 加载配置
load_dotenv()

app = FastAPI()

TEMPLATE_DIR = os.getenv("TEMPLATE_DIR", "./templates")
SESSION_TTL_SECONDS = int(os.getenv("SESSION_TTL_HOURS", 12)) * 3600
MAX_VAULT_SIZE_BYTES = int(os.getenv("MAX_VAULT_SIZE_MB", 1024)) * 1024 * 1024
MAX_UPLOAD_SIZE_BYTES = int(os.getenv("MAX_UPLOAD_SIZE_MB", 64)) * 1024 * 1024
SESSION_COOKIE_NAME = os.getenv("SESSION_COOKIE_NAME", "aegis_session")
SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true"

templates = Jinja2Templates(directory=TEMPLATE_DIR)
session_store = SessionStore(ttl_seconds=SESSION_TTL_SECONDS)
rate_limiter = RateLimiter(max_attempts=5, window_seconds=600, lockout_seconds=900)


def set_session_cookie(response: Response, session_id: str) -> None:
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=session_id,
        httponly=True,
        secure=SESSION_COOKIE_SECURE,
        samesite="lax",
        max_age=SESSION_TTL_SECONDS,
        path="/",
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(key=SESSION_COOKIE_NAME, path="/")


def redirect_with_message(message: str | None = None) -> RedirectResponse:
    query = f"?{urlencode({'msg': message})}" if message else ""
    return RedirectResponse(url=f"/{query}", status_code=303)


def client_address(request: Request) -> str:
    return request.client.host if request.client and request.client.host else "unknown"


def get_vault_size() -> int:
    total = 0
    if VAULT_DIR.exists():
        for file_path in VAULT_DIR.rglob("*"):
            if file_path.is_file():
                total += file_path.stat().st_size
    return total


def get_current_session(request: Request) -> tuple[str | None, dict | None]:
    session_store.cleanup()
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    client_ip = client_address(request)
    user_agent = request.headers.get("user-agent", "")
    session = session_store.get(session_id, client_ip=client_ip, user_agent=user_agent)
    if CryptoManager.get_status()["destroyed"] and session_id:
        session_store.clear()
        return None, None
    return session_id, session


def require_session(request: Request, csrf_token: str | None = None, admin_only: bool = False) -> tuple[str, dict]:
    session_id, session = get_current_session(request)
    if not session_id or not session:
        raise HTTPException(status_code=403, detail="会话已失效，请重新登录")
    if not (KEY_DIR / f"{session['user']}.key").exists():
        session_store.destroy(session_id)
        raise HTTPException(status_code=403, detail="会话已失效，请重新登录")
    if csrf_token is not None and csrf_token != session["csrf_token"]:
        session_store.destroy(session_id)
        raise HTTPException(status_code=403, detail="请求令牌无效，请重新登录")
    if admin_only and session["user"] != "admin":
        raise HTTPException(status_code=403, detail="需要管理员权限")
    
    # 检查客户端特征不匹配
    if session.get("_fingerprint_mismatch"):
        client_ip = client_address(request)
        log_event(AuditEvent.INVALID_REQUEST, user=session.get("user"), client_ip=client_ip, 
                  details={"reason": "fingerprint_mismatch"}, success=False)
        session_store.destroy(session_id)
        raise HTTPException(status_code=403, detail="会话客户端特征不匹配，请重新登录")
    
    return session_id, session


def build_context(request: Request, msg: str | None = None, duress_active: bool = False) -> dict:
    status = CryptoManager.get_status()
    exists = (KEY_DIR / "admin.key").exists()
    remaining_seconds = 0
    
    # 检查状态文件是否被篡改
    if status.get("_tampered"):
        log_event(AuditEvent.SYSTEM_DESTROYED, details={"reason": "status_file_tampered"}, success=True)
        CryptoManager.destroy_all()
        session_store.clear()
        msg = "检测到状态文件篡改，系统已自毁"
    
    if exists and not status["destroyed"]:
        elapsed = int(time.time()) - status["last_checkin"]
        remaining_seconds = max(0, CHECKIN_TIMEOUT - elapsed)

    session_id, session = get_current_session(request)
    auth = None
    files = []
    vault_size_mb = None
    csrf_token = None

    if session_id and session and exists and not status["destroyed"] and (KEY_DIR / f"{session['user']}.key").exists():
        auth = {"user": session["user"], "is_admin": session["user"] == "admin"}
        csrf_token = session["csrf_token"]
        user_vault = CryptoManager.get_user_vault_path(session["user"])
        files = sorted([file_path.name for file_path in user_vault.iterdir() if file_path.is_file()])
        if session["user"] == "admin":
            vault_size_mb = round(get_vault_size() / (1024 * 1024), 2)

    return {
        "exists": exists,
        "destroyed": status["destroyed"],
        "remaining_total_s": remaining_seconds,
        "auth": auth,
        "files": files,
        "msg": msg,
        "duress_active": duress_active,
        "vault_size_mb": vault_size_mb,
        "csrf_token": csrf_token,
        "available_users": CryptoManager.list_supported_users(),
        "max_upload_mb": int(MAX_UPLOAD_SIZE_BYTES / (1024 * 1024)),
        "max_vault_mb": int(MAX_VAULT_SIZE_BYTES / (1024 * 1024)),
    }


def read_upload_bytes(upload: UploadFile, max_size: int) -> bytes:
    total = 0
    chunks: list[bytes] = []
    try:
        while True:
            chunk = upload.file.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > max_size:
                raise HTTPException(status_code=400, detail=f"单文件超过 {int(max_size / (1024 * 1024))}MB 限制")
            chunks.append(chunk)
    finally:
        upload.file.close()
    return b"".join(chunks)


def remove_file(path: str) -> None:
    Path(path).unlink(missing_ok=True)


def validate_password_strength(password: str, min_length: int = 12) -> tuple[bool, str]:
    """
    验证密码强度
    返回 (是否有效, 错误消息)
    """
    password = password.strip()
    
    if len(password) < min_length:
        return False, f"密码长度至少需要 {min_length} 个字符"
    
    if len(password) > 256:
        return False, "密码长度不能超过 256 个字符"
    
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
    
    complexity = sum([has_upper, has_lower, has_digit, has_special])
    
    if complexity < 3:
        return False, "密码必须包含至少 3 种类型：大小写、数字、特殊符号"
    
    return True, ""


def validate_code_strength(code: str, min_length: int = 8) -> tuple[bool, str]:
    """
    验证码强度（签到码和胁迫码）
    返回 (是否有效, 错误消息)
    """
    code = code.strip()
    
    if len(code) < min_length:
        return False, f"码长度至少需要 {min_length} 个字符"
    
    if len(code) > 256:
        return False, "码长度不能超过 256 个字符"
    
    # 确保包含数字和字母或特殊符号
    has_alphanum = any(c.isalnum() for c in code)
    has_variety = len(set(code)) >= 4  # 至少 4 种不同字符
    
    if not has_alphanum or not has_variety:
        return False, "码必须包含足够的多样性（混合字符和数字）"
    
    return True, ""


def monitor_switch() -> None:
    CryptoManager.ensure_dirs()
    while True:
        status = CryptoManager.get_status()
        if not status["destroyed"] and (KEY_DIR / "admin.key").exists():
            # 检查状态文件是否被篡改
            if status.get("_tampered"):
                CryptoManager.destroy_all()
                log_event(AuditEvent.SYSTEM_DESTROYED, details={"reason": "status_file_tampered"}, success=True)
                session_store.clear()
            else:
                # 正常的自毁计时器检查
                elapsed = int(time.time()) - status["last_checkin"]
                if elapsed > CHECKIN_TIMEOUT:
                    CryptoManager.destroy_all()
                    log_event(AuditEvent.SYSTEM_DESTROYED, details={"reason": "checkin_timeout", "elapsed_seconds": elapsed}, success=True)
                    session_store.clear()
        time.sleep(60)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com data:; "
        "img-src 'self' data:; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none';"
    )
    return response


@app.on_event("startup")
async def startup_event():
    threading.Thread(target=monitor_switch, daemon=True).start()


@app.get("/", response_class=HTMLResponse)
async def index(request: Request, msg: str | None = None):
    context = build_context(request, msg=msg)
    return templates.TemplateResponse(request=request, name="index.html", context=context)


@app.post("/login")
async def login(request: Request, password: str = Form(...)):
    client_ip = client_address(request)
    user_agent = request.headers.get("user-agent", "")
    scope_key = client_ip
    retry_after = rate_limiter.check("login", scope_key)
    if retry_after:
        log_event(AuditEvent.RATE_LIMIT_EXCEEDED, client_ip=client_ip, details={"action": "login"}, success=False)
        return redirect_with_message(f"尝试过多，请在 {retry_after} 秒后重试")

    auth_result = CryptoManager.authenticate(password)
    if auth_result == "DURESS_TRIGGERED":
        log_event(AuditEvent.DURESS_TRIGGERED, client_ip=client_ip, success=True)
        session_store.clear()
        rate_limiter.reset("login", scope_key)
        response = redirect_with_message("身份验证失败")
        clear_session_cookie(response)
        return response

    if not auth_result:
        retry_after = rate_limiter.failure("login", scope_key)
        log_event(AuditEvent.AUTH_LOGIN_FAILED, client_ip=client_ip, details={"reason": "invalid_password"}, success=False)
        if retry_after:
            return redirect_with_message(f"尝试过多，请在 {retry_after} 秒后重试")
        return redirect_with_message("身份验证失败")

    rate_limiter.reset("login", scope_key)
    session_id, _ = session_store.create(auth_result["user"], auth_result["private_key"], 
                                        client_ip=client_ip, user_agent=user_agent)
    log_event(AuditEvent.AUTH_LOGIN_SUCCESS, user=auth_result["user"], client_ip=client_ip, success=True)
    response = RedirectResponse(url="/", status_code=303)
    set_session_cookie(response, session_id)
    return response


@app.post("/checkin")
async def checkin(request: Request, checkin_code: str = Form(...)):
    client_ip = client_address(request)
    scope_key = client_ip
    retry_after = rate_limiter.check("checkin", scope_key)
    if retry_after:
        log_event(AuditEvent.RATE_LIMIT_EXCEEDED, client_ip=client_ip, details={"action": "checkin"}, success=False)
        return redirect_with_message(f"签到尝试过多，请在 {retry_after} 秒后重试")

    if CryptoManager.verify_duress(checkin_code):
        log_event(AuditEvent.DURESS_TRIGGERED, client_ip=client_ip, success=True)
        CryptoManager.destroy_all()
        session_store.clear()
        rate_limiter.reset("checkin", scope_key)
        response = redirect_with_message("签到失败")
        clear_session_cookie(response)
        return response

    if CryptoManager.verify_checkin(checkin_code):
        CryptoManager.update_checkin()
        rate_limiter.reset("checkin", scope_key)
        log_event(AuditEvent.CHECKIN_SUCCESS, client_ip=client_ip, success=True)
        return redirect_with_message("签到成功，计时器已重置")

    retry_after = rate_limiter.failure("checkin", scope_key)
    log_event(AuditEvent.CHECKIN_FAILED, client_ip=client_ip, details={"reason": "invalid_code"}, success=False)
    if retry_after:
        return redirect_with_message(f"签到尝试过多，请在 {retry_after} 秒后重试")
    return redirect_with_message("签到码错误")


@app.post("/logout")
async def logout(request: Request):
    session_id, session = get_current_session(request)
    if session:
        log_event(AuditEvent.AUTH_LOGOUT, user=session.get("user"), client_ip=client_address(request), success=True)
    session_store.destroy(session_id)
    response = RedirectResponse(url="/", status_code=303)
    clear_session_cookie(response)
    return response


@app.post("/setup")
async def setup(
    master_password: str = Form(...),
    confirm_master_password: str = Form(...),
    checkin_code: str = Form(...),
    confirm_checkin_code: str = Form(...),
):
    if (KEY_DIR / "admin.key").exists():
        return redirect_with_message("系统已初始化")
    
    if master_password != confirm_master_password:
        return redirect_with_message("两次输入的管理员密码不一致")
    
    valid, msg = validate_password_strength(master_password)
    if not valid:
        return redirect_with_message(msg)
    
    if checkin_code != confirm_checkin_code:
        return redirect_with_message("两次输入的签到码不一致")
    
    valid, msg = validate_code_strength(checkin_code)
    if not valid:
        return redirect_with_message(msg)
    
    CryptoManager.init_admin(master_password, checkin_code)
    log_event(AuditEvent.SYSTEM_RESET, details={"action": "initialization"}, success=True)
    return redirect_with_message("初始化完成，请登录")


@app.post("/reset")
async def reset(request: Request, csrf_token: str | None = Form(None)):
    status = CryptoManager.get_status()
    if not status["destroyed"]:
        require_session(request, csrf_token=csrf_token, admin_only=True)
    session_store.clear()
    CryptoManager.reset_system()
    log_event(AuditEvent.SYSTEM_RESET, details={"action": "manual_reset"}, success=True)
    response = redirect_with_message("系统已重置")
    clear_session_cookie(response)
    return response


@app.post("/manage_user")
async def manage_user(
    request: Request,
    csrf_token: str = Form(...),
    target_user: str = Form(...),
    target_pass: str = Form(...),
    confirm_target_pass: str = Form(...),
):
    _, session = require_session(request, csrf_token=csrf_token, admin_only=True)
    
    if target_pass != confirm_target_pass:
        return redirect_with_message("两次输入的访问密码不一致")
    
    valid, msg = validate_password_strength(target_pass)
    if not valid:
        return redirect_with_message(msg)
    
    try:
        CryptoManager.validate_username(target_user)
    except ValueError as exc:
        return redirect_with_message(str(exc))
    
    if (KEY_DIR / f"{target_user}.key").exists():
        user_vault = CryptoManager.get_user_vault_path(target_user)
        if any(file_path.is_file() for file_path in user_vault.iterdir()):
            return redirect_with_message("目标用户已有加密文件，当前版本禁止直接重置密钥")
    
    CryptoManager.create_user_keys(target_user, target_pass)
    log_event(AuditEvent.USER_PASSWORD_UPDATED, user=session["user"], details={"target_user": target_user}, success=True)
    session_store.invalidate_user(target_user)
    
    if target_user == "admin":
        response = redirect_with_message("管理员密码已更新，请重新登录")
        clear_session_cookie(response)
        return response
    return redirect_with_message(f"用户 {target_user} 密钥已更新")


@app.post("/update_checkin_code")
async def update_checkin_code(request: Request, csrf_token: str = Form(...), new_code: str = Form(...), confirm_code: str = Form(...)):
    _, session = require_session(request, csrf_token=csrf_token, admin_only=True)
    
    if new_code != confirm_code:
        return redirect_with_message("两次输入的签到码不一致")
    
    valid, msg = validate_code_strength(new_code)
    if not valid:
        return redirect_with_message(msg)
    
    CryptoManager.set_checkin_code(new_code)
    log_event(AuditEvent.CHECKIN_CODE_UPDATED, user=session["user"], success=True)
    return redirect_with_message("签到协议更新成功")


@app.post("/update_duress_code")
async def update_duress_code(request: Request, csrf_token: str = Form(...), duress_code: str = Form(...), confirm_duress: str = Form(...)):
    _, session = require_session(request, csrf_token=csrf_token, admin_only=True)
    
    if duress_code != confirm_duress:
        return redirect_with_message("两次输入的胁迫销毁码不一致")
    
    valid, msg = validate_code_strength(duress_code)
    if not valid:
        return redirect_with_message(msg)
    
    CryptoManager.set_duress_code(duress_code)
    log_event(AuditEvent.DURESS_CODE_UPDATED, user=session["user"], success=True)
    return redirect_with_message("胁迫销毁协议已激活")


@app.post("/upload")
async def upload(request: Request, csrf_token: str = Form(...), file: UploadFile = File(...)):
    _, session = require_session(request, csrf_token=csrf_token)
    try:
        safe_name = CryptoManager.normalize_filename(file.filename or "")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    content = read_upload_bytes(file, MAX_UPLOAD_SIZE_BYTES)
    if get_vault_size() + len(content) > MAX_VAULT_SIZE_BYTES:
        raise HTTPException(status_code=400, detail=f"保险库已满 ({int(MAX_VAULT_SIZE_BYTES / (1024 * 1024))}MB 限制)")

    CryptoManager.encrypt_file(content, safe_name, session["user"])
    log_event(AuditEvent.FILE_UPLOADED, user=session["user"], details={"filename": safe_name, "size_bytes": len(content)}, success=True)
    return redirect_with_message("上传成功")


@app.post("/download")
async def download(request: Request, filename: str = Form(...), csrf_token: str = Form(...)):
    _, session = require_session(request, csrf_token=csrf_token)
    try:
        safe_name = CryptoManager.normalize_filename(filename)
        decrypted_content = CryptoManager.decrypt_file(safe_name, session["user"], session["private_key"])
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="文件不存在") from exc
    except Exception:
        log_event(AuditEvent.FILE_DOWNLOADED, user=session["user"], details={"filename": filename, "status": "decrypt_failed"}, success=False)
        return redirect_with_message("解密失败")

    download_name = safe_name[:-4] if safe_name.endswith(".aes") else safe_name
    temp_dir = Path("/tmp/aegis")
    temp_dir.mkdir(exist_ok=True)
    fd, temp_path = tempfile.mkstemp(prefix="aegis-", suffix=f"-{download_name}", dir=temp_dir)
    with os.fdopen(fd, "wb") as temp_file:
        temp_file.write(decrypted_content)

    log_event(AuditEvent.FILE_DOWNLOADED, user=session["user"], details={"filename": safe_name, "size_bytes": len(decrypted_content)}, success=True)
    
    return FileResponse(
        temp_path,
        filename=download_name,
        background=BackgroundTask(remove_file, temp_path),
        headers={"Cache-Control": "no-store"},
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return redirect_with_message(exc.detail if isinstance(exc.detail, str) else "请求失败")


if __name__ == "__main__":
    port = int(os.getenv("PORT", 46746))
    uvicorn.run(app, host="0.0.0.0", port=port)
