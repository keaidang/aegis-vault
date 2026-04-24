import os
import threading
import time
import json
from ipaddress import ip_address, ip_network
from datetime import datetime
from pathlib import Path
from urllib.parse import quote, unquote
from zoneinfo import ZoneInfo

import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from audit_logger import AuditEvent, get_audit_logs, log_event, verify_audit_chain
from crypto import CHECKIN_TIMEOUT, KEY_DIR, VAULT_DIR, CryptoManager
from notes_manager import NotesManager
from session_manager import RateLimiter, SessionStore

# 加载配置
load_dotenv()

app = FastAPI()

TEMPLATE_DIR = os.getenv("TEMPLATE_DIR", "./templates")
STATIC_DIR = os.getenv("STATIC_DIR", "./static")
SESSION_TTL_SECONDS = int(os.getenv("SESSION_TTL_HOURS", 12)) * 3600
MAX_VAULT_SIZE_BYTES = int(os.getenv("MAX_VAULT_SIZE_MB", 1024)) * 1024 * 1024
MAX_UPLOAD_SIZE_BYTES = int(os.getenv("MAX_UPLOAD_SIZE_MB", 64)) * 1024 * 1024
SESSION_COOKIE_NAME = os.getenv("SESSION_COOKIE_NAME", "aegis_session")
SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true"
MONITOR_INTERVAL_SECONDS = int(os.getenv("MONITOR_INTERVAL_SECONDS", "5"))
FLASH_COOKIE_NAME = "aegis_flash"
SHANGHAI_TZ = ZoneInfo("Asia/Shanghai")
TRUSTED_PROXY_IPS = [
    item.strip()
    for item in os.getenv("TRUSTED_PROXY_IPS", "127.0.0.1,::1").split(",")
    if item.strip()
]

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
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


def redirect_with_message(message: str | None = None, url: str = "/") -> RedirectResponse:
    response = RedirectResponse(url=url, status_code=303)
    if message:
        response.set_cookie(
            key=FLASH_COOKIE_NAME,
            value=quote(message, safe=""),
            httponly=True,
            secure=SESSION_COOKIE_SECURE,
            samesite="lax",
            max_age=20,
            path="/",
        )
    else:
        response.delete_cookie(key=FLASH_COOKIE_NAME, path="/")
    return response


def render_page(request: Request, template_name: str, context: dict) -> HTMLResponse:
    flash_message = request.cookies.get(FLASH_COOKIE_NAME)
    if flash_message and not context.get("msg"):
        context["msg"] = unquote(flash_message)
    response = templates.TemplateResponse(request=request, name=template_name, context=context)
    if flash_message:
        response.delete_cookie(key=FLASH_COOKIE_NAME, path="/")
    return response


def client_address(request: Request) -> str:
    direct_host = request.client.host if request.client and request.client.host else "unknown"
    try:
        direct_ip = ip_address(direct_host)
        trusted = any(direct_ip in ip_network(proxy, strict=False) for proxy in TRUSTED_PROXY_IPS)
    except ValueError:
        trusted = False
    if trusted:
        forwarded_for = request.headers.get("x-forwarded-for", "")
        forwarded_host = forwarded_for.split(",", 1)[0].strip()
        if forwarded_host:
            try:
                return str(ip_address(forwarded_host))
            except ValueError:
                pass
    return direct_host


def download_bytes_response(content: bytes, filename: str) -> StreamingResponse:
    quoted_name = quote(filename)
    headers = {
        "Cache-Control": "no-store",
        "Content-Disposition": f"attachment; filename*=UTF-8''{quoted_name}",
        "Content-Length": str(len(content)),
    }
    return StreamingResponse(iter([content]), media_type="application/octet-stream", headers=headers)


def get_vault_size() -> int:
    total = 0
    if VAULT_DIR.exists():
        for file_path in VAULT_DIR.rglob("*"):
            if file_path.is_file():
                try:
                    total += file_path.stat().st_size
                except OSError:
                    continue
    return total


def append_message(current: str | None, extra: str) -> str:
    if not current:
        return extra
    if extra in current:
        return current
    return f"{current}；{extra}"


def format_local_timestamp(timestamp: int | None) -> str:
    if not timestamp:
        return "-"
    return datetime.fromtimestamp(int(timestamp), tz=SHANGHAI_TZ).strftime("%Y-%m-%d %H:%M:%S")


def format_audit_timestamp(timestamp: str | None) -> str:
    if not timestamp:
        return "-"
    try:
        utc_dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        return utc_dt.astimezone(SHANGHAI_TZ).strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return timestamp


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


def require_session(
    request: Request,
    csrf_token: str | None = None,
    admin_only: bool = False,
    required_mode: str | None = None,
) -> tuple[str, dict]:
    session_id, session = get_current_session(request)
    if not session_id or not session:
        raise HTTPException(status_code=403, detail="会话已失效，请重新登录")
    expected_key_path = KEY_DIR / f"{session['user']}.key"
    if session.get("mode") == "notes":
        expected_key_path = KEY_DIR / f"{session['user']}.notes.key"
    if not expected_key_path.exists():
        session_store.destroy(session_id)
        raise HTTPException(status_code=403, detail="会话已失效，请重新登录")
    if required_mode is not None and session.get("mode") != required_mode:
        raise HTTPException(status_code=403, detail="当前会话无权访问该功能")
    if csrf_token is not None and csrf_token != session["csrf_token"]:
        session_store.destroy(session_id)
        raise HTTPException(status_code=403, detail="请求令牌无效，请重新登录")
    if admin_only and session["user"] != "admin":
        raise HTTPException(status_code=403, detail="需要管理员权限")
    if session.get("_fingerprint_mismatch"):
        client_ip = client_address(request)
        log_event(
            AuditEvent.INVALID_REQUEST,
            user=session.get("user"),
            client_ip=client_ip,
            details={"reason": "fingerprint_mismatch"},
            success=False,
        )
        session_store.destroy(session_id)
        raise HTTPException(status_code=403, detail="会话客户端特征不匹配，请重新登录")
    return session_id, session


def require_note_session(request: Request, csrf_token: str | None = None) -> tuple[str, dict]:
    session_id, session = require_session(request, csrf_token=csrf_token, required_mode="notes")
    if not NotesManager.is_enabled(session["user"]):
        raise HTTPException(status_code=403, detail="当前账户未启用神盾笔记")
    return session_id, session


def verify_note_action_password(username: str, password: str):
    try:
        return CryptoManager.load_note_private_key(username, password)
    except ValueError:
        return None


def decorate_note(note: dict) -> dict:
    note_data = dict(note)
    note_data["created_at_label"] = format_local_timestamp(note_data.get("created_at"))
    note_data["updated_at_label"] = format_local_timestamp(note_data.get("updated_at"))
    note_data["modification_history_labels"] = [
        format_local_timestamp(item) for item in reversed(note_data.get("modification_history", []))
    ]
    note_data["attachment_count"] = len(note_data.get("attachments", []))

    attachments = []
    for attachment in note_data.get("attachments", []):
        attachment_data = dict(attachment)
        attachment_data["created_at_label"] = format_local_timestamp(attachment_data.get("created_at"))
        attachments.append(attachment_data)
    note_data["attachments"] = attachments
    return note_data


def build_common_context(
    request: Request,
    msg: str | None = None,
    current_page: str = "vault",
    auth_mode: str | None = None,
) -> dict:
    status = CryptoManager.get_status()
    exists = (KEY_DIR / "admin.key").exists()
    reinit_required = CryptoManager.requires_reinitialization()
    remaining_seconds = 0

    if status.get("_tampered"):
        log_event(AuditEvent.SYSTEM_DESTROYED, details={"reason": "status_file_tampered"}, success=True)
        CryptoManager.destroy_all()
        session_store.clear()
        msg = "检测到状态文件篡改，系统已自毁"
        status = CryptoManager.get_status()

    if exists and not status["destroyed"] and not reinit_required:
        elapsed = int(time.time()) - status["last_checkin"]
        remaining_seconds = max(0, CHECKIN_TIMEOUT - elapsed)

    session_id, session = get_current_session(request)
    auth = None
    csrf_token = None
    vault_size_mb = None
    note_enabled_map = {}

    session_mode = session.get("mode") if session else None
    session_key_exists = False
    if session:
        session_key_name = f"{session['user']}.key"
        if session_mode == "notes":
            session_key_name = f"{session['user']}.notes.key"
        session_key_exists = (KEY_DIR / session_key_name).exists()

    if (
        session_id
        and session
        and exists
        and not status["destroyed"]
        and not reinit_required
        and session_key_exists
        and (auth_mode is None or session_mode == auth_mode)
    ):
        auth = {"user": session["user"], "is_admin": session["user"] == "admin"}
        csrf_token = session["csrf_token"]
        if session["user"] == "admin" and session_mode == "vault":
            try:
                vault_size_mb = round(get_vault_size() / (1024 * 1024), 2)
            except OSError:
                vault_size_mb = None
                msg = append_message(msg, "保险库容量统计失败，请检查数据目录权限")
            note_enabled_map = {
                user: NotesManager.is_enabled(user) for user in CryptoManager.list_supported_users()
            }

    return {
        "exists": exists,
        "reinit_required": reinit_required,
        "destroyed": status["destroyed"],
        "remaining_total_s": remaining_seconds,
        "auth": auth,
        "msg": msg,
        "duress_active": False,
        "vault_size_mb": vault_size_mb,
        "csrf_token": csrf_token,
        "available_users": CryptoManager.list_supported_users(),
        "max_upload_mb": int(MAX_UPLOAD_SIZE_BYTES / (1024 * 1024)),
        "max_vault_mb": int(MAX_VAULT_SIZE_BYTES / (1024 * 1024)),
        "current_page": current_page,
        "note_enabled_map": note_enabled_map,
    }


def build_vault_context(request: Request, msg: str | None = None) -> dict:
    context = build_common_context(request, msg=msg, current_page="vault", auth_mode="vault")
    files = []
    if context["auth"] and not context["destroyed"]:
        try:
            user_vault = CryptoManager.get_user_vault_path(context["auth"]["user"])
            files = sorted(file_path.name for file_path in user_vault.iterdir() if file_path.is_file())
        except OSError:
            context["msg"] = append_message(context.get("msg"), "保险库目录不可访问，请检查部署目录权限")
            files = []
    context["files"] = files
    return context


def build_notes_context(
    request: Request,
    session_id: str | None = None,
    session: dict | None = None,
    msg: str | None = None,
    selected_note_id: str | None = None,
    selected_note: dict | None = None,
) -> dict:
    context = build_common_context(request, msg=msg, current_page="notes", auth_mode="notes")
    is_create_mode = selected_note_id == "create"
    context["note_entries"] = []
    context["selected_note"] = None
    context["selected_note_id"] = selected_note_id
    context["note_view_requires_password"] = bool(selected_note_id and not is_create_mode)

    if not session:
        current_session_id, current_session = get_current_session(request)
        if session_id is None:
            session_id = current_session_id
        session = current_session if current_session and current_session.get("mode") == "notes" else None
    if not session or not context["auth"]:
        return context

    note_entries = []
    for item in NotesManager.list_note_entries(session["user"]):
        entry = dict(item)
        entry["created_at_label"] = format_local_timestamp(entry.get("created_at"))
        entry["updated_at_label"] = format_local_timestamp(entry.get("updated_at"))
        note_entries.append(entry)

    valid_note_ids = {item["note_id"] for item in note_entries}
    active_note = None
    if selected_note_id and not is_create_mode:
        active_note = session_store.get_active_note(session_id, selected_note_id)

    if not selected_note_id and note_entries:
        selected_note_id = note_entries[0]["note_id"]
        active_note = session_store.get_active_note(session_id, selected_note_id)

    if selected_note_id not in valid_note_ids and not is_create_mode:
        selected_note_id = None
        active_note = None
        selected_note = None

    if selected_note is None and active_note:
        selected_note = active_note["note"]

    context["note_entries"] = note_entries
    context["selected_note"] = decorate_note(selected_note) if selected_note else None
    context["selected_note_id"] = selected_note_id
    context["note_view_requires_password"] = bool(selected_note_id and selected_note is None and selected_note_id != "create")
    return context


def build_logs_context(request: Request, session: dict, msg: str | None = None) -> dict:
    context = build_common_context(request, msg=msg, current_page="logs", auth_mode="vault")
    logs = []
    for event in get_audit_logs(limit=200):
        event_data = dict(event)
        details = event_data.get("details", {})
        detail_items = []
        if isinstance(details, dict):
            for key, value in details.items():
                if isinstance(value, (dict, list)):
                    display_value = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
                elif value is None:
                    display_value = "-"
                else:
                    display_value = str(value)
                detail_items.append({"key": str(key), "value": display_value})
        event_data["timestamp_label"] = format_audit_timestamp(event_data.get("timestamp"))
        event_data["detail_items"] = detail_items
        logs.append(event_data)

    context["logs"] = logs
    context["audit_chain_ok"] = verify_audit_chain()
    context["log_count"] = len(logs)
    context["session_user"] = session["user"]
    return context


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


def validate_password_strength(password: str, min_length: int = 12) -> tuple[bool, str]:
    password = password.strip()
    if len(password) < min_length:
        return False, f"密码长度至少需要 {min_length} 个字符"
    if len(password) > 256:
        return False, "密码长度不能超过 256 个字符"

    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
    if sum([has_upper, has_lower, has_digit, has_special]) < 3:
        return False, "密码必须包含至少 3 种类型：大小写、数字、特殊符号"
    return True, ""


def validate_code_strength(code: str, min_length: int = 8) -> tuple[bool, str]:
    code = code.strip()
    if len(code) < min_length:
        return False, f"码长度至少需要 {min_length} 个字符"
    if len(code) > 256:
        return False, "码长度不能超过 256 个字符"

    has_alphanum = any(c.isalnum() for c in code)
    has_variety = len(set(code)) >= 4
    if not has_alphanum or not has_variety:
        return False, "码必须包含足够的多样性（混合字符和数字）"
    return True, ""


def monitor_switch() -> None:
    CryptoManager.ensure_dirs()
    while True:
        status = CryptoManager.get_status()
        if not status["destroyed"] and (KEY_DIR / "admin.key").exists() and not CryptoManager.requires_reinitialization():
            if status.get("_tampered"):
                CryptoManager.destroy_all()
                log_event(AuditEvent.SYSTEM_DESTROYED, details={"reason": "status_file_tampered"}, success=True)
                session_store.clear()
            else:
                elapsed = int(time.time()) - status["last_checkin"]
                if elapsed > CHECKIN_TIMEOUT:
                    CryptoManager.destroy_all()
                    log_event(
                        AuditEvent.SYSTEM_DESTROYED,
                        details={"reason": "checkin_timeout", "elapsed_seconds": elapsed},
                        success=True,
                    )
                    session_store.clear()
        time.sleep(MONITOR_INTERVAL_SECONDS)


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
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "font-src 'self' data:; "
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
async def index(request: Request):
    return render_page(request, "index.html", build_vault_context(request))


@app.get("/notes", response_class=HTMLResponse)
async def notes_page(request: Request, note: str | None = Query(default=None)):
    session_id, session = get_current_session(request)
    if not session or session.get("mode") != "notes":
        return render_page(request, "notes.html", build_notes_context(request, selected_note_id=note))
    if not NotesManager.is_enabled(session["user"]):
        session_store.destroy(request.cookies.get(SESSION_COOKIE_NAME))
        return render_page(request, "notes.html", build_notes_context(request, msg="当前账户未启用神盾笔记"))
    return render_page(
        request,
        "notes.html",
        build_notes_context(request, session_id=session_id, session=session, selected_note_id=note),
    )


@app.get("/logs", response_class=HTMLResponse)
async def logs_page(request: Request):
    _, session = require_session(request, admin_only=True, required_mode="vault")
    log_event(AuditEvent.AUDIT_VIEWED, user=session["user"], client_ip=client_address(request), success=True)
    return render_page(request, "logs.html", build_logs_context(request, session=session))


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

    if auth_result:
        rate_limiter.reset("login", scope_key)
        session_id, _ = session_store.create(auth_result["user"], client_ip=client_ip, user_agent=user_agent, mode="vault")
        log_event(AuditEvent.AUTH_LOGIN_SUCCESS, user=auth_result["user"], client_ip=client_ip, success=True)
        response = RedirectResponse(url="/", status_code=303)
        set_session_cookie(response, session_id)
        return response

    notes_auth_result = NotesManager.authenticate(password)
    if not notes_auth_result:
        retry_after = rate_limiter.failure("login", scope_key)
        log_event(
            AuditEvent.AUTH_LOGIN_FAILED,
            client_ip=client_ip,
            details={"reason": "invalid_password"},
            success=False,
        )
        if retry_after:
            return redirect_with_message(f"尝试过多，请在 {retry_after} 秒后重试")
        return redirect_with_message("身份验证失败")

    rate_limiter.reset("login", scope_key)
    session_id, _ = session_store.create(notes_auth_result["user"], client_ip=client_ip, user_agent=user_agent, mode="notes")
    log_event(AuditEvent.NOTE_ACCESS_SUCCESS, user=notes_auth_result["user"], client_ip=client_ip, success=True)
    response = RedirectResponse(url="/notes", status_code=303)
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
    request: Request,
    master_password: str = Form(...),
    confirm_master_password: str = Form(...),
    checkin_code: str = Form(...),
):
    if (KEY_DIR / "admin.key").exists():
        return redirect_with_message("系统已初始化")
    if master_password != confirm_master_password:
        return redirect_with_message("两次输入的管理员密码不一致")

    valid, msg = validate_password_strength(master_password)
    if not valid:
        return redirect_with_message(msg)
    valid, msg = validate_code_strength(checkin_code)
    if not valid:
        return redirect_with_message(msg)

    CryptoManager.init_admin(master_password, checkin_code)
    log_event(
        AuditEvent.SYSTEM_RESET,
        client_ip=client_address(request),
        details={"action": "initialization"},
        success=True,
    )
    return redirect_with_message("初始化完成，请登录")


@app.post("/reset")
async def reset(request: Request, csrf_token: str | None = Form(None)):
    status = CryptoManager.get_status()
    session = None
    if not status["destroyed"] and not CryptoManager.requires_reinitialization():
        _, session = require_session(request, csrf_token=csrf_token, admin_only=True, required_mode="vault")
    session_store.clear()
    CryptoManager.reset_system()
    log_event(
        AuditEvent.SYSTEM_RESET,
        user=session["user"] if session else None,
        client_ip=client_address(request),
        details={"action": "manual_reset"},
        success=True,
    )
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
    _, session = require_session(request, csrf_token=csrf_token, admin_only=True, required_mode="vault")

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
    log_event(
        AuditEvent.USER_PASSWORD_UPDATED,
        user=session["user"],
        client_ip=client_address(request),
        details={"target_user": target_user},
        success=True,
    )
    session_store.invalidate_user(target_user)

    if target_user == "admin":
        response = redirect_with_message("管理员密码已更新，请重新登录")
        clear_session_cookie(response)
        return response
    return redirect_with_message(f"用户 {target_user} 密钥已更新")


@app.post("/manage_notes_feature")
async def manage_notes_feature(
    request: Request,
    csrf_token: str = Form(...),
    target_user: str = Form(...),
    enabled: str | None = Form(None),
    note_password: str = Form(""),
    confirm_note_password: str = Form(""),
):
    _, session = require_session(request, csrf_token=csrf_token, admin_only=True, required_mode="vault")

    try:
        CryptoManager.validate_username(target_user)
    except ValueError as exc:
        return redirect_with_message(str(exc))

    should_enable = enabled == "on"
    note_password = note_password.strip()
    confirm_note_password = confirm_note_password.strip()

    if should_enable:
        requires_password = not NotesManager.note_keys_exist(target_user) or bool(note_password)
        if requires_password:
            if note_password != confirm_note_password:
                return redirect_with_message("两次输入的笔记密码不一致")
            valid, msg = validate_password_strength(note_password)
            if not valid:
                return redirect_with_message(msg)
            if NotesManager.note_keys_exist(target_user) and NotesManager.has_any_notes(target_user):
                return redirect_with_message("目标用户已有笔记，当前版本禁止直接重置笔记密钥")
            CryptoManager.create_note_keys(target_user, note_password)

        NotesManager.set_enabled(target_user, True)
        session_store.invalidate_user(target_user)
        log_event(
            AuditEvent.NOTE_FEATURE_UPDATED,
            user=session["user"],
            client_ip=client_address(request),
            details={"target_user": target_user, "enabled": True},
            success=True,
        )
        return redirect_with_message(f"{target_user} 的神盾笔记已启用")

    NotesManager.set_enabled(target_user, False)
    session_store.invalidate_user(target_user)
    log_event(
        AuditEvent.NOTE_FEATURE_UPDATED,
        user=session["user"],
        client_ip=client_address(request),
        details={"target_user": target_user, "enabled": False},
        success=True,
    )
    return redirect_with_message(f"{target_user} 的神盾笔记已关闭")


@app.post("/update_checkin_code")
async def update_checkin_code(request: Request, csrf_token: str = Form(...), new_code: str = Form(...)):
    _, session = require_session(request, csrf_token=csrf_token, admin_only=True, required_mode="vault")
    valid, msg = validate_code_strength(new_code)
    if not valid:
        return redirect_with_message(msg)

    CryptoManager.set_checkin_code(new_code)
    log_event(AuditEvent.CHECKIN_CODE_UPDATED, user=session["user"], client_ip=client_address(request), success=True)
    return redirect_with_message("签到协议更新成功")


@app.post("/update_duress_code")
async def update_duress_code(request: Request, csrf_token: str = Form(...), duress_code: str = Form(...)):
    _, session = require_session(request, csrf_token=csrf_token, admin_only=True, required_mode="vault")
    valid, msg = validate_code_strength(duress_code)
    if not valid:
        return redirect_with_message(msg)

    CryptoManager.set_duress_code(duress_code)
    log_event(AuditEvent.DURESS_CODE_UPDATED, user=session["user"], client_ip=client_address(request), success=True)
    return redirect_with_message("胁迫销毁协议已激活")


@app.post("/upload")
async def upload(request: Request, csrf_token: str = Form(...), file: UploadFile = File(...)):
    _, session = require_session(request, csrf_token=csrf_token, required_mode="vault")
    try:
        safe_name = CryptoManager.normalize_filename(file.filename or "")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    content = read_upload_bytes(file, MAX_UPLOAD_SIZE_BYTES)
    if get_vault_size() + len(content) > MAX_VAULT_SIZE_BYTES:
        raise HTTPException(status_code=400, detail=f"保险库已满 ({int(MAX_VAULT_SIZE_BYTES / (1024 * 1024))}MB 限制)")

    CryptoManager.encrypt_file(content, safe_name, session["user"])
    log_event(
        AuditEvent.FILE_UPLOADED,
        user=session["user"],
        client_ip=client_address(request),
        details={"filename": safe_name, "size_bytes": len(content)},
        success=True,
    )
    return redirect_with_message("上传成功")


@app.post("/delete_file")
async def delete_file(
    request: Request,
    csrf_token: str = Form(...),
    filename: str = Form(...),
    password: str = Form(...),
):
    _, session = require_session(request, csrf_token=csrf_token, required_mode="vault")
    client_ip = client_address(request)
    scope_key = f"{client_ip}:{session['user']}"
    retry_after = rate_limiter.check("delete_file", scope_key)
    if retry_after:
        log_event(
            AuditEvent.RATE_LIMIT_EXCEEDED,
            user=session["user"],
            client_ip=client_ip,
            details={"action": "delete_file"},
            success=False,
        )
        return redirect_with_message(f"删除尝试过多，请在 {retry_after} 秒后重试")

    try:
        private_key = CryptoManager.load_private_key(session["user"], password)
    except ValueError:
        private_key = None

    if private_key is None:
        retry_after = rate_limiter.failure("delete_file", scope_key)
        log_event(
            AuditEvent.FILE_DELETED,
            user=session["user"],
            client_ip=client_ip,
            details={"filename": filename, "status": "invalid_password"},
            success=False,
        )
        if retry_after:
            return redirect_with_message(f"删除尝试过多，请在 {retry_after} 秒后重试")
        return redirect_with_message("访问密码错误")

    try:
        safe_name = CryptoManager.normalize_filename(filename)
        CryptoManager.delete_encrypted_file(session["user"], safe_name)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="文件不存在") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    rate_limiter.reset("delete_file", scope_key)
    log_event(
        AuditEvent.FILE_DELETED,
        user=session["user"],
        client_ip=client_ip,
        details={"filename": safe_name},
        success=True,
    )
    return redirect_with_message("文件已删除")


@app.post("/download")
async def download(
    request: Request,
    filename: str = Form(...),
    csrf_token: str = Form(...),
    password: str = Form(...),
):
    _, session = require_session(request, csrf_token=csrf_token, required_mode="vault")
    client_ip = client_address(request)
    scope_key = f"{client_ip}:{session['user']}"
    retry_after = rate_limiter.check("download", scope_key)
    if retry_after:
        log_event(
            AuditEvent.RATE_LIMIT_EXCEEDED,
            user=session["user"],
            client_ip=client_ip,
            details={"action": "download"},
            success=False,
        )
        return redirect_with_message(f"下载尝试过多，请在 {retry_after} 秒后重试")

    try:
        safe_name = CryptoManager.normalize_filename(filename)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    try:
        private_key = CryptoManager.load_private_key(session["user"], password)
    except ValueError:
        private_key = None

    if private_key is None:
        retry_after = rate_limiter.failure("download", scope_key)
        log_event(
            AuditEvent.FILE_DOWNLOADED,
            user=session["user"],
            client_ip=client_ip,
            details={"filename": filename, "status": "invalid_password"},
            success=False,
        )
        if retry_after:
            return redirect_with_message(f"下载尝试过多，请在 {retry_after} 秒后重试")
        return redirect_with_message("访问密码错误")

    try:
        decrypted_content = CryptoManager.decrypt_file(safe_name, session["user"], private_key)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="文件不存在") from exc
    except Exception:
        retry_after = rate_limiter.failure("download", scope_key)
        log_event(
            AuditEvent.FILE_DOWNLOADED,
            user=session["user"],
            client_ip=client_ip,
            details={"filename": filename, "status": "decrypt_failed"},
            success=False,
        )
        if retry_after:
            return redirect_with_message(f"下载尝试过多，请在 {retry_after} 秒后重试")
        return redirect_with_message("解密失败")

    rate_limiter.reset("download", scope_key)
    download_name = safe_name[:-4] if safe_name.endswith(".aes") else safe_name
    log_event(
        AuditEvent.FILE_DOWNLOADED,
        user=session["user"],
        client_ip=client_ip,
        details={"filename": safe_name, "size_bytes": len(decrypted_content)},
        success=True,
    )
    return download_bytes_response(decrypted_content, download_name)


@app.post("/notes/view")
async def view_note(
    request: Request,
    csrf_token: str = Form(...),
    note_id: str = Form(...),
    note_password: str = Form(...),
):
    session_id, session = require_note_session(request, csrf_token=csrf_token)
    client_ip = client_address(request)
    scope_key = f"{client_ip}:{session['user']}:{note_id}"
    retry_after = rate_limiter.check("view_note", scope_key)
    if retry_after:
        log_event(
            AuditEvent.RATE_LIMIT_EXCEEDED,
            user=session["user"],
            client_ip=client_ip,
            details={"action": "view_note", "note_id": note_id},
            success=False,
        )
        return redirect_with_message(f"尝试过多，请在 {retry_after} 秒后重试", f"/notes?note={note_id}")

    note_private_key = verify_note_action_password(session["user"], note_password)
    if note_private_key is None:
        retry_after = rate_limiter.failure("view_note", scope_key)
        log_event(
            AuditEvent.NOTE_ACCESS_FAILED,
            user=session["user"],
            client_ip=client_ip,
            details={"reason": "invalid_note_password", "note_id": note_id},
            success=False,
        )
        if retry_after:
            return redirect_with_message(f"尝试过多，请在 {retry_after} 秒后重试", f"/notes?note={note_id}")
        return redirect_with_message("笔记密码错误", f"/notes?note={note_id}")

    try:
        selected_note = NotesManager.get_note(session["user"], note_id, note_private_key)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="笔记不存在") from exc

    rate_limiter.reset("view_note", scope_key)
    session_store.set_active_note(session_id, note_id, selected_note)
    log_event(
        AuditEvent.NOTE_ACCESS_SUCCESS,
        user=session["user"],
        client_ip=client_ip,
        details={"action": "view_note", "note_id": note_id},
        success=True,
    )
    return render_page(
        request,
        "notes.html",
        build_notes_context(
            request,
            session_id=session_id,
            session=session,
            selected_note_id=note_id,
            selected_note=selected_note,
        ),
    )


@app.post("/notes/save")
async def save_note(
    request: Request,
    csrf_token: str = Form(...),
    note_id: str = Form(""),
    title: str = Form(""),
    content: str = Form(""),
):
    session_id, session = require_note_session(request, csrf_token=csrf_token)
    note_id = note_id.strip()
    existing_note = None
    if note_id:
        active_note = session_store.get_active_note(session_id, note_id)
        if not active_note:
            return redirect_with_message("请先输入笔记密码查看当前笔记", f"/notes?note={note_id}")
        existing_note = active_note["note"]

    try:
        saved_note_id, saved_note = NotesManager.save_note(
            username=session["user"],
            note_id=note_id or None,
            title=title,
            content=content,
            existing_note=existing_note,
        )
    except ValueError:
        redirect_note = note_id or "create"
        return redirect_with_message("请先输入笔记密码查看当前笔记", f"/notes?note={redirect_note}")

    session_store.set_active_note(session_id, saved_note_id, saved_note)
    log_event(
        AuditEvent.NOTE_SAVED,
        user=session["user"],
        client_ip=client_address(request),
        details={"note_id": saved_note_id, "title": (title or "").strip() or "未命名笔记"},
        success=True,
    )
    return redirect_with_message("笔记已保存", f"/notes?note={saved_note_id}")


@app.post("/notes/delete")
async def delete_note(
    request: Request,
    csrf_token: str = Form(...),
    note_id: str = Form(...),
    note_password: str = Form(...),
):
    session_id, session = require_note_session(request, csrf_token=csrf_token)
    client_ip = client_address(request)
    scope_key = f"{client_ip}:{session['user']}"
    retry_after = rate_limiter.check("delete_note", scope_key)
    if retry_after:
        log_event(
            AuditEvent.RATE_LIMIT_EXCEEDED,
            user=session["user"],
            client_ip=client_ip,
            details={"action": "delete_note"},
            success=False,
        )
        return redirect_with_message(f"删除尝试过多，请在 {retry_after} 秒后重试", f"/notes?note={note_id}")

    confirmed_note_key = verify_note_action_password(session["user"], note_password)
    if confirmed_note_key is None:
        retry_after = rate_limiter.failure("delete_note", scope_key)
        log_event(
            AuditEvent.NOTE_DELETED,
            user=session["user"],
            client_ip=client_ip,
            details={"note_id": note_id, "status": "invalid_password"},
            success=False,
        )
        if retry_after:
            return redirect_with_message(f"删除尝试过多，请在 {retry_after} 秒后重试", f"/notes?note={note_id}")
        return redirect_with_message("笔记密码错误", f"/notes?note={note_id}")

    try:
        NotesManager.delete_note(session["user"], note_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="笔记不存在") from exc

    rate_limiter.reset("delete_note", scope_key)
    session_store.clear_active_note(session_id, note_id)
    log_event(
        AuditEvent.NOTE_DELETED,
        user=session["user"],
        client_ip=client_ip,
        details={"note_id": note_id},
        success=True,
    )
    return redirect_with_message("笔记已删除", "/notes")


@app.post("/notes/attachment/upload")
async def upload_note_attachment(
    request: Request,
    csrf_token: str = Form(...),
    note_id: str = Form(...),
    file: UploadFile = File(...),
):
    session_id, session = require_note_session(request, csrf_token=csrf_token)
    active_note = session_store.get_active_note(session_id, note_id)
    if not active_note:
        return redirect_with_message("请先输入笔记密码查看当前笔记", f"/notes?note={note_id}")
    if not str(file.content_type or "").startswith("image/"):
        raise HTTPException(status_code=400, detail="笔记附件仅支持图片文件")
    try:
        safe_name = CryptoManager.normalize_filename(file.filename or "")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    content = read_upload_bytes(file, MAX_UPLOAD_SIZE_BYTES)
    if get_vault_size() + len(content) > MAX_VAULT_SIZE_BYTES:
        raise HTTPException(status_code=400, detail=f"保险库已满 ({int(MAX_VAULT_SIZE_BYTES / (1024 * 1024))}MB 限制)")

    attachment, updated_note = NotesManager.add_attachment(
        session["user"],
        note_id,
        safe_name,
        content,
        active_note["note"],
    )
    session_store.set_active_note(session_id, note_id, updated_note)
    log_event(
        AuditEvent.NOTE_ATTACHMENT_UPLOADED,
        user=session["user"],
        client_ip=client_address(request),
        details={"note_id": note_id, "filename": safe_name, "attachment_id": attachment["attachment_id"]},
        success=True,
    )
    return redirect_with_message("附件已上传", f"/notes?note={note_id}")


@app.post("/notes/attachment/download")
async def download_note_attachment(
    request: Request,
    csrf_token: str = Form(...),
    note_id: str = Form(...),
    attachment_id: str = Form(...),
    note_password: str = Form(...),
):
    _, session = require_note_session(request, csrf_token=csrf_token)
    client_ip = client_address(request)
    note_private_key = verify_note_action_password(session["user"], note_password)
    if note_private_key is None:
        log_event(
            AuditEvent.NOTE_ATTACHMENT_DOWNLOADED,
            user=session["user"],
            client_ip=client_ip,
            details={"note_id": note_id, "attachment_id": attachment_id, "status": "invalid_password"},
            success=False,
        )
        return redirect_with_message("笔记密码错误", f"/notes?note={note_id}")
    try:
        attachment, content = NotesManager.get_attachment(session["user"], note_id, attachment_id, note_private_key)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="附件不存在") from exc

    log_event(
        AuditEvent.NOTE_ATTACHMENT_DOWNLOADED,
        user=session["user"],
        client_ip=client_ip,
        details={"note_id": note_id, "attachment_id": attachment_id, "filename": attachment["name"]},
        success=True,
    )
    return download_bytes_response(content, attachment["name"])


@app.post("/notes/attachment/delete")
async def delete_note_attachment(
    request: Request,
    csrf_token: str = Form(...),
    note_id: str = Form(...),
    attachment_id: str = Form(...),
    note_password: str = Form(...),
):
    session_id, session = require_note_session(request, csrf_token=csrf_token)
    client_ip = client_address(request)
    scope_key = f"{client_ip}:{session['user']}"
    retry_after = rate_limiter.check("delete_note_attachment", scope_key)
    if retry_after:
        log_event(
            AuditEvent.RATE_LIMIT_EXCEEDED,
            user=session["user"],
            client_ip=client_ip,
            details={"action": "delete_note_attachment"},
            success=False,
        )
        return redirect_with_message(f"删除尝试过多，请在 {retry_after} 秒后重试", f"/notes?note={note_id}")

    confirmed_note_key = verify_note_action_password(session["user"], note_password)
    if confirmed_note_key is None:
        retry_after = rate_limiter.failure("delete_note_attachment", scope_key)
        log_event(
            AuditEvent.NOTE_ATTACHMENT_DELETED,
            user=session["user"],
            client_ip=client_ip,
            details={"note_id": note_id, "attachment_id": attachment_id, "status": "invalid_password"},
            success=False,
        )
        if retry_after:
            return redirect_with_message(f"删除尝试过多，请在 {retry_after} 秒后重试", f"/notes?note={note_id}")
        return redirect_with_message("笔记密码错误", f"/notes?note={note_id}")

    try:
        note_private_key = verify_note_action_password(session["user"], note_password)
        if note_private_key is None:
            raise ValueError("invalid_note_password")
        attachment, updated_note = NotesManager.delete_attachment(
            session["user"],
            note_id,
            attachment_id,
            note_private_key,
        )
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="附件不存在") from exc
    except ValueError:
        retry_after = rate_limiter.failure("delete_note_attachment", scope_key)
        log_event(
            AuditEvent.NOTE_ATTACHMENT_DELETED,
            user=session["user"],
            client_ip=client_ip,
            details={"note_id": note_id, "attachment_id": attachment_id, "status": "invalid_password"},
            success=False,
        )
        if retry_after:
            return redirect_with_message(f"删除尝试过多，请在 {retry_after} 秒后重试", f"/notes?note={note_id}")
        return redirect_with_message("笔记密码错误", f"/notes?note={note_id}")

    rate_limiter.reset("delete_note_attachment", scope_key)
    session_store.set_active_note(session_id, note_id, updated_note)
    log_event(
        AuditEvent.NOTE_ATTACHMENT_DELETED,
        user=session["user"],
        client_ip=client_ip,
        details={"note_id": note_id, "attachment_id": attachment_id, "filename": attachment["name"]},
        success=True,
    )
    return redirect_with_message("附件已删除", f"/notes?note={note_id}")


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    target_url = "/"
    detail = exc.detail if isinstance(exc.detail, str) else "请求失败"
    _, session = get_current_session(request)
    log_event(
        AuditEvent.INVALID_REQUEST,
        user=session.get("user") if session else None,
        client_ip=client_address(request),
        details={"method": request.method, "path": request.url.path, "status_code": exc.status_code, "detail": detail},
        success=False,
    )
    if request.url.path.startswith("/notes") and detail in {"需要输入笔记密码", "笔记访问失败"}:
        target_url = "/notes"
    return redirect_with_message(detail, target_url)


if __name__ == "__main__":
    port = int(os.getenv("PORT", 46746))
    uvicorn.run(app, host="0.0.0.0", port=port)
