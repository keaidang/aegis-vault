from fastapi import FastAPI, Form, UploadFile, File, Request, BackgroundTasks, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse
from fastapi.templating import Jinja2Templates
import uvicorn
import os
import time
import threading
from pathlib import Path
from dotenv import load_dotenv

# 加载配置
load_dotenv()

from crypto import CryptoManager, CHECKIN_TIMEOUT, KEY_DIR, VAULT_DIR

app = FastAPI()
# 支持自定义模板路径
TEMPLATE_DIR = os.getenv("TEMPLATE_DIR", "/root/aegis-vault/templates")
templates = Jinja2Templates(directory=TEMPLATE_DIR)

def monitor_switch():
    CryptoManager.ensure_dirs()
    while True:
        status = CryptoManager.get_status()
        if not status["destroyed"] and (KEY_DIR / "admin.key").exists():
            elapsed = int(time.time()) - status["last_checkin"]
            if elapsed > CHECKIN_TIMEOUT:
                CryptoManager.destroy_all()
        time.sleep(60)

@app.on_event("startup")
async def startup_event():
    threading.Thread(target=monitor_switch, daemon=True).start()

def get_vault_size():
    total = 0
    if VAULT_DIR.exists():
        for f in VAULT_DIR.rglob("*"):
            if f.is_file():
                total += f.stat().st_size
    return total

@app.get("/", response_class=HTMLResponse)
async def index(request: Request, msg: str = None):
    status = CryptoManager.get_status()
    exists = (KEY_DIR / "admin.key").exists()
    elapsed = int(time.time()) - status["last_checkin"]
    remaining_seconds = max(0, CHECKIN_TIMEOUT - elapsed)
    
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "exists": exists,
            "destroyed": status["destroyed"],
            "remaining_total_s": remaining_seconds,
            "auth": None,
            "msg": msg
        }
    )

@app.post("/", response_class=HTMLResponse)
async def index_post(
    request: Request, 
    password: str = Form(None), 
    checkin_code: str = Form(None), 
    msg_override: str = None
):
    status = CryptoManager.get_status()
    exists = (KEY_DIR / "admin.key").exists()
    elapsed = int(time.time()) - status["last_checkin"]
    remaining_seconds = max(0, CHECKIN_TIMEOUT - elapsed)

    msg = msg_override
    duress_triggered = False
    
    # 严谨判定签到码：排除 FastAPI Form 对象、空字符串和 None
    is_form_obj = "Form" in str(checkin_code)
    actual_checkin_code = None if (is_form_obj or not checkin_code or str(checkin_code).strip() == "") else checkin_code

    if actual_checkin_code:
        if CryptoManager.verify_duress(actual_checkin_code):
            CryptoManager.destroy_all()
            duress_triggered = True
        elif CryptoManager.verify_checkin(actual_checkin_code):
            CryptoManager.update_checkin()
            msg = "签到成功，计时器已重置"
            remaining_seconds = CHECKIN_TIMEOUT
        else:
            msg = "签到码错误"

    # 处理登录
    auth_user = None
    files = []
    if password and not duress_triggered:
        auth_user = CryptoManager.authenticate(password)
        if auth_user == "DURESS_TRIGGERED":
            duress_triggered = True
            auth_user = None
        elif auth_user:
            user_vault = CryptoManager.get_user_vault_path(auth_user)
            files = [f.name for f in user_vault.iterdir() if f.is_file()]
        else:
            # 明确清空密码并设置错误提示，强制触发前端返回登录界面
            password = None
            if not msg: msg = "身份验证失败或会话已过期"

    # 计算保险库大小逻辑保护
    v_size = 0
    if auth_user == "admin":
        v_size = round(get_vault_size() / (1024*1024), 2)

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "exists": exists,
            "destroyed": status["destroyed"],
            "remaining_total_s": remaining_seconds,
            "auth": {"user": auth_user, "password": password} if (auth_user and password) else None,
            "files": files,
            "msg": msg,
            "duress_active": duress_triggered,
            "vault_size_mb": v_size if auth_user == "admin" else None
        }
    )

@app.post("/setup")
async def setup(master_password: str = Form(...), checkin_code: str = Form(...)):
    if not (KEY_DIR / "admin.key").exists():
        CryptoManager.init_admin(master_password, checkin_code)
    return RedirectResponse(url="/", status_code=303)

@app.post("/reset")
async def reset():
    CryptoManager.reset_system()
    return RedirectResponse(url="/", status_code=303)

@app.post("/manage_user")
async def manage_user(request: Request, admin_pass: str = Form(...), target_user: str = Form(...), target_pass: str = Form(...)):
    auth_user = CryptoManager.authenticate(admin_pass)
    if auth_user == "admin":
        CryptoManager.create_user_keys(target_user, target_pass)
        if target_user == "admin":
            return RedirectResponse(url="/?msg=管理员密码已更新，请重新登录", status_code=303)
        return await index_post(request, password=admin_pass, checkin_code=None, msg_override=f"用户 {target_user} 密码更新成功")
    raise HTTPException(status_code=403)

@app.post("/update_checkin_code")
async def update_checkin_code(request: Request, admin_pass: str = Form(...), new_code: str = Form(...)):
    if CryptoManager.authenticate(admin_pass) == "admin":
        CryptoManager.set_checkin_code(new_code)
        return await index_post(request, password=admin_pass, checkin_code=None, msg_override="签到协议更新成功")
    raise HTTPException(status_code=403)

@app.post("/update_duress_code")
async def update_duress_code(request: Request, admin_pass: str = Form(...), duress_code: str = Form(...)):
    if CryptoManager.authenticate(admin_pass) == "admin":
        CryptoManager.set_duress_code(duress_code)
        return await index_post(request, password=admin_pass, checkin_code=None, msg_override="胁迫销毁协议已激活")
    raise HTTPException(status_code=403)

@app.post("/upload")
async def upload(request: Request, password: str = Form(...), file: UploadFile = File(...)):
    user = CryptoManager.authenticate(password)
    if not user: raise HTTPException(status_code=403)
    
    content = await file.read()
    if get_vault_size() + len(content) > 1024 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="保险库已满 (1GB 限制)")
    
    CryptoManager.encrypt_file(content, file.filename, user)
    return await index_post(request, password=password, msg_override="上传成功")

@app.post("/download")
async def download(filename: str = Form(...), password: str = Form(...)):
    user = CryptoManager.authenticate(password)
    if not user: raise HTTPException(status_code=403)
    try:
        decrypted_content = CryptoManager.decrypt_file(filename, user, password)
        # 使用临时文件返回
        temp_dir = Path("/tmp/aegis")
        temp_dir.mkdir(exist_ok=True)
        temp_path = temp_dir / filename.replace(".aes", "")
        temp_path.write_bytes(decrypted_content)
        return FileResponse(temp_path, filename=temp_path.name)
    except Exception as e:
        return RedirectResponse(url=f"/?msg=解密失败: {str(e)}", status_code=303)

if __name__ == "__main__":
    port = int(os.getenv("PORT", 46746))
    uvicorn.run(app, host="0.0.0.0", port=port)
