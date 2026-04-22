"""
审计日志系统 - 记录所有安全相关的关键操作
"""
import json
import logging
import os
import threading
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

AUDIT_LOG_PATH = Path(os.getenv("AUDIT_LOG_DIR", "./data")) / "audit.log"
AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(AUDIT_LOG_PATH),
        logging.StreamHandler()
    ]
)

audit_logger = logging.getLogger("AUDIT")
audit_lock = threading.RLock()


class AuditEvent:
    """审计事件"""
    
    # 事件类型常量
    AUTH_LOGIN_SUCCESS = "AUTH_LOGIN_SUCCESS"
    AUTH_LOGIN_FAILED = "AUTH_LOGIN_FAILED"
    AUTH_LOGOUT = "AUTH_LOGOUT"
    CHECKIN_SUCCESS = "CHECKIN_SUCCESS"
    CHECKIN_FAILED = "CHECKIN_FAILED"
    DURESS_TRIGGERED = "DURESS_TRIGGERED"
    FILE_UPLOADED = "FILE_UPLOADED"
    FILE_DOWNLOADED = "FILE_DOWNLOADED"
    FILE_DELETED = "FILE_DELETED"
    SYSTEM_DESTROYED = "SYSTEM_DESTROYED"
    SYSTEM_RESET = "SYSTEM_RESET"
    USER_CREATED = "USER_CREATED"
    USER_PASSWORD_UPDATED = "USER_PASSWORD_UPDATED"
    CHECKIN_CODE_UPDATED = "CHECKIN_CODE_UPDATED"
    DURESS_CODE_UPDATED = "DURESS_CODE_UPDATED"
    RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"
    INVALID_REQUEST = "INVALID_REQUEST"


def log_event(
    event_type: str,
    user: str | None = None,
    client_ip: str | None = None,
    details: dict | None = None,
    success: bool = True
) -> None:
    """
    记录审计事件
    
    Args:
        event_type: 事件类型
        user: 用户名
        client_ip: 客户端 IP
        details: 事件详情字典
        success: 是否成功
    """
    with audit_lock:
        event_data = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "event_type": event_type,
            "user": user or "anonymous",
            "client_ip": client_ip or "unknown",
            "success": success,
            "details": details or {}
        }
        
        # 日志级别
        level = logging.INFO if success else logging.WARNING
        
        # 记录为 JSON 便于解析
        audit_logger.log(level, json.dumps(event_data, ensure_ascii=False))


def get_audit_logs(limit: int = 100, event_type: str | None = None) -> list[dict]:
    """
    获取审计日志
    
    Args:
        limit: 返回的最大日志数
        event_type: 过滤的事件类型，为 None 时返回所有
        
    Returns:
        审计事件列表
    """
    logs = []
    
    if not AUDIT_LOG_PATH.exists():
        return logs
    
    with audit_lock:
        try:
            with open(AUDIT_LOG_PATH, "r", encoding="utf-8") as f:
                lines = f.readlines()
                # 从末尾开始读取，最多 limit 条
                for line in reversed(lines[-limit * 10:]):
                    try:
                        # 解析 JSON 日志
                        if " - AUDIT - " in line:
                            json_str = line.split(" - AUDIT - ", 1)[1].strip()
                            event = json.loads(json_str)
                            
                            if event_type is None or event.get("event_type") == event_type:
                                logs.append(event)
                                
                            if len(logs) >= limit:
                                break
                    except (json.JSONDecodeError, IndexError):
                        continue
        except Exception as e:
            audit_logger.error(f"读取审计日志失败: {e}")
    
    return logs
