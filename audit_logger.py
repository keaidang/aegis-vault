"""
审计日志系统 - 记录所有安全相关的关键操作
支持链式哈希以防篡改
"""
import json
import logging
import os
import threading
import hashlib
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

AUDIT_LOG_PATH = Path(os.getenv("AUDIT_LOG_DIR", "./data")) / "audit.log"
AUDIT_LOG_HASH_PATH = Path(os.getenv("AUDIT_LOG_DIR", "./data")) / "audit.hash"
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


def _compute_chain_hash(current_hash: str, previous_hash: str = "") -> str:
    """计算链式哈希"""
    chain_input = f"{previous_hash}:{current_hash}"
    return hashlib.sha256(chain_input.encode()).hexdigest()


def _get_previous_chain_hash() -> str:
    """获取前一条日志的链式哈希"""
    if not AUDIT_LOG_HASH_PATH.exists():
        return ""
    try:
        with open(AUDIT_LOG_HASH_PATH, "r") as f:
            return f.read().strip()
    except Exception:
        return ""


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
        
        # 计算事件的哈希
        event_json = json.dumps(event_data, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
        event_hash = hashlib.sha256(event_json.encode()).hexdigest()
        
        # 获取前一条的链式哈希
        previous_chain_hash = _get_previous_chain_hash()
        
        # 计算本条的链式哈希
        chain_hash = _compute_chain_hash(event_hash, previous_chain_hash)
        
        # 添加链式哈希到事件数据
        event_data["_hash"] = event_hash
        event_data["_chain_hash"] = chain_hash
        
        # 日志级别
        level = logging.INFO if success else logging.WARNING
        
        # 记录为 JSON 便于解析
        audit_logger.log(level, json.dumps(event_data, ensure_ascii=False))
        
        # 更新链式哈希文件
        try:
            with open(AUDIT_LOG_HASH_PATH, "w") as f:
                f.write(chain_hash)
        except Exception:
            pass


def verify_audit_chain() -> bool:
    """验证审计日志的链式完整性"""
    if not AUDIT_LOG_PATH.exists():
        return True
    
    try:
        with audit_lock:
            with open(AUDIT_LOG_PATH, "r", encoding="utf-8") as f:
                lines = f.readlines()
            
            previous_chain_hash = ""
            for line in lines:
                try:
                    if " - AUDIT - " not in line:
                        continue
                    
                    json_str = line.split(" - AUDIT - ", 1)[1].strip()
                    event = json.loads(json_str)
                    
                    event_hash = event.get("_hash", "")
                    chain_hash = event.get("_chain_hash", "")
                    
                    # 验证链式哈希
                    expected_chain = _compute_chain_hash(event_hash, previous_chain_hash)
                    if chain_hash != expected_chain:
                        return False
                    
                    previous_chain_hash = chain_hash
                except (json.JSONDecodeError, IndexError):
                    continue
            
            return True
    except Exception:
        return False


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
