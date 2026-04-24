# 🛡️ Aegis Vault (宙斯盾保险库)

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/docker-supported-green.svg)](https://www.docker.com/)

**Aegis Vault** 是一个面向高隐私、高胁迫场景的自托管加密保险库。它不是通用网盘，而是一个强调“失联自毁、胁迫销毁、最小暴露面”的小型 FastAPI 单体应用。

它的目标很明确：

- 在正常场景下提供按用户隔离的加密文件存储
- 在用户长期未签到时自动触发销毁
- 在遭遇胁迫时允许通过伪装成正常输入的方式直接销毁系统
- 在部署层面保持足够简单，便于个人或小团队自托管与审计

---

## 📖 项目定位

传统加密存储默认的前提通常是“只要密码没泄露，数据就是安全的”。但真实威胁往往不是这么干净：

- 设备被扣押
- 服务器被接管
- 使用者被迫交出口令
- 使用者失联，敏感数据不应无限期保留

Aegis Vault 试图处理的就是这些高压场景。它提供：

- **Dead Man's Switch**：长时间未签到时自动销毁
- **Duress Destruction**：输入胁迫码时立即销毁
- **Per-user Encryption**：每个用户独立密钥、独立保险库目录
- **Tamper Detection**：状态文件和审计日志具备防篡改能力

这不是成熟的企业级零信任文件平台，也不是多租户协作系统。它更适合小范围、固定成员、强安全偏好的部署。

---

## ✨ 当前功能

### 核心能力

- 首次启动初始化管理员账户和签到协议
- 固定四个账户槽位：`admin`、`user1`、`user2`、`user3`
- 每个用户独立 RSA-4096 密钥对与独立保险库目录
- 支持统一登录入口，自动识别“保险库口令”或“笔记口令”并进入对应模式
- 文件上传时使用 AES-256-GCM 加密，再用用户公钥封装随机文件密钥
- 登录后使用服务端会话，不再通过前端隐藏字段传递明文密码
- 已登录界面接入 60 秒无操作自动登出倒计时
- 每次下载文件都需要再次输入当前用户访问密码
- 管理员可按用户启用或关闭“神盾笔记”，并为其设置独立笔记密码
- 神盾笔记使用独立 RSA-4096 密钥对、独立目录与独立会话模式
- 支持新建、查看、编辑、删除加密笔记
- 支持为单篇笔记上传、下载、删除图片附件
- 查看笔记、删除笔记、下载附件、删除附件时都要求重新输入笔记密码
- 提供审计日志页面，支持直接查看最近日志与链完整性状态
- 支持签到重置倒计时
- 支持设置和更新胁迫销毁码
- 支持密钥与密文的安全删除 / 物理粉碎
- 支持移动端与桌面端自适应界面

### 已落地的安全加固

- `HttpOnly` 会话 Cookie
- CSRF Token 防护
- 登录 / 签到失败限流
- 会话绑定客户端特征（IP + User-Agent 指纹）
- 笔记查看 / 删除 / 附件删除的失败限流与审计
- `status.json` 的 HMAC-SHA256 完整性保护
- 审计日志链式哈希防篡改
- 文件名规范化与路径穿越防护
- 笔记模式与保险库模式分离，界面不互相暴露直达入口
- 下载后的临时明文文件自动清理
- 管理员重置接口鉴权
- 已有加密文件时禁止直接重建该用户密钥
- 已有笔记时禁止直接重置该用户笔记密钥
- 基础密码 / 签到码 / 胁迫码强度校验

---

## 🧱 项目结构

```text
aegis-vault-oss/
├── audit_logger.py            # 审计日志、链式哈希、日志读取与校验
├── crypto.py                  # 密钥管理、文件加解密、状态管理、自毁逻辑
├── main.py                    # FastAPI 主入口、路由、安全头、中间件
├── notes_manager.py           # 神盾笔记、笔记附件、笔记配置管理
├── session_manager.py         # 进程内会话、限流、客户端指纹校验
├── templates/
│   ├── base.html              # 共享基础模板与样式
│   ├── index.html             # 保险库主页与管理界面
│   ├── logs.html              # 审计日志页面
│   └── notes.html             # 神盾笔记页面
├── docs/
│   └── SECURITY_HARDENING.md  # 部署安全加固指南
├── THREAT_MODEL.py            # 威胁分析辅助文件
├── .env.example               # 环境变量模板
├── Dockerfile                 # 容器构建脚本
├── docker-compose.yml         # Docker Compose 配置
└── README.md                  # 项目文档
```

默认数据目录在 `AEGIS_DATA_DIR`，结构如下：

```text
data/
├── keys/
│   ├── admin.key
│   ├── admin.notes.key
│   ├── admin.notes.pub
│   ├── admin.pub
│   ├── checkin.hash
│   ├── duress.hash
│   └── status.key
├── notes_config.json
├── vault/
│   ├── admin/
│   │   └── notes/
│   │       └── <note_id>/
│   │           ├── note.aes
│   │           └── attachments/
│   │               └── <attachment_id>.aes
│   ├── user1/
│   ├── user2/
│   └── user3/
├── status.json
├── status.hmac
├── audit.log
└── audit.hash
```

---

## 🔐 安全模型

### 1. 加密模型

- 每个用户拥有一对 **RSA-4096** 密钥
- 每个上传文件单独生成一把随机 **AES-256** 文件密钥
- 文件内容使用 **AES-GCM** 加密，提供机密性和完整性校验
- 文件密钥使用对应用户的公钥通过 **RSA-OAEP(SHA-256)** 封装
- 用户私钥使用用户密码加密后落盘保存

这意味着：

- 用户之间默认无法互相解密文件
- 同一用户的不同文件不会复用同一把文件密钥
- 拿到密文文件本身并不足以恢复明文

### 2. 会话模型

当前版本已经从“前端回传密码”切换为“服务端持有登录态”：

- 登录成功后，服务端生成随机 `session_id`
- 浏览器仅持有 `HttpOnly` Cookie
- 会话存储在进程内内存
- 会话带有明确模式：`vault` 或 `notes`
- 会话中包含：
  - 当前用户身份
  - 当前模式
  - 过期时间
  - CSRF Token
  - 客户端指纹信息
- 会话中**不再缓存已解锁私钥**
- 已登录页面带有 60 秒无操作倒计时，触发后会自动提交登出

需要注意：

- 这是**进程内会话**，不是 Redis 或数据库会话
- 服务重启后所有会话会失效
- 不适合多实例横向扩展
- `SESSION_TTL_HOURS` 控制服务端会话总时长，前端 60 秒空闲登出是额外的一层交互保护

### 3. 多用户模型

项目采用固定槽位模型，而不是开放注册模型：

- `admin`
- `user1`
- `user2`
- `user3`

机制说明：

- 只有 `admin` 可以管理其他用户的密钥
- 每个用户的私钥 / 公钥保存在 `keys/`
- 每个用户的加密文件保存在 `vault/<username>/`
- 登录时系统会尝试使用提交的口令解锁现有私钥，以识别对应用户

这套模型的优点是边界简单、容易审计；缺点是不支持动态扩容和复杂权限系统。

### 4. 神盾笔记模型

“神盾笔记”不是保险库文件功能的别名，而是一套独立的加密子系统：

- 由 `admin` 为目标用户单独启用
- 每个启用笔记的用户拥有独立的 `*.notes.key` / `*.notes.pub`
- 笔记密文保存在 `vault/<username>/notes/<note_id>/note.aes`
- 每篇笔记可带图片附件，附件单独加密存储在对应 `attachments/` 目录
- 笔记登录与保险库登录共用一个入口，但会进入不同的会话模式
- 查看单篇笔记时需要重新输入笔记密码，已解锁内容仅短暂缓存于当前会话

这意味着：

- 保险库口令和笔记口令可以完全不同
- 启用了笔记的用户，不代表自动拥有保险库访问权，反之亦然
- 即使已处于笔记模式，敏感操作仍要求再次验证笔记密码
- 当前实现禁止在已有笔记的情况下直接重建笔记密钥，避免历史内容永久不可解

### 5. Dead Man's Switch

后台线程按 `MONITOR_INTERVAL_SECONDS` 轮询状态，默认每 5 秒检查一次：

- 读取 `status.json`
- 验证 `status.hmac`
- 计算距上次签到的时间差
- 如果超出 `CHECKIN_TIMEOUT`，执行 `destroy_all()`

只要签到成功，系统会刷新 `last_checkin`。

### 6. Duress Destruction

胁迫码有两个入口：

- 在登录处输入
- 在签到处输入

命中后会：

- 立即触发销毁
- 清空现有会话
- 前端仅表现为失败或普通状态变化，不暴露内部处理细节

### 7. 状态文件防篡改

`status.json` 与 `status.hmac` 联动工作：

- 系统写入状态时同步生成 HMAC-SHA256
- 读取状态时校验 HMAC
- 若 HMAC 不匹配，系统会将其视为篡改并触发销毁

这可以防止攻击者通过伪造状态文件来关闭或绕过自毁机制。

### 8. 审计日志防篡改

审计日志写入 `audit.log`，并维护单独的链式哈希：

- 每条日志带有事件哈希 `_hash`
- 同时包含基于上一条日志派生的 `_chain_hash`
- 任意中途修改、插入、删除都可能破坏整条链
- 可通过 `verify_audit_chain()` 进行完整性检查

### 9. 销毁模型

销毁逻辑优先使用系统 `shred`：

- 密钥文件：3 轮覆盖
- 密文文件：1 轮覆盖
- 覆盖后删除文件并清理目录

如果系统没有 `shred`，则退化为直接删除。这仍然能完成逻辑销毁，但不能保证传统意义上的物理不可恢复。

---

## 🛡️ 已实现的安全机制

### 认证与会话安全

- 去除前端明文密码回传
- 统一登录入口，按口令命中结果进入保险库或笔记模式
- `HttpOnly` + `SameSite=Lax` Cookie
- 服务端 CSRF Token 校验
- 登录与签到的失败限流
- 会话绑定客户端 IP 与 User-Agent 指纹
- 已登录页面 60 秒无操作自动登出
- 当用户密钥变更后自动失效该用户现有会话
- 当笔记功能状态或笔记密钥变更后自动失效该用户现有会话

### 输入与路径安全

- 文件名通过 `Path(filename).name` 规范化
- `note_id` 与 `attachment_id` 同样经过规范化校验
- 拒绝目录跳转与非法文件名
- 不再拼接 shell 命令执行批量销毁

### 状态与日志完整性

- `status.json` HMAC 签名校验
- 篡改状态文件时自动销毁
- 审计日志链式哈希
- 笔记启用、查看、保存、删除、附件操作都进入审计日志

### 明文暴露面控制

- 会话内不缓存已解锁私钥
- 每次下载都要求重新输入访问密码
- 下载时才临时加载私钥并解密
- 下载后的明文临时文件在响应结束后删除
- 笔记查看、删除、附件下载、附件删除同样要求重新输入笔记密码

### 基础安全策略

- 管理员密码强度要求：至少 12 位，且至少满足 3 类字符
- 签到码 / 胁迫码强度要求：至少 8 位，且具备足够字符多样性
- 整体保险库容量限制
- 单文件上传大小限制
- 笔记附件当前仅允许图片文件
- 基础安全响应头：
  - `CSP`
  - `X-Frame-Options`
  - `X-Content-Type-Options`
  - `Referrer-Policy`
  - `Permissions-Policy`
  - 禁止缓存

说明：

- **HSTS 不由应用直接设置**，应在 Nginx / Caddy / Traefik 等 HTTPS 反向代理层启用

---

## 🧪 威胁视角下的效果

| 场景 | 当前防护 | 效果 |
| :--- | :--- | :--- |
| 读取磁盘上的加密私钥 | RSA-4096 + 密码加密私钥 | 🟢 需要正确用户密码 |
| 篡改 `status.json` 禁用自毁 | HMAC 校验 + 自动销毁 | 🟢 篡改会被检测 |
| 盗用会话 Cookie | `HttpOnly` + 客户端指纹绑定 | 🟡 仍受同源环境和代理场景影响 |
| 篡改审计日志 | 链式哈希 | 🟢 篡改容易暴露 |
| 路径穿越读写任意文件 | 文件名规范化 | 🟢 已显著收敛 |
| 利用下载遗留明文 | 响应结束后自动清理 | 🟢 降低残留暴露面 |
| 服务器离线镜像恢复数据 | 依赖 FDE 与底层存储 | ⚠️ 应用层无法完全解决 |
| 从长期会话内存提取私钥 | 会话内不缓存已解锁私钥，下载时临时加载 | 🟡 降低常驻暴露时间，但服务端解密期间仍可接触私钥与明文 |

---

## 🌐 界面与移动端

前端采用 Jinja2 服务端渲染，并针对移动端做了适配：

- 小屏文件列表改为更易点击的卡片布局
- 笔记列表、笔记编辑区、附件区域采用分栏布局并适配移动端
- 表单、按钮和输入框尺寸针对触控设备优化
- 信息分区更清晰，减少手机端横向挤压
- 支持保险库主页、神盾笔记页、审计日志页三类核心界面
- 登录、签到、上传、管理操作统一在单页交互中完成
- 笔记界面与保险库界面默认不互相显示直达入口，降低模式暴露

技术栈：

- FastAPI
- Jinja2
- TailwindCSS CDN
- 少量原生 JavaScript

---

## 🚀 部署方式

### 方案一：Docker Compose

1. 克隆项目并进入目录(自行安装git)
```bash
git clone https://github.com/keaidang/aegis-vault.git
cd aegis-vault
```

2. 复制配置文件

```bash
cp .env.example .env
```

3. 启动服务

```bash
docker-compose up -d
```

默认访问地址：

```text
http://localhost:46746
```

当前 `docker-compose.yml` 会：

- 暴露 `46746`
- 将 `./data` 挂载到容器内 `/app/data`
- 设置 `AEGIS_DATA_DIR=/app/data`

如果你希望更稳妥地使用 `mlock()`，可以按环境需要额外配置容器权限。

### 方案二：源码部署

建议优先在 Linux 上运行，因为项目依赖：

- `shred`
- 常见 POSIX 文件系统行为
- `mlock()` 的最佳兼容性

以下以 **Ubuntu / Debian** 为例，项目地址使用：

```text
https://github.com/keaidang/aegis-vault
```

#### 1. 安装系统依赖

```bash
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip build-essential libssl-dev libffi-dev python3-dev coreutils
```

说明：

- `git` 用于拉取项目
- `python3-venv` 用于创建虚拟环境
- `coreutils` 提供 `shred`
- `build-essential`、`libssl-dev`、`libffi-dev`、`python3-dev` 用于编译部分 Python 依赖，避免某些环境下安装失败

你可以先确认 `shred` 可用：

```bash
shred --version
```

#### 2. 克隆项目

```bash
cd /opt
sudo git clone https://github.com/keaidang/aegis-vault.git
sudo chown -R "$USER":"$USER" /opt/aegis-vault
cd /opt/aegis-vault
```

如果你不想放在 `/opt`，也可以克隆到家目录：

```bash
git clone https://github.com/keaidang/aegis-vault.git
cd aegis-vault
```

#### 3. 创建虚拟环境并安装 Python 依赖

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
```

#### 4. 准备配置文件

```bash
cp .env.example .env
```

然后编辑 `.env`：

```bash
nano .env
```

一个适合本机源码部署的最小示例：

```env
PORT=46746
AEGIS_DATA_DIR=./data
TEMPLATE_DIR=./templates
CHECKIN_TIMEOUT=72
SESSION_TTL_HOURS=12
SESSION_COOKIE_NAME=aegis_session
SESSION_COOKIE_SECURE=false
MAX_VAULT_SIZE_MB=1024
MAX_UPLOAD_SIZE_MB=64
AUDIT_LOG_DIR=./data
```

如果你后面会挂 Nginx / Caddy 并启用 HTTPS，建议改成：

```env
SESSION_COOKIE_SECURE=true
```

#### 5. 启动服务

```bash
python3 main.py
```

启动后默认监听：

```text
http://0.0.0.0:46746
```

本机访问通常使用：

```text
http://127.0.0.1:46746
```

#### 6. 后台运行的简单方式

如果你只是临时测试，可以使用：

```bash
cd /opt/aegis-vault
source .venv/bin/activate
nohup python3 main.py > aegis.log 2>&1 &
```

查看日志：

```bash
tail -f aegis.log
```

#### 7. 推荐方式：使用 systemd 持久运行

先创建专用用户：

```bash
sudo useradd --system --create-home --shell /usr/sbin/nologin aegis
sudo chown -R aegis:aegis /opt/aegis-vault
```

编辑 systemd 服务文件：

```bash
sudo nano /etc/systemd/system/aegis-vault.service
```

写入：

```ini
[Unit]
Description=Aegis Vault
After=network.target

[Service]
Type=simple
User=aegis
Group=aegis
WorkingDirectory=/opt/aegis-vault
EnvironmentFile=/opt/aegis-vault/.env
ExecStart=/opt/aegis-vault/.venv/bin/python3 /opt/aegis-vault/main.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

启用并启动：

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now aegis-vault
```

检查状态：

```bash
sudo systemctl status aegis-vault
```

查看日志：

```bash
sudo journalctl -u aegis-vault -f
```

#### 8. 放行端口

如果系统启用了 UFW，可放行默认端口：

```bash
sudo ufw allow 46746/tcp
sudo ufw reload
```

#### 9. 生产环境建议

- 不要直接裸露在公网，优先放到 Nginx / Caddy 之后
- 启用 HTTPS 后把 `SESSION_COOKIE_SECURE=true`
- 将 `AEGIS_DATA_DIR` 放到独立磁盘或加密分区
- 对 `data/` 目录收紧权限
- 定期备份 `audit.log` 与 `audit.hash`

如需物理粉碎能力，确保系统存在 `shred` 命令；如部署在 SSD、快照盘或 CoW 文件系统上，应理解 `shred` 的实际效果会打折扣。

---

## 🔧 配置说明

`.env.example` 当前支持以下变量：

| 变量名 | 默认值 | 说明 |
| :--- | :--- | :--- |
| `PORT` | `46746` | Web 服务监听端口 |
| `AEGIS_DATA_DIR` | `./data` | 密钥、密文、状态、审计日志的存储目录 |
| `TEMPLATE_DIR` | `./templates` | HTML 模板目录 |
| `CHECKIN_TIMEOUT` | `72` | 签到超时时间，单位小时 |
| `CHECKIN_TIMEOUT_SECONDS` | 未设置 | 仅测试用途，秒级覆盖 `CHECKIN_TIMEOUT` |
| `MONITOR_INTERVAL_SECONDS` | `5` | 后台状态监测与销毁检查轮询间隔，单位秒 |
| `SESSION_TTL_HOURS` | `12` | 登录会话有效期，单位小时 |
| `SESSION_COOKIE_NAME` | `aegis_session` | 会话 Cookie 名称 |
| `SESSION_COOKIE_SECURE` | `false` | 是否仅通过 HTTPS 发送 Cookie |
| `MAX_VAULT_SIZE_MB` | `1024` | 整个保险库总容量上限 |
| `MAX_UPLOAD_SIZE_MB` | `64` | 单文件上传大小上限 |
| `AUDIT_LOG_DIR` | `./data` | 审计日志与链式哈希存储目录 |

补充说明：

- 前端已登录页面存在固定 `60s` 无操作自动登出机制
- 该 `60s` 计时目前写在前端模板中，尚未独立做成环境变量

生产建议：

- 通过反向代理启用 HTTPS，并设置 `SESSION_COOKIE_SECURE=true`
- 将 `AEGIS_DATA_DIR` 放到独立加密磁盘或受保护挂载点
- 对数据目录启用严格权限控制
- 结合全磁盘加密使用
- 定期备份 `audit.log` 与 `audit.hash`

更完整的部署建议见 [docs/SECURITY_HARDENING.md](/root/aegis-vault-oss/docs/SECURITY_HARDENING.md:1)。

---

## 🧭 使用流程

### 首次启动

1. 打开首页
2. 设置管理员密码
3. 设置签到码
4. 完成初始化
5. 使用管理员密码登录

### 创建或更新用户

1. 使用 `admin` 登录
2. 在系统管理区域选择目标用户
3. 输入该用户的新访问密码
4. 提交后生成或更新该用户密钥

注意：

- 当前只支持固定四个用户槽位
- 若目标用户已有加密文件，系统会阻止直接重建其密钥
- 若更新的是 `admin` 密钥，当前会话会被强制失效并要求重新登录

### 签到

1. 在首页输入签到码
2. 成功后刷新 `last_checkin`
3. 若超时未签到，后台线程会自动执行销毁

### 上传与下载

1. 登录对应用户
2. 上传文件
3. 系统写入该用户独立保险库目录中的 `.aes` 密文
4. 已登录后若连续 60 秒无操作，前端会自动登出
5. 下载时需要再次输入当前用户访问密码
6. 系统临时解密并返回原文件名
7. 响应完成后自动删除临时明文文件

### 神盾笔记

1. 使用 `admin` 登录保险库
2. 在系统管理区域为目标用户启用神盾笔记，并设置独立笔记密码
3. 目标用户在统一登录入口输入笔记密码后进入 `/notes`
4. 可新建、保存、删除加密笔记
5. 查看指定笔记时需要再次输入笔记密码
6. 可为已解锁笔记上传图片附件；下载或删除附件时再次验证笔记密码

注意：

- 神盾笔记与保险库文件是两套独立密钥体系
- 如果目标用户已有笔记，系统会阻止直接重置该用户笔记密钥
- 笔记列表按更新时间排序；新建状态不会复用上一条已解锁笔记内容

### 胁迫销毁

1. 在登录或签到入口输入胁迫码
2. 系统立即销毁密钥与密文
3. 清空会话并更新系统状态

---

## 📋 审计事件

当前审计系统会记录以下关键事件：

- 登录成功 / 失败
- 登出
- 签到成功 / 失败
- 胁迫销毁触发
- 文件上传 / 下载 / 删除
- 神盾笔记启用 / 关闭
- 笔记查看成功 / 失败
- 笔记保存 / 删除
- 笔记附件上传 / 下载 / 删除
- 系统销毁 / 重置
- 用户创建或密码更新
- 签到码 / 胁迫码更新
- 限流命中
- 非法请求或异常客户端特征

如果你要把它用于长期运行环境，建议：

- 对 `audit.log` 做日志轮转
- 备份 `audit.log` 与 `audit.hash`
- 定期执行链式完整性校验

---

## ⚠️ 已知限制

- 用户模型是固定槽位，不支持动态注册
- 登录识别方式仍是“尝试用口令解锁现有私钥”
- 会话保存在单进程内存，不适合多实例部署
- 没有数据库、对象存储、消息队列等外部依赖
- 没有文件分享、版本控制、审批流和细粒度 ACL
- 下载过程仍需在服务端短暂创建明文临时文件
- 神盾笔记当前不支持全文检索、标签、协作编辑、历史版本恢复
- 笔记附件当前仅支持图片文件
- 前端 60 秒空闲登出当前为固定值，尚未配置化
- `shred` 在 SSD、快照盘、日志结构文件系统、CoW 文件系统上不能视为绝对可靠
- 离线磁盘防护仍然依赖操作系统级全磁盘加密

---

## 📝 本次更新记录

### v1.2.0 - 2026-04-24

这次版本的重点是新增“神盾笔记”子系统，并把登录入口、界面隔离和审计能力扩展到笔记场景。

#### 新增功能

- 新增独立的神盾笔记模式，支持以笔记密码直接登录 `/notes`
- 新增按用户启用 / 关闭笔记功能的管理入口
- 为启用笔记的用户生成独立 `*.notes.key` / `*.notes.pub`
- 新增笔记的创建、查看、编辑、删除能力
- 新增图片附件上传、下载、删除能力
- 新增审计日志页面，可直接查看最近日志与链完整性状态

#### 安全与交互变化

- 统一系统登录入口，可自动识别保险库口令与笔记口令
- 笔记查看、删除、附件下载、附件删除均要求再次输入笔记密码
- 笔记相关操作纳入独立审计事件类型
- 已有笔记时禁止直接重置该用户笔记密钥
- 笔记界面不再显示保险库入口，保险库模式与笔记模式降低互相暴露

#### 近期修复与细节调整

- 修复笔记查看流程中的异常与界面显示问题
- 优化笔记编辑界面与移动端布局
- 修复新建笔记时可能带出旧已解锁内容的问题
- 笔记列表改为按更新时间排序，避免新笔记被随机目录名顺序干扰

### v1.1.0 - 2026-04-22

这次版本的重点是把项目从“基础可用”推进到“具备更明确安全边界和部署说明”的状态。

#### 安全能力升级

- 彻底移除前端明文密码传递，改为服务端会话模型
- 引入 `HttpOnly` Cookie 与 CSRF Token
- 为登录和签到加入基于来源地址的失败限流
- 会话绑定客户端 IP 与 User-Agent 指纹，降低会话盗用风险
- 已登录页面新增 60 秒无操作自动登出机制
- 为 `status.json` 增加 HMAC-SHA256 完整性保护，阻止通过篡改状态关闭自毁机制
- 新增审计日志模块，并通过链式哈希提升日志防篡改能力
- 修复 `/reset` 在非销毁状态下缺乏管理员鉴权的问题
- 修复上传和下载路径缺乏严格文件名校验的问题
- 将销毁逻辑改为逐文件安全调用 `shred`，移除危险的 shell 拼接执行方式
- 下载完成后自动删除临时明文文件
- 下载改为每次都要求重新输入访问密码，会话内不再缓存已解锁私钥
- 当目标用户已有加密文件时，禁止直接重建该用户密钥，避免历史文件永久不可解

#### 架构与代码层变化

- 新增 [session_manager.py](/root/aegis-vault-oss/session_manager.py:1)，集中处理会话与限流
- 新增 [audit_logger.py](/root/aegis-vault-oss/audit_logger.py:1)，用于审计记录与完整性校验
- 重构 [main.py](/root/aegis-vault-oss/main.py:1) 的认证、会话、下载与安全头逻辑
- 扩展 [crypto.py](/root/aegis-vault-oss/crypto.py:1) 的状态完整性保护与安全删除逻辑
- 补充 [docs/SECURITY_HARDENING.md](/root/aegis-vault-oss/docs/SECURITY_HARDENING.md:1) 作为生产环境加固指南

#### 前端与使用体验

- 重写模板交互以适配新的会话与 CSRF 流程
- 优化移动端文件列表与表单布局
- 增加容量限制和错误提示的可见性
- 文档补充了部署、安全边界、威胁模型与运维建议

---

## 🛡️ 适用场景建议

更适合：

- 个人自托管敏感文件保险库
- 少量固定成员的小团队
- 需要“失联自毁 / 胁迫销毁”机制的实验性部署

不适合：

- 大规模多租户 SaaS
- 需要复杂审批、协作、分享、细粒度权限的企业环境
- 对 HSM、KMS、密钥托管、强合规证明有明确要求的生产体系

---

## ⚠️ 免责声明

**数据自毁是不可逆操作。**

本项目的安全目标是“宁可数据永久消失，也不要在高压场景中轻易落入他人手中”。在使用前，请先理解以下事实：

- 忘记签到可能导致系统自动销毁
- 输入胁迫码会立即销毁数据
- 错误重建用户密钥会导致历史文件永久不可解
- 底层文件系统、磁盘介质和部署方式会直接影响“安全删除”的真实效果

任何因误操作、部署不当、密码遗失、环境漏洞、物理攻击或其他不可控因素造成的数据损失，项目开发者概不负责。

---

*Powered by Aegis Protocol.*
