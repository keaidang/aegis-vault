# 🛡️ Aegis Vault (宙斯盾保险库)

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/docker-supported-green.svg)](https://www.docker.com/)

**Aegis Vault** 是一款专为极致隐私和极端安全场景设计的自托管加密存储解决方案。它不仅提供工业级的加解密保护，更引入了**“死人开关 (Dead Man's Switch)”**与**“胁迫自毁 (Duress Destruction)”**机制，确保在用户失去系统控制权或受迫泄露密码时，敏感数据能从物理层面永久消失。

---

## 📖 项目简介

在传统的加密存储中，如果攻击者通过物理或法律手段强迫你交出密码，数据保护将瞬间失效。Aegis Vault 的初衷是提供一种**“主动防御”**手段：
- **主动销毁**：如果你未能在预设时间内“签到”，系统判定你已处于危险或失联状态，从而启动自毁程序。
- **被动自毁**：如果你被迫提供密码，你可以提供预设的“胁迫码”，系统会立即触发不可逆的粉碎逻辑。

---

## 📂 项目结构

```text
aegis-vault/
├── main.py              # 核心 Web 服务 (FastAPI) 及自毁监控线程
├── crypto.py            # 加解密引擎与物理粉碎逻辑 (Cryptography/PyCryptodome)
├── requirements.txt     # 项目依赖清单
├── .env.example         # 环境变量配置模板
├── Dockerfile           # 容器镜像构建脚本
├── docker-compose.yml   # 容器编排配置
├── templates/
│   └── index.html       # 霓虹科技感交互界面 (Jinja2 + TailwindCSS)
└── README.md            # 项目指南
```

---

## ⚙️ 实现原理

### 1. 加密体系
- **混合加密架构**：系统为每个用户生成一对 **RSA-4096** 密钥。
- **文件加密**：上传文件时，系统生成一个随机的 **AES-256** 密钥，使用 **GCM (Galois/Counter Mode)** 模式对文件进行认证加密。
- **密钥保护**：AES 密钥通过用户的 RSA 公钥加密存储。用户的 RSA 私钥则通过用户密码加密后存储在磁盘。
- **身份验证**：通过尝试解密 RSA 私钥来验证用户身份，内存中不存储明文密码。

### 2. 物理销毁逻辑
不同于传统的 `rm` 删除，Aegis Vault 调用 Linux 内核级别的 `shred` 工具：
- **密钥销毁**：对密钥目录执行 **3 轮** 随机数据覆盖 + 零填充 + 物理删除。
- **数据销毁**：对加密数据执行 **1 轮** 随机填充并删除。
- **不可逆性**：一旦触发，即便通过专业的磁盘取证技术也极难找回原始二进制数据。

### 3. 自毁触发机制
- **Dead Man's Switch**：后台监控线程每分钟检查一次 `last_checkin` 时间。若 `当前时间 - 签到时间 > 预设阈值`，立即执行 `destroy_all()`。
- **Duress Logic**：在登录界面或签到界面输入“胁迫码”时，系统会优先触发销毁程序，随后页面会模拟解密失败的假象，为用户争取撤离时间。

---

## 🚀 部署方式

### 方案一：Docker Compose (强烈推荐)
确保你的宿主机已安装 Docker 和 Docker Compose。

1. **克隆项目并进入目录**
2. **准备配置**：
   ```bash
   cp .env.example .env
   ```
3. **启动容器**：
   ```bash
   docker-compose up -d
   ```
   服务将运行在 `http://localhost:46746`。

### 方案二：源码部署 (Linux)
由于项目依赖 `shred` 工具，建议在 Linux 环境下运行。

1. **安装系统依赖**：
   ```bash
   sudo apt-get install coreutils findutils
   ```
2. **创建虚拟环境并安装 Python 依赖**：
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```
3. **启动服务**：
   ```bash
   python3 main.py
   ```

---

## 🔧 配置说明 (.env)

| 变量名 | 默认值 | 说明 |
| :--- | :--- | :--- |
| `PORT` | 46746 | Web 服务监听端口 |
| `AEGIS_DATA_DIR` | ./data | 密钥和加密文件的存储路径 |
| `CHECKIN_TIMEOUT` | 72 | 签到超时时间 (单位：小时) |
| `TEMPLATE_DIR` | ./templates | HTML 模板目录路径 |

---

## 🛡️ 兼容性与限制

- **操作系统**：原生支持 Linux (Debian/Ubuntu/CentOS)。由于依赖 `shred` 指令，Windows 或 macOS 环境下自毁逻辑将回退至普通删除（不推荐用于生产安全环境）。
- **文件系统**：建议使用 ext4。在某些具有写时复制 (CoW) 特性的文件系统（如 Btrfs 或 SSD 特有的某些层）上，物理覆盖的效果可能受限。
- **浏览器**：兼容所有支持现代 JavaScript 和 TailwindCSS 渲染的浏览器（Chrome, Firefox, Edge, Safari）。

---

## ⚠️ 免责声明

**数据自毁是不可逆的操作。** 本工具的设计初衷是宁愿数据永久丢失也不愿其落入他人之手。在使用前，请务必理解“死人开关”的运行逻辑。因忘记签到或误触发自毁导致的任何数据损失，项目开发者概不负责。

---
*Powered by Aegis Protocol.*
