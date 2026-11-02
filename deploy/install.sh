#!/usr/bin/env bash
# probe-api 一键安装与配置脚本
# 支持 Debian / Ubuntu / CentOS / RHEL / AlmaLinux / RockyLinux 等常用 Linux 发行版
# 使用方式：
#   curl -fsSL https://raw.githubusercontent.com/<USER>/<REPO>/main/deploy/install.sh | sudo bash
# 或指定参数：
#   sudo bash deploy/install.sh --port 8787 --token my_secret_token

set -euo pipefail

# 默认配置
INSTALL_DIR="/opt/probe-api"
SERVICE_NAME="probe-api"
ENV_FILE="/etc/probe-api.env"
SYSTEMD_DIR="/etc/systemd/system"
DEFAULT_PORT="8787"
PORT="${PORT:-$DEFAULT_PORT}"
TOKEN="${TOKEN:-}"
REPO_URL="https://github.com/yuanzhou029/probe-api" # 默认或回退地址

# 打印美化
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_err()  { echo -e "${RED}[ERROR]${NC} $1"; }

# 1. 检查 root 权限
if [ "$(id -u)" -ne 0 ]; then
    log_err "请使用 root 权限或 sudo 运行此脚本。"
    exit 1
fi

# 2. 解析命令行参数
while [[ $# -gt 0 ]]; do
    case "$1" in
        --port)
            PORT="$2"
            shift 2
            ;;
        --token)
            TOKEN="$2"
            shift 2
            ;;
        --dir)
            INSTALL_DIR="$2"
            shift 2
            ;;
        --help|-h)
            echo "用法: sudo bash install.sh [选项]"
            echo "选项:"
            echo "  --port <PORT>      指定监听端口 (默认: 8787)"
            echo "  --token <TOKEN>    指定鉴权 Token (留空则随机生成)"
            echo "  --dir <PATH>       安装目标目录 (默认: /opt/probe-api)"
            exit 0
            ;;
        *)
            log_warn "忽略未知参数: $1"
            shift
            ;;
    esac
done

# 3. 基础依赖检查与自动安装 (curl, git, tar)
log_info "检查基础依赖 (curl, git, tar)..."
PACKAGES_TO_INSTALL=()
for tool in curl git tar; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        PACKAGES_TO_INSTALL+=("$tool")
    fi
done

if [ ${#PACKAGES_TO_INSTALL[@]} -ne 0 ]; then
    log_info "正在安装缺失的基础工具: ${PACKAGES_TO_INSTALL[*]}"
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -y && apt-get install -y "${PACKAGES_TO_INSTALL[@]}"
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y "${PACKAGES_TO_INSTALL[@]}"
    elif command -v yum >/dev/null 2>&1; then
        yum install -y "${PACKAGES_TO_INSTALL[@]}"
    else
        log_warn "未识别的包管理器，请确保已安装: ${PACKAGES_TO_INSTALL[*]}"
    fi
fi

# 4. 检查与安装 Node.js (需要 >= 18)
NEED_NODE_INSTALL=false
if command -v node >/dev/null 2>&1; then
    NODE_VER=$(node -v)
    NODE_MAJOR=${NODE_VER#v}
    NODE_MAJOR=${NODE_MAJOR%%.*}
    if [ "$NODE_MAJOR" -lt 18 ] 2>/dev/null; then
        log_warn "当前 Node.js 版本 ($NODE_VER) 过低，需要 >= 18"
        NEED_NODE_INSTALL=true
    else
        log_info "检测到 Node.js 版本: $NODE_VER"
    fi
else
    NEED_NODE_INSTALL=true
fi

if [ "$NEED_NODE_INSTALL" = true ]; then
    log_info "正在配置并安装 Node.js LTS (20.x)..."
    if command -v apt-get >/dev/null 2>&1; then
        curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
        apt-get install -y nodejs
    elif command -v dnf >/dev/null 2>&1; then
        dnf module install -y nodejs:20 || (curl -fsSL https://rpm.nodesource.com/setup_20.x | bash - && dnf install -y nodejs)
    elif command -v yum >/dev/null 2>&1; then
        curl -fsSL https://rpm.nodesource.com/setup_20.x | bash -
        yum install -y nodejs
    else
        log_err "无法自动安装 Node.js，请手动安装 Node.js >= 18 后重试。"
        exit 1
    fi
fi

NODE_BIN=$(command -v node)
log_info "Node 可执行文件路径: $NODE_BIN"

# 5. 准备工作目录与源码拉取/复制
log_info "准备安装目录: $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || echo "")"
SOURCE_ROOT="$(cd "$SCRIPT_DIR/.." 2>/dev/null && pwd || echo "")"

if [ -f "$SOURCE_ROOT/src/server.js" ] && [ "$SOURCE_ROOT" != "$INSTALL_DIR" ]; then
    log_info "检测到本地源码，正在同步到 $INSTALL_DIR..."
    cp -r "$SOURCE_ROOT"/* "$INSTALL_DIR/"
elif [ ! -f "$INSTALL_DIR/src/server.js" ]; then
    log_info "正在从 GitHub 获取最新代码..."
    if [ -d "$INSTALL_DIR/.git" ]; then
        cd "$INSTALL_DIR" && git pull
    else
        git clone "$REPO_URL" "$INSTALL_DIR"
    fi
fi

# 6. 配置运行用户
if ! id probe >/dev/null 2>&1; then
    log_info "创建专用服务用户 probe..."
    useradd --system --no-create-home --shell /usr/sbin/nologin probe 2>/dev/null || true
fi
chown -R probe:probe "$INSTALL_DIR"

# 7. 环境变量文件配置 (/etc/probe-api.env)
if [ ! -f "$ENV_FILE" ]; then
    log_info "生成配置文件: $ENV_FILE"
    if [ -f "$INSTALL_DIR/deploy/probe-api.env.example" ]; then
        cp "$INSTALL_DIR/deploy/probe-api.env.example" "$ENV_FILE"
    else
        cat <<EOF > "$ENV_FILE"
PORT=8787
HOST=0.0.0.0
PROBE_TOKEN=
BATCH_LIMIT=200
CONCURRENCY=20
TARGET_HOST=www.iplocate.io
TARGET_PORT=443
TARGET_PATH=/api/lookup
CHECK_TIMEOUT_MS=12000
CONNECT_TIMEOUT_MS=9999
READ_TIMEOUT_MS=8000
MAX_RESPONSE_BYTES=98304
EOF
    fi

    # 生成安全随机 Token
    if [ -z "$TOKEN" ]; then
        TOKEN=$(head -c 18 /dev/urandom | base64 | tr -d '/+=' | cut -c 1-24)
    fi

    sed -i "s#^PORT=.*#PORT=$PORT#" "$ENV_FILE"
    sed -i "s#^PROBE_TOKEN=.*#PROBE_TOKEN=$TOKEN#" "$ENV_FILE"
    chmod 600 "$ENV_FILE"
    log_info "已配置监听端口: $PORT"
    log_info "已生成鉴权 Token: $TOKEN"
else
    log_info "检测到已有配置文件 $ENV_FILE，保留现有配置。"
    TOKEN=$(grep '^PROBE_TOKEN=' "$ENV_FILE" | cut -d '=' -f2- || echo "")
fi

# 8. 配置 systemd 服务单元
log_info "配置 systemd 服务单元..."
cat <<EOF > "$SYSTEMD_DIR/$SERVICE_NAME.service"
[Unit]
Description=probe-api 代理存活探测 API
Documentation=file:$INSTALL_DIR/README.md
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=probe
Group=probe
WorkingDirectory=$INSTALL_DIR
EnvironmentFile=$ENV_FILE
ExecStart=$NODE_BIN $INSTALL_DIR/src/server.js
Restart=always
RestartSec=3
LimitNOFILE=65535
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictSUIDSGID=true
ReadWritePaths=$INSTALL_DIR

[Install]
WantedBy=multi-user.target
EOF

# 9. 启动服务与自检
log_info "重新加载 systemd 并启动 $SERVICE_NAME..."
systemctl daemon-reload
systemctl enable --now "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"

sleep 1

# 检查运行状态
if systemctl is-active --quiet "$SERVICE_NAME"; then
    log_info "服务已成功启动！"
else
    log_err "服务启动失败，请通过 'journalctl -u $SERVICE_NAME -e' 查看日志。"
    exit 1
fi

# 10. 健康检查
SERVER_PORT=$(grep '^PORT=' "$ENV_FILE" | cut -d '=' -f2- || echo "$PORT")
SERVER_PORT=${SERVER_PORT:-8787}
HEALTH_URL="http://127.0.0.1:${SERVER_PORT}/health"
AUTH_HEADER=""
if [ -n "$TOKEN" ]; then
    AUTH_HEADER="Authorization: Bearer $TOKEN"
fi

log_info "正在进行本地健康检查 ($HEALTH_URL)..."
if curl -fsSL -H "$AUTH_HEADER" "$HEALTH_URL" >/dev/null 2>&1; then
    log_info "健康检查通过！"
else
    log_warn "健康检查未立即响应，可通过 'curl $HEALTH_URL' 手工确认。"
fi

# 打印最终安装信息
PUBLIC_IP=$(curl -4fsS -m 5 https://api.ipify.org 2>/dev/null || curl -4fsS -m 5 https://icanhazip.com 2>/dev/null || echo "<你的VPS公网IP>")

echo ""
echo "=========================================================="
echo -e "${GREEN}  probe-api 一键安装成功！${NC}"
echo "=========================================================="
echo "服务状态:   systemctl status $SERVICE_NAME"
echo "日志查看:   journalctl -u $SERVICE_NAME -f"
echo "配置文件:   $ENV_FILE"
echo "安装目录:   $INSTALL_DIR"
echo "API 地址:   http://${PUBLIC_IP}:${SERVER_PORT}"
echo "鉴权 Token: ${TOKEN}"
echo ""
echo "测试命令示例:"
if [ -n "$TOKEN" ]; then
    echo "  curl -H 'Authorization: Bearer ${TOKEN}' 'http://127.0.0.1:${SERVER_PORT}/health'"
    echo "  curl 'http://127.0.0.1:${SERVER_PORT}/check?socks5=1.2.3.4:1080&token=${TOKEN}'"
else
    echo "  curl 'http://127.0.0.1:${SERVER_PORT}/health'"
fi
echo "=========================================================="
echo "提醒：如果外网无法连接，请检查云服务商安全组控制台是否放行了端口 ${SERVER_PORT}。"
echo "=========================================================="
