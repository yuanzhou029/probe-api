#!/usr/bin/env bash
# probe-api 部署前环境预检。用法：bash deploy/preflight.sh
# 只读检查，不改系统；退出码 = 失败项数量（0 表示可以部署）。
set -u

PASS=0; WARN=0; FAIL=0
ok()   { printf '  \033[32m[PASS]\033[0m %s\n' "$1"; PASS=$((PASS + 1)); }
warn() { printf '  \033[33m[WARN]\033[0m %s\n' "$1"; WARN=$((WARN + 1)); }
bad()  { printf '  \033[31m[FAIL]\033[0m %s\n' "$1"; FAIL=$((FAIL + 1)); }
sec()  { printf '\n== %s ==\n' "$1"; }

sec "系统"
if [ -r /etc/os-release ]; then
	# shellcheck disable=SC1091
	. /etc/os-release
	printf '  %s / 内核 %s / %s\n' "${PRETTY_NAME:-unknown}" "$(uname -r)" "$(uname -m)"
else
	warn "读不到 /etc/os-release，系统信息未知"
fi
awk '/MemTotal/{printf "  内存 %.0f MB\n", $2/1024}' /proc/meminfo 2>/dev/null
df -h /opt 2>/dev/null | awk 'NR==2{print "  /opt 可用 "$4"（服务本体 <1MB，够用）"}'
[ "$(id -u)" -eq 0 ] && ok "当前是 root（安装 systemd 服务需要）" || warn "当前非 root，安装步骤要加 sudo"

sec "Node.js（需要 >= 18）"
if command -v node >/dev/null 2>&1; then
	NODE_BIN=$(command -v node)
	NODE_VER=$(node -v)
	NODE_MAJOR=${NODE_VER#v}
	NODE_MAJOR=${NODE_MAJOR%%.*}
	if [ "$NODE_MAJOR" -ge 18 ] 2>/dev/null; then
		ok "node $NODE_VER（$NODE_BIN）"
	else
		bad "node $NODE_VER 版本过低，需要 >= 18"
	fi
	if [ "$NODE_BIN" = "/usr/bin/node" ]; then
		ok "路径与 deploy/probe-api.service 的 ExecStart 一致"
	elif [ "$NODE_BIN" = "/usr/local/bin/node" ] || [ "$NODE_BIN" = "/usr/local/bin/nodejs" ]; then
		warn "node 在 $NODE_BIN，部署时把 unit 里的 ExecStart 改成这个路径"
	else
		warn "node 在 $NODE_BIN（nvm/其它方式安装），systemd 看不到它：改 ExecStart 为绝对路径，或改用系统包安装的 node"
	fi
else
	bad "未安装 node：Ubuntu/Debian 执行 curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - && sudo apt install -y nodejs；CentOS/RHEL 用 dnf module install nodejs:20"
fi

sec "systemd"
if [ "$(ps -p 1 -o comm= 2>/dev/null)" = "systemd" ]; then
	ok "PID 1 是 systemd"
	command -v systemctl >/dev/null 2>&1 && ok "systemctl 可用" || bad "systemctl 不存在"
else
	bad "不是 systemd 环境（LXC/容器？）：unit 文件用不了，改用 nohup 或 pm2 守护"
fi

sec "下载与解压工具（从云盘取包）"
for tool in curl wget unzip tar; do
	if command -v "$tool" >/dev/null 2>&1; then
		ok "$tool 已安装"
	else
		warn "缺 $tool（apt install -y $tool / yum install -y $tool）"
	fi
done

sec "端口"
PORT_CHECK=${PORT:-8787}
if command -v ss >/dev/null 2>&1; then
	LISTEN=$(ss -lnt 2>/dev/null)
elif command -v netstat >/dev/null 2>&1; then
	LISTEN=$(netstat -lnt 2>/dev/null)
else
	LISTEN=""
	warn "没有 ss/netstat，跳过端口检查"
fi
if [ -n "$LISTEN" ]; then
	if printf '%s\n' "$LISTEN" | grep -q ":$PORT_CHECK "; then
		warn "端口 $PORT_CHECK 已被占用：启动时用 PORT=其它端口，或先停掉占用进程"
	else
		ok "端口 $PORT_CHECK 空闲"
	fi
fi

sec "DNS 与出网（探测目标 www.iplocate.io）"
if command -v getent >/dev/null 2>&1; then
	if getent hosts www.iplocate.io >/dev/null 2>&1; then
		ok "DNS 可解析 www.iplocate.io"
	else
		bad "DNS 解析失败：检查 /etc/resolv.conf"
	fi
fi
if command -v curl >/dev/null 2>&1; then
	if curl -4fsS -m 10 -o /dev/null https://www.iplocate.io/api/lookup 2>/dev/null; then
		ok "IPv4 可直连探测目标（443/TLS 通）"
	elif curl -6fsS -m 10 -o /dev/null https://www.iplocate.io/api/lookup 2>/dev/null; then
		warn "只有 IPv6 能通探测目标，IPv4 出口可能受限"
	else
		bad "访问不了探测目标：检查出网策略/云厂商封禁，或改用自建回显接口（TARGET_HOST/PORT/PATH）"
	fi
fi

sec "防火墙（只提示，不判定）"
if command -v ufw >/dev/null 2>&1; then
	ufw status 2>/dev/null | head -3
elif command -v firewall-cmd >/dev/null 2>&1; then
	printf '  firewalld: %s\n' "$(firewall-cmd --state 2>/dev/null)"
elif command -v iptables >/dev/null 2>&1; then
	printf '  iptables 规则条数：%s\n' "$(iptables -S 2>/dev/null | wc -l)"
else
	echo "  未检测到常见防火墙"
fi
echo "  提醒：云厂商安全组要在控制台单独放行端口，脚本看不到"

sec "结论"
printf '  PASS %d / WARN %d / FAIL %d\n' "$PASS" "$WARN" "$FAIL"
if [ "$FAIL" -eq 0 ]; then
	echo "  可以部署：按 README「部署（Ubuntu / Debian）」往下走。"
	echo "  说明：SSTP 是用户空间实现（PPP over TLS），不需要 TUN/内核模块/root 特权，不用装 ppp、wireguard。"
else
	echo "  先把上面 [FAIL] 补齐再部署。"
fi
exit "$FAIL"
