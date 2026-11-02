# probe-api — VPS 代理存活探测 API

把根目录 `_worker.js`（CF-Workers-CheckSocks5）的探测逻辑移植到 VPS 上跑，用 Node.js 标准库实现，无第三方依赖。

和 Worker 版的关键差异：

| | `_worker.js` | 本服务 |
| --- | --- | --- |
| 协议 | socks5 / http / https | 加上 **sstp**（Worker 里做不到） |
| 出口 | Cloudflare 边缘 | 你自己的 VPS IP |
| 判定标准 | 经代理建隧道 → 目标站点真实 TLS → 拿到出口 IP | 完全一致 |

判定「存活」的方式不是「端口能连」，而是：经代理建隧道 → 对 `www.iplocate.io` 做真实 TLS 握手 → 请求 `/api/lookup` → 解析出出口 IP 才算活。这样需要认证的代理、能连但无出口的节点不会被误判。

## 目录

```
src/server.js    HTTP 服务（路由、鉴权、批量并发）
src/check.js     四种协议的探测主流程与结果组装
src/parse.js     代理地址/链接解析（socks5:// user:pass@ host:port #备注）
src/tunnel.js    socks5 / http / https 隧道建立
src/sstp.js      SSTP（PPP + LCP/PAP/IPCP + 合成 TCP，走 TLS）
src/util.js      ByteReader、超时、校验和等
test/            集成自测（三个本地 mock 代理）+ 手工探测 CLI
deploy/          systemd unit 与环境变量样例
```

## 环境变量

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `PORT` | `8787` | 监听端口 |
| `HOST` | `0.0.0.0` | 监听地址 |
| `PROBE_TOKEN` | 空 | 非空时启用鉴权，接受 `Authorization: Bearer <TOKEN>` 或 `?token=<TOKEN>` |
| `BATCH_LIMIT` | `200` | 单次批量最多目标数 |
| `CONCURRENCY` | `20` | 批量探测并发数 |
| `TARGET_HOST` / `TARGET_PORT` / `TARGET_PATH` | `www.iplocate.io` / `443` / `/api/lookup` | 探测目标，换成自己的回显接口需返回 JSON 且含 `ip` 字段 |
| `CHECK_TIMEOUT_MS` | `12000` | 单个代理的总超时 |
| `CONNECT_TIMEOUT_MS` | `9999` | 建连/握手阶段超时 |
| `READ_TIMEOUT_MS` | `8000` | 读目标响应超时 |
| `MAX_RESPONSE_BYTES` | `98304` | 目标响应体上限 |

## 接口

单个探测（`socks5` / `http` / `https` / `sstp` 任选一个做参数名，也可以 `?proxy=socks5://host:port`）：

```bash
curl 'http://127.0.0.1:8787/check?socks5=1.2.3.4:1080'
curl 'http://127.0.0.1:8787/check?sstp=user:pass@1.2.3.4:443&pretty'
curl -H 'Authorization: Bearer <TOKEN>' 'http://127.0.0.1:8787/check/http=1.2.3.4:8080'
curl 'http://127.0.0.1:8787/check/socks5=1.2.3.4:1080'   # 路径形式，方便直接拼链接
```

批量（POST，单条可以带 `#备注`，裸 `host:port` 用 `type` 补类型）：

```bash
curl -X POST 'http://127.0.0.1:8787/check/batch' \
  -H 'Content-Type: application/json' \
  -d '{"targets":["sstp://vpn:vpn@1.2.3.4:443#日本","1.2.3.5:1080"],"type":"socks5"}'
```

返回：

```json
{
  "success": true,
  "total": 2, "alive": 1, "dead": 1,
  "averageResponseTime": 1400, "elapsed": 1620,
  "target": { "host": "www.iplocate.io", "port": 443, "path": "/api/lookup" },
  "results": [
    {
      "candidate": "1.2.3.4:1080", "type": "socks5",
      "hostname": "1.2.3.4", "port": 1080,
      "success": true, "responseTime": 1359,
      "exit": { "ip": "203.0.113.7", "country": "Japan", "country_code": "JP", "city": "Tokyo" }
    },
    { "candidate": "1.2.3.5:1080", "success": false, "error": "代理 TCP 连接失败 1.2.3.5:1080: connect ECONNREFUSED" }
  ]
}
```

单条探测返回的是 `results[0]` 那个对象；失败时 `success: false` + `error`，HTTP 状态码仍是 200（便于批量调用方统一处理）。

其他：`GET /health` 健康检查、`GET /` 自描述、`GET /ip.json` 看服务自身出口、`OPTIONS` 预检放行（已带 CORS 头）。

## 部署（Ubuntu / Debian）

```bash
# 0. 预检：Node 版本、systemd、端口占用、能否直连探测目标
bash deploy/preflight.sh

# 1. 放到 /opt（整包搬进去，含 src/ deploy/ test/）
sudo rm -rf /opt/probe-api && sudo mv probe-api /opt/probe-api
sudo find /opt/probe-api -type f | sort   # 核对文件齐全，缺 src/ 会启动失败

# 2. 环境变量（PROBE_TOKEN 留空=不鉴权，公网暴露必须设）
sudo cp /opt/probe-api/deploy/probe-api.env.example /etc/probe-api.env
sudo sed -i "s#^PROBE_TOKEN=.*#PROBE_TOKEN=$(head -c 18 /dev/urandom | base64 | tr -d '/+=')#" /etc/probe-api.env
sudo chmod 600 /etc/probe-api.env

# 3. 专用用户 + systemd
sudo useradd --system --no-create-home --shell /usr/sbin/nologin probe 2>/dev/null || true
sudo cp /opt/probe-api/deploy/probe-api.service /etc/systemd/system/
# node 不在 /usr/bin/node（nvm / 手工解压安装）时，把 ExecStart 换成实际绝对路径：
sudo sed -i "s#^ExecStart=.*#ExecStart=$(command -v node) /opt/probe-api/src/server.js#" /etc/systemd/system/probe-api.service
sudo systemctl daemon-reload && sudo systemctl enable --now probe-api
sudo systemctl status probe-api --no-pager -l | head -20
sudo journalctl -u probe-api -n 20 --no-pager      # 起不来先看这里，status=203/EXEC 就是 ExecStart 路径不对

# 4. 本机自测
TOKEN=$(sudo sed -n 's/^PROBE_TOKEN=//p' /etc/probe-api.env)
curl -s "http://127.0.0.1:8787/health" -H "Authorization: Bearer $TOKEN"; echo
curl -s "http://127.0.0.1:8787/check?socks5=1.2.3.4:1080&token=$TOKEN" | head -c 500; echo
```

从外网访问还要在**云厂商安全组**放行端口（脚本看不到安全组），裸端口暴露时务必设置 `PROBE_TOKEN`。

需要对外提供 HTTPS 时，用 nginx 反代即可（批量请求可能跑几十秒，注意放宽读超时）：

```nginx
location /probe/ {
    proxy_pass http://127.0.0.1:8787/;
    proxy_read_timeout 180s;
    proxy_set_header X-Forwarded-For $remote_addr;
}
```

## 自测

```bash
node test/integration.mjs    # 三个本地 mock 代理 → 真实 TLS 到 www.iplocate.io
node test/probe.mjs socks5://1.2.3.4:1080   # 手工探测真实节点，输出完整 JSON
```

`test/integration.mjs` 全过即为「socks5 / http CONNECT / sstp 三条链路都能打通并拿到出口 IP」。

## 已知限制

- SSTP 只实现 PAP 认证，且不校验证书（自签 VPN 常用），也不做 MS-CHAPv2；需要 MS-CHAPv2 的服务器会握手失败。
- 合成 TCP 只支持单个连接、固定 MSS，不处理乱序/重传/拥塞控制——用于「探测一次请求」足够，不能当通用隧道。
- 探测目标是 `www.iplocate.io`，被墙或被限流时所有节点都会判死；换成自建回显接口（`TARGET_*`）更稳。
- 无内置限流，公网暴露请务必设置 `PROBE_TOKEN` 并在反代层限速。
