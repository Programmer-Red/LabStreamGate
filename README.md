# LabStreamGate

LabStreamGate 是由 TKKC Sec 维护、面向 CTF 平台的单入口 TCP-over-WebSocket 隧道网关。平台只需暴露一个
HTTPS/WSS 入口，即可通过不同的高熵通道标识承载 Web、Pwn、SSH 等动态靶机连接，无需在
公网服务器上维护大范围端口转发。

## 项目来源与许可证

本项目基于 [XDSEC/WebSocketReflectorX](https://github.com/XDSEC/WebSocketReflectorX)
二次开发，原项目由 XDSEC 与 Reverier-Xu 开发并使用 MIT License 发布。

- 原始版权声明和 MIT 许可文本保留在 [LICENSE](LICENSE) 中。
- 二次开发说明见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
- TKKC Sec 的产品命名、平台适配与新增代码不会改变原项目的版权归属。

## 平台模式

```bash
export WSRX_ADMIN_TOKEN='至少包含 32 字节随机熵的管理令牌'
export WSRX_STATE_FILE='/var/lib/streamgate/tunnels.json'
export WSRX_ALLOWED_TARGET_HOSTS='127.0.0.1,::1'
export WSRX_MAX_CONNECTIONS='4096'
export WSRX_MAX_CONNECTIONS_PER_TUNNEL='32'
export WSRX_CONNECTION_TIMEOUT_SECONDS='1800'
export WSRX_MAX_CAPTURE_BYTES='67108864'
export WSRX_CAPTURE_RETENTION_DAYS='7'
export WSRX_CAPTURE_MAX_TOTAL_BYTES='21474836480'

labstreamgate serve --host 0.0.0.0 --port 8080
```

平台通过受保护的管理接口注册通道：

```http
POST /pool
Authorization: Bearer <WSRX_ADMIN_TOKEN>
Content-Type: application/json

{
  "key": "一段至少16位的URL安全高熵随机值",
  "target": "127.0.0.1:20001",
  "expiresAt": 1790000000
}
```

用户侧连接地址为：

```text
wss://chall.xujclab.com/<key>
```

管理接口还支持：

- `GET /pool`：查看有效通道。
- `DELETE /pool`，请求体 `{"key":"..."}`：删除通道。
- `GET /health`：无需鉴权的容器健康检查。
- `OPTIONS /<key>`：检查通道是否存在且仍在有效期内。
- `/traffic/<key>`：为原版客户端保留的兼容路径，新平台不再生成该地址。

## 单入口部署关系

```text
参赛者本机 TCP 客户端
        │
        ▼
LabStreamGate Desktop（本机端口）
        │ WSS :443 /<key>
        ▼
公网 Caddy（chall.xujclab.com）
        │ 单一内网 HTTP/WebSocket 上游
        ▼
内网 StreamGate Gateway :8788
        │ 127.0.0.1:<受控靶机端口>
        ▼
动态靶机容器
```

公网服务器只承担 TLS 与 WebSocket 反向代理，不运行大范围 GOST 端口映射。

## 安全约束

- 管理令牌优先通过 `WSRX_ADMIN_TOKEN` 环境变量注入，避免出现在进程参数中。
- `--allow-target-host`/`WSRX_ALLOWED_TARGET_HOSTS` 将目标限制为明确的 IP 地址。
- 通道标识必须是 16–128 位 URL 安全字符；平台应生成至少 32 字节随机熵。
- 可为每条通道设置 `expiresAt`，过期通道会自动清理。
- 通道表采用原子文件替换持久化，进程重启后可恢复未过期通道。
- `WSRX_MAX_CONNECTIONS` 控制并发连接上限，避免低配置网关被连接耗尽。
- 每个通道默认最多 32 个并发连接，单次连接最长 30 分钟，避免单题耗尽全局资源。

## 连接审计与 PCAP

平台模式会为每次连接记录连接 ID、靶机/题目/用户/赛事关联、来源 IP、开始与结束时间、双向字节数和结束原因。
审计日志按靶机写入 `audit/<instanceId>.jsonl`，单文件达到 16 MiB 时轮换。

题目启用流量捕获后，LabStreamGate 将双向 TCP 载荷封装成标准 PCAP，保存到
`captures/<instanceId>/<connectionId>.pcap`，供平台后台鉴权下载。默认每条连接最多捕获 64 MiB、
保留 7 天且全部 PCAP 总量不超过 20 GiB；达到限制时优先清理最旧文件。PCAP 可能包含 flag、凭据或选手输入，
因此不提供公开下载地址，并应仅向授权管理员开放。

## 本地客户端

保留原项目的 CLI、桌面端与网页控制本地客户端的能力。CLI 示例：

```bash
labstreamgate connect \
  'wss://chall.xujclab.com/<key>' \
  --host 127.0.0.1 \
  --port 9000
```

之后使用题目要求的原生客户端连接 `127.0.0.1:9000`。

## 开发构建

```bash
cargo build --release -p wsrx --bin labstreamgate
```

桌面应用仍位于 `crates/desktop`。平台网关可使用仓库根目录的 `Dockerfile` 构建。
