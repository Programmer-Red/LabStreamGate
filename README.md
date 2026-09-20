# LabStreamGate

![LabStreamGate](arts/logo.png)

LabStreamGate 是 xujclab 靶机的本地连接器。它会把题目页给出的 WSS 连接转成本机 TCP 地址，供浏览器、SSH、nc 和调试器使用。

## 下载

请前往 [Releases](https://github.com/Programmer-Red/LabStreamGate/releases/latest) 下载适合自己系统的版本：

| 系统 | 推荐文件 |
| --- | --- |
| Windows 10/11 | `LabStreamGate-*-installer-windows-x86_64.exe` |
| macOS Apple 芯片 | `LabStreamGate-*-macos-aarch64.dmg` |
| macOS Intel 芯片 | `LabStreamGate-*-macos-x86_64.dmg` |
| Linux x86_64 | `LabStreamGate-*-linux-x86_64.AppImage` |

## 使用

1. 安装并启动 LabStreamGate，保持它在后台运行。
2. 在 xujclab 题目页启动靶机。
3. 点击「使用 LabStreamGate 连接」，首次使用时在客户端中允许 xujclab。
4. 按题目页显示的本机地址连接，例如 `127.0.0.1:32123`。

macOS 如果提示应用无法打开，先将应用拖入「应用程序」，再执行：

```bash
sudo xattr -cr /Applications/LabStreamGate.app
```

## 常见问题

- **网页显示未检测到客户端**：确认 LabStreamGate 已启动，然后刷新题目页。
- **连接后立即断开**：检查靶机是否过期，重新启动靶机后再连接。
- **安全软件拦截**：允许 LabStreamGate 访问本机网络，不需要对外开放任何端口。

## 开源说明

本项目基于 [XDSEC/WebSocketReflectorX](https://github.com/XDSEC/WebSocketReflectorX) 修改，按 MIT License 发布。原始版权与完整说明见 [LICENSE](LICENSE) 和 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
