[English](RELEASE_NOTES_0.2.0.md) · [简体中文](RELEASE_NOTES_0.2.0.zh-CN.md)

# ReinsCredential 0.2.0

ReinsCredential 0.2.0 报告哪个桌面应用打开了已登记的敏感文件，以及该进程是已上传、尝试失败、没有离机发送，还是看不到。

## 安装

打开 `ReinsCredential-0.2.0-local.dmg`，或解压 `ReinsCredential-0.2.0-local.zip`，把 `ReinsCredential.app` 放进“应用程序”。临时签名版第一次启动会登记本用户的 LaunchAgent。Developer ID 构建使用系统登录项服务。打开安装包前核对 `SHA256SUMS.txt`。

## 四句结论

- **已上传 / Uploaded。** 已登记字节出现在返回成功的代理 HTTP 正文里，或同一进程向非回环地址发送的 TCP 字节数足以容纳该文件（`flow_txbytes`）。这个计数不是解密后的正文，也不是对端回执。
- **已尝试未成功 / Attempted。** 匹配的正文已发出但传输失败，或离机连接在文件字节送出之前失败，包括连接被拒绝。
- **未发现 / Not found。** 进程和它的 TCP 计数可见，没有看到该文件的离机上传。留在 `127.0.0.1` 的发送是这一句（`loopback_not_off_host`）。
- **看不到 / Not visible。** 描述符列表或通道读不到。UDP 和 QUIC 是这一句。这不是清白结论。

## 限制

没有进入本地代理的 TLS 不会被解密。代理不是系统级的。不会把 CA 放进钥匙串，也不会修改其它应用的 MCP 设置。FSEvents 仍然不能指出读取文件的进程。

## 升级与卸载

替换之前先退出应用并停止监控。`~/Library/Application Support/ReinsCredential` 里的证据会保留。要移除应用和它的 LaunchAgent、同时留下证据：

```sh
macOSClient/scripts/uninstall-local.sh
```

只有在确实要删掉证据目录时才加 `--delete-evidence`。
