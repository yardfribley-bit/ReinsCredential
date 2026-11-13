[English](RELEASE_NOTES_0.2.0.md) · [简体中文](RELEASE_NOTES_0.2.0.zh-CN.md)

# ReinsCredential 0.2.0

ReinsCredential 0.2.0 报告哪个桌面应用打开了已登记的敏感文件，以及该进程是已上传、尝试失败、没有离机发送，还是看不到。

## 安装

把 `ReinsCredential-0.2.0-local.dmg`、`ReinsCredential-0.2.0-local.zip` 和 `SHA256SUMS.txt` 下载到同一个文件夹。校验文件里的两个安装包都是文件名。先核对，再打开磁盘映像或解压，把 `ReinsCredential.app` 放进 `/Applications` 或 `~/Applications`：

```sh
shasum -a 256 -c SHA256SUMS.txt
```

临时签名版第一次启动会登记本用户的 LaunchAgent。Developer ID 构建使用系统登录项服务。ad-hoc 安装包未公证。如果 Gatekeeper 拦住，按住 Control 点这个 App，选择“打开”，再选“打开”。不要关闭系统安全设置。

## 四句结论

- **已上传 / Uploaded。** 已登记字节出现在返回成功的代理 HTTP 正文里，或进程树在持有文件和短暂收尾窗口里测到的离机发送（TCP 与 UDP/QUIC 合计）落在压缩下界和原始大小加 64 KiB 之间（`flow_txbytes`，数据报带走时是 `flow_txbytes_udp`）。大约 100 毫秒就关闭的连接，关闭之后仍然计入。这个计数不是解密后的正文，也不是对端回执。
- **已尝试未成功 / Attempted。** 匹配的正文已发出但传输失败，或离机连接在文件字节送出之前失败，包括短的被拒绝连接。
- **未发现 / Not found。** 该窗口里每条离机通道都测到了，并且合计低于压缩下界。留在 `127.0.0.1` 的发送是这一句（`loopback_not_off_host`）。
- **看不到 / Not visible。** 通道在拿到字节数之前就关了、描述符不完整，或测到的合计超过窗口。这不是清白结论，也不会改写成未发现。

## 限制

没有进入本地代理的 TLS 不会被解密。客户端握手发送不超过 1024 字节不是上传。对端名字在解析器有结果时用反向 DNS，或使用网络统计源里已经有的主机名。不从套接字上抄 ClientHello。压缩下界是 gzip、zlib 或 raw deflate，不是 zstd。代理不是系统级的。不会把 CA 放进钥匙串，也不会修改其它应用的 MCP 设置。FSEvents 仍然不能指出读取文件的进程。网络统计控制没有报告的连接，仍然可能漏掉。

## 升级与卸载

替换之前先退出应用并停止监控。`~/Library/Application Support/ReinsCredential` 里的证据会保留。要移除应用和它的 LaunchAgent、同时留下证据：

```sh
macOSClient/scripts/uninstall-local.sh
```

只有在确实要删掉证据目录时才加 `--delete-evidence`。
