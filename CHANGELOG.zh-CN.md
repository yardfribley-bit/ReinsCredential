[English](CHANGELOG.md) · [简体中文](CHANGELOG.zh-CN.md)

# 更新记录

## 0.2.0

- 实时检测跟的是已登记文件被打开，而不是已知 Agent 名单。属主是该进程周围的桌面 `.app`。上面还有桌面应用时，Xcode 和它的 `Python.app` 只是工具链，不是属主。
- 每个行为者单独收口为已上传、已尝试未成功、未发现或看不到。启动自检的正文匹配不会取消后来另一个进程对同一文件的结论。
- 仪表盘可以导出 JSON 证据链和同一条链的 Markdown。两者都不含密钥原文。
- 本地构建使用 ad-hoc 签名。只有设置了对应环境变量时才做 Developer ID 签名和公证。
- 卸载会移除本产品的 LaunchAgent 和 App。除非传入 `--delete-evidence`，证据会留下。
