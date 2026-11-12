# NexusLab 隐私政策

**NexusLab Privacy Policy**

版本 1.0 · 生效日期：2026-11-12<br>
Version 1.0 · Effective: 2026-11-12

## 1. 概述 / Overview

NexusLab 在本机运行。本项目不运营任何用于收集用户数据的服务器，软件不包含遥测、使用统计或广告 SDK。

NexusLab runs locally. The project operates no server that collects user data. The software contains no telemetry, usage analytics, or advertising SDKs.

## 2. 本地处理与存储 / Local Processing and Storage

软件在你的设备上创建并维护以下目录：

- `config/`：运行时配置、WebUI 证书与私钥、许可同意记录
- `logs/`：运行日志（可能包含 QQ 号、账号昵称等标识信息；可选按账号分目录）
- `data/`：账号资料与本地缓存（如账号 JSON、系统表情目录）

软件会读取本机 QQ 客户端的数据文件以识别账号；QQ 登录凭据由 QQ 客户端自身处理，NexusLab 不接触账号密码。

The software creates and maintains the following directories on your device:

- `config/`: runtime configuration, WebUI certificate and private key, consent records
- `logs/`: runtime logs (may contain QQ numbers, nicknames and similar identifiers)
- `data/`: account profiles and local caches (e.g. account JSON, system face catalog)

The software reads local QQ client data files to identify accounts. Login credentials are handled by the QQ client itself; NexusLab never touches account passwords.

## 3. 网络通信 / Network Communication

- **QQ 服务器**：与 QQ 服务器的通信由本机 QQ 客户端完成，NexusLab 不直接建立该连接。
- **更新检查**：会访问 GitHub 的发布页 / API 及可选镜像地址（可在设置中关闭或改为直连）。
- **OneBot / HTTP / WebSocket**：仅连接你自行配置的地址，用于推送事件与接收动作。
- **WebUI**：默认仅绑定 `127.0.0.1:5099`，不对外网开放；如你修改绑定地址，请自行配置防火墙与访问控制。

- **QQ servers**: communication with QQ servers is performed by the local QQ client; NexusLab does not open that connection itself.
- **Update checks**: GitHub release pages / API and optional mirrors (can be disabled or switched to direct mode).
- **OneBot / HTTP / WebSocket**: only connects to endpoints you configure.
- **WebUI**: binds to `127.0.0.1:5099` by default and is not exposed externally; if you change the bind address, secure it yourself.

## 4. 我们不收集什么 / What We Do Not Collect

不收集 QQ 密码、不上传聊天内容、不采集设备指纹、不进行使用统计。消息数据仅在本机处理，并按你的配置转发给你指定的端点。

We do not collect QQ passwords, do not upload chat content, do not fingerprint devices, and do not track usage. Message data is processed locally and forwarded only to endpoints you configure.

## 5. 第三方 / Third Parties

- **腾讯 / QQ**：QQ 客户端对你的数据的处理受腾讯相关协议与隐私政策约束。
- **镜像加速服务**：更新检查可能经由公开的 GitHub 镜像转发请求，其仅能看到更新请求本身。

- **Tencent / QQ**: the QQ client's handling of your data is governed by Tencent's terms and privacy policy.
- **Mirror services**: update checks may be relayed through public GitHub mirrors, which only see the update request itself.

## 6. 数据删除 / Data Deletion

删除软件目录（或其中的 `config/`、`logs/`、`data/`）即可删除全部本地数据。本项目不保存云端副本，因此没有额外需要删除的远程数据。

Deleting the software directory (or `config/`, `logs/`, `data/` within it) removes all local data. No cloud copies are kept by the project.

## 7. 未成年人 / Minors

本软件不面向未满 14 周岁（或所在司法辖区法定年龄）的用户。

The software is not intended for users under 14 years of age (or the legal age in your jurisdiction).

## 8. 政策变更 / Changes

本政策的更新随项目仓库发布；变更后继续使用即视为接受更新后的政策。

Updates to this policy are published in the project repository. Continued use after a change constitutes acceptance of the updated policy.

## 9. 联系方式 / Contact

隐私相关问题请通过项目仓库的 Issues 联系维护者。

For privacy questions, contact the maintainers via the project repository's Issues.