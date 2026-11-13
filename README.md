# NexusLab

**让 QQ 原生会话，连接你的应用。**

QQ 客户端的 TypeScript 互操作运行时，配套自研原生组件。<br>
OneBot v11 · WebUI · SDK · MCP

将 QQ 原生会话转换为 [OneBot v11](https://github.com/botuniverse/onebot-11) 动作与事件，通过 WebSocket、HTTP、WebUI、SDK 和 MCP 提供统一入口。

多账号会话、消息与媒体、连接配置和实时日志，在一个运行时中管理。

<sub>Windows x64 · Linux x64 / arm64</sub>

> [!CAUTION]
> NexusLab 是独立的第三方项目，与腾讯 / QQ 无隶属或授权关系。项目仅供学习与技术研究，请遵守《QQ 用户协议》及适用法律；软件按「现状」提供，使用风险自负。

## 核心能力

| 场景 | 能力 |
| --- | --- |
| OneBot 接入 | OneBot v11 动作与事件；WebSocket 服务端 / 客户端及 HTTP 服务端 / 上报 |
| 消息与媒体 | 文本、图片、语音、视频、文件、回复、提及、转发及常见卡片 |
| 多账号运行 | 各账号独立维护会话、身份映射、消息存储和网络配置 |
| WebUI 管理 | 账号状态、实时日志、连接配置、动作调试和存储管理 |
| 开发者工具 | [`@nexuslab/sdk`](packages/sdk/README.md) 与 [`@nexuslab/mcp`](packages/mcp/README.md) |
| 原生组件 | 自研 QQ 注入 DLL 与手动映射加载器（Windows x64） |

## 仓库结构

| 目录 | 说明 |
| --- | --- |
| `packages/` | TypeScript 运行时：`bridge`、`protocol`、`runtime`、`onebot`、`core`、`webui`、`sdk`、`mcp` 等 |
| `dll-framework/` | Windows QQ 注入 DLL 源码（C++ / MSVC，产物 `nexuslab-win32-x64.dll`） |
| `native-rewrite/` | 手动映射加载器源码（node-gyp 附加组件） |
| `packages/runtime/native/` | 发行时使用的原生二进制槽位 |

运行链路：会话接入、协议解析、身份映射、OneBot 转换和网络适配保持独立边界；多个 QQ 账号可并行运行。

## 快速开始（从源码）

需要 Node.js 24+ 与 pnpm：

```bash
git clone https://github.com/ylh440104/NexusLab.git
cd NexusLab
pnpm install --frozen-lockfile
pnpm build:all
pnpm start
```

打开 [`http://localhost:5099`](http://localhost:5099)，使用启动日志中的初始密码登录 WebUI，按引导接入 QQ 进程并配置 OneBot 连接。

开发模式（热加载，无需构建）：

```bash
pnpm dev
```

账号识别由登录数据库的文件变化、进程和登录事件或手动操作触发，不做周期探测。需要重查时可点击 WebUI 进程行的刷新/重连。

## 原生组件构建（Windows）

注入 DLL 使用 MSVC 构建。构建前需从原生二进制槽位提取 resident 镜像并生成嵌入 blob：

```bat
python extract_resident.py packages\runtime\native\nexuslab-win32-x64.dll dll-framework\build\resident_embed.dll
python dll-framework\tools\gen_blob.py dll-framework\build\resident_embed.dll dll-framework\build\resident_blob.cpp
```

随后用 `cl.exe` 将 `dll-framework\src` 下的源码与生成的 `resident_blob.cpp` 一起编译链接为 DLL。

加载器附加组件：

```bash
cd native-rewrite
npx node-gyp rebuild
```

## 接入与文档

| 入口 | 文档 |
| --- | --- |
| TypeScript SDK | [`packages/sdk/README.md`](packages/sdk/README.md) |
| MCP | [`packages/mcp/README.md`](packages/mcp/README.md) |
| OneBot 动作 | 见 WebUI「动作调试」面板 |

JSON 消息段接受标准的 `data.data` 字符串，也兼容 `data.data` 非数组对象和 `{ type: "json", data: "..." }` 简写；`data` 必填，最终内容必须是 JSON 对象。

## 开发

```bash
pnpm typecheck
pnpm test
```

## 使用边界与许可

> [!IMPORTANT]
> NexusLab 以 **GNU Affero General Public License version 3（AGPL-3.0）** 授权。你可以自由使用、修改并再分发本软件，再分发时须保留本许可并提供对应的完整源码。**若你将修改后的版本作为网络服务对外提供，也必须向使用者提供完整源码。**

完整条款见 [`LICENSE`](LICENSE)；二进制发行包另受 [`EULA.md`](EULA.md) 与 [`PRIVACY.md`](PRIVACY.md) 约束。

NexusLab is licensed under the GNU Affero General Public License version 3 (AGPL-3.0). You may use, modify, and redistribute it; redistribution must retain the license and provide the corresponding complete source code. **If you make a modified version available as a network service, you must also offer its complete source code to users of that service.**

## 致谢

项目参考了 [LagrangeV2](https://github.com/LagrangeDev/LagrangeV2) 的协议定义与 [NapCatQQ](https://github.com/NapNeko/NapCatQQ) 的实现思路，并基于 NexusLab 源码继续维护、重写了原生组件。