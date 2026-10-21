# SCT AI 工具环境自查

网页版：**[sctcamp.com/tools/network](https://sctcamp.com/tools/network)**

检查 AI 工具的网络出口、代理设置、DNS、证书和公开服务连通性。只读，不修改系统设置，不需要账号或 API Key，不预测封号。

## 给第一次使用的学员

1. 先打开网页版，点击“开始检测”。
2. 在页面下载 ZIP，解压到自己的电脑。
3. Windows 双击 `开始检测.cmd`；macOS 双击 `开始检测.command`；Linux 在解压目录运行 `bash start.sh`。
4. 检测结束会自动打开本机 HTML 报告。同目录的 `network-report.json` 可导入网页版，对照浏览器与终端访问 SCT 检测站的出口。

无需管理员权限。有 Node.js 20+ 时直接使用；否则启动器从 **nodejs.org** 下载固定版本的官方便携运行时，并用官方 SHASUMS256 校验，保存在用户缓存目录，不改 PATH。公司设备的软件策略可能阻止下载或脚本运行，请联系管理员，不要绕过安全设置。macOS 如果不允许双击脚本，可以在终端进入解压目录运行 `bash start.sh`；工具不要求关闭 Gatekeeper 或删除系统安全属性。

Windows 需要自带的 Windows PowerShell；联网探测使用系统 `curl`（Windows 10/11 与 macOS 通常自带）。缺少 curl 的 Linux 环境仍可完成离线、DNS 和 Node HTTPS 检查，curl 项会标为未完成。

## 开发者运行

零 npm 依赖，无需 `npm install`。

```sh
git clone https://github.com/scotti1i/ai-network-check.git
cd ai-network-check
node src/cli.mjs
node src/cli.mjs --offline --no-open
node src/cli.mjs --output ./reports/my-check
node --test
```

`--offline` 不发起外部请求或本地端口探测，仅检查允许读取的系统与网络配置。默认报告目录为 `~/Downloads/SCT-Network-Reports/<时间>/`；无 Downloads 目录时写入用户目录。

## 检测范围

| 项目 | 实际做什么 | 不能证明什么 |
|---|---|---|
| 环境变量代理 | 仅提取网络白名单；代理用户名、密码、查询与路径隐藏 | 不代表桌面客户端或项目设置 |
| 系统代理 | macOS scutil / Windows 用户 Internet Settings | 不代表所有应用遵从系统代理；Linux 桌面需自行核对 |
| 本地代理端口 | 只连接环境变量明确配置的 loopback 端口 | 能连上不代表上游可用，不进行端口扫描 |
| DNS | 读取解析器配置，查询四个 Claude 域名的 A 记录 | 不做权威 DNS 泄漏判断；fake-IP 不判错 |
| IPv4 / IPv6 | 向指定 IP 目标发 HTTPS 请求，记录返回的出口信息 | 代理可能代连 IPv6，不证明原生 IPv6，也不等于泄漏 |
| HTTPS | 无鉴权访问固定公开端点，保持 TLS 校验 | 401 不代表账号有效；403 不等于封号 |
| 应用代理对照 | 同一 SCT 端点分别使用 curl 默认代理环境与禁用应用代理 | 后者仍可能经过 VPN／TUN，不能称为物理直连 |
| Node TLS | 强制启用校验发起 Node HTTPS 请求 | 不自动使用代理变量，不等同于原生 Claude Code 的实际流量 |
| UDP / STUN | Cloudflare STUN 取得本地 UDP 出口 | 不等于浏览器 WebRTC，差异不直接判为泄漏 |
| Claude Code 设置 | 仅查看用户 settings 的网络 env 字段 | 不读取凭据／对话，不覆盖项目和进程实际设置 |

不会读取支付信息、账号 Cookie、凭据文件、聊天记录、MAC 地址或完整环境变量。不会根据时区、语言、虚拟网卡、住宅／机房标签编造风控评分。

**平台支持范围取决于实际使用者和所在地等条件，代理出口不是资格证明。** 请核对官方条款及支持范围。

## 隐私与报告

- 外部探测固定访问 SCT、Cloudflare、Anthropic、OpenAI、ipapi.is 和 tls.peet.ws；这些服务能看到连接 IP。无账号鉴权，不读取 `.curlrc`，不发送 API Key。
- 本工具不上传报告。HTML 报告的 CSP 禁止联网，没有统计脚本。
- 原始 JSON 含完整公网 IP，方便本人对照；请勿直接公开。需要分享时，用 HTML 报告的“导出脱敏 JSON”。
- 网页导入仅在浏览器内解析，不发送报告到服务器。SCT 和其他探测端点可能保留基础访问日志。
- 原始报告在支持权限模式的系统上以目录 `700`、文件 `600` 创建；Windows 继承用户目录 ACL。
- 不自动修复。每项提供证据、边界和下一步，由使用者决定是否修改配置。

## 状态说明

`正常`：取得可验证的正常检测结果。

`需处理`：出现明确错误或需要结合环境判断的响应，例如 TLS 失败或 HTTP 403。

`已记录`：记录事实，不单独评判好坏。

`未取得结果`：证据不足或当前能力无法检测；明确的连接失败和超时显示为检测失败；不会冒充“通过”。

## 维护

`src/core.mjs` 是只读检测核心，`src/html.mjs` 生成离线报告，`src/cli.mjs` 写入报告并打开浏览器。`start.sh` / `start.ps1` 只负责启动与官方运行时准备。

CI 在 Windows、macOS、Linux 的 Node 20/22 上运行测试和离线报告／启动器验证。网络依赖不在 CI 里假装全通过，线上验收另测真实端点。没有 Windows GUI 的现场验收记录时，不宣称已验证所有 Windows 双击体验。

## v1.1.0 专项检查

新增 Claude API、网页、登录/授权、安装更新链路；官方服务状态；三次 Claude API 连续连接；出口 IP/ASN/运营商；本地 curl 的 JA3/JA4、TCP SYN 和 p0f 观测；Claude Code 代理协议、变量优先级、ALL_PROXY 与 NO_PROXY 冲突检查；自定义 API 地址提示。DNS 现在逐个检测 Claude 的四个域名并明确显示失败。

指纹来自本次 curl 请求，代理可能决定目标看到的 TCP 栈；不把 p0f 签名直接翻译为设备封禁。IP 归属来自 ipapi.is 匿名查询（每个出口每天30次，浏览器按IP缓存30分钟）；匿名接口没有住宅、机房或滥用信誉标记，缺失时不编造。指纹服务为 tls.peet.ws。外部信息请求失败或受限时显示缺失，不重试刷接口。

原文中的邮箱、支付、账号共享、手机权限、实际所在地与设备历史，在网页提供六项人工自查，不收取账号、卡号、密码或精确位置。系统 DNS 配置与公共 DNS 查询都不冒充权威 DNS 泄漏检测。

发布版本：`node scripts/package.mjs <网站 public/network-check 目录>` 生成固定版本 ZIP、tar.gz、SHA256SUMS 和一键启动入口；源码和同版本下载包应一起发布。下载包不包含课程网站源码、环境配置或报告。

## 依据

- [WebRTC IP 地址处理标准 RFC 8828](https://www.rfc-editor.org/rfc/rfc8828)
- [Chromium 代理机制](https://github.com/chromium/chromium/blob/main/net/docs/proxy.md)
- [Claude 保障措施和申诉](https://support.claude.com/en/articles/8241253-safeguards-warnings-and-appeals)
- [Claude Code 网络配置](https://code.claude.com/docs/en/network-config)

MIT License · [Scott 的课程与实操案例](https://sctcamp.com/?view=public)
