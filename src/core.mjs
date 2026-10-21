import {
  proxyDiagnostics,
  gatewayDiagnostic,
  fingerprintCheck,
  metadataCheck,
} from "./diagnostics.mjs";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { access, readFile } from "node:fs/promises";
import { homedir, networkInterfaces, platform, release } from "node:os";
import { join } from "node:path";
import { isIP, createConnection } from "node:net";
import { Resolver } from "node:dns/promises";
import { createSocket } from "node:dgram";
import { randomBytes } from "node:crypto";
import https from "node:https";

export const VERSION = "1.1.0";
const execute = promisify(execFile);
const proxyKeys = [
  "http_proxy",
  "https_proxy",
  "all_proxy",
  "no_proxy",
  "HTTP_PROXY",
  "HTTPS_PROXY",
  "ALL_PROXY",
  "NO_PROXY",
];
const networkKeys = [
  ...proxyKeys,
  "ANTHROPIC_BASE_URL",
  "OPENAI_BASE_URL",
  "NODE_EXTRA_CA_CERTS",
  "SSL_CERT_FILE",
  "CURL_CA_BUNDLE",
  "NODE_TLS_REJECT_UNAUTHORIZED",
  "CLAUDE_CODE_CERT_STORE",
  "CLAUDE_CODE_CLIENT_CERT",
  "CLAUDE_CODE_CLIENT_KEY",
  "DISABLE_TELEMETRY",
  "DISABLE_ERROR_REPORTING",
  "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC",
];

export function maskText(text) {
  return String(text)
    .replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, (ip) =>
      isIP(ip) ? `${ip.split(".").slice(0, 2).join(".")}.x.x` : ip,
    )
    .replace(/[0-9a-f]*:[0-9a-f:]+/gi, (ip) =>
      isIP(ip) === 6 ? `${ip.split(":").slice(0, 2).join(":")}:…` : ip,
    );
}

export function safeEndpoint(value) {
  try {
    const url = new URL(value.includes("://") ? value : `http://${value}`);
    if (
      !["http:", "https:", "socks:", "socks4:", "socks5:", "socks5h:"].includes(
        url.protocol,
      )
    )
      return "已设置（无法识别的协议）";
    return `${url.protocol}//${url.hostname}${url.port ? `:${url.port}` : ""}${url.username || url.password ? "（含认证信息，已隐藏）" : ""}`;
  } catch {
    return "已设置（地址格式无法识别，未回显原文）";
  }
}

export function selectedEnvironment(env) {
  return Object.fromEntries(
    networkKeys
      .filter((key) => Object.hasOwn(env, key) && env[key])
      .map((key) => {
        if (key.toLowerCase() === "no_proxy")
          return [key, "已设置（规则内容不回显）"];
        if (/proxy$|BASE_URL$/i.test(key)) return [key, safeEndpoint(env[key])];
        if (/CERT/.test(key)) return [key, "已配置自定义证书文件（路径隐藏）"];
        return [
          key,
          ["0", "1", "true", "false"].includes(env[key]) ? env[key] : "已设置",
        ];
      }),
  );
}

export function classifyHTTP(status, curlCode = 0, tlsResult = 0) {
  if (curlCode) {
    const reasons = {
      5: "代理服务器域名解析失败",
      6: "目标域名解析失败",
      7: "连接未建立",
      28: "请求超时",
      35: "TLS 握手失败",
      60: "证书校验失败",
      97: "代理握手失败",
      56: "接收响应时连接中断",
    };
    return {
      status: curlCode === -1 ? "unknown" : "error",
      summary: reasons[curlCode] || `连接探测未完成（curl ${curlCode}）`,
      action:
        curlCode === 60
          ? "核对系统时间、企业证书和可信 CA；不要关闭证书校验。"
          : "检查网络、代理监听与目标服务状态，再复测。",
    };
  }
  if (tlsResult)
    return {
      status: "review",
      summary: "TLS 校验结果需要检查。",
      action: "核对证书信任链和系统时间，不要绕过证书校验。",
    };
  if (status === 401)
    return {
      status: "ok",
      summary: "已收到服务响应：需要鉴权（HTTP 401）。",
      action:
        "网络请求已到达响应方。此次没有发送账号凭据，不能判断登录或订阅状态。",
    };
  if (status === 403)
    return {
      status: "review",
      summary: "响应方拒绝了这次自动请求（HTTP 403）。",
      action:
        "可能是浏览器挑战、网络策略或地区限制，不能据此判断封号；在官方浏览器页面核对具体提示。",
    };
  if (status === 429)
    return {
      status: "review",
      summary: "响应方返回限流（HTTP 429）。",
      action:
        "等待后再试，不要反复重测；本次请求没有使用账户，不能据此判断账户额度。",
    };
  if (status >= 500)
    return {
      status: "review",
      summary: `服务端返回错误（HTTP ${status}）。`,
      action: "检查官方服务状态并稍后复测，先不要修改本地配置。",
    };
  if (status >= 200 && status < 400)
    return {
      status: "ok",
      summary: `已收到 HTTPS 响应（HTTP ${status}）。`,
      action:
        "说明本次连接成功，不代表账户权限、应用全部功能或其他网络路径正常。",
    };
  return {
    status: "info",
    summary: `响应方返回 HTTP ${status}。`,
    action:
      "已取得 HTTP 响应；路径、请求方式或服务策略需要单独核对，不能等同于封号。",
  };
}

async function command(file, args, timeout = 4500) {
  try {
    return {
      ok: true,
      ...(await execute(file, args, {
        timeout,
        maxBuffer: 256 * 1024,
        windowsHide: true,
        encoding: "utf8",
      })),
    };
  } catch (error) {
    return {
      ok: false,
      code: error.code,
      stdout: typeof error.stdout === "string" ? error.stdout : "",
    };
  }
}

function proxyFreeEnvironment() {
  const env = { ...process.env };
  for (const key of proxyKeys) delete env[key];
  return env;
}

async function curl(url, { body = false, noProxy = false } = {}) {
  const args = [
    "-q",
    "--silent",
    "--show-error",
    "--connect-timeout",
    "5",
    "--max-time",
    "10",
    "--max-filesize",
    "262144",
    "--proto",
    "=https",
    "--max-redirs",
    "0",
  ];
  if (!body)
    args.push("--output", platform() === "win32" ? "NUL" : "/dev/null");
  if (noProxy) args.push("--noproxy", "*");
  args.push(
    "--write-out",
    "\nSCT_RESULT:%{http_code}|%{ssl_verify_result}|%{time_total}",
    url,
  );
  let output = "",
    code = 0;
  try {
    output = (
      await execute(platform() === "win32" ? "curl.exe" : "curl", args, {
        timeout: 11500,
        maxBuffer: 300 * 1024,
        windowsHide: true,
        encoding: "utf8",
        env: noProxy ? proxyFreeEnvironment() : process.env,
      })
    ).stdout;
  } catch (error) {
    code = typeof error.code === "number" ? error.code : -1;
    output = typeof error.stdout === "string" ? error.stdout : "";
  }
  const at = output.lastIndexOf("\nSCT_RESULT:");
  const [http = "0", tls = "0", duration = "0"] =
    at >= 0
      ? output
          .slice(at + 12)
          .trim()
          .split("|")
      : [];
  return {
    code,
    http: Number(http),
    tls: Number(tls),
    ms: Math.round(Number(duration) * 1000),
    body: body && at >= 0 ? output.slice(0, at) : "",
  };
}

async function systemSettings() {
  let evidence = [],
    dns = [];
  if (platform() === "darwin") {
    const [proxy, resolvers] = await Promise.all([
      command("scutil", ["--proxy"]),
      command("scutil", ["--dns"]),
    ]);
    for (const line of proxy.stdout.split("\n")) {
      const m = line
        .trim()
        .match(
          /^(HTTPEnable|HTTPSEnable|SOCKSEnable|ProxyAutoConfigEnable|ProxyAutoDiscoveryEnable|HTTPPort|HTTPSPort|SOCKSPort)\s*:\s*(\d+)$/,
        );
      if (m) evidence.push(`${m[1]}：${m[2]}`);
      const host = line
        .trim()
        .match(/^(HTTPProxy|HTTPSProxy|SOCKSProxy)\s*:\s*(.+)$/);
      if (host) evidence.push(`${host[1]}：${safeEndpoint(host[2])}`);
    }
    dns = [...resolvers.stdout.matchAll(/nameserver\[\d+\]\s*:\s*(\S+)/g)]
      .map((m) => m[1])
      .filter((ip) => isIP(ip));
    if (!proxy.ok) evidence.push("未读取到 macOS 系统代理。");
  } else if (platform() === "win32") {
    const [proxy, resolvers] = await Promise.all([
      command("powershell.exe", [
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        String.raw`$p=Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'; @{enabled=$p.ProxyEnable; server=$p.ProxyServer; pac=[bool]$p.AutoConfigURL} | ConvertTo-Json -Compress`,
      ]),
      command("powershell.exe", [
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        "@(Get-DnsClientServerAddress -ErrorAction SilentlyContinue | ForEach-Object {$_.ServerAddresses}) | ConvertTo-Json -Compress",
      ]),
    ]);
    try {
      const p = JSON.parse(proxy.stdout);
      evidence.push(
        `Windows 用户代理：${p.enabled ? "开启" : "关闭"}`,
        `PAC 配置：${p.pac ? "有" : "无"}`,
      );
      if (p.server)
        for (const entry of String(p.server).split(";"))
          evidence.push(
            `代理端点：${safeEndpoint(entry.includes("=") ? entry.slice(entry.indexOf("=") + 1) : entry)}`,
          );
    } catch {
      evidence.push("未读取到 Windows 用户代理。");
    }
    try {
      const values = JSON.parse(resolvers.stdout);
      dns = (Array.isArray(values) ? values : [values]).filter(
        (ip) => typeof ip === "string" && isIP(ip),
      );
    } catch {
      /* 下方使用 Node 配置兜底 */
    }
  } else {
    try {
      const content = await readFile("/etc/resolv.conf", "utf8");
      dns = [...content.matchAll(/^nameserver\s+(\S+)/gm)]
        .map((m) => m[1])
        .filter((ip) => isIP(ip));
    } catch {
      /* Resolver.getServers() 兜底 */
    }
    evidence.push(
      "Linux 桌面代理因桌面环境不同而异，本工具未自动读取；请结合环境变量检查。",
    );
  }
  const resolver = new Resolver({ timeout: 1800, tries: 1 });
  return {
    evidence,
    dns: [...new Set(dns.length ? dns : resolver.getServers())],
  };
}

async function localProxyListeners(env) {
  const targets = new Map();
  for (const key of proxyKeys.filter((k) => k.toLowerCase() !== "no_proxy")) {
    if (!env[key]) continue;
    try {
      const u = new URL(
        env[key].includes("://") ? env[key] : `http://${env[key]}`,
      );
      if (["127.0.0.1", "localhost", "[::1]"].includes(u.hostname))
        targets.set(
          `${u.hostname}:${u.port || (u.protocol === "https:" ? "443" : "80")}`,
          u,
        );
    } catch {
      /* 地址格式由环境变量检查解释 */
    }
  }
  return Promise.all(
    [...targets.values()].map(
      (u) =>
        new Promise((resolve) => {
          const socket = createConnection({
            host: u.hostname.replace(/^\[|\]$/g, ""),
            port: Number(u.port || (u.protocol === "https:" ? 443 : 80)),
          });
          let finished = false;
          const finish = (ok) => {
            if (finished) return;
            finished = true;
            socket.destroy();
            resolve({ endpoint: safeEndpoint(u.toString()), ok });
          };
          socket.setTimeout(1600, () => finish(false));
          socket.once("connect", () => finish(true));
          socket.once("error", () => finish(false));
        }),
    ),
  );
}

async function claudeSettings() {
  const evidence = [];
  let issueCount = 0;
  for (const filename of ["settings.json", "settings.local.json"]) {
    try {
      const content = await readFile(
        join(homedir(), ".claude", filename),
        "utf8",
      );
      if (content.length > 1024 * 1024) {
        evidence.push(`${filename} 超过 1 MB，跳过读取`);
        continue;
      }
      const parsed = JSON.parse(content);
      const selected = selectedEnvironment(parsed.env || {});
      const diagnosis = proxyDiagnostics(parsed.env || {});
      if (diagnosis.status === "review") {
        issueCount += diagnosis.evidence.length;
        evidence.push(
          ...diagnosis.evidence.map((line) => `${filename}：${line}`),
        );
      }
      if (parsed.env?.NODE_TLS_REJECT_UNAUTHORIZED === "0") {
        issueCount++;
        evidence.push(`${filename}：关闭了 Node 证书校验。`);
      }
      evidence.push(`${filename}：存在`);
      for (const [key, value] of Object.entries(selected))
        evidence.push(`${filename} / ${key}：${value}`);
    } catch (error) {
      if (error.code !== "ENOENT")
        evidence.push(`${filename}：未能读取有效 JSON`);
    }
  }
  return { evidence, issueCount };
}

function udpExit() {
  return new Promise((resolve) => {
    const tx = randomBytes(12),
      packet = Buffer.alloc(20),
      magic = Buffer.from([0x21, 0x12, 0xa4, 0x42]);
    packet.writeUInt16BE(1, 0);
    magic.copy(packet, 4);
    tx.copy(packet, 8);
    const socket = createSocket("udp4");
    let done = false;
    const timer = setTimeout(() => finish(null), 3500);
    function finish(ip) {
      if (done) return;
      done = true;
      clearTimeout(timer);
      socket.close();
      resolve(ip);
    }
    socket.on("error", () => finish(null));
    socket.on("message", (message) => {
      if (
        message.length < 20 ||
        message.readUInt16BE(0) !== 0x101 ||
        !message.subarray(8, 20).equals(tx)
      )
        return;
      const end = Math.min(message.length, 20 + message.readUInt16BE(2));
      for (let at = 20; at + 4 <= end;) {
        const type = message.readUInt16BE(at),
          size = message.readUInt16BE(at + 2),
          start = at + 4;
        if (start + size > end) break;
        if (
          (type === 0x20 || type === 1) &&
          size >= 8 &&
          message[start + 1] === 1
        ) {
          const bytes = [...message.subarray(start + 4, start + 8)].map(
            (b, i) => (type === 0x20 ? b ^ magic[i] : b),
          );
          return finish(bytes.join("."));
        }
        at = start + ((size + 3) & ~3);
      }
    });
    socket.send(packet, 3478, "stun.cloudflare.com", (error) => {
      if (error) finish(null);
    });
  });
}

async function nodeTLS() {
  return new Promise((resolve) => {
    const request = https.get(
      "https://api.anthropic.com/v1/models",
      {
        timeout: 7000,
        rejectUnauthorized: true,
        headers: { "user-agent": `SCT-Network-Check/${VERSION}` },
      },
      (response) => {
        response.resume();
        resolve({ code: response.statusCode || 0 });
      },
    );
    request.once("timeout", () =>
      request.destroy(
        Object.assign(new Error("timeout"), { code: "ETIMEDOUT" }),
      ),
    );
    request.once("error", (error) =>
      resolve({
        error: String(error.code || "UNKNOWN")
          .replace(/[^A-Z0-9_]/g, "")
          .slice(0, 80),
      }),
    );
  });
}

export async function collect({ offline = false, onCheck = () => {} } = {}) {
  const checks = [],
    exits = [];
  const add = (item) => {
    checks.push(item);
    onCheck(item);
  };
  const check = (id, title, status, summary, evidence, action) =>
    add({ id, title, status, summary, evidence, action });
  const timeZone = Intl.DateTimeFormat().resolvedOptions().timeZone || "未知";
  const createdAt = new Date().toISOString();
  check(
    "runtime",
    "系统与运行时",
    "info",
    "记录本次检测器运行的环境。",
    [
      `系统：${platform()} ${release()} / ${process.arch}`,
      `Node.js：${process.version}`,
      `时区：${timeZone}`,
      `系统时间：${createdAt}`,
    ],
    "本工具的 Node.js／curl 请求不等于 Claude 桌面或 Bun 原生客户端的全部网络行为；时区差异不单独判为问题。",
  );
  const selected = selectedEnvironment(process.env);
  const hasInvalid = proxyKeys.some((key) =>
    selected[key]?.includes("无法识别"),
  );
  check(
    "proxy-env",
    "终端代理与网络变量",
    hasInvalid ? "review" : "info",
    Object.keys(selected).length
      ? "已找到相关网络配置。"
      : "当前进程没有相关网络变量。",
    Object.entries(selected).map(([key, value]) => `${key}：${value}`),
    "未设置代理变量也可能正常使用 VPN／TUN。核对是否符合你的实际网络方案，不要为了“全绿”叠加代理。",
  );
  add(proxyDiagnostics(process.env));
  add(gatewayDiagnostic(process.env));
  const settings = await systemSettings();
  check(
    "system-proxy",
    "系统代理",
    "info",
    "读取操作系统可见的代理配置。",
    settings.evidence,
    "系统代理、终端环境变量和应用内设置可能独立生效；这里不自动修改任何一项。",
  );
  const interfaces = Object.entries(networkInterfaces()).filter(
    ([, addresses]) => addresses?.some((a) => !a.internal),
  );
  check(
    "interfaces",
    "网络接口与 IPv6",
    "info",
    "记录活动接口类型；不采集 MAC 地址。",
    interfaces.map(
      ([name, addresses]) =>
        `${name.slice(0, 80)}：${[...new Set(addresses.filter((a) => !a.internal).map((a) => a.family))].join(" / ")}`,
    ),
    "虚拟网卡本身不是故障。接口存在不代表流量经过它，IPv6 存在也不代表泄漏。",
  );
  const cliConfig = await claudeSettings();
  check(
    "client-config",
    "Claude Code 用户网络配置",
    cliConfig.issueCount ? "review" : "info",
    cliConfig.issueCount
      ? `发现 ${cliConfig.issueCount} 项用户网络配置问题。`
      : cliConfig.evidence.length
        ? "已检查用户设置中的网络字段。"
        : "没有读取到 Claude Code 用户设置。",
    cliConfig.evidence,
    "只提取白名单中的网络字段，不读取凭据文件或对话。项目设置、桌面进程和其他客户端仍可能覆盖这些值。",
  );
  const tlsDisabled = process.env.NODE_TLS_REJECT_UNAUTHORIZED === "0";
  const certEvidence = [
    `Node 全局证书校验：${tlsDisabled ? "被环境变量关闭" : "未发现关闭标志"}`,
  ];
  let certMissing = false;
  for (const key of [
    "NODE_EXTRA_CA_CERTS",
    "SSL_CERT_FILE",
    "CURL_CA_BUNDLE",
    "CLAUDE_CODE_CLIENT_CERT",
    "CLAUDE_CODE_CLIENT_KEY",
  ]) {
    if (!process.env[key]) continue;
    try {
      await access(process.env[key]);
      certEvidence.push(`${key}：文件存在（路径隐藏）`);
    } catch {
      certMissing = true;
      certEvidence.push(`${key}：文件不可访问（路径隐藏）`);
    }
  }
  check(
    "cert-config",
    "证书信任配置",
    tlsDisabled || certMissing ? "review" : "info",
    tlsDisabled || certMissing
      ? "发现需要核对的证书设置。"
      : "未发现已关闭校验或不可访问的自定义 CA 文件。",
    certEvidence,
    "保持证书校验开启；企业网络需安装可信 CA。此项不是对所有客户端证书库的完整审计。",
  );
  if (offline) {
    check(
      "offline",
      "联网探测",
      "unknown",
      "本次使用离线模式，没有发起网络请求或本地端口连接。",
      [],
      "移除 --offline 后可检查 DNS、监听端口和 HTTPS／STUN 连接。",
    );
  } else {
    const listeners = await localProxyListeners(process.env);
    check(
      "proxy-listeners",
      "环境变量指定的本地代理端口",
      listeners.some((p) => !p.ok)
        ? "review"
        : listeners.length
          ? "ok"
          : "info",
      listeners.length
        ? "已尝试连接明确配置的本机代理端口。"
        : "环境变量未指定本机代理端口，无需扫描。",
      listeners.map(
        (p) =>
          `${p.endpoint}：${p.ok ? "可以建立 TCP 连接" : "未能建立 TCP 连接"}`,
      ),
      "能连接端口不代表代理上游正常；连接失败时检查代理是否运行、端口是否填对。不会扫描其他本地端口。",
    );
    const resolver = new Resolver({ timeout: 1800, tries: 1 });
    const domains = [
      "claude.ai",
      "api.anthropic.com",
      "platform.claude.com",
      "downloads.claude.ai",
    ];
    let dnsSuccess = 0;
    const dnsEvidence = [...settings.dns.map((ip) => `系统 DNS：${ip}`)];
    await Promise.all(
      domains.map(async (domain) => {
        try {
          const addresses = await resolver.resolve4(domain);
          if (addresses.length) dnsSuccess++;
          dnsEvidence.push(`${domain} A：${addresses.join("、")}`);
        } catch {
          dnsEvidence.push(`${domain} A：本次未解析成功`);
        }
      }),
    );
    check(
      "dns",
      "Claude 域名 DNS 解析",
      dnsSuccess === domains.length ? "ok" : dnsSuccess ? "review" : "error",
      `${dnsSuccess}/${domains.length} 个 Claude 域名解析成功。`,
      dnsEvidence,
      "198.18.0.0/15 可能是代理的 fake-IP，不单独判错。配置和解析结果不能证明 DNS 是否泄漏；本工具没有权威 DNS 侧观测。",
    );
    const probes = [
      [
        "sct",
        "SCT 检测站",
        "https://sctcamp.com/api/network-check/echo",
        true,
        false,
      ],
      [
        "sct-no-proxy",
        "不使用应用代理的 SCT 对照",
        "https://sctcamp.com/api/network-check/echo",
        true,
        true,
      ],
      ["ipv4", "IPv4 目标连接", "https://1.1.1.1/cdn-cgi/trace", true, false],
      [
        "ipv6",
        "IPv6 目标连接",
        "https://[2606:4700:4700::1111]/cdn-cgi/trace",
        true,
        false,
      ],
      [
        "anthropic",
        "Anthropic API",
        "https://api.anthropic.com/v1/models",
        false,
        false,
      ],
      [
        "openai",
        "OpenAI API",
        "https://api.openai.com/v1/models",
        false,
        false,
      ],
      [
        "claude-login",
        "Claude 登录与授权",
        "https://platform.claude.com/",
        false,
        false,
      ],
      ["claude-signin", "Claude 登录入口", "https://claude.com/", false, false],
      [
        "claude-download",
        "Claude 安装与更新",
        "https://downloads.claude.ai/claude-code-releases/latest",
        false,
        false,
      ],
      ["claude-web", "Claude 网页端点", "https://claude.ai/", false, false],
      ["chatgpt-web", "ChatGPT 网页端点", "https://chatgpt.com/", false, false],
    ];
    // 两批并发控制探测量；所有请求固定目标、不带账号鉴权、不读取 .curlrc。
    for (let offset = 0; offset < probes.length; offset += 4)
      await Promise.all(
        probes
          .slice(offset, offset + 4)
          .map(async ([id, title, url, body, noProxy]) => {
            const result = await curl(url, { body, noProxy });
            const classification = classifyHTTP(
              result.http,
              result.code,
              result.tls,
            );
            const evidence = [
              `目标：${url}`,
              `HTTP：${result.http || "未取得"}`,
              `总耗时：${result.ms} ms`,
              noProxy
                ? "未使用应用代理，仍可能经过 VPN／TUN。"
                : "curl 依当前进程的代理环境变量发起请求；不自动应用操作系统桌面代理。",
            ];
            if (body && result.http === 200 && !result.code) {
              try {
                if (id.startsWith("sct")) {
                  const data = JSON.parse(result.body);
                  if (isIP(data.ip)) {
                    exits.push({
                      label: title,
                      ip: data.ip,
                      source: noProxy ? "sct-no-proxy" : "sct-echo",
                    });
                    evidence.push(`出口：${data.ip}`);
                  } else {
                    classification.status = "unknown";
                    classification.summary =
                      "请求完成，但检测站没有返回有效出口地址。";
                  }
                } else {
                  const data = Object.fromEntries(
                    result.body
                      .trim()
                      .split("\n")
                      .map((line) => {
                        const n = line.indexOf("=");
                        return [line.slice(0, n), line.slice(n + 1)];
                      }),
                  );
                  if (isIP(data.ip)) {
                    exits.push({
                      label: title,
                      ip: data.ip,
                      country: data.loc,
                      source: id,
                    });
                    evidence.push(
                      `出口：${data.ip}`,
                      `地区代码：${data.loc || "未知"}`,
                    );
                  } else {
                    classification.status = "unknown";
                    classification.summary = "检测端点没有返回有效出口信息。";
                  }
                }
              } catch {
                classification.status = "unknown";
                classification.summary = "检测端点响应格式无法识别。";
              }
            }
            if (id === "ipv6")
              classification.action =
                "IPv6 目标不可达不一定是故障，代理也可能代连 IPv6；结合接口信息和实际应用是否正常来判断。";
            check(
              id,
              title,
              classification.status,
              classification.summary,
              evidence,
              classification.action,
            );
          }),
      );
    // 外部信息只存白名单字段，不写入原始网络包、会话随机数或供应商响应全文。
    const supplemental = [
      [
        "transport-fingerprint",
        "本地 curl 的 TCP / TLS 网络指纹",
        "https://tls.peet.ws/api/all",
      ],
      [
        "claude-status",
        "Claude 官方服务状态",
        "https://status.claude.com/api/v2/summary.json",
      ],
    ];
    const ip = exits.find((e) => e.source === "ipv4")?.ip;
    if (ip)
      supplemental.push([
        "ip-profile",
        "出口 IP、ASN 与运营商",
        `https://api.ipapi.is/?q=${encodeURIComponent(ip)}`,
      ]);
    await Promise.all(
      supplemental.map(async ([id, title, url]) => {
        try {
          const result = await curl(url, { body: true });
          if (result.code || result.http !== 200)
            throw new Error(`HTTP ${result.http} / curl ${result.code}`);
          const data = JSON.parse(result.body);
          if (id === "transport-fingerprint") add(fingerprintCheck(data));
          else if (id === "ip-profile") add(metadataCheck(data, ip));
          else {
            const components = (data.components || []).filter((c) =>
              /claude.ai|Claude API|Claude Code|Claude Console/.test(
                c.name || "",
              ),
            );
            if (!components.length) throw new Error("官方状态格式无法识别");
            const bad =
              components.some((c) => c.status !== "operational") ||
              (data.incidents || []).length > 0;
            check(
              id,
              title,
              bad ? "review" : "ok",
              bad
                ? "官方报告存在服务异常或事故。"
                : "官方报告 Claude 服务运行正常。",
              components.map((c) => `${c.name}：${c.status}`),
              "访问 status.claude.com 查看最新进展；与本机结果对照。",
            );
          }
        } catch (error) {
          check(
            id,
            title,
            "unknown",
            "本次未取得有效结果。",
            [String(error.message).slice(0, 180)],
            "没有记为正常；检查端点连接或供应商调用额度后复测。",
          );
        }
      }),
    );
    if (!ip)
      check(
        "ip-profile",
        "出口 IP、ASN 与运营商",
        "unknown",
        "缺少有效的 IPv4 出口。",
        [],
        "先处理 IPv4 检测失败。",
      );
    const series = [];
    for (let i = 0; i < 3; i++)
      series.push(await curl("https://api.anthropic.com/v1/models"));
    const successes = series.filter(
      (r) => !r.code && ((r.http >= 200 && r.http < 400) || r.http === 401),
    );
    check(
      "claude-stability",
      "Claude API 连续连接",
      successes.length === 3 ? "ok" : successes.length ? "review" : "error",
      `${successes.length}/3 次取得正常或需鉴权的响应。`,
      series.map(
        (r, i) =>
          `第 ${i + 1} 次：HTTP ${r.http || "无响应"} / curl ${r.code} / ${r.ms} ms`,
      ),
      successes.length === 3
        ? "本轮连续连接稳定。"
        : "查看每次 HTTP 状态与 curl 错误，检查线路稳定性、代理或服务拒绝原因。",
    );
    const [stunIP, tls] = await Promise.all([udpExit(), nodeTLS()]);
    if (stunIP)
      exits.push({ label: "本地 UDP / STUN", ip: stunIP, source: "stun" });
    check(
      "stun",
      "UDP / STUN 网络出口",
      stunIP ? "info" : "unknown",
      stunIP ? "已取得本地 UDP 请求的公网出口。" : "本次没有取得 STUN 结果。",
      stunIP ? [`出口：${stunIP}`] : ["目标：stun.cloudflare.com:3478"],
      "本地 UDP 不等于浏览器 WebRTC。不同出口可能来自分流或多线路；没有响应也可能是 UDP 被拦截，不能直接判定泄漏。",
    );
    check(
      "node-tls",
      "Node.js HTTPS 与证书校验",
      tls.error ? "error" : classifyHTTP(tls.code).status,
      tls.error
        ? "Node.js 网络栈未完成 HTTPS 请求。"
        : `Node.js 已收到 HTTP ${tls.code} 响应。`,
      tls.error
        ? [`错误类型：${tls.error}`]
        : [
            "目标：api.anthropic.com/v1/models",
            "本次强制启用证书校验；未附带 API Key。",
          ],
      "此探测不自动使用代理环境变量，仍可能经过 VPN／TUN；它与 curl 和原生 Claude Code 的网络行为可能不同，不能等同于客户端实际请求。",
    );
  }
  return {
    schemaVersion: 1,
    product: "sct-network-check",
    version: VERSION,
    mode: "local",
    createdAt,
    checks,
    observations: {
      exits,
      timeZone,
      platform: `${platform()} ${process.arch}`,
    },
  };
}
