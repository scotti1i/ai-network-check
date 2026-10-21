// 仅分析允许的网络字段；不回显认证、路径、NO_PROXY 规则或账号资料。
export function proxyDiagnostics(env) {
  const names = ["https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY"];
  const configured = names.filter((k) => env[k]);
  const issues = [];
  for (const key of configured) {
    try {
      const u = new URL(env[key]);
      if (!["http:", "https:"].includes(u.protocol))
        issues.push(
          `${key} 使用 Claude Code 不支持的代理协议；请配置 HTTP/HTTPS 代理。`,
        );
    } catch {
      issues.push(`${key} 不是有效的完整代理 URL。`);
    }
  }
  if (!configured.length && (env.ALL_PROXY || env.all_proxy))
    issues.push(
      "只有 ALL_PROXY：curl 可能使用它，Claude Code 的官方 HTTP/HTTPS 代理配置不使用它。",
    );
  if (new Set(configured.map((k) => env[k])).size > 1)
    issues.push(
      `多个代理变量值不同，Claude Code 优先读取 ${configured[0]}；curl 或其他工具可能使用不同变量。`,
    );
  for (const key of ["no_proxy", "NO_PROXY"]) {
    if (!env[key]) continue;
    const rules = env[key].split(/[\s,]+/).filter(Boolean);
    const hits = [
      "api.anthropic.com",
      "claude.ai",
      "platform.claude.com",
    ].filter((host) =>
      rules.some((rule) => {
        const value = rule
          .toLowerCase()
          .replace(/:\d+$/, "")
          .replace(/^\*/, "");
        return (
          rule === "*" ||
          host === value ||
          (value.startsWith(".") && host.endsWith(value))
        );
      }),
    );
    if (hits.length)
      issues.push(`${key} 会让这些目标绕过应用代理：${hits.join("、")}`);
  }
  return {
    id: "proxy-compat",
    title: "Claude Code 代理兼容与冲突",
    status: issues.length ? "review" : "ok",
    summary: issues.length
      ? `发现 ${issues.length} 个代理配置问题。`
      : "未发现代理协议、优先级或 Claude 域名绕过冲突。",
    evidence: issues.length
      ? issues
      : ["核对 HTTPS/HTTP 变量、ALL_PROXY、NO_PROXY 和官方代理优先级。"],
    action: issues.length
      ? "按证据核对代理配置；修改后重新启动 Claude Code 再测。"
      : "保持现有网络方案；没有代理变量时，也可能由系统 VPN/TUN 承载。",
  };
}

export function gatewayDiagnostic(env) {
  const value = env.ANTHROPIC_BASE_URL;
  let custom = false,
    invalid = false;
  if (value) {
    try {
      const url = new URL(value);
      invalid = url.protocol !== "https:";
      custom = url.hostname !== "api.anthropic.com";
    } catch {
      invalid = true;
    }
  }
  return {
    id: "gateway",
    title: "Claude API 地址与中转配置",
    status: invalid ? "review" : "info",
    summary: invalid
      ? "ANTHROPIC_BASE_URL 格式无效或未使用 HTTPS。"
      : custom
        ? "已配置自定义 API 地址，当前使用的是网关／中转路线。"
        : "未发现自定义 Anthropic API 主机。",
    evidence: [`自定义地址：${value ? "已配置（原文不回显）" : "未配置"}`],
    action: custom
      ? "核对网关的模型、鉴权与代理要求。固定官方端点检测不能替代此网关的功能验收。"
      : "官方直连使用 api.anthropic.com；本工具不读取 API Key。",
  };
}

export function fingerprintCheck(data) {
  if (!data?.tls || !data?.tcpip)
    throw new Error("指纹服务没有返回 TLS/TCP 数据");
  const safe = (v) =>
    typeof v === "string" || typeof v === "number"
      ? String(v).slice(0, 400)
      : "未提供";
  const tcp = data.tcpip.tcp_syn || {};
  return {
    id: "transport-fingerprint",
    title: "本地 curl 的 TCP / TLS 网络指纹",
    status: "info",
    summary: `TLS ${{ 771: "1.2", 772: "1.3" }[data.tls.tls_version_negotiated] || safe(data.tls.tls_version_negotiated)} · ${safe(data.http_version)} · 已取得网络层观测`,
    evidence: [
      `JA3：${safe(data.tls.ja3_hash)}`,
      `JA4：${safe(data.tls.ja4)}`,
      `p0f：${safe(data.tcpip.p0f)}`,
      `TCP SYN TTL：${safe(tcp.ttl)}`,
      `TCP 窗口：${safe(tcp.window)} · MSS：${safe(tcp.mss)}`,
      `TCP 选项顺序：${safe(tcp.option_order)}`,
      "来源：tls.peet.ws；这是本次 curl 请求，目标可能看到代理出口的 TCP 栈。",
    ],
    action:
      "与网页浏览器的网络行为分开看。p0f 签名不直接等于操作系统型号，更不能证明 Claude 的设备封禁或风控分。",
  };
}

export function metadataCheck(data, expectedIP) {
  if (!data?.ip || data.ip !== expectedIP || data.error)
    throw new Error("IP 归属查询未返回匹配的数据");
  const value = (v) =>
    typeof v === "string" || typeof v === "number"
      ? String(v).slice(0, 160)
      : "未知";
  const location = data.location || data;
  const asn =
    typeof data.asn === "object"
      ? `AS${value(data.asn?.asn)} ${value(data.asn?.org)}`
      : value(data.asn);
  const company =
    typeof data.company === "object"
      ? value(data.company?.name)
      : value(data.company);
  return {
    id: "ip-profile",
    title: "出口 IP、ASN 与运营商",
    status: "info",
    summary: `${value(location.country)} · ${asn}`,
    evidence: [
      `出口：${expectedIP}`,
      `城市：${value(location.city)}`,
      `归属：${company}`,
      `数据库时区：${value(location.timezone)}`,
      "来源：ipapi.is；匿名查询没有住宅/机房、VPN 或滥用信誉标记。",
    ],
    action:
      "用 ASN 与归属核对线路供应商的描述；没有信誉数据库结果时，不给纯净或住宅 IP 认证。",
  };
}
