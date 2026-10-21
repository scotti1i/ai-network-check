import test from "node:test";
import assert from "node:assert/strict";
import {
  classifyHTTP,
  collect,
  maskText,
  safeEndpoint,
  selectedEnvironment,
} from "../src/core.mjs";
import { renderHTML } from "../src/html.mjs";

test("401 是未鉴权；403、429 和 5xx 不推断成封号", () => {
  assert.equal(classifyHTTP(401).status, "ok");
  for (const status of [403, 429, 503]) {
    assert.equal(classifyHTTP(status).status, "review");
    assert.doesNotMatch(classifyHTTP(status).summary, /被封|封禁|泄漏/);
  }
  assert.equal(classifyHTTP(0, 28).status, "error");
  assert.equal(classifyHTTP(0, 60).status, "error");
  assert.match(classifyHTTP(0, 60).action, /不要关闭/);
});

test("网络配置只输出白名单，不泄露认证和查询参数", () => {
  const output = JSON.stringify(
    selectedEnvironment({
      HTTPS_PROXY:
        "http://username:fake-password@127.0.0.1:7890/private?token=fake-token",
      ANTHROPIC_API_KEY: "fake-api-key",
      ANTHROPIC_BASE_URL:
        "https://fake-user:fake-secret@example.com/v1?key=hidden",
      NO_PROXY: "private-company.example",
      NODE_EXTRA_CA_CERTS: "/Users/private-person/company.pem",
    }),
  );
  assert.match(output, /127\.0\.0\.1:7890/);
  for (const value of [
    "fake-password",
    "fake-token",
    "fake-api-key",
    "fake-secret",
    "fake-user",
    "private-company",
    "private-person",
    "?key",
    "/v1",
  ])
    assert.ok(!output.includes(value), value);
  assert.equal(
    safeEndpoint("not a proxy"),
    "已设置（地址格式无法识别，未回显原文）",
  );
});

test("分享脱敏保留时间格式，隐藏 IPv4 和 IPv6 地址", () => {
  assert.equal(maskText("IP: 203.0.113.42"), "IP: 203.0.x.x");
  assert.equal(maskText("IP: 2001:4860:4860::8888"), "IP: 2001:4860:…");
  assert.equal(
    maskText("2026-10-21T08:10:15.000Z"),
    "2026-10-21T08:10:15.000Z",
  );
});

test("离线报告形状完整，默认不包含主目录或凭据", async () => {
  const report = await collect({ offline: true });
  assert.equal(report.product, "sct-network-check");
  assert.equal(report.mode, "local");
  assert.equal(report.schemaVersion, 1);
  assert.ok(
    report.checks.some((c) => c.id === "offline" && c.status === "unknown"),
  );
  assert.equal(report.observations.exits.length, 0);
  assert.ok(
    report.checks.every((c) =>
      ["ok", "review", "info", "unknown", "error"].includes(c.status),
    ),
  );
  assert.ok(
    !JSON.stringify(report).includes(
      process.env.HOME || "THIS_SHOULD_NOT_MATCH",
    ),
  );
});

test("HTML 中的配置文本不能闭合 script 注入代码", () => {
  const report = {
    observations: { platform: "test" },
    checks: [
      {
        title: "</script><img src=x onerror=alert(1)>",
        summary: "x",
        evidence: [],
        action: "x",
        status: "info",
      },
    ],
  };
  const html = renderHTML(report);
  assert.ok(!html.includes("</script><img"));
  assert.ok(html.includes("connect-src 'none'"));
  assert.equal((html.match(/<script>/g) || []).length, 1);
});

test("代理兼容检查发现 SOCKS、优先级、ALL_PROXY 和 Claude 绕过规则，不回显秘密", async () => {
  const { proxyDiagnostics, gatewayDiagnostic } =
    await import("../src/diagnostics.mjs");
  const result = proxyDiagnostics({
    HTTPS_PROXY: "socks5://user:fake-secret@localhost:7890",
    https_proxy: "http://localhost:8000",
    NO_PROXY: ".anthropic.com",
  });
  assert.equal(result.status, "review");
  assert.match(result.evidence.join(" "), /不支持|优先读取|绕过/);
  assert.doesNotMatch(JSON.stringify(result), /fake-secret/);
  assert.equal(
    proxyDiagnostics({ ALL_PROXY: "socks5://localhost:7890" }).status,
    "review",
  );
  assert.equal(
    proxyDiagnostics({ HTTPS_PROXY: "http://localhost:7890" }).status,
    "ok",
  );
  assert.equal(
    gatewayDiagnostic({
      ANTHROPIC_BASE_URL: "http://example.com/v1?key=private",
    }).status,
    "review",
  );
  assert.doesNotMatch(
    JSON.stringify(
      gatewayDiagnostic({
        ANTHROPIC_BASE_URL: "https://example.com/?key=private",
      }),
    ),
    /private/,
  );
});

test("TCP/TLS 报告只存指定字段，不复制网络包和会话资料", async () => {
  const { fingerprintCheck, metadataCheck } =
    await import("../src/diagnostics.mjs");
  const result = fingerprintCheck({
    http_version: "h2",
    tls: {
      ja3_hash: "test",
      client_random: "private-random",
      session_id: "private-session",
    },
    tcpip: {
      p0f: "signature",
      ip: { src_ip: "8.8.8.8" },
      tcp_syn: { ttl: 64, window: 65535 },
    },
  });
  assert.equal(result.status, "info");
  assert.doesNotMatch(
    JSON.stringify(result),
    /private-random|private-session|8\.8\.8\.8/,
  );
  assert.throws(() => fingerprintCheck({}));
  assert.throws(() => metadataCheck({ ip: "1.1.1.1" }, "8.8.8.8"));
});
